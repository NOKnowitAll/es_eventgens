"""
Copyright (C) 2005 - 2015 Splunk Inc. All Rights Reserved.
"""
import errno
import hashlib
import json
import logging
import lxml
import os
import re
import StringIO
import sys
import time
import urllib

import splunk
import splunk.rest
import splunk.search
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.kvstore import KvStoreHandler
from SolnCommon.log import setup_logger
from SolnCommon.metadata import MetadataReader
from SolnCommon.modinput import BooleanField
from SolnCommon.modinput import Field
from SolnCommon.modinput import IntegerField
from SolnCommon.modinput import ModularInput
from SolnCommon.pathutils import construct_os_path, expandvars_restricted
from SolnCommon.pooling import should_execute

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-ThreatIntelligence", "contrib"]))

from parsers.parser_exceptions import ParserConfigurationException, ParserEmptyException, ParserException
from parsers.ioc_parser import IOCParser
from parsers.csv_parser import CSVParser
from parsers.utils import IntelUtils, LookupUtils, ParserUtils
from parsers.stix_parser import STIXParser

logger = setup_logger(name='threat_intelligence_manager', level=logging.INFO)

# Reroute warnings from python-stix
logging.captureWarnings(True)
warn_logger = logging.getLogger('py.warnings')
warn_logger.propagate = False
warn_logger.handlers = [logger.handlers[0]]


class ThreatIntelMeta(object):

    def __init__(self, app, collection, kv, owner):
        '''Initialize a class for handling of threat intel metadata.

        Arguments:
        app - The app where the metadata collection is housed.
        collection - The name of the collection.
        kv - a KVStoreHandler object.
        owner - The owner of the collection
        '''
        self._app = app
        self._collection = collection
        self._kv = kv
        self._owner = owner

    def get_threatlist_metadata(self, excludes_list, session_key):
        '''Retrieve the last update time of threat intelligence download stanzas as recorded in local.meta.'''

        excludes_search = 'NOT ' + '(' + ' OR '.join(['type="%s"' % i for i in excludes_list]) + ')'

        getargs = {'output_mode': 'json',
                 'search': excludes_search,
                 'count': 0}

        update_times = {}
        response, content = splunk.rest.simpleRequest('/services/data/inputs/threatlist', getargs=getargs, sessionKey=session_key)
        if response.status == 200:
            if content:
                entries = [(i['name'], i['acl']['app']) for i in json.loads(content)['entry']]
                for stanza, app in entries:
                    try:
                        update_times[stanza] = MetadataReader.get_float('inputs', urllib.quote_plus('threatlist://' + stanza), app, 'modtime')
                    except ValueError:
                        update_times[stanza] = 0
        return update_times

    def get_intel_metadata(self, session_key):
        '''Retrieve the last update time from threat_intel_meta.'''
        options = {'collection': self._collection,
                   'app': self._app,
                   'owner': self._owner}
        response, content = self._kv.get('', session_key, options)

        if response.status == 200:
            if content:
                return {i['_key']: i['time'] for i in json.loads(content)}
            else:
                return {}
        else:
            # This will force threat intelligence updates to occur.
            logger.error('Error when getting threat intel metadata.')
            return {}

    def set_intel_metadata(self, collections, session_key):
        '''Update the threat_intel_meta collection with the current time.'''
        records = [{'_key': c} for c in collections]
        options = {'collection': 'threat_intel_meta',
                   'app': self._app,
                   'owner': self._owner}
        response, content = self._kv.batch_create(records, session_key, options, include_ts=True, time_field='time')

        if response.status != 200:
            logger.error('Error when setting threat intel metadata.')

        return response, content


class ThreatIntelligenceManagerModularInput(ModularInput):

    def __init__(self):

        scheme_args = {'title': "Threat Intelligence Manager",
                       'description': "Merges threat information into Threat Intelligence KV Store collections.",
                       'use_external_validation': "true",
                       'streaming_mode': "xml",
                       'use_single_instance': "true"}

        args = [IntegerField("maxsize", "Maximum size", "The maximum size of a single threat intelligence document.", required_on_create=False, required_on_edit=False),
                IntegerField("default_weight", "Default weight", "A default weight assigned to all threat intelligence documents consumed from this directory.", required_on_create=False, required_on_edit=False),
                Field("directory", "Directory", "A directory from which to consume threat intelligence documents.", required_on_create=True, required_on_edit=True),
                BooleanField("sinkhole", "Sinkhole", "If True, delete threat intelligence documents after processing. Defaults to False.", required_on_create=True, required_on_edit=True),
                BooleanField("remove_unusable", "Remove unusable threat documents", "If True, remove unusable threat documents. Defaults to True", required_on_create=False, required_on_edit=False)]

        self._name = 'ThreatIntelligenceManager'

        self.ACCEPTED_ENVVARS = ['SPLUNK_HOME', 'SPLUNK_DB']
        self.DEFAULT_APP = 'DA-ESS-ThreatIntelligence'
        self.DEFAULT_CHECKPOINT = 'default'
        self.DEFAULT_COLLECTIONS = {
            'certificate_intel': 0,
            'email_intel': 0,
            'file_intel': 0,
            'http_intel': 0,
            'ip_intel': 0,
            'process_intel': 0,
            'registry_intel': 0,
            'service_intel': 0,
            'user_intel': 0}
        self.DEFAULT_MAXSIZE = 50 * 1024 * 1024  # 50MB
        self.DEFAULT_THREATGROUP_COLLECTION = 'threat_group_intel'
        self.DEFAULT_METADATA_COLLECTION = 'threat_intel_meta'
        self.DEFAULT_OWNER = 'nobody'
        self.DEFAULT_TIMEOUT = 120  # Timeout for running threat intelligence updating searches.

        self.EXIT_SUCCESS = 0           # Everything is OK.
        self.EXIT_INVALID_DIR = 1       # Attempt to read from invalid directory.
        self.EXIT_LIMITS_UNKNOWN = 2    # Could not determine limits.conf settings for KV store.
        self.EXIT_INVALID_CONFIG = 3    # Invalid configuration received.
        self.EXIT_MULTIPLE_ERRORS = 4   # Invalid configuration received.
        self.EXIT_CHECKPOINT_ERR = 5    # Unable to delete the force_refresh checkpoint file.
        self.EXIT_SENTINEL = 6          # Exit status is initially set to this.

        # Upgrade handling
        self.REFRESH_CHECKPOINT = 'force_refresh'

        self.LOCAL_LOOKUP_STANZA = 'local_lookups'

        # Supported file format identifiers.
        self.FORMAT_CSV = '.csv'
        self.FORMAT_IOC = '.ioc'
        self.FORMAT_TXT = '.txt'
        self.FORMAT_XML = '.xml'

        # Namespace Detection for XML documents
        self.NS_IOC = 'ioc'              # IOC: {http://schemas.mandiant.com/2010/ioc}ioc
        self.NS_STIX = 'STIX_Package'    # STIX Package: {http://stix.mitre.org/stix-1}STIX_Package
        self.NS_TAXII = 'Poll_Response'  # TAXII Poll Response: {http://taxii.mitre.org/messages/taxii_xml_binding-1.1}Poll_Response

        self.FORMATS = {self.FORMAT_CSV: CSVParser,
                        self.NS_IOC: IOCParser,
                        self.NS_STIX: STIXParser,
                        self.NS_TAXII: STIXParser}

        # Results dictionary.
        self._emptyresults = {'discarded': 0,      # Discarded document; no available handler.
                              'empty': 0,          # Empty document; no observables or indicators found.
                              'failed': 0,         # Failed for unknown reasons.
                              'ignored': 0,        # Ignored due to file having already been processed previously.
                              'processed': 0,      # Total count of files processed.
                              'deleted': 0,        # Total count of files removed after processing, if sinkhole option is enabled.
                              'size_exceeded': 0,  # Exceeded maximum allowed size.
                              'success': 0,        # Successfully processed.
                              'rejected': 0}       # Valid document was rejected due to invalid format (bad XML etc.)
        self._results = None
        self._exit_status = {}  # Container for per-stanza exit status.

        self._kvstore_limits = {}  # Container for KVStore limits.conf settings.
        self._maxsize = self.DEFAULT_MAXSIZE
        self._stanza_name = None  # Assigned in run()
        self._collections_updated = set()  # Container for storing the list of updated collections.

        super(ThreatIntelligenceManagerModularInput, self).__init__(scheme_args, args)

        self.hash_alg = hashlib.sha1
        self._parsers = {}

    def collect_local_threatlists(self, basepath):
        '''Collect filenames of any locally-defined threatlists that have been
        modified recently.

        Returns:
            A list of filenames based from $SPLUNK_HOME/etc/apps.
        '''
        lookup_name_rx = re.compile('^lookup://(\S+)$')
        filenames = {}

        try:
            unused_response, content = splunk.rest.simpleRequest('/services/data/inputs/threatlist',
                sessionKey=self._input_config.session_key,
                getargs={'output_mode': 'json',
                         'search': 'url="lookup*" AND disabled="false"'})

            lookups = [(i['name'], i['acl']['app'], i['content']['url']) for i in json.loads(content)['entry']]

            for stanza_name, namespace, lookup_url in lookups:
                transform_name = lookup_name_rx.findall(lookup_url)[0]
                try:
                    filepath = LookupUtils.get_lookup_file_location(namespace, transform_name, self._input_config.session_key)
                    if os.path.commonprefix([basepath, filepath]):
                        filenames[stanza_name] = filepath.replace(basepath, '').lstrip(r'\/')
                except splunk.ResourceNotFound:
                    logger.exception('Error retrieving local threatlist lookup path: transform="%s".', transform_name)

        except (KeyError, ValueError):
            logger.exception('Error retrieving local threatlist lookup paths.')

        return filenames

    def process_file(self, filename, last_run):
        '''Route an individual file to the appropriate handler routine based on
        file extension.

        Arguments:
            filename - A full path to a file.
        '''
        fstat = os.stat(filename)
        if fstat.st_size == 0:
            logger.info('status="Document size is zero." filename="%s"', filename)
            self._results['empty'] += 1
        elif fstat.st_size <= self._maxsize:
            parser, typ = self.detect_content(filename)
            if parser:
                self.process(filename, parser, typ, last_run)
            else:
                logger.error('status="Discarding invalid input file." stanza_name="%s" name="%s"', self._stanza_name, filename)
                self._results['discarded'] += 1
        else:
            logger.info('status="input file exceeded max size" stanza_name="%s" name="%s"', self._stanza_name, filename)
            self._results['size_exceeded'] += 1

    def detect_content(self, filename):
        '''Best-effort detection of the content type based on file name, or on
        simple regex match if the document is an XML document.'''

        fname = filename.lower()

        if fname.endswith(self.FORMAT_CSV):
            return self._parsers[self.FORMAT_CSV], self.FORMAT_CSV
        if fname.endswith(self.FORMAT_TXT):
            return self._parsers[self.FORMAT_CSV], self.FORMAT_CSV
        elif fname.endswith(self.FORMAT_IOC):
            return self._parsers[self.NS_IOC], self.NS_IOC
        elif fname.endswith(self.FORMAT_XML):
            with open(filename, 'r') as f:
                # Read in enough data to avoid getting an error as STIX packages
                # can load tons of other namespaces.
                tmp_data = f.read(10240)

                context = lxml.etree.iterparse(StringIO.StringIO(tmp_data), events=("start", "end"))
                unused_action, elem = context.next()

                if self.NS_IOC in elem.tag:
                    return self._parsers[self.NS_IOC], self.NS_IOC
                elif self.NS_STIX in elem.tag:
                    # Individual STIX package.
                    return self._parsers[self.NS_STIX], self.NS_STIX
                elif self.NS_TAXII in elem.tag:
                    # TAXII document containing possibly multiple STIX Packages.
                    return self._parsers[self.NS_STIX], self.NS_TAXII
                else:
                    # Default to attempting STIX parsing.
                    return self._parsers[self.NS_STIX], self.NS_STIX
        else:
            # Fall back to attempting line-oriented text parsing.
            return self._parsers[self.FORMAT_CSV], self.FORMAT_CSV

    def should_update(self, filename, hash_value, document_id, use_filename=False):
        '''Check to see if the document has previously been processed.

        Arguments:
            filename - The full path to the file.
            hash_value - The hash value of the current document.
            document_id - The ID of the current document
            use_filename - If True, construct the document ID using the filename.

        Note that document_id is usually retrieved by an initial parse of the
        document, but this is not strictly required if document IDs are being
        generated via some other mechanism (for instance, by simple file size or checksum).
        '''
        options = {'collection': 'threat_group_intel',
                   'app': self.DEFAULT_APP,
                   'owner': self.DEFAULT_OWNER}

        # The parser is responsible for assigning the value of _key so that updates
        # can be detected properly.
        if use_filename and filename:
            updated_document_id = '|'.join([document_id, os.path.basename(filename)])
        else:
            updated_document_id = document_id

        # Note that hash_value should be a string to make the KV store query -
        # so we convert here for those cases where the parser may be overloading
        # this field as an integer.
        query = {'$and': [{'_key': updated_document_id}, {'source_digest': str(hash_value)}]}

        try:
            _, content = self.kvstore_handler.query(query, self._input_config.session_key, options)
            if content and json.loads(content):
                # Found a previous entry for this document with the same hash
                # value, so skip update.
                return False
        except ValueError:
            # This is usually an error resulting from inability to access KV store.
            logger.exception('Could not retrieve document status. Skipping update: filename="%s" document_id="%s" hash_value="%s"', filename, document_id, hash_value)
            return False
        except splunk.ResourceNotFound:
            return True
        return True

    def initialize_parsers(self):

        for fmt, parser in self.FORMATS.items():
            try:
                self._parsers[fmt] = parser(self._input_config.session_key)
            except Exception:
                logger.exception('A parser configuration could not be retrieved - some parsing will be disabled: type="%s"', fmt)

    def process(self, filename, parser, typ, last_run):
        '''Process a document.

        Arguments:
            filename - A full path to an IOC document.
            parser - A Parser object.
        '''

        try:
            parser.preprocess(filename, typ)
        except IOError:
            logger.error('Rejected document due to IOError exception." filename="%s"', filename)
            self._results['failed'] += 1
        except ParserException:
            logger.error('Rejected document due to invalid format." filename="%s"', filename)
            self._results['rejected'] += 1
        except ParserConfigurationException:
            logger.error('Rejected document due to invalid parser configuration." filename="%s"', filename)
            self._results['rejected'] += 1
        except Exception:
            logger.exception('Rejected document due to unknown exception (traceback follows)." filename="%s"', filename)
            self._results['failed'] += 1

        if parser.is_valid:
            # Update logic:
            # 1. Stanza was updated.
            # 2. This is not a TAXII document and we think we should update it
            #    because the hash value has changed.
            # 3. This is a TAXII feed and we want to update it because the modtime
            #    has changed. We do not support update of individual STIX documents
            #    from a TAXII Poll_Response at this time because we haven't yet parsed
            #    the full document, so can't key on that here.
            updated = parser.stanza_updated(filename, last_run)
            nontaxii_changed = (typ != self.NS_TAXII and self.should_update(filename, parser.hash_value, parser.doc_id, parser.use_filename))
            taxii_changed = (typ == self.NS_TAXII and os.stat(filename).st_mtime > last_run)
            if updated or nontaxii_changed or taxii_changed:
                logger.debug('status="Processing document." filename="%s", doc_id="%s", hashval="%s"', filename, parser.doc_id, parser.hash_value)
                empty = True
                try:
                    for metadata, intel in parser.parse(self._kvstore_limits):
                        # Intel can be none if there were no observables or indicators.
                        # Avoid writing in this case.
                        if metadata and intel:
                            try:
                                self.write_output(filename, metadata, intel)
                                empty = False
                            except Exception:
                                logger.exception('status="Error when writing output - threat intelligence may be incomplete." filename="%s"', filename)
                        else:
                            # Continue to next package in document.
                            pass
                    if empty:
                        raise ParserEmptyException()
                    self._results['success'] += 1
                except ParserException:
                    logger.exception('status="Error when parsing document." filename="%s"', filename)
                    self._results['failed'] += 1
                except ParserConfigurationException:
                    logger.exception('status="Error when configuring parser." filename="%s"', filename)
                    self._results['failed'] += 1
                except ParserEmptyException:
                    logger.info('status="No observables or indicators found in file." filename="%s"', filename)
                    self._results['empty'] += 1
            else:
                logger.debug('status="Ignoring document with identical hash and ID." filename="%s", hashval="%s", id="%s"', filename, parser.hash_value, parser.doc_id)
                self._results['ignored'] += 1
        else:
            logger.info('status="Document invalid." filename="%s", hashval="%s"', filename, parser.hash_value)

    def write_output(self, filename, metadata, intel):
        '''Write threat intelligence to KV store collections.

        Arguments:
            filename - The input file name (used only for logging).
            metadata - A dictionary corresponding to an entry in the default metadata collection.
            intel -  A dictionary corresponding to entries in threat intelligence collections.

        Format of intel_dict is expected to be:

            {target_collection: [ {intel_dict}, {intel_dict} ...],
             target_collection: [ ... ],
             ... }

        Intel writes will be batched up to the limit imposed by max_documents_per_batch_save.
        The intel may be already batched in this manner by the parser but this is
        not required.

        '''

        # Write metadata.
        metadata_options = {'app': self.DEFAULT_APP, 'collection': self.DEFAULT_THREATGROUP_COLLECTION, 'owner': self.DEFAULT_OWNER}

        # Assign default weight to the artifact if one is defined.
        if self._default_weight is not None and not metadata.get('weight', False):
            try:
                metadata['weight'] = int(self._default_weight)
            except ValueError:
                logger.error('Invalid weight value for stanza %s', self._stanza_name)

        metadata_response, metadata_content = self.kvstore_handler.batch_create(metadata, self._input_config.session_key, metadata_options, include_ts=True, time_field='time')

        if metadata_response.status != 200:
            logger.info('status="Metadata could not be written - key may already exist.", collection="%s", filename="%s"', self.DEFAULT_THREATGROUP_COLLECTION, filename)
        else:
            logger.info('status="Wrote metadata to collection.", collection="%s", filename="%s"', self.DEFAULT_THREATGROUP_COLLECTION, filename)

        lim = int(self._kvstore_limits['max_documents_per_batch_save'])

        # Write threat intel in batches.
        for target_collection, intel_dicts in intel.iteritems():
            total = 0
            intel_options = {'app': self.DEFAULT_APP, 'collection': target_collection, 'owner': self.DEFAULT_OWNER}

            # Add the collection being updated to the list.
            self._collections_updated.add(target_collection)

            if intel:
                if len(intel_dicts) > lim:
                    for chunk in [intel_dicts[i:i + lim] for i in range(0, len(intel_dicts), lim)]:
                        logger.debug('CHUNK: %s', chunk)
                        intel_response, intel_content = self.kvstore_handler.batch_create(chunk, self._input_config.session_key, intel_options, include_ts=True, time_field='time')
                        if intel_response.status != 200:
                            logger.info('status="Some intel could not be written - a key may already exist.", collection="%s", filename="%s"', target_collection, filename)
                        else:
                            total += len(chunk)
                else:
                    logger.debug('CHUNK_DICT: %s', intel_dicts)
                    intel_response, intel_content = self.kvstore_handler.batch_create(intel_dicts, self._input_config.session_key, intel_options, include_ts=True, time_field='time')
                    if intel_response.status != 200:
                        logger.info('status="Intel could not be written - a key may already exist.", collection="%s", filename="%s"', target_collection, filename)
                    else:
                        total += len(intel_dicts)
            else:
                logger.info('status="Received empty intel for a target collection", collection="%s", filename="%s"', target_collection, filename)

            if total > 0:
                logger.info('status="Wrote records to collection", collection="%s", count="%s", filename="%s"', target_collection, total, filename)

    def process_files(self, directory, last_run, includes=None):
        '''Process all files in a directory.'''

        INVALID_PATHS = ['/', '/etc'
                         '$SPLUNK_HOME',
                         '$SPLUNK_HOME/etc',
                         '$SPLUNK_HOME/etc/apps',
                         '$SPLUNK_DB']
        INVALID_PATHS = [expandvars_restricted(i, self.ACCEPTED_ENVVARS) for i in INVALID_PATHS]

        if includes:
            pathgen = [(directory, None, includes)]
        elif os.path.normpath(directory) not in INVALID_PATHS:
            # Disallow processing of certain paths as this would indicate a misconfiguration.
            pathgen = os.walk(directory)
        else:
            logger.error('status="A stanza specified a restricted directory." directory="%s"', directory)
            pathgen = []

        for dirpath, unused_dirnames, filenames in pathgen:
            for filename in filenames:
                fullpath = os.path.join(dirpath, filename)
                self._results['processed'] += 1
                empty_document_count = self._results.get('empty', 0)

                try:
                    self.process_file(fullpath, last_run)
                except Exception:
                    logger.exception('status="Exception when processing file." filename="%s"', filename)
                    self._results['failed'] += 1

                # Explicitly prohibit sinkholing/remove_unusable of local lookup tables.
                if self._stanza_name != self.LOCAL_LOOKUP_STANZA:
                    # If empty document count has increased, the current
                    # document was empty. Mark it for deletion.
                    remove_unusable = (self._results['empty'] > empty_document_count) and self._remove_unusable
                    if self._sinkhole or remove_unusable:
                        try:
                            os.remove(fullpath)
                            self._results['deleted'] += 1
                        except IOError:
                            logger.error('status="Could not remove file after processing." filename="%s"', filename)

        if self._results['processed'] == 0:
            logger.info('status="No files found for processing."')

    def validate_directory(self, directory):
        '''Validate a directory as a container for threat intelligence. Relative paths
        are disallowed.'''

        relpath_rx = re.compile(r'[\/\\]\.+[\/\\]')
        normalized_dir = construct_os_path(directory)
        apps_dir = ThreatIntelligenceManagerModularInput.norm_path(make_splunkhome_path(["etc", "apps"]))
        threatdir_rx = re.compile(os.path.join(apps_dir + r'[\/\\].+?[\/\\](default|local)[\/\\]data[\/\\]threat_intel[\/\\]?$'))
        try:
            # Allow only $SPLUNK_HOME, $SPLUNK_DB replacements.
            normalized_dir = expandvars_restricted(directory, self.ACCEPTED_ENVVARS)
        except ValueError:
            logger.error('status="Invalid variable substitution" stanza_name="%s"', self._stanza_name)
            return None

        if normalized_dir:
            if os.path.isabs(normalized_dir) and not relpath_rx.search(normalized_dir):
                if not threatdir_rx.search(ThreatIntelligenceManagerModularInput.norm_path(normalized_dir)):
                    logger.error('status="Input directory path invalid. Must be in $SPLUNK_HOME/etc/apps/<app_name>/local/data/threat_intel" stanza_name="%s" directory="%s"', self._stanza_name, normalized_dir)
                    return None
                if os.path.isdir(normalized_dir):
                    logger.info('status="Found valid input directory" stanza_name="%s" directory="%s"', self._stanza_name, normalized_dir)
                    return normalized_dir
                elif not os.path.exists(normalized_dir):
                    logger.info('status="Creating input directory" stanza_name="%s" directory="%s"', self._stanza_name, normalized_dir)
                    try:
                        os.makedirs(normalized_dir)
                        return normalized_dir
                    except OSError:
                        logger.error('status="Input directory could not be created" stanza_name="%s" directory="%s"', self._stanza_name, normalized_dir)
                        return None
                else:
                    logger.error('status="Input directory name conflicts with an existing filename" stanza_name="%s" directory="%s"', self._stanza_name, normalized_dir)
            else:
                logger.error('status="Input directory path not absolute" stanza_name="%s"', self._stanza_name)
        else:
            logger.error('status="Invalid input directory provided" stanza_name="%s"', self._stanza_name)

        return None

    def run_lookup_generating_searches(self, last_run):
        '''Run the lookup generating searches based on the update timestamps of
        all threat intelligence collections. This method should normally only be
        run on a cluster master in a SHC configuration, to avoid repeated work.
        '''

        # Threatlist modtime collection
        exclusions = ['asn', 'tld', 'alexa', 'mozilla_psl']
        stanza_modtimes = self.metadata_handler.get_threatlist_metadata(exclusions, self._input_config.session_key)
        updated_stanzas = {k: v for k, v in stanza_modtimes.iteritems() if v > last_run}
        if updated_stanzas:
            logger.info('status="Detected updated threatlist stanzas - ALL lookup gen searches will be executed" last_run="%s" stanzas="%s"', last_run, updated_stanzas)
            updated_collections = {k: int(time.time()) for k, v in self.DEFAULT_COLLECTIONS.iteritems()}
        else:
            # If no stanzas have been updated, detect updated threat intelligence collections.
            # If we can't determine which collections have been updated, this
            # will default to running all lookup-generating searches.
            if self.checkpoint_data_exists(self.REFRESH_CHECKPOINT):
                updated_collections = {k: int(time.time()) for k, v in self.DEFAULT_COLLECTIONS.iteritems()}
                logger.info('status="Detected force_refresh checkpoint file - all threat intelligence lookups will be refreshed" last_run="%s" collections="%s"', last_run, updated_collections)
            else:
                updated_collections = self.metadata_handler.get_intel_metadata(self._input_config.session_key) or self.DEFAULT_COLLECTIONS
                logger.info('status="No updated threatlist stanzas - using collection modtimes for lookup gen dispatch" last_run="%s" collections="%s"', last_run, updated_collections)

        if updated_collections:

            searches_to_run = IntelUtils.get_update_searches(self.DEFAULT_APP, updated_collections, last_run, self._input_config.session_key)
            for search_to_run in searches_to_run:
                job = splunk.search.dispatchSavedSearch(search_to_run, self._input_config.session_key)
                logger.info('status="Dispatched threat intelligence update search" search="%s" sid="%s', search_to_run, job.id)

                elapsed = 0
                while not job.isDone and elapsed < self.DEFAULT_TIMEOUT:
                    time.sleep(1)

                if elapsed > self.DEFAULT_TIMEOUT:
                    logger.info('status="Threat intelligence update search timed out - intelligence may be incomplete." search="%s", sid="%s"', search_to_run, job.id)
                else:
                    logger.info('status="Threat intelligence update search completed." search="%s" elapsed="%s", sid="%s"', search_to_run, elapsed, job.id)
        else:
            logger.info('status="No updated threat intelligence collections detected"', )

    def set_stanza_params(self, stanza):
        self._results = self._emptyresults.copy()
        self._stanza_name = stanza['name'].split('//')[1]
        self._maxsize = abs(int(stanza.get('maxsize', self._maxsize)))
        self._sinkhole = stanza.get('sinkhole', False)
        self._remove_unusable = stanza.get('remove_unusable', True)
        self._default_weight = stanza.get('default_weight', None)

    ## normalize file path
    ## 1. normalizes the path using os.path.normpath
    ## 2. converts forward slashes to backward slashes
    @staticmethod
    def norm_path(filepath):
        return os.path.normpath(filepath).replace(os.path.sep, "/")
    
    def run(self, stanzas):

        logger.debug("Entering run method.")
        logger.debug("Input configuration: %s", self._input_config)
        logger.debug("Cleaned parameters: %s", stanzas)

        # Note: This modular input always runs on all hosts, and exits. Interval
        # is required to be set to a non-zero value for this to work.
        exec_status = True

        # Permit testing from command line if defined.
        if getattr(self, '_alt_session_key', False):
            self._input_config.session_key = self._alt_session_key

        # Reset the list of updated collections.
        self._collections_updated = set()

        # Initialization of handler classes should be kept outside of loop to cut down on REST overhead.
        self.kvstore_handler = KvStoreHandler()
        self.metadata_handler = ThreatIntelMeta(self.DEFAULT_APP, self.DEFAULT_METADATA_COLLECTION, self.kvstore_handler, self.DEFAULT_OWNER)
        self.initialize_parsers()

        for stanza in stanzas:

            if stanza and exec_status:

                # 0. Config self with retrieved parameters.
                self.set_stanza_params(stanza)
                inputdir = stanza.get('directory')

                if not inputdir:
                    logger.info('status="Directory invalid." stanza_name="%s"', self._stanza_name)
                    self._exit_status[self._stanza_name] = self.EXIT_INVALID_CONFIG

                try:
                    self._kvstore_limits = ParserUtils.get_limits('kvstore', self._input_config.session_key)
                except (splunk.ResourceNotFound, splunk.RESTException, ParserException):
                    logger.exception('Limits.conf stanza could not be retrieved thus integrity of KV store updates cannot be ensured. Exiting.')

                # Validate input directory.
                normalized_inputdir = None
                includes = {}
                if self._stanza_name == self.LOCAL_LOOKUP_STANZA:
                    # We process all lookup table files with paths based from $SPLUNK_HOME/etc/apps
                    normalized_inputdir = make_splunkhome_path(["etc", "apps"])
                    includes = self.collect_local_threatlists(normalized_inputdir)
                else:
                    normalized_inputdir = self.validate_directory(inputdir)

                # Retrieve last run time for this stanza.
                stanza_last_run = 0
                checkpoint_data = self.get_checkpoint_data(self._stanza_name)
                if checkpoint_data:
                    stanza_last_run = checkpoint_data.get('last_run', 0)

                # Process files. A default directory will precede a local directory.
                if normalized_inputdir and os.path.exists(normalized_inputdir):
                    if self._kvstore_limits:
                        logger.info('status="Processing directory" stanza_name="%s" directory="%s"', self._stanza_name, normalized_inputdir)
                        self.process_files(normalized_inputdir, stanza_last_run, includes.values())
                        self._exit_status[self._stanza_name] = self.EXIT_SUCCESS
                    else:
                        self._exit_status[self._stanza_name] = self.EXIT_LIMITS_UNKNOWN
                else:
                    logger.error('status="Invalid directory specified" stanza_name="%s"', self._stanza_name)
                    self._exit_status[self._stanza_name] = self.EXIT_INVALID_DIR

                # 3. Set stanza checkpoint data unless an error occurred.
                stanza_current_run = time.time()
                self._results.update({'last_run': stanza_current_run, 'exit_status': self._exit_status[self._stanza_name]})
                self.set_checkpoint_data(self._stanza_name, self._results)

                # 4. Log stanza results.
                logger.info('status="Directory processing complete" stanza_name="%s" %s', self._stanza_name, str(' '.join(["%s=%d" % (k, v) for k, v in self._results.iteritems()])))

            else:
                # Should never get here.
                logger.error('status="no stanza retrieved"')

        # 5. Update collection metadata.
        if self._collections_updated:
            unused_response, unused_content = self.metadata_handler.set_intel_metadata(self._collections_updated, self._input_config.session_key)

        # 6. Get global checkpoint data.
        checkpoint_data = self.get_checkpoint_data(self.DEFAULT_CHECKPOINT)
        if checkpoint_data:
            global_last_run = int(checkpoint_data.get('last_run', 0))
            logger.info('status="retrieved_checkpoint_data" stanza_name="%s"', self.DEFAULT_CHECKPOINT)
        else:
            global_last_run = 0
            logger.info('status="no_checkpoint_data" stanza_name="%s"', self.DEFAULT_CHECKPOINT)

        # 7. If we are the cluster master, run any saved searches for which
        # collections have been updated since the last run, now that we have
        # consumed any new threat intelligence documents.
        exec_status, exec_status_msg = should_execute(session_key=self._input_config.session_key)
        logger.info('Execution status: %s', exec_status_msg)
        if exec_status:
            self.run_lookup_generating_searches(global_last_run)

        # Remove the force_refresh sentinel file if it exists.
        try:
            if not self.delete_checkpoint_data(self.REFRESH_CHECKPOINT):
                logger.error('status="Could not delete sentinel file. Lookup gen searches will be executed on next run." file="%s"', self.REFRESH_CHECKPOINT)
                self._exit_status['default'] = self.EXIT_CHECKPOINT_ERR
        except OSError as e:
            if e.errno == errno.ENOENT:
                logger.info('status="No sentinel file (probably initial run). Lookup gen searches will be executed on next run." file="%s"', self.REFRESH_CHECKPOINT)
            else:
                logger.exception('status="OSError when deleting sentinel file. Lookup gen searches will be executed on next run." file="%s"', self.REFRESH_CHECKPOINT)
                self._exit_status['default'] = self.EXIT_CHECKPOINT_ERR

        # Set exit status to reflect the highest error seen.
        exit_status = self.EXIT_SENTINEL
        if len([i for i in self._exit_status.values() if i != self.EXIT_SUCCESS]) > 1:
            exit_status = self.EXIT_MULTIPLE_ERRORS
        else:
            exit_status = max(self._exit_status.values())

        # Write checkpoint data.
        self._exit_status['last_run'] = time.time()
        self.set_checkpoint_data(self.DEFAULT_CHECKPOINT, self._exit_status)

        # Exit cleanly if no errors encountered; otherwise, exit with the error
        logger.info('status="exiting" exit_status="%s"', exit_status)
        sys.exit(exit_status)

if __name__ == '__main__':
    ThreatIntelligenceManagerModularInput().execute()
