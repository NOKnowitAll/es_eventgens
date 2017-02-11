import abc
import collections
import hashlib
import itertools
import json
import time
import urllib

import splunk
import splunk.rest

from parsers.utils import IntelUtils

# A Collection namedtuple defines the mapping from an input document:
#
#    name =   Name of the input item
#             - IOC: IndicatorItem that will be extracted
#             - CSV: the name of the key field for the output entry.
#             - TODO: STIX mapping
#             - Arbitrary otherwise
#    target = Name of the target KV store collection
#    fields = List of Field namedtuples defining the mapping operations. The
#             mapping operations on fields are conducted in undefined order.
#    key    = The field to be used as the key when persisting the collection
Collection = collections.namedtuple('Collection', ['name', 'target', 'fields'])
Fieldmap = collections.namedtuple('Fieldmap', ['name', 'fields'])

# A Field namedtuple defines a mapping from an input field value to a set of output 
# field values. The function defined by "fn" is a callable taking one argument:
#
#    fn(<dict>):
#        return (<val> or <dict>)
#
# The argument is a dictionary that MUST contain the key defined by "in". The 
# function is responsible for returning a dictionary that MUST have as keys ALL
# of the field names defined in "out", if "out" is a list. 
Field = collections.namedtuple('Field', ['infield', 'outfield', 'func'])
RoutedField = collections.namedtuple('Field', ['input_field', 'output_fields', 'target_collection', 'func'])


class Collections(object):
    
    CERTIFICATE_INTEL = 'certificate_intel'
    HTTP_INTEL ='http_intel'
    EMAIL_INTEL = 'email_intel'
    SERVICE_INTEL = 'service_intel'
    FILE_INTEL = 'file_intel'
    REGISTRY_INTEL ='registry_intel'
    PROCESS_INTEL = 'process_intel'
    IP_INTEL = 'ip_intel'
    USER_INTEL = 'user_intel'
    

class AbstractThreatIntelligenceSchema(object):
    __metaclass__ = abc.ABCMeta


class AbstractThreatIntelligenceParser(object):
    __metaclass__ = abc.ABCMeta
    
    def __init__(self):
        # Read-only
        self._doc_type = None      # Document type

        # Accessible
        self.doc_id = None         # Document ID
        self.filename = None       # Filename
        self.hash_value = None     # Hash value
        self.is_valid = False      # Validity
        self.last_modified = None  # Last modified time
        self.process_time = None   # Time of processing
        self.session_key = None    # Session key
        self.threat_key = None     # Threat key
        self.use_filename = False  # Use the filename in document identification.

        # Private
        self._parsed_data = None   # Container for parsed data
        self._stanzas = None       # Container for stanza content
        self._stanza_meta = {}     # Container for stanza last update times
        self._meta_prefix = urllib.quote_plus('threatlist://')  # Prefix for stanza names in metadata

    @property
    def doc_type(self):
        return self._doc_type

    @property
    def hash_alg(self):
        return hashlib.sha1()

    @abc.abstractmethod
    def parse(self, limits):
        '''Parse the input files.
        Arguments:
            limits - A dictionary containing limits pertaining to the parser.
                     Usually this is used to batch results for writing to the 
                     selected output store.
        '''
        raise NotImplementedError('This method must be overridden by a concrete class.')
    
    @abc.abstractmethod
    def preprocess(self, filename, typ=None):
        '''Preprocess the input files.'''
        raise NotImplementedError('This method must be overridden by a concrete class.')

    def stanza_updated(self, filename, last_run):
        '''Returns True if the metadata corresponding to the filename has been 
        updated since the last run, False otherwise.

        The default implementation always returns False.
        '''
        return False
    
    def _get_stanza_metadata(self, includes=None, excludes=None):
        '''Get the last update times for stanzas that generate files consumed by
        this parser.
        
        Arguments:
            includes - A list of invalid types. Corresponds to the "type" field in threatlist://<name> inputs.conf stanzas.
            excludes - A list of invalid types. Corresponds to the "type" field in threatlist://<name> inputs.conf stanzas.
        '''
        
        # Retrieve all parsing configuration information (may raise exception)
        modinput_uri = '/services/data/inputs/threatlist?output_mode=json&count=0&search=disabled=false'
        _, content = splunk.rest.simpleRequest(modinput_uri, sessionKey=self.session_key)
        stanzas = json.loads(content)['entry']
        
        # Populate stanza cache.
        self._stanzas = {i['name']: i['content'] for i in stanzas}

        # Augment stanzas with their ACLs.
        for stanza in stanzas:
            self._stanzas[stanza['name']]['eai:acl'] = stanza['acl']

        # Populate stanza metadata cache.
        self._stanza_meta = {}
        group_fn = lambda x: x['acl']['app']
        
        def included(x):
            # Include the value of x by default. If specified, "includes" and 
            # "excludes" govern the inclusion of the file. Excludes have higher
            # priority than includes.
            result = True
            if includes:
                result = x in includes
            if excludes:
                result = x not in excludes
            return result
        
        # Group the stanzas by the owning app, and get the last update time for each.
        # Map the update times to their corresponding stanza names.
        for app, stanza_list in itertools.groupby([i for i in stanzas if included(i['content']['type'])], group_fn):
            update_times = IntelUtils.get_stanza_update_times('inputs', app, [self._meta_prefix + i['name'] for i in stanza_list])
            self._stanza_meta.update({k.replace(self._meta_prefix, ''): v for k, v in update_times.iteritems()})
    
    def _clear(self):
        '''Return parser to initial state.'''  
        self.doc_id = None
        self.filename = None
        self.hash_value = None
        self.is_valid = False
        self._parsed_data = None
        self.process_time = time.time()