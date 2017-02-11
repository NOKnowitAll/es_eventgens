import collections
import csv
import logging
import os
import re
import splunk

from parsers import AbstractThreatIntelligenceParser
from parsers.csv_schema import CSVSchemaSpecification
from parsers.utils import LookupUtils, ParserUtils


def reader_gen(fh, ignore_regex):
    # Safe file reader to avoid needing to do our own EOF detection with readline()
    # and to skip lines as needed.
    for line in fh:
        if ignore_regex:
            if not ignore_regex.search(line):
                yield line
            else:
                continue
        else:
            yield line


class CSVParserConfiguration(object):

    def __init__(self, filename, stanza, collection_spec):
        """Set up the parse method and line-ignoring regular expression for the
        CSV parser."""

        self._logger = logging.getLogger('threat_intelligence_manager')

        if 'fields' in stanza and stanza.get('fields'):
            tmp_fields = sorted([i.split(':', 1) for i in csv.reader([stanza['fields']]).next()], key=lambda x: x[1])
            # Fields may be specified out-of-order; for DictReader CSV parsing we need to reorder them.
            self.fields = [i[0].strip() for i in tmp_fields]
            self.replacements = tmp_fields
            for item in collection_spec.keys():
                if item in self.fields:
                    # If predefined field names are in use, determine the target collection
                    # based on the field names.
                    self.item_type = item
                    break
            else:
                raise ValueError('Parser does not extract a field that can be mapped to a threat intelligence collection.')
        else:
            # Field names will be determined dynamically.
            self.fields = None
            self.replacements = None

        # The file handle.
        self.fh = open(filename, 'rU')

        # The regex used to ignore lines in the file.
        self.ignore_regex = self.build_regex(stanza.get('ignore_regex', ''))

        # The line number (note: does not account for lines skipped due to ignore_regex,
        # so setting both ignore_regex and skip_header_lines in threatlist inputs.conf
        # stanza can lead to unexpected behavior.
        self.lineno = 0

        # Type class - only used to determine the parse method used.
        self.match_objtype = type(re.search('', ''))

        # Callable parsing method used for all non-standard CSV parsing.
        self.parse_method = None

        # Number of initial lines in file to skip.
        self.skip_header_lines = int(stanza.get('skip_header_lines', 0))
        if self.skip_header_lines < 0:
            self.skip_header_lines = 0

        # Delimiter to be used in parsing. Mutually exclusive with extract_regex.
        delim = stanza.get('delim_regex', '')

        # Complex regex to be used in parsing. Mutually exclusive with delim_regex.
        extract = stanza.get('extract_regex', '')

        if not self.fields:
            # CSV parsing with inferred field names will be used.
            self.csv_reader = csv.DictReader(reader_gen(self.fh, self.ignore_regex),
                                             delimiter=str(delim or ','))
            self.fields = self.csv_reader.fieldnames
            self.reader = self.csv_reader.next

            # Dynamic determination of the target collection. This relies on
            # the key fields being non-overlapping. The "item_type" field is
            # used to determine which schema gets loaded.
            for item in collection_spec.keys():
                if item in self.fields:
                    self.item_type = item
                    break
            else:
                raise ValueError('Parser does not extract a field that can be mapped to a threat intelligence collection.')
        elif delim and len(delim) == 1 and self.fields:
            # Defined delimiter and fields using Excel-style CSV parsing.
            self.csv_reader = csv.reader(reader_gen(self.fh, self.ignore_regex), delimiter=str(delim))
            self.reader = self.csv_reader.next
        elif delim and len(delim) > 1 and self.fields:
            # A more complex delimiter and defined fields cannot use Excel-style CSV parsing.
            # Complex delimiter.
            gen = reader_gen(self.fh, self.ignore_regex)
            self.reader = gen.next
            self.parse_method = self.build_regex(delim).split
        elif extract and self.fields:
            # Defined complex extraction regex and fields
            gen = reader_gen(self.fh, self.ignore_regex)
            self.reader = gen.next
            self.parse_method = self.build_regex(extract).search
        else:
            raise ValueError('Parser could not be instantiated: one of delim_regex or extract_regex is required.')

    def __iter__(self):
        return self

    def next(self):
        try:
            # Record may be:
            # - a string if delim_regex with a complex delimiter or extract_regex is used
            # - a dict for simple CSV parsing of lookup tables with inferred or predefined fields.
            # Any parse_method() is only applied to strings.
            record = self.reader()
            self.lineno += 1
        except StopIteration:
            self.fh.close()
            raise

        if self.lineno <= self.skip_header_lines:
            # Line ignored.
            self._logger.debug('IGNORED: %s %s', self.lineno, record)
            return None

        # Note: The line is not completely stripped of ALL whitespace,
        # to accommodate tab-delimited formats with leading tabs.
        # Field processors in fields.py are responsible for
        # stripping extraneous whitespace from field content.
        # However, line ending characters are removed.
        if self.parse_method:
            record = self.parse_method(record.strip('\r\n'))

        self._logger.debug('RECORD: %s', record)

        if record and isinstance(record, dict):
            # Simple CSV parsing was used.
            return record
        elif record and isinstance(record, self.match_objtype):
            # Complex extraction was used.
            newfields = {}
            for field_name, replacement_str in self.replacements:
                field_name = field_name.strip()
                # Strip leading and trailing quotes from the regex.
                rx_str = replacement_str.strip('"\' ').replace('$', '\\')
                try:
                    newfields[field_name] = record.expand(rx_str).strip()
                except (re.error, IndexError):
                    # Replacement failed, usually due to an invalid
                    # group reference. Line skipped.
                    self._logger.error('Line skipped due to exception: %s', self.lineno)
                    self._logger.debug('SKIPPED: %s %s', self.lineno, record)
            return newfields
        elif record and isinstance(record, list):
            # Complex delimiter was used in a split().
            newfields = {}

            record_unquoted = (i.strip('"') for i in record)

            for field_name, replacement_str in self.replacements:
                field_name = field_name.strip()
                # Strip leading and trailing quotes from the regex.
                rx_str = replacement_str.strip('"\' ')
                # Since we can't use the MatchObject's expand() method,
                # since we have a list of strings to work with,
                # create a formatter from the replacement string.
                try:
                    formatter = re.sub('\$(\d+)', '{\\1}', replacement_str)
                    # Note the insertion of an extra element - this
                    # allows users to specify fields in the "normal"
                    # fashion counting up from 1.
                    newfields[field_name] = formatter.format('', *[i.strip('"') for i in record]).strip()
                except (re.error, IndexError):
                    # Replacement failed, usually due to an invalid
                    # group reference. Line skipped.
                    self._logger.error('Line skipped due to exception: %s', self.lineno)
                    self._logger.debug('SKIPPED: %s %s', self.lineno, record)
            return newfields
        else:
            # Parsing of the line did not return anything.
            # This generally means there is an error in the parsing
            # configuration, but may also indicate bad data in one line.
            self._logger.error('Parse error on line (possibly empty record): %s', self.lineno)
            self._logger.debug('SKIPPED: %s %s', self.lineno, record)
            return None

    def build_regex(self, pattern):
        """Build a non-empty regular expression from a string."""
        rx = None
        if pattern:
            try:
                tmp = re.compile(pattern, re.UNICODE)
                if tmp.pattern != '':
                    rx = tmp
            except re.error:
                pass
        return rx


class CSVParser(CSVSchemaSpecification, AbstractThreatIntelligenceParser):

    ##
    # This is used when consuming CSV backed Threat Intel Lists that aren't
    # associated with a threatlist lookup stanza. i.e., CSV files dropped and
    # directly consumed from a threat_intelligence_manager modinput folder.
    ##
    THREATLIST_DIRECT_CSV_STANZA = {
        'weight': '',
        'description': '',
        'type': 'threatlist_direct_csv'
    }

    def __init__(self, session_key):
        # Note: MRO requires that the non-abstract mixin class, IOCParserSpecification,
        # precede the abstract class in the declaration.
        super(CSVParser, self).__init__()
        self._doc_type = 'csv'
        self._logger = logging.getLogger('threat_intelligence_manager')
        self.session_key = session_key

        # Populate stanza data (self._stanzas) and metadata (self._stanza_meta).
        # May raise REST exception.
        self._get_stanza_metadata(excludes=['alexa', 'asn', 'mozilla_psl', 'taxii', 'tld'])

        # Get stanza-to-filename mapping.
        self._stanza_filename_map = self._get_stanza_filename_map()

        # Placeholder for the stanza currently being processed.
        self._stanza = None

        # The short file name.
        self._short_filename = None

    def _get_stanza_filename_map(self):
        """Map threatlist stanzas to their actual filenames."""
        output = {}
        transform_rx = re.compile('^\s*lookup://([\w-]+)\s*$')

        for stanza_name, content in self._stanzas.iteritems():
            if content.get('url', '').startswith('http'):
                # Threatlist downloads from external sites use the stanza name
                # as the file name.
                output[stanza_name + '.csv'] = stanza_name
            elif content.get('url', '').startswith('lookup'):
                # Lookup threatlist stanzas may NOT use the same file name. Thus
                # we have to map these.
                m = transform_rx.match(content['url'])
                if m:
                    transform_name = m.group(1)
                    try:
                        tmp = LookupUtils.get_lookup_file_location(content['eai:acl']['app'], transform_name, self.session_key)
                        output[os.path.basename(tmp)] = stanza_name
                    except splunk.ResourceNotFound:
                        self._logger.error('Lookup table file could not be located for a CSV threatlist stanza. stanza="%s"', stanza_name)
                    except Exception:
                        self._logger.exception('Unknown exception when locating lookup table file for a CSV threatlist stanza. stanza="%s"', stanza_name)
                else:
                    self._logger.error('Invalid threatlist stanza. stanza="%s"', stanza_name)
            else:
                self._logger.error('Invalid threatlist stanza. stanza="%s"', stanza_name)

        return output

    def stanza_updated(self, filename, last_run):
        """Returns True if the metadata corresponding to the filename has been
        updated since the last run, False otherwise."""
        originating_file = os.path.basename(filename)
        originating_stanza = self._stanza_filename_map.get(originating_file)
        return self._stanza_meta.get(originating_stanza, 0) > last_run

    def preprocess(self, filename, typ=None):
        """Perform preliminary work prior to parsing:
            - Open handle to the file.
            - Generate internal parser dynamically based on the threatlist inputs.conf stanza.

        Filename is stored and accessible to the parser object after preprocessing.

        Arguments:
            filename - The full path to a file.
            typ - The type of object (currently unused)

        Raises:
            IOError - Could not open file.
            ValueError - No stanza could be located for parsing the current file.
        """

        # Reset state.
        self._clear()

        # Set current state
        # Use file size as hash value; we don't want to read in the entire
        # file twice to get a valid hash at this point.
        self.filename = os.path.abspath(filename)
        file_stat = os.stat(self.filename)
        self._short_filename = os.path.basename(self.filename).replace('.csv', '')
        self.doc_id = self._short_filename  # This is the key for the KV store collection entry.
        self.hash_value = file_stat.st_size
        self.last_modified = file_stat.st_mtime

        # Map the filename to an input stanza.
        self._stanza = self._stanzas.get(self._stanza_filename_map.get(os.path.basename(self.filename)))
        self.is_valid = True
        if not self._stanza:
            self._logger.info('msg="CSV file found with no corresponding threatlist inputs.conf stanza. Simple CSV parsing will be used." file="%s"', self.filename)
            self._stanza = self.THREATLIST_DIRECT_CSV_STANZA

    def get_metadata(self):
        """Construct a dictionary of metadata for the file currently being processed."""
        return {'source_digest': self.hash_value,
                'source_path': self.filename,
                'source_processed_time': self.process_time,
                'source_status': None,  # TODO: what is this?
                'source_type': self.doc_type,
                '_key': self.doc_id}

    def get_attribution_data(self):
        """Construct a dictionary representing attribution information."""

        try:
            weight = int(self._stanza['weight'])
        except (KeyError, ValueError):
            weight = None

        return {'description': str(self._stanza['description']),
                'source_id': self.doc_id,
                'threat_category': self._stanza.get('type', None),
                'threat_group': self.doc_id,
                'time': str(self.last_modified),  # TODO: may need parsing.
                'weight': weight}

    def map_fields(self, intel, field_mapping, key_field_name):
        """Map the data included in a dictionary to the appropriate
        KV store collection defined by self._collection_spec.

        Arguments:
            intel - A dictionary.
            field_mapping - A Field object.

        Output:
            A dictionary of field values to be written to a KV store collection.
        """
        output = collections.defaultdict(set)

        # multi-valued output field implementation
        for field_name, field_value in intel.iteritems():
            # 1. Get the field mapping.
            field = field_mapping.get(field_name)
            if field:
                # 2. Get the components of the mapping:
                #    a. output_field_list -> the allowable output fields
                #    b. convert_function -> a generator that yields (field_name, field_value)
                unused_field_name, output_field_list, convert_function = field
                # Apply the conversion function (a generator).
                for key, value in convert_function(field_name, field_value):
                    if value and key in output_field_list:
                        #output[k].update(v.decode(errors='replace'))
                        output[key].add(value)
                    else:
                        self._logger.debug('status="Parser discarded an invalid field.", field_name="%s", field_value="%s"', field_name, field_value)

                # Add the key field for this entry. Note that we add the
                # ORIGINAL field value rather than the converted value here, so
                # as to be able to tie an entry back to the original line of the CSV.
                if key_field_name in output and '_key' not in output:
                    output['_key'] = '|'.join([self._short_filename, field_value.decode(errors='replace')])

                # TODO: add time field.

            else:
                # Debug logging for this to reduce verbosity - this is common.
                self._logger.debug('status="Parser could not find an appropriate field conversion." field_name="%s" ', field_name)

        return ParserUtils.make_json_serializable(output)

    def parse(self, kvstore_limits):
        """Parse a CSV and populate KV store collection(s).

        Arguments:
            kvstore_limits - A dictionary containing limits.conf settings pertaining to the KV store.

        Returns:
            A generator that produces ({metadata_field: value}, [{target_collection: {intel_dict}])
        """

        # Retrieve metadata.
        document_metadata = self.get_metadata()
        document_attribution = self.get_attribution_data()

        # Merge the documents into one for the "threat_group_intel" target collection.
        metadata = document_metadata.copy()
        metadata.update(document_attribution)

        # Build the parser from the stanza.
        parser = CSVParserConfiguration(self.filename, self._stanza, self._collection_spec)

        # The intel list.
        intel_list = []

        # An empty record will be identifiable by having only a subset of these fields.
        empty_record_set = {'description', 'threat_key'}

        # Get the collection type: ip, domain, url, etc.
        collection = self._collection_spec.get(parser.item_type)
        if collection and collection.fields:
            for count, tmp_intel in enumerate(parser):
                if tmp_intel:
                    try:
                        # Value of collection.name is the field that will be
                        # used as the key when writing entries. Entries are written
                        # as "short_filename|<unconverted value of field>
                        intel = self.map_fields(tmp_intel, collection.fields, collection.name)

                        # If we got no data from the mapping process, skip this record - usually this means
                        # we processed the record and tried to target it to an inappropriate threat intel collection.
                        # Otherwise, insert it.
                        if len(set(intel.keys()) - empty_record_set) > 1:
                            intel['threat_key'] = metadata['source_id']
                            intel_list.append(intel)
                    except Exception:
                        self._logger.exception('status="Exception when mapping field data" intel="%s"', tmp_intel)
                if count % int(kvstore_limits['max_documents_per_batch_save']) == 0:
                    yield metadata, {collection.target: intel_list}
                    intel_list = []
            else:
                yield metadata, {collection.target: intel_list}
