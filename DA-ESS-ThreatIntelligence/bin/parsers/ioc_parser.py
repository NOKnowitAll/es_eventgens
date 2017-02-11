import collections
import itertools
import logging
import lxml
from lxml import etree, objectify
import os

from parsers import AbstractThreatIntelligenceParser
from parsers.ioc_schema import IOCParserSpecification
from parsers.parser_exceptions import ParserException
from parsers.utils import ParserUtils


class IOCParser(IOCParserSpecification, AbstractThreatIntelligenceParser):
    
    def __init__(self, session_key):
        # Note: MRO requires that the non-abstract mixin class, IOCParserSpecification,
        # precede the abstract class in the declaration. 
        super(IOCParser, self).__init__()
        self._doc_type = 'ioc'
        self._logger = logging.getLogger('threat_intelligence_manager')
        self._namespaces = {'ioc1.0': 'http://schemas.mandiant.com/2010/ioc',
                            'ioc1.1': 'http://openioc.org/schemas/OpenIOC_1.1',
                            'xsd': 'http://www.w3.org/2001/XMLSchema',
                            'xsi': 'http://www.w3.org/2001/XMLSchema-instance'}
        
        self.VERSION_IOC_10 = '1.0'
        self.VERSION_IOC_11 = '1.1'
        
        self.session_key = session_key

        self._version = None

    def preprocess(self, filename, typ=None):
        '''Perform preliminary work prior to parsing: 
            - Read in the IOC document.
            - Calculate document hash.
            
        Filename is stored and accessible to the parser object after preprocessing.
        
        Arguments:
            filename - The full path to a file.
            typ - The type of object (currently unused)
            
        Raises:
            IOError - Could not open file.
            ValueError - Invalid or unknown IOC format.
            ParserException - Invalid XML.
            Exception (other) - Any other error.
        '''
        
        # Reset initial state.
        self._clear()
        
        try:
            with open(filename, 'r') as fh:
                data = fh.read()
                hasher = self.hash_alg
                hasher.update(data)
                self.hash_value = hasher.hexdigest()

                # Disable XML external entity processing.
                parser = lxml.objectify.makeparser(resolve_entities=False)
                lxml.objectify.set_default_parser(parser)
                self._parsed_data = lxml.objectify.fromstring(data)
                
                # Detect namespace
                if self._parsed_data.nsmap[None] == self._namespaces['ioc1.0']:
                    self._namespaces['ns'] = self._namespaces['ioc1.0']
                    self._version = self.VERSION_IOC_10
                elif self._parsed_data.nsmap[None] == self._namespaces['ioc1.1']:
                    self._namespaces['ns'] = self._namespaces['ioc1.1']
                    self._version = self.VERSION_IOC_11
                else:
                    raise ValueError('Invalid IOC version found when parsing document.')

                self.doc_id = str(self._parsed_data.attrib.get('id'))
                self.filename = os.path.abspath(filename)
                self.is_valid = True
        except lxml.etree.XMLSyntaxError as e:
            raise ParserException('Received XMLSyntaxError when parsing document.')
        
    def get_metadata(self):
        '''Construct a dictionary of metadata for the IOC currently being processed.'''
        return {'source_digest': self.hash_value,
                'source_path': self.filename,
                'source_processed_time': self.process_time,
                'source_status': None,  # TODO: what is this?
                'source_type': self.doc_type,
                '_key': self.doc_id}
    
    def get_attribution_data(self):
        '''Construct a dictionary representing threat attribution information.'''
        # Threat group and category are currently assumed to be extracted from
        # children of the <links> element

        # Threat attribution changes slightly for different IOC versions.
        # Note that all lxml objects have to be converted to strings for later 
        # processing by json.dumps()
        if self._version == self.VERSION_IOC_10:        
            tg_query = '//ns:link[@rel="threatgroup"]'
            tc_query = '//ns:link[@rel="category"]'
            return {'description': self._parsed_data.description.text,
                    'source_id': self.doc_id,  # TODO: may need to be set if None.
                    'time': str(self._parsed_data.attrib.get('last-modified')),  # TODO: may need parsing.
                    'threat_category': [str(i) for i in self._parsed_data.xpath(tc_query, namespaces=self._namespaces)],
                    'threat_group': [str(i) for i in self._parsed_data.xpath(tg_query, namespaces=self._namespaces)]}
        elif self._version == self.VERSION_IOC_11:
            tg_query = '//ns:link[@rel="threatgroup"]/@href'
            tc_query = '//ns:link[@rel="category"]/@href'
            return {'description': str(self._parsed_data.metadata.description),
                    'source_id': self.doc_id,  # TODO: may need to be set if None.
                    'time': str(self._parsed_data.attrib.get('last-modified')),  # TODO: may need parsing.
                    'threat_category': [str(i) for i in self._parsed_data.xpath(tc_query, namespaces=self._namespaces)],
                    'threat_group': [str(i) for i in self._parsed_data.xpath(tg_query, namespaces=self._namespaces)]}
        else:
            raise ValueError('Invalid IOC version found when generating threat attribution data.')
    
    def get_documents(self):
        '''Returns an iterator of Pythonic representations of IOC IndicatorItems.'''
        documents = self._parsed_data.xpath('//ns:IndicatorItem', namespaces=self._namespaces)
        # For debugging
        # for i in ioc.xpath('//ns:IndicatorItem', namespaces=self._namespaces):
        #     self._logger.debug('search="%s", content="%s"', i.Context.attrib['search'], i.Content)

        # Returns an iterator of tuples of the form (document_type, <iter>)
        return itertools.groupby(documents, lambda x: x.Context.attrib['document'])    
    
    def flatten_documents(self, group_iter, field_mapping):
        '''Flatten the data included in a list of IndicatorItems and map it to the 
        KV store collection defined by <spec>.
        
        Arguments:
            group_iter - An iterator over indicator items.
            field_mapping - A field mapping.
            '''
        output = collections.defaultdict(set)
        
        # multi-valued output field implementation
        for indicator_item in group_iter:
            wildcard = False
            if 'id' in indicator_item.attrib:
                # TODO: Determine key correctly here.
                output['_key'] = indicator_item.attrib['id']
            if 'condition' in indicator_item.attrib:
                if indicator_item.attrib['condition'] == 'contains':
                    wildcard = True
                elif indicator_item.attrib['condition'] in ['isnot', 'containsnot']:
                    # For now, skip this indicator. "Negated lookups" currently
                    # not supported in the threat intelligence framework.
                    continue
            field = field_mapping.get(indicator_item.Context.attrib['search'])
            if field:
                _, output_field_list, convert_function = field
                # Apply conversion function
                # Note that if this is a simple string conversion, the output_field_list
                # has size 1 and the first value is used directly as the output field name.
                for field_name, field_value in convert_function(output_field_list[0], indicator_item.Content.text):
                    if field_value and field_name in output_field_list:
                        if wildcard:
                            output[field_name].add('*' + field_value + '*')
                            # Uncomment the following line to deduplicate wildcard values with their nonwildcarded versions 
                            # output[k].discard(v)
                        else:
                            output[field_name].add(field_value)
                    else:
                        self._logger.warn('status="IOCParser discarded an invalid field.", field_name="%s" field_value="%s"', field_name, field_value)
            else:
                # Debug logging for this due to verbosity.
                self._logger.debug('status="IOCParser could not find an appropriate field conversion." item_type="%s" ', indicator_item.Context.attrib['search'])
            
        return ParserUtils.make_json_serializable(output)
        
    def parse(self, limits):
        '''Parse an IOC and populate KV store collections.
        
        Arguments:
            ioc - An lxml.objectify tree representing an IOC document.
        
        Returns:
            A tuple ({metadata_field: value}, {target_collection: {intel_dict})
            
        '''

        # Retrieve metadata.
        document_metadata = self.get_metadata()
        document_attribution = self.get_attribution_data()

        # Merge the documents into one for the "threat_group_intel" target collection.
        metadata = document_metadata.copy()
        metadata.update(document_attribution)

        # Group all the IndicatorItems found in the IOC by type.
        document_group_iter = self.get_documents()

        # Place the IOC data into the appropriate collections.
        intel = collections.defaultdict(dict)
        for indicator_item_type, document_group in document_group_iter:
            collection = self._collection_spec.get(indicator_item_type)
            if collection and collection.fields:
                tmp_intel = self.flatten_documents(document_group, collection.fields)
                if tmp_intel:
                    # Add source_id for the threat_key field.
                    tmp_intel['threat_key'] = metadata['source_id']
                    intel[collection.target].update(tmp_intel)
                else:
                    self._logger.error('status="IOCParser generated no threat intelligence - please validate the document." filename="%s" indicator_item_type="%s"', self.filename, indicator_item_type)
            else:
                self._logger.info('status="IOCParser skipped an indicator item; no field mapping in specification." filename="%s" indicator_item_type="%s"', self.filename, indicator_item_type)

        # Return the metadata and output - note the use of "yield" so this 
        # can be consumed as an iterator.
        yield metadata, intel

