import json
import logging
import sys

import splunk
import splunk.rest
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))

from parser_exceptions import ParserException
from SolnCommon.metadata import MetadataReader

logger = logging.getLogger('threat_intelligence_manager')


class FieldUtils(object):
        
    PATHSEP_NIX = '/'
    PATHSEP_WIN = '\\'
    EXTSEP = '.'
    
    @classmethod
    def parse_path(cls, unused_field_name, paths, prefix):
        '''Parse any of the following from an IOC:
        
            FileItem/FullPath
            ProcessItem/path
            ServiceItem/path
            ServiceItem/serviceDLL
        
        Arguments:
            unused_field_name - Required for compatibility with the parsing convention.
            pathstr - The textual value of FileItem/FullPath or FileItem/FilePath.
            mapping - A prefix for the field names to be returned by this method. 
            
        Returns:
            A dictionary of path, extension, name if found.
        '''
        
        pathstr = paths[0] if isinstance(paths, list) else paths

        head, sep, tail = pathstr.rpartition(cls.PATHSEP_NIX)
        if head == '' and sep == '' and tail == pathstr:
            # UNIX Path separator not found.
            head, sep, tail = pathstr.rpartition(cls.PATHSEP_WIN)

        ext = None
        # tail will contain the original string in the no-path-separator case.
        if cls.EXTSEP in tail:
            _, ext = tail.rsplit(cls.EXTSEP)

        # Yield the values.
        yield prefix + 'path', head or ''
        yield prefix + 'name', tail or ''
        yield prefix + 'extension', ext or ''

    @classmethod
    def str_gen(cls, field_name, field_value, lstrip_chars=' "', rstrip_chars=' "'):
        '''Simple generator for converting a value to a string.
        
        Arguments:
            field_name - A string representing the field name.
            field_value - A string representing the field value.
            stripchars - An optional list of characters to strip from the field_value.
            
        Returns:
            A generator that yields a tuple of (field_name, field_value)

        Note: The default behavior is to strip leading/trailing whitespace and quotes. 
        '''
        yield field_name, str(field_value).lstrip(lstrip_chars).rstrip(rstrip_chars)

    @classmethod
    def iter_to_str_gen(cls, field_name, field_value, lstrip_chars=' "', rstrip_chars=' "'):
        '''Simple generator for converting a list or set of values to strings.
        If field_value is NOT a list, returns a single item, to prevent 
        automatic iteration over string values that might be mistakenly passed
        in as input.'''
        if isinstance(field_value, (list, set)):
            for v in field_value:
                yield field_name, str(v).lstrip(lstrip_chars).rstrip(rstrip_chars)
        else:
            yield field_name, str(field_value).lstrip(lstrip_chars).rstrip(rstrip_chars)

    @classmethod
    def safe_str_gen(cls, field_name, field_value):
        '''Simple generator for converting a value to a string, avoiding
        decoding errors.'''
        yield field_name, field_value.decode(errors='replace')


class ParserUtils(object):

    @classmethod
    def get_limits(cls, stanza, session_key):
        '''Retrieve limits.conf stanza as a dictionary.

        Arguments:
            stanza - The stanza name.
            session_key - A Splunk session key.
            
        Returns:
            A dictionary of settings in the chosen stanza.
            
        Raises:
            splunk.rest.RESTException or splunk.ResourceNotFound.
        '''

        response, content = splunk.rest.simpleRequest('configs/conf-limits/' + stanza, session_key, {'output_mode': 'json'})

        if response.status == 200:
            return json.loads(content)['entry'][0]['content']
        else:
            raise ParserException('Could not retrieve limits.conf stanza.')
        
    @classmethod
    def make_json_serializable(cls, output_dict):
        '''Iterate over the output_dict, converting it in-place to objects 
        appropriate for later JSON serialization.'''
        for k, v in output_dict.iteritems():
            if isinstance(v, set):
                if len(v) > 1:
                    output_dict[k] = list(v)
                elif len(v) == 1:
                    output_dict[k] = v.pop()
            else:
                output_dict[k] = v
        return output_dict
    
    
class IntelUtils(object):
    
    @classmethod
    def get_threatlist_generating_searches(self, session_key):
        '''Return a complete list of threatlist generating searches as a 
        dictionary of:
        
            {search_name: [kvstore_collection], ...}
        
        '''
        getargs = {'search': "action.threat_outputlookup=1", 'output_mode': 'json', 'count': 0}
        unused_response, content = splunk.rest.simpleRequest('configs/conf-savedsearches', 
            sessionKey=session_key,
            getargs=getargs)
        
        json_content = json.loads(content)['entry']
        output_dict = {}
        for search in json_content:
            search_params = search['content']
            output_dict[search['name']] = search_params['action.threat_outputlookup.collections'].split(',')

        return output_dict
        
    @classmethod
    def get_stanza_update_times(cls, conf, app, stanzas, param='modtime'):
        '''Get last update time of stanzas for a given configuration file.
         
        Arguments:
            conf        - The configuration file name.
            app         - The app containing the collections.
            stanzas     - A list of stanza names. Cannot be empty.
            param       - The parameter to retrieve.
             
        Returns:
            A dictionary of {collection_name: update_time}
             
        If the collection update time cannot be determined, update_time == 0.
         
        '''
         
        update_times = {}
        for stanza in stanzas:
            try:
                update_times[stanza] = MetadataReader.get_float(conf, stanza, app, param)
            except ValueError:
                update_times[stanza] = 0
 
        return update_times
    
    @classmethod
    def get_update_searches(cls, app, collection_dict, last_update, session_key):
        '''Get a list of update searches to run, based on the last update time
        of the threat intelligence collections.
        
        Arguments:
            app             - The app containing the collections.
            collection_dict - A list of collection names and update times.
            last_run        - The last update time to compare against, as an epoch timestamp.
            key             - A Splunk session key.
        '''

        updated = {c for c, ts in collection_dict.iteritems() if ts > last_update}
        if updated:
            logger.info('Detected updated collections: %s', ','.join(updated))
        else:
            logger.info('No collections updated.')            
        generating_searches = cls.get_threatlist_generating_searches(session_key)

        searches_to_run = set()
        for search, collections in generating_searches.iteritems():
            if updated & set(collections):
                searches_to_run.add(search)
                
        return list(searches_to_run)
    
    
class LookupUtils(object):
    
    @classmethod
    def get_lookup_file_location(cls, app, transform_name, session_key):
        '''Retrieve full path to lookup file given a transform name.
        
        Arguments:
            app - The app owning the lookup table transform.
            transform_name - The transforms.conf stanza name referring to the lookup table.
            session_key - A Splunk session key.
            
        Returns:
            A full path to a file.
            
        Assumes:
            The transforms.conf entry and the lookup table file MUST reside in 
            the same app. Callers are expected to handle exceptions.
         '''
        
        _, c = splunk.rest.simpleRequest('/servicesNS/-/%s/configs/conf-transforms/%s' % (app, transform_name),
            sessionKey=session_key,
            getargs={'output_mode': 'json'})
        
        filename = json.loads(c)['entry'][0]['content']['filename']
        
        _, c = splunk.rest.simpleRequest('/servicesNS/-/%s/data/lookup-table-files/%s' % (app, filename),
            sessionKey=session_key,
            getargs={'output_mode': 'json'})
        
        filepath = json.loads(c)['entry'][0]['content']['eai:data']

        return filepath