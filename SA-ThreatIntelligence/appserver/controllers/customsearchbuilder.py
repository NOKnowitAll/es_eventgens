import cherrypy
import json
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.appserver.mrsparkle.lib import jsonresponse
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
from splunk.rest import simpleRequest
import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-ThreatIntelligence", "bin"]))
from custom_search_builder.base                    import CustomSearchBuilderBase
from custom_search_builder.exceptions              import *
from custom_search_builder.make_correlation_search import makeCorrelationSearch
from custom_search_builder.make_lookup_generating_search import makeLookupGeneratingSearch

sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
from cim_models import DataModels

import logging
logger = logging.getLogger('splunk.appserver.SA-ThreatIntelligence.controllers.CustomSearchBuilder')


class CustomSearchBuilder(controllers.BaseController):

    @route('/:get_data_models=get_data_models')
    @expose_page(must_login=True, methods=['GET']) 
    def getDataModelsAndObjects(self, **kwargs):
        
        # Get the session key
        sessionKey = cherrypy.session.get('sessionKey')
        
        # This will contain all of the information about the data-models and the associated objects
        data_models_info = []
        
        # Get the list of data-models
        for data_model in DataModels.getDatamodelList(sessionKey):
            
            try:
                data_models_info.append( {
                                          'name' : data_model,
                                          'objects' : DataModels.getDatamodelObjectList(data_model, sessionKey)
                                          } )
            except:
                pass
        
        return self.render_json(data_models_info)

    @route('/:get_available_fields=get_available_fields')
    @expose_page(must_login=True, methods=['GET']) 
    def getAvailableFieldsFromSpec(self, search_spec, **kwargs):
        # Get the session key
        sessionKey = cherrypy.session.get('sessionKey')
        
        # Parse the JSON
        search_spec_parsed = json.loads(search_spec)
        
        # Get instance of CustomSearchBuilderBase
        csb = CustomSearchBuilderBase(sessionKey, logger)
        
        try:
            available_fields = csb.getAvailableFields(search_spec_parsed)
            
        except (InvalidResultFilter, InvalidAggregate, InvalidDatamodelObject, InvalidInputlookup) as e:
            return self.render_json( {
                                      'success': False,
                                      'message': 'Search specification is invalid: '  + str(e),
                                      })

        except Exception as e:
            return self.render_json( {
                                      'success': False,
                                      'message': 'Search specification could not be converted: ' + str(e)
                                      })
        
        return self.render_json( {
                                  'success'   : True,
                                  'available_fields' : available_fields,
                                  'message'    : 'Search specification converted successfully'
                                  })

    @route('/:make_search_from_spec=make_search_from_spec')
    @expose_page(must_login=True, methods=['GET']) 
    def makeSearchFromSpec(self, routine, search_spec, **kwargs):
        
        # Get the session key
        sessionKey = cherrypy.session.get('sessionKey')
            
        # Parse the JSON
        search_spec_parsed = json.loads(search_spec)

        
        # Make the correlation search string
        try:
            if routine == 'makeCorrelationSearch':
              raw_search, parses = makeCorrelationSearch(search_spec_parsed, sessionKey=sessionKey, logger=logger)
            elif routine == 'makeLookupGeneratingSearch':
              raw_search, parses = makeLookupGeneratingSearch(search_spec_parsed, sessionKey=sessionKey, logger=logger)
            elif routine == 'raw':
              ## Get instance of CustomSearchBuilderBase
              ## This validates sessionKey and logger
              rsb = CustomSearchBuilderBase(sessionKey, logger)
              rs = search_spec_parsed.get('search', {})
              if rs.get('inputlookup', False):
                raw_search = rsb.makeInputlookup(rs)
              else:
                raw_search = rsb.makeRaw(rs, modelJson=None)
              response, contents = simpleRequest("search/parser", sessionKey=sessionKey, getargs={'q': raw_search, 'parse_only': 't', 'output_mode': 'json'})
              parses = (response.status == 200)
            else:
              return self.render_json( {
                                      'success': False,
                                      'message': 'Routine not supported: ' + str(routine),
                                      })
        except (InvalidResultFilter, InvalidAggregate, InvalidDatamodelObject, InvalidInputlookup) as e:
            return self.render_json( {
                                      'success': False,
                                      'message': 'Search specification is invalid: '  + str(e),
                                      })

        except Exception as e:
            return self.render_json( {
                                      'success': False,
                                      'message': 'Search specification could not be converted: ' + str(e)
                                      })
        
        return self.render_json( {
                                  'success'    : True,
                                  'raw_search' : raw_search,
                                  'parses'     : parses,
                                  'message'    : 'Search specification converted successfully'
                                  })

