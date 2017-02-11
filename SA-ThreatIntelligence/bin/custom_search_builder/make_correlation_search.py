import json
import sys

from .base       import CustomSearchBuilderBase
from .exceptions import InvalidOutputMode, InvalidSearchPart

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.rest                         import simpleRequest

sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
from cim_models import DataModels

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.searchutils import parse_search_string


def makeCorrelationSearch(correlationSearchJson, modelJson=None, sessionKey=None, logger=None, outputMode="single"):
    ## Get instance of CustomSearchBuilderBase
    ## This validates sessionKey and logger
    csb = CustomSearchBuilderBase(sessionKey, logger)
    
    searchString = ''
    
    ## get correlation search parts           
    correlationSearchParts = correlationSearchJson.get('searches', [])
    correlationSearchPartCount = len(correlationSearchParts)
    
    ## single part search
    if correlationSearchPartCount==1:
        cs = correlationSearchParts[0]
        
        ## if single mode is requested
        if outputMode=='single':
            datamodel = cs.get('datamodel', False)
            
            ## if search part contains a datamodel
            if datamodel and cs.get('object', False):
                
                if modelJson is None:
                    ## get the model
                    model_id = DataModels.build_id(datamodel, None, None)
                    model = DataModels.get(id=model_id, sessionKey=sessionKey)
    
                    ## load the json
                    modelJson = json.loads(model.data)
                    
                raw        = csb.makeRaw(cs, modelJson=modelJson)
                raw_length = len(raw)
                
                tstats        = csb.makeTstats(cs, modelJson=modelJson, strictMode=False, addTimeConstraints=False)
                tstats_length = len(tstats)
                
                parses = False
                
                ## if a non zero length tstats search is available, take it                    
                if tstats_length>0:
                    ## validate search with splunk's parser
                    ## we do parsing here, in case a complex where clause is passed to tstats
                    try:
                        contents = parse_search_string(tstats, sessionKey)
                        parses = True
                        searchString += tstats
                    except ValueError as e:
                        logger.warn("tstats search does not parse, tstats search cannot be used")
                                
                ## if tstats was zero length or does not parse, take raw search
                if (tstats_length==0 or (tstats_length>0 and not parses)) and raw_length>0:
                    searchString += raw
                
                ## if tstats was zero length or does not parse, and no raw search    
                elif (tstats_length==0 or (tstats_length>0 and not parses)) and raw_length==0:
                    e = 'Single output mode with specified datamodel %s did not return a valid tstats %s or raw %s search' % (datamodel, tstats, raw)
                    logger.error(e)
                    raise InvalidSearchPart(e)
            
            ## if search part contains an inputlookup
            elif cs.get('inputlookup', False):
                searchString += csb.makeInputlookup(cs)
            
            else:
                e = 'A search part must specify either a datamodel and object, or an inputlookup'
                logger.error(e)
                raise InvalidSearchPart(e)

       ## output multi search
        elif outputMode=='multi':
            e = 'Output mode "multi" not available for single-part searches.  Use output mode "single".'
            logger.error(e)
            raise InvalidOutputMode(e)
    
        else:
            e = 'Output mode %s not recognized' % (outputMode)
            logger.error(e)
            raise InvalidOutputMode(e)
            
    ## multi-part search
    elif correlationSearchPartCount>1:
    
        ## output raw event search
        if (outputMode=='raw' or outputMode=='tstats' or outputMode=='inputlookup'):
            e = 'Output mode "%s" not available for multi-part searches.  Use output mode "multi".' % (outputMode)
            logger.error(e)
            raise InvalidOutputMode(e)
            
        ## output multi search
        elif outputMode=='multi':
            part = 0
            allAvailableFields = []
            
            joinTemplate = ' | join type=inner cs_key [%s]'

            ## iterate over each search part
            for cs in correlationSearchParts:
                searchStringPart = ''
                
                ## this is necessary as we iterate
                ## also, modelJson can not be passed for a multi-part search
                modelJson = None
                
                if modelJson is None and cs.get('datamodel', False):
                    ## get the model
                    model_id = DataModels.build_id(cs['datamodel'], None, None)
                    model = DataModels.get(id=model_id, sessionKey=sessionKey)
    
                    ## load the json
                    modelJson = json.loads(model.data)
                
                ## if search part is a datmodel/object
                if cs.get('datamodel', False) and cs.get('object', False):
                    searchStringPart = csb.makeTstats(cs, modelJson)
                
                ## if search part is a inputlookup
                elif cs.get('inputlookup', False):
                    searchStringPart = csb.makeInputlookup(cs)
                
                else:
                    e = 'A search part must specify either a datamodel and object, or an inputlookup'
                    logger.error(e)
                    raise InvalidSearchPart(e)
                
                ## if we got back a positive search string part
                if len(searchStringPart) > 0:
                    '''
                    !important - here is where we test for field overlaps between search parts
                                 however, we need to allow overlap for the key field
                                 this also means we need to test key validity earlier
                    '''
                    availableFields = csb.getAvailableFields(cs, modelJson=modelJson)
                    
                    ## verify that a key is specified
                    if cs.get('key', False):
                        for availableField in availableFields:
                            if availableField in allAvailableFields and availableField!=cs['key']:
                                e = 'Overlap in fields detected.  Each search part in a multi-part search must output a unique set of fields.'
                                logger.error(e)
                                raise InvalidSearchPart(e)
                    
                    else:
                        e = 'Each search part in a mult-part search must specify a valid key'
                        logger.error(e)
                        raise InvalidSearchPart(e)
                    
                    ## collect additional available fields        
                    allAvailableFields.extend(availableFields)
                    
                    ## verify that a key is in availableFields
                    if cs['key'] in availableFields:
                        searchStringPart += ' %s' % (CustomSearchBuilderBase.getKeyEval(cs))
                        
                    else:
                        e = 'Each search part in a mult-part search must specify a valid key'
                        logger.error(e)
                        raise InvalidSearchPart(e)
                    
                    ## if not first part add as join
                    if part > 0:
                        searchString += joinTemplate % (searchStringPart)
                    
                    else:
                        searchString += searchStringPart
                
                else:
                    e = 'The search part specification %s was parsed into a zero length search.  This likely represents an unhandled error.' % (cs)
                    logger.error(e)
                    raise InvalidSearchPart(e)
                
                part += 1
                         
        else:
            e = 'Output mode %s not recognized' % (outputMode)
            logger.error(e)
            raise InvalidOutputMode(e)
                    
    else:
        logger.warn('No search parts were found. Please verify your correlationSearchJson and try again.')                    
    
    ## clean up search string 
    searchString = searchString.strip()
    
    ## initialize parses boolean
    parses = False
   
    ## if we have a positive length search string
    if len(searchString)>0:
        ## get constDedupId
        constDedupId = CustomSearchBuilderBase.getConstDedupId(correlationSearchJson)
        if len(constDedupId)>0:
            searchString += ' %s' % (constDedupId)
        
        ## validate search with splunk's parser
        status, contents = simpleRequest("search/parser", sessionKey=sessionKey, method='GET', getargs={'q': searchString, 'parse_only': 't', 'output_mode': "json"})
    
        if status.status == 200:
            parses = True
                
    return searchString, parses