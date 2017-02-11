import datetime
import json
import sys

from .base       import CustomSearchBuilderBase
from .exceptions import InvalidAggregate, InvalidSplitBy, InvalidSearchPart
from splunk.rest import simpleRequest

from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
from cim_models import DataModels

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.searchutils import parse_search_string

    
class InvalidRetentionFilter(Exception):
    pass

class LookupSearchBuilderBase(CustomSearchBuilderBase):
    
    def getConsolidatingAggregates(self, ls):
        aggregateString = ''
        
        if ls.get('aggregates', False):
            for aggregate in ls['aggregates']:
                function = aggregate.get('function', False)
                ## We must have a function
                if function:
                    ## We must have an attribute
                    if aggregate.get('attribute', False):
                        if function == 'count':
                            function = 'sum'
                        ## If we have an alias
                        if aggregate.get('alias', False):
                            aggregateTemplate = '%s(%s) as "%s",'
                            aggregateString += aggregateTemplate % (function,aggregate['alias'],aggregate['alias'])

                        else:
                            aggregateTemplate = '%s(%s(%s)) as "%s(%s)",'
                            aggregateString += aggregateTemplate % (function,aggregate['function'],aggregate['attribute'],aggregate['function'],aggregate['attribute'])
                    ## Unless function is count
                    elif function == 'count':
                        aggregateTemplate = '%s(%s) as "%s",'
                        function          = 'sum'
                        alias             = aggregate.get('alias', 'count')
                        aggregateString  += aggregateTemplate % (function,alias,alias)
                    else:
                        e = 'All functions except count must have an attribute'
                        self.logger.error(e)
                        raise InvalidAggregate(e)
                else:
                    e = 'Aggregate with no function not possible'
                    self.logger.error(e)
                    raise InvalidAggregate(e)
        
        aggregateString = aggregateString.rstrip(',')
        if len(aggregateString)<1:
            e = 'At least one valid aggregate is required'
            self.logger.error(e)
            raise InvalidAggregate(e)            

        return aggregateString

    def getConsolidatingSplitBy(self, ls):
        splitbyTemplate = 'by %s'

        if ls.get('splitby', False):
            splitbyString = ''
            for splitby in ls['splitby']:
                attribute = splitby.get('attribute', False)
                if attribute:
                    alias = splitby.get('alias', False)
                    if alias:
                        attribute = alias
                    splitbyString += '"%s"' % attribute
                    splitbyString += ','
                else:
                    e = 'A valid splitby must specify an attribute'
                    self.logger.error(e)
                    raise InvalidSplitBy(e)

            return splitbyTemplate % splitbyString.rstrip(',')

        else:
            self.logger.warn('No splitby specified')
        
        return ''
    
    def getRetentionFilter(self, ls, modelJson=None):
        retentionTemplate = '''| where strptime('%s', "%s")>=relative_time(now(), "%s")'''
             
        retentionDict     = ls.get('retention', False)
        if retentionDict:
            earliestTime      = retentionDict.get('earliestTime', False)
            timeField         = retentionDict.get('timeField', False)
            timeFormat        = retentionDict.get('timeFormat', False)

            if earliestTime and timeField and timeFormat:
                r, c = simpleRequest('/search/timeparser', sessionKey=self.sessionKey, getargs={'output_mode': 'json', 'time': earliestTime})
                if r.status != 200:
                    e = 'A valid retention period must specify a valid earliestTime'
                    self.logger.error(e)
                    raise InvalidRetentionFilter(e)
                
                if timeField not in self.getAvailableFields(ls, modelJson=modelJson):
                    e = 'A valid retention period must specify a valid timeField'
                    self.logger.error(e)
                    raise InvalidRetentionFilter(e)
                
                ts = datetime.datetime.now()
                tf = ts.strftime(timeFormat)

                ## python returns this differently depending on the platform
                if tf == timeFormat or tf == timeFormat.replace('%', ''):
                    e = 'A valid retention period must specify a valid timeFormat'
                    self.logger.error(e)
                    raise InvalidRetentionFilter(e)
                
                return retentionTemplate % (timeField, timeFormat, earliestTime)
                
            else:
                e = 'A valid retention period must specify an earliestTime, timeField, and timeFormat'
                self.logger.error(e)
                raise InvalidRetentionFilter(e)  
        else:
            self.logger.warn('No retention period specified')
        
        return '' 
        

def makeLookupGeneratingSearch(lookupSearchJson, modelJson=None, sessionKey=None, logger=None):
    ## Get instance of CustomSearchBuilderBase
    ## This validates sessionKey and logger
    lsb           = LookupSearchBuilderBase(sessionKey, logger)
    
    searchString  = ''
    initialSearch = ''
    template      = [
        '%s ',                        ## 0 - tstats/raw (initial) portion of search 
        '| inputlookup append=T %s ', ## 1 - inputlookup on outputlookup
        '| bin %s span=%s ',          ## 2 - bin (if necessary)                                                             
        '| stats %s %s ',             ## 3 - consolidating stats                                                      
        '%s ',                        ## 4 - retention
        '| outputlookup %s ',         ## 5 - outputlookup on outputlookup
        '| stats count'               ## 6 - stats count
    ]
        
    ls           = lookupSearchJson.get('search', {})
    datamodel    = ls.get('datamodel', False)
    outputlookup = ls.get('outputlookup', False)

    ## if search part contains a datamodel
    if datamodel and ls.get('object', False) and outputlookup:
        
        if modelJson is None:
            ## get the model
            model_id = DataModels.build_id(datamodel, None, None)
            model    = DataModels.get(id=model_id, sessionKey=sessionKey)
            ## load the json
            modelJson = json.loads(model.data)
        
        ## no RT
        if LookupSearchBuilderBase.isSearchRT(ls):
            e = 'Lookup Search Builder does not support RT'
            logger.error(e)
            raise InvalidSearchPart(e)
        
        raw           = lsb.makeRaw(ls, modelJson=modelJson)
        raw_length    = len(raw)
        
        tstats        = lsb.makeTstats(ls, modelJson=modelJson, strictMode=False, addTimeConstraints=False)
        tstats_length = len(tstats)
        
        parses        = False
        
        ## if a non zero length tstats search is available, take it                    
        if tstats_length>0:
            ## validate search with splunk's parser
            ## we do parsing here, in case a complex where clause is passed to tstats
            try:
                contents      = parse_search_string(tstats, sessionKey)
                parses        = True
                initialSearch = tstats
            except ValueError as e:
                logger.warn('tstats search does not parse, tstats search cannot be used')
                        
        ## if tstats was zero length or does not parse, take raw search
        if (tstats_length==0 or (tstats_length>0 and not parses)) and raw_length>0:
            initialSearch = raw
        
        ## if tstats was zero length or does not parse, and no raw search    
        elif (tstats_length==0 or (tstats_length>0 and not parses)) and raw_length==0:
            e = 'Single output mode with specified datamodel %s did not return a valid tstats %s or raw %s search' % (datamodel, tstats, raw)
            logger.error(e)
            raise InvalidSearchPart(e)
    
    ## if search part contains an inputlookup
    elif ls.get('inputlookup', False) and outputlookup:
        initialSearch = lsb.makeInputlookup(ls)
    
    else:
        e = 'A search part must specify an outputlookup and either a datamodel and object, or an inputlookup'
        logger.error(e)
        raise InvalidSearchPart(e)
    
    ## clean up initial search
    initialSearch = initialSearch.strip()
    ## initialize parses boolean
    parses = False
    ## if we have a positive length search string
    if len(initialSearch)>0:        
        searchString  = template[0] % initialSearch
        searchString += template[1] % outputlookup
        
        ## get splitby span
        addSpan, spanField, span = lsb.getSplitBySpan(ls)        
        if addSpan:
            searchString += template[2] % (spanField, span)
        
        searchString += template[3] % (lsb.getConsolidatingAggregates(ls), lsb.getConsolidatingSplitBy(ls))
        searchString += template[4] % lsb.getRetentionFilter(ls, modelJson=modelJson)
        searchString += template[5] % outputlookup
        searchString += template[6]
        
        ## validate search with splunk's parser
        response, contents = simpleRequest("search/parser", sessionKey=sessionKey, getargs={'q': searchString, 'parse_only': 't', 'output_mode': 'json'})
    
        if response.status == 200:
            parses = True
                
    return searchString, parses
