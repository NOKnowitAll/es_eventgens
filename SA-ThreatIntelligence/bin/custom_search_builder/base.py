import json
import logging
import splunk
import splunk.rest
import splunk.util as util
import sys
import time

from .exceptions import LoggerMissing, InvalidDatamodelObject, InvalidInputlookup, InvalidSplitBy, InvalidAggregate, InvalidResultFilter, InvalidSearchPart

from splunk              import AuthenticationFailed
from splunk.models.base  import SplunkAppObjModel
from splunk.models.field import Field
from splunk.rest         import simpleRequest

from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
from cim_models import DataModels

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.searchutils import parse_search_string



class CorrelationSearchesRH(SplunkAppObjModel):
    '''Class for correlation searches built using JSON Advanced Search Specification'''

    resource = '/configs/conf-correlationsearches'

    search = Field()
    
    rule_title = Field()
    rule_description = Field()
    drilldown_name = Field()
    drilldown_search = Field()


class CustomSearchBuilderBase(object):
    def __init__(self, sessionKey, logger):
        if sessionKey:
            self.sessionKey=sessionKey
        else:
            raise AuthenticationFailed
        
        if logger:
            self.logger=logger
            
        else:
            raise LoggerMissing('Please specify a valid logger instance')

    @staticmethod
    def isSearchRT(cs):
       return cs.get('earliest', '').startswith('rt') or cs.get('latest', '').startswith('rt')

    @staticmethod
    def isRTPossible(correlationSearchJson, sessionKey=None):
        if not sessionKey:
            raise AuthenticationFailed
        
        ## get correlation search parts
        correlationSearchParts     = correlationSearchJson.get('searches', [])
        correlationSearchPartCount = len(correlationSearchParts)
        
        if correlationSearchPartCount==1:
            cs = correlationSearchParts[0]
            
            if 'datamodel' in cs and 'object' in cs:
                ## get the model
                model_id  = DataModels.build_id(cs['datamodel'], None, None)
                model     = DataModels.get(id=model_id, sessionKey=sessionKey)
                ## load the json
                modelJson = json.loads(model.data)
                
                if DataModels.getObjectLineage(cs['object'], modelJson, includeBaseObject=True).startswith('BaseEvent'):
                    return True
        
        return False
                            
    @staticmethod
    def getEarliest(cs):
        earliestTemplate = 'earliest=%s'

        if cs.get('earliest', False):
            return earliestTemplate % cs['earliest']
        
        return ''

    @staticmethod
    def getLatest(cs):
        latestTemplate = 'latest=%s'

        if cs.get('latest', False):
            return latestTemplate % cs['latest']

        return ''
    
    @staticmethod
    def getSplitByRename(cs):
        renameTemplate = '| rename %s'
        asTemplate     = '"%s" as "%s",'
        
        renameString = ''
        
        if cs.get('splitby', False):
            for splitby in cs['splitby']:
                if splitby.get('alias', False) and splitby.get('attribute', False):
                    renameString += asTemplate % (splitby['attribute'],splitby['alias'])
        
        if len(renameString)>0:
            return renameTemplate % (renameString.rstrip(','))
        
        return ''
    
    @staticmethod
    def getConstDedupId(correlationSearchJson):
        ## alert.suppress.fields should be a list
        constDedupString = '| eval const_dedup_id="const_dedup_id"'
        
        ## if alert.suppress exists, if alert.suppress is on, and no alert.suppress.fields specified  
        if correlationSearchJson.get('alert.suppress', False):
            suppress               = util.normalizeBoolean(correlationSearchJson['alert.suppress'], includeIntegers=True)
            suppress_fields        = correlationSearchJson.get('alert.suppress.fields', [])
            suppress_fields_length = len(suppress_fields)
            
            if suppress and (suppress_fields_length==0 or (suppress_fields_length==1 and suppress_fields[0]=="const_dedup_id")):
                return constDedupString
        
        ## else return empty string    
        return ''
        
    @staticmethod
    def getKeyEval(cs):
        template = "| eval cs_key='%s'"
        
        if cs.get('key', False):
            return template % (cs['key'])
         
        return ''
             
    def getObjectLineage(self, cs, modelJson=None, includeBaseObject=False):
        ## proceed if datamodel and object are specified
        if cs.get('datamodel', False) and cs.get('object', False):
               lineage = []

               if modelJson is None:
                   ## get the model
                   model_id = DataModels.build_id(cs['datamodel'], None, None)
                   model = DataModels.get(id=model_id, sessionKey=self.sessionKey)

                   ## load the json
                   modelJson = json.loads(model.data)

               lineage = DataModels.getObjectLineage(cs['object'], modelJson, includeBaseObject=includeBaseObject)

               if len(lineage)>0:
                   return lineage
               
               else:
                   e = "Could not determine lineage for datamodel: %s, object: %s" % (cs['datamodel'],cs['object'])
                   self.logger.error(e)
                   raise InvalidDatamodelObject(e)
        
        else:
            self.logger.warn('Both datamodel and object are required to build nodename')
        
        return ''

    def getSearchBasedTimeFilters(self, cs):
        ## This is `make_ts_value(2)`
        timequalTemplate   = 'eval %s=case(match("%s", "^\d"), tostring("%s"),  match("%s", "^([@\+-]){1}"), relative_time(time(), "%s"),  true(), time())'
        timefilterTemplate = '| %s | %s | where (%s>=earliestQual AND %s<=latestQual) | fields - earliestQual, latestQual'

        if cs.get('inputlookup', False) and cs['inputlookup'].get('timeField', False):
            timeField = cs['inputlookup']['timeField']

            if cs.get('earliest', False):
                earliest = cs['earliest']
            else:
                earliest = '0'
                self.logger.warn("No earliest qualifier specified.  Using 0.")

            if cs.get('latest', False):
                latest = cs['latest']
            else:
                latest = '+0s'
                self.logger.warn("No latest qualifier specified. Using default (now).")
            
            earliestQual = timequalTemplate % ('earliestQual', earliest, earliest, earliest, earliest)
            latestQual = timequalTemplate % ('latestQual', latest, latest, latest, latest)

            ## If this is an all time search, there is no point in doing work
            if earliest=='0' and (latest=='now' or latest=='+0s'):
                return ''
            
            else:
                return timefilterTemplate % (earliestQual, latestQual, timeField, timeField)

        else:
            self.logger.warn("No time field specified")
        
        return ''

    def getEventFilter(self, cs, tstats=False):
        ## Proper field handling is crucial since this is slated for use in both:
        ## 1. The tstats where clause
        ## 2. Use with "| search" or "| where"
        ##
        ## tstats (like stats) uses double quotes for field names
        ## where uses single quotes for field names
        ## for now we will just replace single quotes w/ double quotes

        ## we also have issues that not all event filters can be injected into tstats

        if cs.get('eventFilter', False):
            if tstats:
                return cs['eventFilter'].replace('\'','"')
            else:
                return cs['eventFilter']
                
        else:
            self.logger.warn("No event filter specified")
        
        return ''

    def getAggregates(self, cs):
        aggregateString = ''
        
        if cs.get('aggregates', False):
            for aggregate in cs['aggregates']:

                ## We must have a function
                if aggregate.get('function', False):

                    ## We must have an attribute
                    if aggregate.get('attribute', False):
                        
                        ## If we have an alias
                        if aggregate.get('alias', False):
                            aggregateTemplate = '%s(%s) as "%s",'
                            aggregateString += aggregateTemplate % (aggregate['function'],aggregate['attribute'],aggregate['alias'])

                        else:
                            aggregateTemplate = "%s(%s),"
                            aggregateString += aggregateTemplate % (aggregate['function'],aggregate['attribute'])

                    ## Unless function is count
                    elif aggregate['function'] == 'count':

                        ## If we have an alias
                        if aggregate.get('alias', False):
                            aggregateTemplate = '%s as "%s",'
                            aggregateString += aggregateTemplate % (aggregate['function'],aggregate['alias'])

                        else:
                            aggregateTemplate = '%s,'
                            aggregateString += aggregateTemplate % aggregate['function']

                    else:
                        e = 'All functions except count must have an attribute'
                        self.logger.error(e)
                        raise InvalidAggregate(e)

                else:
                    e = 'Aggregate with no function not possible'
                    self.logger.error(e)
                    raise InvalidAggregate(e)

        else:
            self.logger.warn("No aggregates specified")

        return aggregateString.rstrip(',')

    def getSplitBy(self, cs):
        splitbyTemplate = 'by %s'

        if cs.get('splitby', False):
            splitbyString = ''
            for splitby in cs['splitby']:
                if splitby.get('attribute', False):
                    splitbyString += '"%s"' % (splitby['attribute'])
                    splitbyString += ','
                else:
                    e = 'A valid splitby must specify an attribute'
                    self.logger.error(e)
                    raise InvalidSplitBy

            return splitbyTemplate % (splitbyString).rstrip(',')

        else:
            self.logger.warn("No splitby specified")
        
        return ''

    def getSplitBySpan(self, cs):
        ## span validation
        spanValidationTemplate = '| makeresults | bucket _time span=%s'
        
        ## return variables
        addSpan   = False
        spanField = '_time'
        span      = ''
        
        ## check for splitby
        if cs.get('splitby', False):
            ## iterate splitby
            for splitby in cs['splitby']:
                ## if splitby attribute is _time
                if splitby.get('attribute', False) and splitby['attribute'] == '_time':
                    ## if a span is specified
                    if splitby.get('span', False):
                        ## validate span with splunk's parser
                        spanValidation = spanValidationTemplate % splitby['span']

                        try:
                            contents = parse_search_string(spanValidation, self.sessionKey)
                            addSpan = True
                            span    = splitby['span']
                        except ValueError as e:
                            self.logger.warn("The value for option span (%s) is invalid" % splitby['span'])
                    break
        
        return addSpan, spanField, span      

    def getAvailableFields(self, cs, modelJson=None):
        ## aggregates imply a transformation of the results so we know what the search output will look like
        availableFields = []

        ## if aggregates are present
        if cs.get('aggregates', False):
            ## iterate through the aggregates
            for aggregate in cs['aggregates']:
                ## if we have an alias, add that
                if aggregate.get('alias', False):
                    availableFields.append(aggregate['alias'])
                ## if not, add the function attribute
                elif aggregate.get('function', False) and aggregate.get('attribute', False):
                    aggregateTemplate = "%s(%s)"
                    availableFields.append(aggregateTemplate % (aggregate['function'],aggregate['attribute']))
                ## if not, see if the function is count
                elif aggregate.get('function', False) == 'count':
                    availableFields.append(aggregate['function'])

            ## if splitbys are present
            if cs.get('splitby', False):
                for splitby in cs['splitby']:
                    if splitby.get('alias', False):
                        availableFields.append(splitby['alias'])
                    elif splitby.get('attribute', False):
                        availableFields.append(splitby['attribute'])

        ## elif datamodel/object
        elif cs.get('datamodel', False) and cs.get('object', False):
            if modelJson is None:
                ## get the model
                model_id = DataModels.build_id(cs['datamodel'], None, None)
                model = DataModels.get(id=model_id, sessionKey=self.sessionKey)

                ## load the json
                modelJson = json.loads(model.data)
                
            ## getAvailableFields for non-transforming search
            tempFields = DataModels.getAvailableFields(cs.get('object'),modelJson)
            
            ## if we were able to determine lineage extend fields
            if tempFields is not None:
                availableFields.extend(tempFields)

            else:
                e = "Could not determine lineage for datamodel: %s, object: %s" % (cs['datamodel'],cs['object'])
                self.logger.error(e)
                raise InvalidDatamodelObject(e)
        
        ## elif inputlookup
        elif cs.get('inputlookup', False) and cs['inputlookup'].get('lookupName', False):
            availableFields = self.get_lookup_fields(cs['inputlookup']['lookupName']) or None

        return availableFields

    def get_lookup_fields(self, candidate):
        getargs = {'output_mode': 'json'}

        if candidate.endswith(('.csv', '.csv.gz')):
            getargs.update({'search': 'filename=%s' % candidate})
            uri = 'data/transforms/lookups'
        else:
            uri = 'data/transforms/lookups/%s' % candidate

        try:
            r, c = splunk.rest.simpleRequest(uri, self.sessionKey, getargs=getargs)
            parsed_content = json.loads(c)['entry'][0]['content']
            lookupFields   = parsed_content['fields_list'].split(',')
        except (splunk.RESTException, AttributeError, ValueError) as e:
            lookupFields = None

        return lookupFields

    def getResultFilter(self, cs, availableFields=None, modelJson=None):
        filterTemplate = "'%s'%s%s"

        if cs.get('resultFilter', False):

            if cs['resultFilter'].get('field', False) and cs['resultFilter'].get('comparator', False) and cs['resultFilter'].get('value', False):
                
                if availableFields is None:
                    availableFields = self.getAvailableFields(cs, modelJson=modelJson)
                   
                if cs['resultFilter']['field'] in availableFields:
                     ## Todo: Properly quote value if it is a string
                     return filterTemplate % (cs['resultFilter']['field'], cs['resultFilter']['comparator'], cs['resultFilter']['value'])

                else:
                    e = 'Field %s must be in the list of available fields: %s' % (cs['resultFilter']['field'], availableFields)
                    self.logger.error(e)
                    raise InvalidResultFilter(e)

            else:
                e = 'Valid result filters must have a field, comparator, and value'
                self.logger.error(e)
                raise InvalidResultFilter(e)

        else:
            self.logger.warn('No result filters specified')
        
        return ''
    
    def getCorrelationSearch(self, savedsearch):
        correlationSearchJson = {}
        savedsearchId = CorrelationSearchesRH.build_id(savedsearch, None, None)
        correlationSearchRaw = CorrelationSearchesRH.get(id=savedsearchId, sessionKey=self.sessionKey)
        correlationSearchJson = json.loads(correlationSearchRaw.search)

        return correlationSearchJson

    def makeRaw(self, cs, modelJson):
        searchString = ''
        
        ## span vars
        addSpan   = False
        spanField = ''
        span      = ''
    
        ## here is the raw search template
        template = ['| datamodel "%s" "%s" search ',  #0 - datamodel (Datamodel/Object)
                    '| where %s ',                    #1 - where (Event Filter)
                    '| bucket span=%s %s ',           #2 - bucket (for timestamp Splitby)
                    '| stats %s %s ',                 #3 - stats (Aggregates/Splitby)
                    '%s ',                            #4 - Splitby rename
                    '| where %s '                     #5 - where (Result Filter)
                   ]

        ## check for datamodel and object
        if cs.get('datamodel', False) and cs.get('object', False):
            ## start building string
            searchString += template[0] % (cs['datamodel'],cs['object'])

            ## get event filters
            eventFilter = self.getEventFilter(cs)
            if len(eventFilter) > 0:
                searchString += template[1] % (eventFilter)

            ## get aggregates and splitby
            aggregates = self.getAggregates(cs)
            splitby = self.getSplitBy(cs)

            ## if we have both
            if len(aggregates)>0 and len(splitby)>0:
                ## get splitby span
                addSpan, spanField, span = self.getSplitBySpan(cs)
                
                if addSpan:
                    searchString += template[2] % (span, spanField)
                
                searchString += template[3] % (aggregates,splitby)
                
                ## get splitby rename
                splitbyRename = CustomSearchBuilderBase.getSplitByRename(cs)
                if len(splitbyRename)>0:
                    searchString += template[4] % (splitbyRename)

            ## aggregates only
            elif len(aggregates)>0:
                searchString += '| stats %s ' % (aggregates)

            ## splitby only
            elif len(splitby)>0:
                e = 'Splitby specified with no aggregates'
                self.logger.error(e)
                raise InvalidSearchPart(e)

            ## get available fields
            availableFields = self.getAvailableFields(cs, modelJson=modelJson)

            ## get result filter
            resultFilter = self.getResultFilter(cs, availableFields=availableFields)
            if len(resultFilter)>0:
                searchString += template[5] % (resultFilter)

        else:
            self.logger.error('Raw search requires valid datamodel and object')
        
        return searchString.strip()

    def makeTstats(self, cs, modelJson, strictMode=True, addTimeConstraints=True):
        searchString = ''
        ## here is the tstats search template
        #0 - tstats (summariesonly/aggregates/datamodel/object/where/splitby/span)
        #1 - Splitby rename
        #2 - where (Result Filter) 
        template = ['| tstats %s allow_old_summaries=true %s from datamodel=%s.%s %s %s %s ',
                    '%s ',                                                                 
                    '| where %s '                                                        
                   ]
        
        ## where (earliest/latest/nodename/eventFilter)
        whereTemplate = 'where %s %s %s %s'
        
        ## span vars
        spanTemplate  = 'span=%s'
        addSpan       = False
        spanField     = ''
        span          = ''
        
        ## per SOLNESS-4987: we need not return tstats if RT is requested
        if CustomSearchBuilderBase.isSearchRT(cs):
            e = 'RT search requested.  Cannot produce a valid tstats search.'
        
            if strictMode:
                self.logger.error(e)
                raise InvalidSearchPart(e)
            
            else:
                self.logger.warn(e)
                return '' 
        
        ## per SOLNESS-4979: we need not return tstats if _raw aggregates/splitbys are present
        if cs.get('aggregates', False):
            ## iterate aggregates
            for aggregate in cs['aggregates']:
                ## aggregate should have an attribute
                if aggregate.get('attribute', False) and aggregate['attribute'] == '_raw':
                    e = '_raw aggregates detected.  Cannot produce a valid tstats search.'
                    
                    if strictMode:
                        self.logger.error(e)
                        raise InvalidSearchPart(e)
                    
                    else:
                        self.logger.warn(e)
                        return ''
        
        if cs.get('splitby', False):
            ## iterate splitby
            for splitby in cs['splitby']:
                ## splitby should have an attribute
                if splitby.get('attribute', False) and splitby['attribute'] == '_raw':
                    e = '_raw splitby detected.  Cannot produce a valid tstats search.'
                    
                    if strictMode:
                        self.logger.error(e)
                        raise InvalidSearchPart(e)
                    
                    else:
                        self.logger.warn(e)
                        return ''
        
        aggregates = self.getAggregates(cs)
        
        nodename   = self.getObjectLineage(cs, modelJson=modelJson, includeBaseObject=True)
        ## per SOLNESS-4995: Only allow BaseEvent objects
        if nodename.startswith('BaseEvent'):
            nodename = nodename.lstrip('BaseEvent.')
            ## per SOLNESS-7938: use nodename (list) length to
            ## 1. set childobj as the child of BaseEvent
            ## 2. determine if a nodename filter is required
            nodename = nodename.split('.')
            childobj = nodename[0]
            if len(nodename)==1:
                nodename = ''
            else:
                nodename = 'nodename=%s' % '.'.join(nodename)
            
        else:
            e = 'Non BaseEvent object detected.  Cannot produce a valid tstats search.'
        
            if strictMode:
                self.logger.error(e)
                raise InvalidSearchPart(e)
            
            else:
                self.logger.warn(e)
                return ''
        
        if cs.get('datamodel', False) and len(childobj)>0 and len(aggregates)>0:
            earliest    = ''
            latest      = ''
            eventFilter = self.getEventFilter(cs, tstats=True)
            splitby     = self.getSplitBy(cs)
            
            ## get splitby span
            addSpan, spanField, span = self.getSplitBySpan(cs)        
            if addSpan:
                span = spanTemplate % span
            else:
                span = ''
                
            if addTimeConstraints:
                earliest = CustomSearchBuilderBase.getEarliest(cs)
                latest   = CustomSearchBuilderBase.getLatest(cs)
            
            ## get where
            where = whereTemplate % (earliest, latest, nodename, eventFilter)
            if where.strip() == 'where':
                where = ''           
            
            ## SOLNESS-8271
            ## adding backwards-compatible support for summariesonly
            ## if unspecified we don't specify (inherit system default)
            if cs.get('summariesonly') and util.normalizeBoolean(cs['summariesonly']):
                summariesonly = 'summariesonly=true'
            elif cs.get('summariesonly'):
                summariesonly = 'summariesonly=false'
            else:
                summariesonly = ''
            
            searchString += template[0] % (summariesonly, aggregates, cs['datamodel'], childobj, where, splitby, span)
            
            ## get splitby rename
            splitbyRename = CustomSearchBuilderBase.getSplitByRename(cs)
            if len(splitbyRename)>0:
                searchString += template[1] % (splitbyRename)
                
            ## get available fields
            availableFields = self.getAvailableFields(cs, modelJson=modelJson)

            ## get result filter
            resultFilter = self.getResultFilter(cs, availableFields=availableFields)
            if len(resultFilter)>0:
                searchString += template[2] % (resultFilter)
            
        else:
            e = 'Tstats searches must have a datamodel, object, and aggregate'
            
            if strictMode:
                self.logger.error(e)
                raise InvalidSearchPart(e)
            
            else:
                self.logger.warn(e)

        return searchString.strip() 

    def makeInputlookup(self, cs):
        searchString = ''
        
        ## span vars
        addSpan   = False
        spanField = ''
        span      = ''
        
        ## here is the inputlookup search template
        template = ['| inputlookup append=T %s %s ',  #0 - inputlookup (Table)
                    '| where %s ',                    #1 - where (Event Filter)
                    '| bucket span=%s %s ',           #2 - bucket (for timestamp Splitby)
                    '| stats %s %s ',                 #3 - stats (Aggregate/Splitby)
                    '%s ',                            #4 - Splitby rename
                    '| where %s '                     #5 - where (Result Filter)
                   ]

        ## check for inputlookup
        if cs.get('inputlookup', False) and cs['inputlookup'].get('lookupName', False):
             
            ## per SOLNESS-4987: we should except if RT is requested
            if cs['inputlookup'].get('timeField', False) and CustomSearchBuilderBase.isSearchRT(cs):
                e = 'RT search requested.  Cannot produce a valid inputlookup search.'
                self.logger.error(e)
                raise InvalidSearchPart(e)
        
            ## get time based filters
            timeFilter = self.getSearchBasedTimeFilters(cs)

            ## start building string
            searchString += template[0] % (cs['inputlookup']['lookupName'], timeFilter)

            ## get event filters
            eventFilter = self.getEventFilter(cs)
            if len(eventFilter) > 0:
                   searchString += template[1] % (eventFilter)

            ## get aggregates and splitby
            aggregates = self.getAggregates(cs)
            splitby = self.getSplitBy(cs)

            ## if we have both
            if len(aggregates)>0 and len(splitby)>0:
                ## get splitby span
                addSpan, spanField, span = self.getSplitBySpan(cs)
                
                if addSpan:
                    searchString += template[2] % (span, spanField)
                
                searchString += template[3] % (aggregates,splitby)
                
                ## get splitby rename
                splitbyRename = CustomSearchBuilderBase.getSplitByRename(cs)
                if len(splitbyRename)>0:
                    searchString += template[4] % (splitbyRename)
            
            ## aggregates only
            elif len(aggregates)>0:
                searchString += '| stats %s ' % (aggregates)

            ## splitby only
            elif len(splitby)>0:
                e = 'Splitby specified with no aggregates'
                self.logger.error(e)
                raise InvalidSearchPart(e)

            ## get available fields
            availableFields = self.getAvailableFields(cs)

            ## get result filter
            resultFilter = self.getResultFilter(cs, availableFields=availableFields)
            if len(resultFilter)>0:
                searchString += template[5] % (resultFilter)
                
        else:
            e = 'inputlookup search requires lookup name'
            self.logger.error(e)
            raise InvalidInputlookup(e)
 
        return searchString.strip()
