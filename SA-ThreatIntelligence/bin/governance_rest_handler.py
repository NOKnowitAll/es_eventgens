"""
Copyright (C) 2005 - 2016 Splunk Inc. All Rights Reserved.
"""
import json
import logging
import re
import splunk.admin as admin
import splunk.entity as entity
import splunk.rest as rest
import sys

if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)

from splunk import ResourceNotFound
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
from SolnCommon.log import setup_logger, SHORT_FORMAT
from SolnCommon.kvstore import KvStoreHandler
from SolnCommon.pooling import should_execute

logger = setup_logger('governance_rest_handler', level=logging.INFO, format=SHORT_FORMAT)


class UnauthorizedUserException(Exception):
    pass


class InvalidConfigException(Exception):
    pass


class InvalidParameterValueException(InvalidConfigException):
    """
    Describes a config parameter that has an invalid value.
    """
    
    def __init__(self, field, value, value_must_be):
        message = "The value for the parameter '%s' is invalid: %s (was %s)" % (field, value_must_be, value)
        super(InvalidConfigException, self).__init__( message)
      
        
class UnsupportedParameterException(InvalidConfigException):
    """
    Describes a config parameter that is unsupported.
    """
    pass


class IncompleteComplianceException(InvalidConfigException):
    """
    Describes a compliance parameter that is incomplete.
    """
    pass


def _getFieldValue(args, name, default_value=None, max_length=None):
    """
    Get the field value from the argument list.
    """
    
    # Get the value if defined or the default value if not defined
    value = args[name][0] or default_value if name in args else default_value
    
    # Check the length
    if value and max_length and len(value) > max_length:
        raise admin.ArgValidationException(
            'App %s cannot be longer than %s character%s.' % (name, max_length, "s" if max_length > 1 else ""))
    # return the value
    return value
    

def _addToDictIfNonNull(dict, name, value):
      """
      Add the given name and value to the dictionary if the value is not none.
      
      Arguments:
      dict -- the dictionary to add to
      name -- the name of the object to add
      value -- the value of the object to add (if not none)
      """
      
      if value is not None:
          dict[name] = value

          
class Governance(admin.MConfigHandler):
    '''
    Set up supported arguments
    '''
    ## admin.py constants
    REQUESTED_ACTIONS   = { '1': 'ACTION_CREATE', '2': 'ACTION_LIST', '4': 'ACTION_EDIT', '8': 'ACTION_REMOVE', '16': 'ACTION_MEMBERS', '32': 'ACTION_RELOAD' }
  
    ## Permissions
    WRITE_CAPABILITY    = 'edit_correlationsearches'

    ## Defaults Param
    PARAM_DISABLED      = 'disabled'
    PARAM_SAVEDSEARCH   = 'savedsearch'
    PARAM_GOVERNANCE    = 'governance'
    PARAM_CONTROL       = 'control'
    PARAM_TAG           = 'tag'
    PARAM_LOOKUP_TYPE   = 'lookup_type'
  
    VALID_PARAMS        = []
    REQUIRED_PARAMS     = []
    REQUIRED_COMPLIANCE = [PARAM_GOVERNANCE, PARAM_CONTROL]
  
    IGNORED_PARAMS      = [PARAM_DISABLED]

    ## Default Vals
    DEFAULT_NAMESPACE   = 'SA-ThreatIntelligence'
    DEFAULT_OWNER       = 'nobody'
    DEFAULT_LOOKUP_TYPE = 'default'
    TAG_LOOKUP_TYPE     = 'tag'
  
    governanceRE        = re.compile('^(compliance\.(\d+))\.' + PARAM_GOVERNANCE + '$')
    controlRE           = re.compile('^(compliance\.(\d+))\.' + PARAM_CONTROL + '$')
    tagRE               = re.compile('^(compliance\.(\d+))\.' + PARAM_TAG + '$')  
  
    def setup(self):
        logger.info('Setting up governance_rest_handler')
      
        ## set write capability
        self.setWriteCapability(Governance.WRITE_CAPABILITY)       
       
        if self.requestedAction == admin.ACTION_EDIT or self.requestedAction == admin.ACTION_CREATE:         
            ## Fill required params
            for arg in Governance.REQUIRED_PARAMS:
                self.supportedArgs.addReqArg(arg)
              
            ## Fill valid params
            for arg in Governance.VALID_PARAMS:
                if arg not in Governance.REQUIRED_PARAMS:
                    self.supportedArgs.addOptArg(arg)

            ## Fill wildcarded params
            for arg in Governance.REQUIRED_COMPLIANCE:
                wildcardParam = 'compliance.*'
                if wildcardParam not in Governance.REQUIRED_PARAMS:
                    self.supportedArgs.addOptArg(wildcardParam)
  
    def handleCreate(self, confInfo):
        """
        Handles creation of a governance configuration
        """
        ## Get requested action
        actionStr = str(self.requestedAction)
        if Governance.REQUESTED_ACTIONS.has_key(actionStr):
            actionStr = Governance.REQUESTED_ACTIONS[actionStr]
          
        logger.info('Entering %s' % (actionStr))
      
        ## Refresh
        self.handleReload(makeKVS=False)

        name = self.callerArgs.id
        args = self.callerArgs.data
      
        # Make sure the name is not empty
        if not name or len(name) == 0:
            raise admin.ArgValidationException("The name of the governance configuration must not be empty")
      
        # Make sure the item does not already exist
        if name in self.readConf('governance'):
            raise admin.AlreadyExistsException("A governance configuration already exists for %s" % (name))
      
        ## Get a new entry from the conf-postprocess interface
        conf = entity.getEntity('configs/conf-governance', '_new', sessionKey=self.getSessionKey())
    
        conf.namespace = self.appName # always save things to SOME app context.
        conf.owner = self.context == admin.CONTEXT_APP_AND_USER and self.userName or "-"
      
        conf['name'] = name
      
        for arg in args:
            governanceMatch = Governance.governanceRE.match(arg)
            controlMatch = Governance.controlRE.match(arg)
            tagMatch = Governance.tagRE.match(arg)
          
            ## Add the field values to a configuration dictionary (that will be verified)
            if governanceMatch or controlMatch or tagMatch or arg in Governance.VALID_PARAMS:
                _addToDictIfNonNull(conf, arg, args[arg][0])
    
        ## Check the configuration
        try:
            Governance.checkConf(conf, name)
      
        except InvalidConfigException as e:
            e = "The configuration for the new governance entry '%s' is invalid and could not be created: %s" % (name, str(e))
            logger.error(e)
            raise admin.ArgValidationException(e)
    
        ## Write out an update to the reviewstatuses config file
        entity.setEntity(conf, sessionKey=self.getSessionKey())

        logger.info('Successfully added governance configuration: %s' % (name))
      
        ## Reload governance (makeKVS)
        self.handleReload()
      
        logger.info('%s completed successfully' % (actionStr))
      
    def handleList(self, confInfo):      
        """
        Handles listing of a governance entry
        """
        ## Get requested action
        actionStr = str(self.requestedAction)
        if Governance.REQUESTED_ACTIONS.has_key(actionStr):
            actionStr = Governance.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s' % (actionStr))
        
        ## Refresh
        self.handleReload(makeKVS=False)
         ## Get the configurations from governance.conf
        governanceDict = self.readConfCtx('governance')
        
        ## Get all governance configurations and provide the relevant options
        if governanceDict is not None: 
            
            ## Check each conf
            for stanza, settings in governanceDict.items():
                if stanza != 'default':
                    try:
                        ## Check config
                        Governance.checkConf(settings, stanza, confInfo)
                     
                    except InvalidConfigException as e:
                        logger.error( "The configuration for governance entry '%s' is invalid: %s" % ( stanza, str(e)) )                  
               
        logger.info('%s completed successfully' % (actionStr) ) 
                
    def handleReload(self, confInfo=None, makeKVS=True):
        """
        Handles refresh/reload of the configuration options
        """
        ## Get requested action
        actionStr = str(self.requestedAction)
        if Governance.REQUESTED_ACTIONS.has_key(actionStr):
            actionStr = Governance.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s' % (actionStr))
        try:
            refreshInfo = entity.refreshEntities('properties/governance', sessionKey=self.getSessionKey())
            
        except Exception as e:
            logger.warn('Could not refresh governance configurations via properties endpoint: %s' % str(e))
       
        if makeKVS:
            # Only execute on standalone or on cluster master. 
            exec_status, exec_status_msg = should_execute(session_key=self.getSessionKey())
            logger.info(exec_status_msg)
            if exec_status:
                self.makeKVS()
         
        logger.info('%s completed successfully' % (actionStr))
        
    def makeKVS(self, collection='governance', governanceDict=None):
        """
        Handles maintenance of governance kvstore collection
        """
        logger.info('Creating %s collection', collection)
        ## options
        options = {'app': Governance.DEFAULT_NAMESPACE, 'owner': Governance.DEFAULT_OWNER, 'collection': collection}
        ## get correlationsearches conf
        governanceDict = governanceDict or self.readConf('governance')
        
        if not governanceDict:
            logger.error('Governance dictionary is None; cannot makeKVS')
        else:
            ## get reviewstatuses collection
            gr, gc = KvStoreHandler.get(None, self.getSessionKey(), options)
            
            if gr.status==200:
                removedKeys = [x['_key'] for x in json.loads(gc)]
                governances = []
                for stanza, settings in governanceDict.items():
                    if stanza!='default':
                        governanceFlat = {'governance': {}, 'control': {}, 'tag': {}}
                        for key, val in settings.items():
                            governanceMatch = Governance.governanceRE.match(key)
                            controlMatch    = Governance.controlRE.match(key)
                            tagMatch        = Governance.tagRE.match(key)
                            if governanceMatch and val:
                                governanceFlat['governance'][governanceMatch.group(2)] = val
                            elif controlMatch:
                                governanceFlat['control'][controlMatch.group(2)] = val or None
                            elif tagMatch:
                                governanceFlat['tag'][tagMatch.group(2)] = val or None
                        
                        for key, val in governanceFlat['governance'].items():                            
                            if governanceFlat['control'].get(key, None):
                                governance = {
                                    '_key':        stanza + '|' + key,
                                    'savedsearch': stanza,
                                    'governance':  val,
                                    'control':     governanceFlat['control'][key],
                                    'tag':         governanceFlat['tag'].get(key, None),
                                    'lookup_type': Governance.DEFAULT_LOOKUP_TYPE  
                                }
                                if governance['tag']:
                                    governance['lookup_type'] = Governance.TAG_LOOKUP_TYPE                                    
                                governances.append(governance)            

                pr, pc = KvStoreHandler.batch_create(governances, self.getSessionKey(), options)
                if pr.status!=200:
                    logger.error('Error in upserting records to %s collection: %s', collection, pc)
                
                removedKeys = list(set(removedKeys).difference([x['_key'] for x in governances])) 
                if len(removedKeys)>0:
                    duri   = '/servicesNS/{owner}/{app}/storage/collections/data/{collection}'.format(**options)
                    dquery = {'$or': []}
                    
                    for removedKey in removedKeys:
                        dquery['$or'].append({'_key': removedKey})
                    
                    dr, dc = rest.simpleRequest(duri, sessionKey=self.getSessionKey(), method='DELETE', getargs={'query': json.dumps(dquery)})
                    
                    if dr.status!=200:
                        logger.error('Error in deleting records from %s collection: %s', collection, dc)
            else:
                logger.error('Error retrieving records from %s collection: %s', collection, gc)     

    def handleEdit(self, confInfo):
        """
        Handles edits to the configuration options
        """
        ## Get requested action
        actionStr = str(self.requestedAction)
        if Governance.REQUESTED_ACTIONS.has_key(actionStr):
            actionStr = Governance.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s' % (actionStr))
        
        ## Refresh
        self.handleReload(makeKVS=False)
        
        name = self.callerArgs.id
        args = self.callerArgs
        
        if name is not None:
            try:
                conf = entity.getEntity('configs/conf-governance', name, sessionKey=self.getSessionKey())
                  
            except ResourceNotFound:
                raise admin.NotFoundException("A governance configuration with the given name '%s' could not be found" % (name))
        else:
            # Stop if no name was provided
            raise admin.ArgValidationException("No name provided")
        
        ## Create the resulting configuration that would be persisted if the settings provided are applied
        ## This rest handler supports the addition of arguments based on convention; therefore we merge args a little differently
        for arg in args:
            governanceMatch = Governance.governanceRE.match(arg)
            controlMatch = Governance.controlRE.match(arg)
            tagMatch = Governance.tagRE.match(arg)
            if governanceMatch or controlMatch or tagMatch or arg in Governance.VALID_PARAMS:
                conf[arg] = args[arg][0]
        
        for key, val in conf.items():      
            if key == admin.EAI_ENTRY_ACL:
                if val.has_key('app') and val['app'] is not None and len(val['app']) > 0:
                    conf.namespace = val['app']
              
                if val.has_key('owner') and val['owner'] is not None and len(val['owner']) > 0:
                    conf.owner = val['owner']
                      
        if conf.namespace is None or len(conf.namespace) == 0:
            conf.namespace = Governance.DEFAULT_NAMESPACE
              
        if conf.owner is None or len(conf.owner) == 0:
            conf.owner = Governance.DEFAULT_OWNER
              
        try:
            ## Check config
            Governance.checkConf(conf, name)
                 
        except InvalidConfigException as e:
            e = "The edit attempt for the governance entry '%s' produced an invalid configuration: %s" % (name, str(e))
            logger.error(e)
            raise admin.ArgValidationException(e)
         ## Write out an update to the governance config file
        entity.setEntity(conf, sessionKey=self.getSessionKey())
        logger.info("Successfully updated the '%s' governance configuration" % (name))
        
        ## Reload governance (makeKVS)
        self.handleReload()
        
        logger.info('%s completed successfully' % (actionStr))
      
    def handleRemove(self, confInfo):
        owner = ((self.context == admin.CONTEXT_APP_AND_USER) and self.userName) or "-"
        entity.deleteEntity('configs/conf-governance', self.callerArgs.id, namespace=self.appName, owner=owner, sessionKey=self.getSessionKey())
    
    @staticmethod
    def checkConf(settings, stanza=None, confInfo=None, throwExceptionOnError=False):
        """
        Checks the settings and raises an exception if the configuration is invalid.
        """ 
        ## Below is a list of the required fields. The entries in this list will be removed as they
        ## are observed. An empty list at the end of the config check indicates that all necessary
        ## fields where provided.
        required_fields = Governance.REQUIRED_PARAMS[:]
        
        compliances = {}
        
        if stanza is not None and confInfo is not None:
             # Add each of the settings
            for key, val in settings.items():
                governanceMatch = Governance.governanceRE.match(key)
                controlMatch = Governance.controlRE.match(key)
                tagMatch = Governance.tagRE.match(key)
                
                ## Set val to empty if None
                if val is None:
                    val = ''
                    
                if key in Governance.VALID_PARAMS:
                    confInfo[stanza].append(key, val)
                    
                elif governanceMatch:
                    complianceKey = governanceMatch.group(1)
                    
                    if compliances.has_key(complianceKey):
                        compliances[complianceKey][Governance.PARAM_GOVERNANCE] = val
                        
                    else:
                        compliance = {}
                        compliance[Governance.PARAM_GOVERNANCE] = val
                        compliances[complianceKey] = compliance
                                              
                elif controlMatch:
                    complianceKey = controlMatch.group(1)
                    
                    if compliances.has_key(complianceKey):
                        compliances[complianceKey][Governance.PARAM_CONTROL] = val
                        
                    else:
                        compliance = {}
                        compliance[Governance.PARAM_CONTROL] = val
                        compliances[complianceKey] = compliance
                        
                elif tagMatch:
                    complianceKey = tagMatch.group(1)
                    
                    if compliances.has_key(complianceKey):
                        compliances[complianceKey][Governance.PARAM_TAG] = val
                        
                    else:
                        compliance = {}
                        compliance[Governance.PARAM_TAG] = val
                        compliances[complianceKey] = compliance
                
                ## Key is eai; Set meta  
                elif key.startswith(admin.EAI_ENTRY_ACL):
                    confInfo[stanza].setMetadata(key, val)
                            
                ## Key is eai; userName/appName
                elif key.startswith(admin.EAI_META_PREFIX):
                    confInfo[stanza].append(key, val)
                    
                ## Key is not proper
                else:
                    pass
            
            ## Add compliance settings
            for complianceKey in compliances:
                compliance = compliances[complianceKey]
                val = []
                
                ## Add governance as settings[0], control as settings[1], tag as settings[2]
                val.append(compliance.get(Governance.PARAM_GOVERNANCE, ''))
                val.append(compliance.get(Governance.PARAM_CONTROL, ''))
                val.append(compliance.get(Governance.PARAM_TAG, ''))
                    
                confInfo[stanza].append(complianceKey, val)
        else:
            pass
        ## end if statement
                    
        ## Check each of the settings
        logger.info("Checking general settings for the '%s' governance configuration" % (stanza))
        for key, val in settings.items():
            governanceMatch = Governance.governanceRE.match(key)
            controlMatch = Governance.controlRE.match(key)
            tagMatch = Governance.tagRE.match(key)
            
            if val is None:
                val = ''
                      
            if governanceMatch:
                complianceKey = governanceMatch.group(1)
                    
                if compliances.has_key(complianceKey):
                    compliances[complianceKey][Governance.PARAM_GOVERNANCE] = val
                        
                else:
                    compliance = {}
                    compliance[Governance.PARAM_GOVERNANCE] = val
                    compliances[complianceKey] = compliance
                                              
            elif controlMatch:
                complianceKey = controlMatch.group(1)
                    
                if compliances.has_key(complianceKey):
                    compliances[complianceKey][Governance.PARAM_CONTROL] = val
                        
                else:
                    compliance = {}
                    compliance[Governance.PARAM_CONTROL] = val
                    compliances[complianceKey] = compliance
                    
            elif tagMatch:
                complianceKey = tagMatch.group(1)
                
                if compliances.has_key(complianceKey):
                    compliances[complianceKey][Governance.PARAM_TAG] = val
                    
                else:
                    compliance = {}
                    compliance[Governance.PARAM_TAG] = val
                    compliances[complianceKey] = compliance
            
            elif key in Governance.REQUIRED_PARAMS:
                ## Remove the field from the list of required fields
                try:
                    required_fields.remove(key)
                        
                except ValueError:
                    pass # Field not available, probably because it is not required
            elif key in Governance.VALID_PARAMS:
                pass
                    
            ## Key is ignored
            elif key in Governance.IGNORED_PARAMS:
                pass        
                                   
            ## Key is eai
            elif key.startswith(admin.EAI_META_PREFIX):
                pass
                 
            ## Key is not proper
            else:
                if throwExceptionOnError:
                    raise UnsupportedParameterException()
                
                else:
                    logger.warn("The configuration for the '%s' governance entry contains an unsupported parameter: %s" % (stanza, key))
                     
        for complianceKey in compliances:
            compliance = compliances[complianceKey]
            Governance.checkCompliance(compliance, complianceKey, stanza, throwExceptionOnError)
        
        ## Warn if some of the required fields were not provided
        if len(required_fields) > 0:
            raise InvalidConfigException('The following fields must be defined in the configuration but were not: ' + ', '.join(required_fields).strip())
          
    @staticmethod 
    def checkCompliance(compliance, complianceKey, stanza=None, throwExceptionOnError=False):
        logger.info("Checking '%s' settings for the '%s' governance configuration" % (complianceKey, stanza))
        required_fields = Governance.REQUIRED_COMPLIANCE[:]
        
        for field in Governance.REQUIRED_COMPLIANCE:
            if compliance.has_key(field) and len(compliance[field]) > 0:
                ## Remove the field from the list of required fields
                try:
                    required_fields.remove(field)
              
                except ValueError:
                    pass # Field not available, probably because it is not required 
            
        if len(required_fields) > 0:
            if throwExceptionOnError:
                raise IncompleteComplianceException()
            
            else:
                for field in required_fields:
                    logger.warn("The parameter '%s' for configuration '%s' is incomplete; missing '%s.%s'" % (complianceKey, stanza, complianceKey, field) )  
                               
# initialize the handler
admin.init(Governance, admin.CONTEXT_APP_AND_USER)
