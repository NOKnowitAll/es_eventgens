"""
Copyright (C) 2005 - 2016 Splunk Inc. All Rights Reserved.
"""
import json
import logging
import logging.handlers
import splunk.admin as admin
import splunk.entity as entity
import splunk.rest as rest
import splunk.util as util
import sys
import time

if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)

from splunk import ResourceNotFound
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
from SolnCommon.log     import setup_logger, SHORT_FORMAT
from SolnCommon.kvstore import KvStoreHandler
from SolnCommon.pooling import should_execute

logger = setup_logger('reviewstatuses_rest_handler', level=logging.INFO, format=SHORT_FORMAT)


def time_function_call(fx):
    """
    This decorator will provide a log message measuring how long a function call took.
    
    Arguments:
    fx -- The function to measure
    """
    
    def wrapper(*args, **kwargs):
        t = time.time()
        
        r = fx(*args, **kwargs)
        
        logger.debug('%s, duration=%.3f', fx.__name__, time.time() - t)
        
        return r
    return wrapper

"""
This class provides a mechanism for determining how long operations take. Results are submitted as debug
calls to the logger provided in the constructor or the instance in the global variable logger if no logger
is provided in the constructor.

Example:
with TimeLogger("doing_something", Logger()):
    time.sleep(2)
"""
class TimeLogger():

    def __init__(self, title, logger=None):
        self.title = title
        self.logger = logger
    
    def __enter__(self):
        
        # Define the start time
        self.start_time = int(time.time())

    def __exit__(self, type, value, traceback):
        
        # Determine how long the operation took
        time_spent = int(time.time()) - self.start_time
        
        # See if we can find a logger as a global variable
        if self.logger is None:
            try:
                self.logger = logger
            except NameError:
                raise Exception('Could not get a logger instance for the purposes of recording performance')
        
        # Log the time spent
        self.logger.debug('%s, duration=%d', self.title, time_spent)

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


class MissingTransitionException(InvalidConfigException):
    """
    Describes a capability that is missing.
    """
    def __init__(self, transitions):
        self.transitions = transitions
        super(InvalidConfigException, self).__init__( 'Missing transition detected' )
    
    
def _getFieldValue(args, name, default_value=None, max_length=None):
    """
    Get the field value from the argument list.
    """
    
    ## Get the value if defined or the default value if not defined
    value = args[name][0] or default_value if name in args else default_value
    
    ## Check the length
    if value and max_length and len(value) > max_length:
        raise admin.ArgValidationException(
            'App %s cannot be longer than %s character%s.' % (name, max_length, 's' if max_length > 1 else ''))
    ## return the value
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

          
class ReviewStatuses(admin.MConfigHandler):
    '''
    Set up supported arguments
    '''
    ## admin.py constants
    REQUESTED_ACTIONS       = { '1': 'ACTION_CREATE', '2': 'ACTION_LIST', '4': 'ACTION_EDIT', '8': 'ACTION_REMOVE', '16': 'ACTION_MEMBERS', '32': 'ACTION_RELOAD' }  
     ## Permissions
    WRITE_CAPABILITY        = 'edit_reviewstatuses'
     ## Default Params
    PARAM_DISABLED          = 'disabled'
    PARAM_LABEL             = 'label'
    PARAM_DESCRIPTION       = 'description'
    PARAM_DEFAULT           = 'default'
    PARAM_SELECTED          = 'selected'
    PARAM_HIDDEN            = 'hidden'
    PARAM_END               = 'end'
    
    BOOLEAN_PARAMS          = [PARAM_DISABLED, PARAM_DEFAULT, PARAM_SELECTED, PARAM_HIDDEN, PARAM_END]
    
    VALID_PARAMS            = [PARAM_DISABLED, 
                               PARAM_LABEL, 
                               PARAM_DESCRIPTION, 
                               PARAM_DEFAULT, 
                               PARAM_SELECTED, 
                               PARAM_HIDDEN, 
                               PARAM_END]
    
    ## collections do not support '.' or '$' in params
    COLLECTION_PARAMS       = [PARAM_DISABLED, 
                               PARAM_LABEL, 
                               PARAM_DESCRIPTION, 
                               PARAM_DEFAULT, 
                               PARAM_SELECTED, 
                               PARAM_HIDDEN, 
                               PARAM_END]
    
    REQUIRED_PARAMS         = [PARAM_DISABLED, PARAM_LABEL, PARAM_DEFAULT, PARAM_HIDDEN]
     ## Default Vals
    DEFAULT_NAMESPACE       = 'SA-ThreatIntelligence'
    DEFAULT_OWNER           = 'nobody'
    DEFAULT_DISABLED        = 0
    DEFAULT_DEFAULT         = 0
    DEFAULT_SELECTED        = 0
    DEFAULT_HIDDEN          = 0
    DEFAULT_END             = 0
    
    PARAM_UNASSIGNED_STANZA = '0'
    PARAM_UNASSIGNED_DICT   = {PARAM_DISABLED:    DEFAULT_DISABLED,
                               PARAM_LABEL:       'Unassigned',
                               PARAM_DESCRIPTION: 'An error is preventing the issue from having a valid status assignment',
                               PARAM_DEFAULT:     DEFAULT_DEFAULT,
                               PARAM_SELECTED:    DEFAULT_SELECTED,
                               PARAM_HIDDEN:      DEFAULT_HIDDEN,
                               PARAM_END:         DEFAULT_END}
    
    def setup(self):
        logger.info('Setting up reviewstatuses_rest_handler')
        
        ## set write capability
        self.setWriteCapability(ReviewStatuses.WRITE_CAPABILITY)    
         
        if self.requestedAction == admin.ACTION_EDIT or self.requestedAction == admin.ACTION_CREATE:         
            ## Fill required params
            for arg in ReviewStatuses.REQUIRED_PARAMS:
                self.supportedArgs.addReqArg(arg)
                
            ## Fill valid params
            for arg in ReviewStatuses.VALID_PARAMS:
                if arg not in ReviewStatuses.REQUIRED_PARAMS:
                    self.supportedArgs.addOptArg(arg)
                
    @time_function_call
    def handleCreate(self, confInfo):
        """
        Handles creation of a review status
        """
        sessionKey = self.getSessionKey()
        ## Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in ReviewStatuses.REQUESTED_ACTIONS:
            actionStr = ReviewStatuses.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
        
        ## Refresh
        self.handleReload(makeKVS=False)
        
        authorizeDict         = self.readConf('authorize')
        reviewstatusesDict    = self.readConfCtx('reviewstatuses')
        
        name = self.callerArgs.id
        args = self.callerArgs.data
        
        ## Check name
        if not name:
            raise admin.ArgValidationException('The name (stanza) of the status must not be empty')
        ## Make sure the item is not '0'
        ## '0' is reserved for the Unassigned status
        elif name==ReviewStatuses.PARAM_UNASSIGNED_STANZA:
            raise admin.ArgValidationException('The name (stanza) of the status must not be 0 (this is reserved for the Unassigned status)')
        ## Make sure the item does not already exist
        ## This should not be possible based on getUID, but no hurt in double checking
        elif name in reviewstatusesDict:
            raise admin.AlreadyExistsException('A reviewstatuses.conf entry already exists for status ID %s' % name)
        
        ## Get the field values
        disabled    = _getFieldValue(args, ReviewStatuses.PARAM_DISABLED)
        label       = _getFieldValue(args, ReviewStatuses.PARAM_LABEL)
        description = _getFieldValue(args, ReviewStatuses.PARAM_DESCRIPTION)
        default     = _getFieldValue(args, ReviewStatuses.PARAM_DEFAULT)      
        selected    = _getFieldValue(args, ReviewStatuses.PARAM_SELECTED)
        hidden      = _getFieldValue(args, ReviewStatuses.PARAM_HIDDEN)
        end         = _getFieldValue(args, ReviewStatuses.PARAM_END)
        
        ## Add the field values to a configuration dictionary (that will be verified)
        conf           = entity.getEntity('configs/conf-reviewstatuses', '_new', sessionKey=sessionKey) 
        conf.namespace = self.appName # always save things to SOME app context.
        conf.owner     = ((self.context == admin.CONTEXT_APP_AND_USER) and self.userName) or "-"
        conf['name']   = name
          
        _addToDictIfNonNull(conf, ReviewStatuses.PARAM_DISABLED, disabled)
        _addToDictIfNonNull(conf, ReviewStatuses.PARAM_LABEL, label)
        _addToDictIfNonNull(conf, ReviewStatuses.PARAM_DESCRIPTION, description)
        _addToDictIfNonNull(conf, ReviewStatuses.PARAM_DEFAULT, default)
        _addToDictIfNonNull(conf, ReviewStatuses.PARAM_SELECTED, selected) 
        _addToDictIfNonNull(conf, ReviewStatuses.PARAM_HIDDEN, hidden) 
        _addToDictIfNonNull(conf, ReviewStatuses.PARAM_END, end)
        
        ## Check the configuration
        ## on create we don't care about other default statuses because we are going to unset them
        ## we do however need to ensure that we are not creating a disabled default
        try:
            if util.normalizeBoolean(default):
                ReviewStatuses.checkConf(conf, name, defaultStatuses=[name], checkDefault=True)
            else:
                ReviewStatuses.checkConf(conf, name, checkDefault=False)
            
        except InvalidConfigException as e:            
            e = "The configuration for the new review status is invalid and could not be created: %s" % e
            logger.error(e)
            raise admin.ArgValidationException(e)
        
        ## switch default
        if util.normalizeBoolean(default):
            self.switchDefault(reviewstatusesDict)
          
        ## Write out an update to the reviewstatuses config file
        entity.setEntity(conf, sessionKey=sessionKey)
        logger.info('Successfully added review status: %s', label)
        
        ## Create new transitions
        transitions = []
        transitions.extend(ReviewStatuses.makeTransitions('0', name, toOnly=True))
        
        for stanza in reviewstatusesDict:
            if stanza != 'default' and stanza != ReviewStatuses.PARAM_UNASSIGNED_STANZA:
                transitions.extend(ReviewStatuses.makeTransitions(name, stanza))
        
        transitions.sort()
              
        ## Write out an update to the authorize config file
        conf             = entity.getEntity('configs/conf-authorize', '_new', sessionKey=sessionKey)
        conf.namespace   = self.appName # always save things to SOME app context.
        conf.owner       = ((self.context == admin.CONTEXT_APP_AND_USER) and self.userName) or "-"
        conf[ReviewStatuses.PARAM_DISABLED] = '0'
        with TimeLogger('setting_transitions', logger):
            for transition in transitions:
                if transition in authorizeDict:
                    logger.warn('An authorize.conf entry already exists for %s', transition)
                
                else:
                    conf['name'] = transition
                    entity.setEntity(conf, sessionKey=sessionKey)
                    logger.info('Successfully added transition %s', transition)
        
        ## Reload reviewstatuses (makeKVS)
        self.handleReload()
        
        logger.info('%s completed successfully', actionStr)
    
    @time_function_call
    def switchDefault(self, reviewstatusesDict):
        """
        Handles the unsetting of the default flag if this is the new default
        
        raises Exceptions for any issues with unsetting perceived defaults
        """
        for stanza in reviewstatusesDict:
            reviewstatus = reviewstatusesDict[stanza]
            if stanza != 'default' and util.normalizeBoolean(reviewstatus[ReviewStatuses.PARAM_DEFAULT]):
                logger.info('Unsetting default param for reviewstatus %s', stanza)
                response, content = rest.simpleRequest(
                    '/servicesNS/nobody/%s/configs/conf-reviewstatuses/%s' % (reviewstatus[admin.EAI_ENTRY_ACL]['app'], stanza), 
                    sessionKey=self.getSessionKey(), postargs={'default': 0}, raiseAllErrors=True
                )
    
    @time_function_call
    def handleList(self, confInfo):      
        """
        Handles listing of a review statuses
        """
        ## Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in ReviewStatuses.REQUESTED_ACTIONS:
            actionStr = ReviewStatuses.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
        
        ## Refresh
        self.handleReload(makeKVS=False)
         
        ## Get the configurations from reviewstatuses.conf
        reviewstatusesDict = self.readConfCtx('reviewstatuses')
        authorizeDict      = self.readConf('authorize')
        
        ## Get all correlations searches and provide the relevant options
        if reviewstatusesDict:
            ## Check default count
            defaultCount = len(ReviewStatuses.getSpecialStatuses(reviewstatusesDict))
            if defaultCount!=1:
                logger.error('The reviewstatuses.conf configurations are invalid because %s default statuses are set; should be one', defaultCount)
            
            ## Check end count
            endCount = len(ReviewStatuses.getSpecialStatuses(reviewstatusesDict, ReviewStatuses.PARAM_END))
            if endCount!=1:
                logger.error('The reviewstatuses.conf configurations are invalid because %s end statuses are set; should be one', endCount)
            
            ## Check each conf
            for stanza, settings in reviewstatusesDict.items():
                ## Make sure the item is not '0'
                ## '0' is reserved for the Unassigned status
                if stanza != 'default' and stanza != ReviewStatuses.PARAM_UNASSIGNED_STANZA:
                    try:
                        ## Check config
                        ReviewStatuses.checkConf(settings, stanza, confInfo)
                        
                        ## Check transitions
                        ReviewStatuses.checkTransitions(stanza, reviewstatusesDict, authorizeDict)
                    
                    except MissingTransitionException as e:
                        for exc in e.transitions:
                            logger.error("The configuration for status ID '%s' is invalid: %s", stanza, exc)
                            
                    except InvalidConfigException as e:
                        logger.error("The configuration for status ID '%s' is invalid: %s", stanza, e)                  
            
            ## Add static "Unassigned"
            for key, val in ReviewStatuses.PARAM_UNASSIGNED_DICT.items():
                confInfo[ReviewStatuses.PARAM_UNASSIGNED_STANZA].append(key, val)
             
        logger.info('%s completed successfully', actionStr)
        
    @time_function_call
    def handleReload(self, confInfo=None, makeKVS=True):
        """
        Handles refresh/reload of the configuration options
        """
        ## Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in ReviewStatuses.REQUESTED_ACTIONS:
            actionStr = ReviewStatuses.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
        logger.info('Refreshing reviewstatuses configurations via properties endpoint')
        try:
            refreshInfo = entity.refreshEntities('properties/reviewstatuses', sessionKey=self.getSessionKey())
        except Exception as e:
            logger.warn('Could not refresh reviewstatuses configurations via properties endpoint: %s', e)
          
        logger.info('Refreshing authorize configurations via properties endpoint')    
        try:
            refreshInfo = entity.refreshEntities('properties/authorize', sessionKey=self.getSessionKey())
        except Exception as e:
            logger.warn('Could not refresh authorize configurations via properties endpoint: %s', e)
            
        if makeKVS:
            # Only execute on standalone or on cluster master. 
            exec_status, exec_status_msg = should_execute(session_key=self.getSessionKey())
            logger.info(exec_status_msg)
            if exec_status:
                self.makeKVS()
         
        logger.info('%s completed successfully', actionStr)
    
    @time_function_call
    def makeKVS(self, collection='reviewstatuses', reviewstatusesDict=None):
        """
        Handles maintenance of reviewstatuses kvstore collection
        """
        logger.info('Creating %s collection', collection)
        ## options
        options = {'app': ReviewStatuses.DEFAULT_NAMESPACE, 'owner': ReviewStatuses.DEFAULT_OWNER, 'collection': collection}
        ## get reviewstatuses conf
        reviewstatusesDict = reviewstatusesDict or self.readConf('reviewstatuses')
        
        if not reviewstatusesDict:
            logger.error('Reviewstatuses dictionary is None; cannot makeKVS')
        else:
            ## get reviewstatuses collection
            gr, gc = KvStoreHandler.get(None, self.getSessionKey(), options)
            
            if gr.status==200:
                existing_keys  = [x['_key'] for x in json.loads(gc)]
                reviewstatuses = []
                
                ## Iterate reviewstatuses
                for stanza, settings in sorted(reviewstatusesDict.items()):
                    if stanza!='default':
                        reviewstatus = { '_key': stanza, 'status': stanza }
                        is_default   = False
                        for key, val in settings.items():
                            if not is_default and key == ReviewStatuses.PARAM_DEFAULT:
                                if util.normalizeBoolean(val):
                                    is_default = True
                            if key in ReviewStatuses.COLLECTION_PARAMS:
                                ## kvstore prefers None over empty string
                                reviewstatus[key] = val or None
                        reviewstatuses.append(reviewstatus)
                        
                        if is_default:
                            default_reviewstatus = reviewstatus.copy()
                            default_reviewstatus['_key'] = '-1'
                            reviewstatuses.append(default_reviewstatus)
                
                pr, pc = KvStoreHandler.batch_create(reviewstatuses, self.getSessionKey(), options)
                if pr.status!=200:
                    logger.error('Error in upserting records to %s collection: %s', collection, pc)
                
                removed_keys = list(set(existing_keys).difference([x['_key'] for x in reviewstatuses])) 
                if len(removed_keys)>0:
                    duri   = '/servicesNS/{owner}/{app}/storage/collections/data/{collection}'.format(**options)
                    dquery = {'$or': []}
                    
                    for removed_key in removed_keys:
                        dquery['$or'].append({'_key': removed_key})
                    
                    dr, dc = rest.simpleRequest(duri, sessionKey=self.getSessionKey(), method='DELETE', getargs={'query': json.dumps(dquery)})
                    
                    if dr.status!=200:
                        logger.error('Error in deleting records from %s collection: %s', collection, dc)
            else:
                logger.error('Error retrieving records from %s collection: %s', collection, gc)            
                      
    @time_function_call
    def correctMissingTransition(self, transition, save=True):
        """
        Create the messing transition and return the created transition.
        """
        logger.info('Transition %s does not exist but should, it will be created', transition)
        # Get the _new entity in order to start editing
        conf = entity.getEntity('configs/conf-authorize', '_new', sessionKey=self.getSessionKey())
        # Set the namespace and owner
        conf.namespace   = self.appName
        conf.owner       = ReviewStatuses.DEFAULT_OWNER
        # Set the transition
        conf['name']     = transition
        conf[ReviewStatuses.PARAM_DISABLED] = '1'
        
        # Save the transition
        if save:
            entity.setEntity(conf, sessionKey=self.getSessionKey())
            logger.info('Successfully added transition %s', transition)
        else:
            logger.info('Preparing the creation of the missing transition %s; save is deferred until other edits are complete', transition)
        
        return conf
                      
    @time_function_call
    def handleEdit(self, confInfo):
        """
        Handles edits to the configuration options
        """
        sessionKey = self.getSessionKey()
        ## Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in ReviewStatuses.REQUESTED_ACTIONS:
            actionStr = ReviewStatuses.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
        
        ## Refresh
        self.handleReload(makeKVS=False)
        
        reviewstatusesDict = self.readConfCtx('reviewstatuses')
        
        name = self.callerArgs.id
        args = self.callerArgs
        
        # Stop if no name was provided
        if not name:
            raise admin.ArgValidationException('No name provided')
        elif name==ReviewStatuses.PARAM_UNASSIGNED_STANZA:
            raise admin.ArgValidationException('The name (stanza) of the status must not be 0 (this is reserved for the Unassigned status)')
        try:
            conf = entity.getEntity('configs/conf-reviewstatuses', name, sessionKey=sessionKey)
        except ResourceNotFound:
            raise admin.NotFoundException("A status with the given name '%s' could not be found" % name)
            
        # Create the resulting configuration that would be persisted if the settings provided are applied
        for key, val in conf.items():
            if key in args.data: 
                # Get the new value
                new_value = args[key][0]
                # Set the value to a single space if empty or none, otherwise, Splunk won't save it (SOLNPCI-532)
                if new_value in [None, '']:
                    new_value = ' '
                # Assign the value
                conf[key] = new_value
        
        ## namespace/owner     
        if admin.EAI_ENTRY_ACL in conf:
            conf.namespace = conf[admin.EAI_ENTRY_ACL].get('app', None) or ReviewStatuses.DEFAULT_NAMESPACE
            conf.owner     = conf[admin.EAI_ENTRY_ACL].get('owner', None) or ReviewStatuses.DEFAULT_OWNER
        else:
            conf.namespace = ReviewStatuses.DEFAULT_NAMESPACE
            conf.owner     = ReviewStatuses.DEFAULT_OWNER
        
        ## Check the resulting configuration
        ## here we need to pass the existing defaults
        defaultStatuses = ReviewStatuses.getSpecialStatuses(reviewstatusesDict)
        try:
            ReviewStatuses.checkConf(conf, name, defaultStatuses=defaultStatuses, checkDefault=True)
        except InvalidConfigException as e:
            e = "The edit attempt for review status '%s' produced an invalid configuration: %s" % (name, e)
            logger.error(e)
            raise admin.ArgValidationException(e)
        
        ## switch default
        if util.normalizeBoolean(conf['default']):
            self.switchDefault(reviewstatusesDict)

         ## Retain is_disabled
        status_disabled = util.normalizeBoolean(conf[ReviewStatuses.PARAM_DISABLED])
              
        ## Enable/Disable transitions
        transitions = []
        transitions.extend(ReviewStatuses.makeTransitions('0', name, toOnly=True))
        logger.info('transitions: %s', transitions)
        
        for stanza in reviewstatusesDict:
            if stanza != 'default' and stanza != ReviewStatuses.PARAM_UNASSIGNED_STANZA:
                transitions.extend(ReviewStatuses.makeTransitions(name, stanza))
        
        transitions.sort()
        logger.info('transitions: %s', transitions)
        
        # Get the existing set of transition capabilities; we are going to store these so that we don't have to call
        # getEntity on each capability since this takes a long time (about 20 seconds each)
        existing_transitions = entity.getEntities('configs/conf-authorize', sessionKey=sessionKey, count=-1)
        
        ## Write out an update to the authorize config file
        for transition in transitions:
            changed = False
            
            # Get the entry that we are editing
            if transition in existing_transitions:
                transition_conf = existing_transitions[transition]
            else:
                # Uh oh, the transition wasn't found. Go ahead and create it.
                transition_conf = self.correctMissingTransition(transition, save=False)
                
                # If the transition was not returned, then skip this entry.
                if transition_conf is None:
                    continue
                
                changed = True
            
            transition_conf.namespace = self.appName
            transition_conf.owner = ReviewStatuses.DEFAULT_OWNER
            
            ## Disable only transitions to the disabled status
            if status_disabled and transition.find('to_%s' % name) != -1:
                action = 'disabled'
                
                # Note that we are changing the value
                if str(transition_conf['disabled']) != '1':
                    changed = True
                    transition_conf['disabled'] = '1'
                
            else:
                action = 'enabled'
                
                # Note that we are changing the value
                if str(transition_conf['disabled']) != '0':
                    changed = True
                    transition_conf['disabled'] = '0'
                
            # Set the settings if they have changed; try to avoid performing the changes unless we need to since this is a slow operation
            if changed:
                with TimeLogger( ('Set %s transition in handleEdit: %s' % (action, transition)), logger):
                    entity.setEntity(transition_conf, sessionKey=sessionKey)
                logger.info('Successfully %s transition: %s', action, transition)
        
        ## Write out an update to the reviewstatuses config file
        ## Note that we are doing this after setting the transitions 
        with TimeLogger('setting entity in handleEdit', logger):
            entity.setEntity(conf, sessionKey=sessionKey)
        
        logger.info('Successfully updated review status id %s', name)
        
        ## Reload reviewstatuses (makeKVS)
        self.handleReload()
        
        logger.info('%s completed successfully', actionStr)
            
    def handleRemove(self, confInfo):
        pass
    
    @staticmethod
    def getUID(reviewstatuses=[]):
        """
        Returns a unique identifier to be used as a stanza name
        """
        statusInts = []      
        for reviewstatus in reviewstatuses:
            try:
                statusInt = int(reviewstatus)
                if statusInt > 0:
                    statusInts.append(statusInt)   
            except:
                pass
        if len(statusInts)==0:
            uid = 1
        else:
            uid = sorted(statusInts)[-1] + 1
        
        return uid
    
    @staticmethod
    def getSpecialStatuses(confDict, typ=PARAM_DEFAULT):
        logger.info('Retrieving statuses with %s set', typ)
        statuses = [x for x in confDict if util.normalizeBoolean(confDict[x][typ])]
        logger.info('Successfully retrieved status(es) with %s set: %s', typ, statuses)
        return statuses
                  
    @staticmethod
    def checkConf(settings, stanza=None, confInfo=None, defaultStatuses=[], checkDefault=False, throwExceptionOnError=False):
        """
        Checks the settings and raises an exception if the configuration is invalid.
        """ 
        ## Below is a list of the required fields. The entries in this list will be removed as they
        ## are observed. An empty list at the end of the config check indicates that all necessary
        ## fields where provided.
        required_fields = ReviewStatuses.REQUIRED_PARAMS[:]
        
        if stanza is not None and confInfo is not None:
            # Add each of the settings
            for key, val in settings.items():
                ## Set val to empty if None
                if val is None:
                    val = ''
                    
                if key in ReviewStatuses.VALID_PARAMS:
                    confInfo[stanza].append(key, val)
                
                ## Key is eai;acl Set meta  
                elif key.startswith(admin.EAI_ENTRY_ACL):
                    confInfo[stanza].setMetadata(key, val)
                            
                ## Key is eai; userName/appName
                elif key.startswith(admin.EAI_META_PREFIX):
                    confInfo[stanza].append(key, val)
                    
                ## Key is not proper
                else:
                    pass
            
        ## Check each of the settings individually
        logger.info("Checking general settings for the '%s' review status", stanza)
        for key, val in settings.items():
            ## Set val to empty if None
            if val is None:
                val = ''
            
            ## Check the disabled/selected value
            if key in ReviewStatuses.BOOLEAN_PARAMS:
                try:
                    util.normalizeBoolean(val, enableStrictMode=True)
                    
                    ## Remove the field from the list of required fields
                    try:
                        required_fields.remove(key)
                        
                    except ValueError:
                        pass # Field not available, probably because it is not required
                        
                except ValueError:
                    raise InvalidParameterValueException(key, val, 'must be a valid boolean')
                    
            elif key in ReviewStatuses.REQUIRED_PARAMS:
                ## Remove the field from the list of required fields
                try:
                    required_fields.remove(key)
                        
                except ValueError:
                    pass # Field not available, probably because it is not required
                        
            elif key in ReviewStatuses.VALID_PARAMS:
                pass
                                   
            ## Key is eai
            elif key.startswith(admin.EAI_META_PREFIX):
                pass
                 
            ## Key is not proper
            else:
                if throwExceptionOnError:
                    raise UnsupportedParameterException()
                
                else:
                    logger.warn("The configuration for the '%s' review status contains an unsupported parameter: %s", stanza, key)
         ## Error if some of the required fields were not provided
        if len(required_fields) > 0:
            raise InvalidConfigException('The following fields must be defined in the configuration but were not: ' + ', '.join(required_fields).strip())
     
        ## Error if checkDefault and...
        if checkDefault:
            ## disabled
            disabled = util.normalizeBoolean(ReviewStatuses.DEFAULT_DISABLED)
            if ReviewStatuses.PARAM_DISABLED in settings:
                disabled = util.normalizeBoolean(settings[ReviewStatuses.PARAM_DISABLED])
            ## default
            default = util.normalizeBoolean(ReviewStatuses.DEFAULT_DEFAULT)
            if ReviewStatuses.PARAM_DEFAULT in settings:    
                default = util.normalizeBoolean(settings[ReviewStatuses.PARAM_DEFAULT])
            if default:
                defaultStatuses.append(stanza)
            else:
                try:
                    defaultStatuses.remove(stanza)
                except:
                    pass

            ## end
            end = util.normalizeBoolean(ReviewStatuses.DEFAULT_END)
            if ReviewStatuses.PARAM_END in settings:       
                end = util.normalizeBoolean(settings[ReviewStatuses.PARAM_END])
                          
            ## 1. No disabled defaults
            if default and disabled:
                raise InvalidConfigException('Default review statuses cannot be disabled.  If you want to disable this status, then unset default.')
            
            ## 2. One default always
            defaultStatuses = set(defaultStatuses)
            if len(defaultStatuses)==0:
                raise InvalidConfigException('There must be one default review status at all times')
            elif len(defaultStatuses)>1:
                logger.warn('More than one default status detected: %s', defaultStatuses)
                
            ## 3. No end defaults
            if default and end:
                raise InvalidConfigException('Default review status cannot also be end status.  If you want this status to be default, then unset end.')
    
    @staticmethod
    def makeTransitions(statusA, statusB, toOnly=False):
        transitions = []
        
        if statusA != statusB:
            transitions.append('capability::transition_reviewstatus-%s_to_%s' % (statusA, statusB))
            if not toOnly:
                transitions.append('capability::transition_reviewstatus-%s_to_%s' % (statusB, statusA))
        
        return transitions
    
    @staticmethod
    def checkTransitions(status, reviewstatusesDict, authorizeDict):
        transitions = []
        missingTransitions = []
        transitions.extend(ReviewStatuses.makeTransitions('0', status, toOnly=True))
        
        for stanza in reviewstatusesDict:
            if stanza != 'default' and stanza != '0':        
                transitions.extend(ReviewStatuses.makeTransitions(status, stanza))
                
        for transition in transitions:
            if transition not in authorizeDict:
                missingTransitions.append('Missing capability ' + transition)
                    
        if len(missingTransitions) > 0:
            raise MissingTransitionException(missingTransitions)
  
# initialize the handler
admin.init(ReviewStatuses, admin.CONTEXT_APP_AND_USER)
