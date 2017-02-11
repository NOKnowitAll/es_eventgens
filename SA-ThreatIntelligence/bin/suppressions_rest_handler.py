"""
Copyright (C) 2005 - 2016 Splunk Inc. All Rights Reserved.
"""
import logging
import sys

if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)

import splunk.admin as admin
import splunk.entity as entity
import splunk.util as util

from notable_event_suppression import NotableEventSuppression
from splunk import ResourceNotFound
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.log import setup_logger, SHORT_FORMAT

logger = setup_logger('suppressions_rest_handler', format=SHORT_FORMAT)
logger.setLevel(logging.INFO)


class InvalidConfigException(Exception):
    pass


class InvalidParameterValueException(InvalidConfigException):
    """
    Describes a config parameter that has an invalid value.
    """
    
    def __init__(self, field, value, value_must_be):
        message = "The value for the parameter '%s' is invalid: %s (was %s)" % (field, value_must_be, value)
        super(InvalidConfigException, self).__init__(message)
      
        
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
        super(InvalidConfigException, self).__init__("Missing transition detected")
    
    
def _getFieldValue(args, name, default_value=None, max_length=None):
    '''Get the field value from the argument list.'''
    
    # Get the value if defined or the default value if not defined
    value = args[name][0] or default_value if name in args else default_value
    
    # Check the length
    if value and max_length and len(value) > max_length:
        raise admin.ArgValidationException(
            'App %s cannot be longer than %s character%s.' % (name, max_length, "s" if max_length > 1 else ""))
    return value
    

def _addToDictIfNonNull(d, name, value):
    '''Add the given name and value to the dictionary if the value is not none.
      
    Arguments:
      d -- the dictionary to add to
      name -- the name of the object to add
      value -- the value of the object to add (if not none)
    '''
    if value is not None:
        d[name] = value

          
class Suppressions(admin.MConfigHandler):
    '''
    Set up supported arguments
    '''
    # admin.py constants
    REQUESTED_ACTIONS = {'1': 'ACTION_CREATE', '2': 'ACTION_LIST', '4': 'ACTION_EDIT', '8': 'ACTION_REMOVE', '16': 'ACTION_MEMBERS', '32': 'ACTION_RELOAD'}

    # Permissions
    WRITE_CAPABILITY = 'edit_suppressions'

    # Default Params
    PARAM_DISABLED = 'disabled'
    PARAM_SEARCH = 'search'
    PARAM_DESCRIPTION = 'description'
  
    VALID_PARAMS = [PARAM_DISABLED, PARAM_SEARCH, PARAM_DESCRIPTION]
    REQUIRED_PARAMS = [PARAM_DISABLED, PARAM_SEARCH]
  
    # Configuration key mapping
    CONF_KEY_MAPPING = {'app': 'namespace', 'owner': 'owner'}
  
    # Default Vals
    DEFAULT_NAMESPACE = 'SA-ThreatIntelligence'
    DEFAULT_OWNER = 'nobody'

    DEFAULT_DISABLED = 0
  
    def setup(self):
        logger.info('Setting up suppressions_rest_handler')
      
        # set write capability
        self.setWriteCapability(Suppressions.WRITE_CAPABILITY)            
       
        if self.requestedAction == admin.ACTION_EDIT or self.requestedAction == admin.ACTION_CREATE:         
            # Fill required params
            for arg in Suppressions.REQUIRED_PARAMS:
                self.supportedArgs.addReqArg(arg)
              
            # Fill valid params
            for arg in Suppressions.VALID_PARAMS:
                if arg not in Suppressions.REQUIRED_PARAMS:
                    self.supportedArgs.addOptArg(arg)
  
    def handleCreate(self, confInfo):
        '''Handles creation of a suppression.'''
      
        # Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in Suppressions.REQUESTED_ACTIONS:
            actionStr = Suppressions.REQUESTED_ACTIONS[actionStr]
          
        logger.info('Entering %s', actionStr)
      
        # Refresh
        self.handleReload()
        
        name = self.callerArgs.id
        args = self.callerArgs.data
        
        # Make sure the name is not empty
        if not name or len(name) == 0:
            raise admin.ArgValidationException("The name of the suppression must not be empty")
        
        # Make sure the name follows the convention
        nameMatch = NotableEventSuppression.suppressionRE.match(name)
        
        if not nameMatch:
            raise admin.ArgValidationException("The name of the suppression must follow proper convention")
        
        # Make sure the item does not already exist
        if name in self.readConf('eventtypes'):
            raise admin.AlreadyExistsException("A suppression entry already exists for %s" % (name))
        
        # Get the field values
        disabled = _getFieldValue(args, Suppressions.PARAM_DISABLED)
        search = _getFieldValue(args, Suppressions.PARAM_SEARCH)
        description = _getFieldValue(args, Suppressions.PARAM_DESCRIPTION)
        
        # Add the field values to a configuration dictionary (that will be verified)
        conf = entity.getEntity('saved/eventtypes', '_new', sessionKey=self.getSessionKey())
        
        conf.namespace = self.appName  # always save things to SOME app context.
        conf.owner = self.context == admin.CONTEXT_APP_AND_USER and self.userName or "-"
        
        conf['name'] = name
        
        _addToDictIfNonNull(conf, Suppressions.PARAM_DISABLED, disabled)
        _addToDictIfNonNull(conf, Suppressions.PARAM_SEARCH, search)
        _addToDictIfNonNull(conf, Suppressions.PARAM_DESCRIPTION, description)
        
        ## Notable Suppression Audit Log Data
        log_data = {
            'action': 'create',
            'suppression': conf['name'][len(NotableEventSuppression.SUPPRESSION_START):],
            'user': conf['eai:acl']['owner'],
            'status': 'success',
            'signature': 'Notable event suppression successfully created'
        }
        
        # Check the configuration
        try:
            Suppressions.checkConf(conf, name)
        
        except InvalidConfigException as e:
            e = "The configuration for the new suppression '%s' is invalid and could not be created: %s" % (name, str(e))
            logger.error(e)
            log_data['status'] = 'failure'
            log_data['signature'] = 'Unable to save the event suppression'
            logger.error('SuppressionAudit - suppression={suppression}; action={action}; status={status}; signature={signature}; user={user};'.format(**log_data))
            raise admin.ArgValidationException(e)
        
        # Write out an update to the eventtypes config file
        entity.setEntity(conf, sessionKey=self.getSessionKey())
        
        logger.info('Successfully added suppression: %s', name)
        
        # Reload suppressions
        self.handleReload()
        
        logger.info('%s completed successfully', actionStr)
        logger.info('SuppressionAudit - suppression={suppression}; action={action}; status={status}; signature={signature}; user={user};'.format(**log_data))

    def handleCustom(self, confInfo):
        logger.info('Handling custom action: %s', self.customAction)
        if self.customAction == '_autodisable':
            expired_count, enabled_count = NotableEventSuppression.disable_expired_suppressions(session_key=self.getSessionKey())
            logger.info("%s expired suppressions detected; %s were enabled (now disabled)", expired_count, enabled_count)
        else:
            self.actionNotImplemented()

    def handleList(self, confInfo):      
        """
        Handles listing of a suppression
        """
        # Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in Suppressions.REQUESTED_ACTIONS:
            actionStr = Suppressions.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
        
        self.handleReload()
         
        # Get the configurations from suppression.conf
        suppressionDict = self.readConfCtx('eventtypes')
        
        # Get all suppressions and provide the relevant options
        if suppressionDict != None:
            # Check each conf
            for stanza, settings in suppressionDict.items():
                stanzaMatch = NotableEventSuppression.suppressionRE.match(stanza)
                
                if stanzaMatch:
                    try:
                        # Check config
                        Suppressions.checkConf(settings, stanza, confInfo)
                            
                    except InvalidConfigException as e:
                        logger.error("The configuration for suppression '%s' is invalid: %s", stanza, str(e))
             
        logger.info('%s completed successfully', actionStr)

    def handleReload(self, confInfo=None, makeCSV=True):
        """
        Handles refresh/reload of the configuration options
        """
        # Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in Suppressions.REQUESTED_ACTIONS:
            actionStr = Suppressions.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
    
        logger.info('Refreshing suppression configurations via properties endpoint')
        try:
            refreshInfo = entity.refreshEntities('properties/eventtypes', sessionKey=self.getSessionKey())
        except Exception as e:
            logger.warn('Could not refresh suppression configurations via properties endpoint: %s', str(e))
         
        logger.info('%s completed successfully', actionStr)
    
    def handleEdit(self, confInfo):
        """
        Handles edits to the configuration options
        """
        
        # Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in Suppressions.REQUESTED_ACTIONS:
            actionStr = Suppressions.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
    
        # Refresh
        self.handleReload()
        
        name = self.callerArgs.id
        args = self.callerArgs
        
        if name is not None:
            # Make sure the name follows the convention
            nameMatch = NotableEventSuppression.suppressionRE.match(name)
            
            if not nameMatch:
                raise admin.ArgValidationException("The name of the suppression must follow proper convention")
        
            try:
                conf = entity.getEntity('saved/eventtypes', name, sessionKey=self.getSessionKey())
                
            except ResourceNotFound:
                raise admin.NotFoundException("A suppression configuration with the given name '%s' could not be found" % (name))
      
        else:
            # Stop if no name was provided
            raise admin.ArgValidationException("No name provided")
        
        ## Notable Suppression Audit Log Data
        log_data = {
            'status': 'success',
            'action': 'edit',
            'signature': 'Notable event suppression successfully saved',
            'suppression': name[len(NotableEventSuppression.SUPPRESSION_START):],
            'user': conf['eai:userName']
        }
        
        # Create the resulting configuration that would be persisted if the settings provided are applied
        for key, val in conf.items():
            if key in args.data:
                
                # Set the value to a single space so that the field is set to a blank value
                new_value = args[key][0]
                
                if new_value in [None, '']:
                    new_value = ' '
                
                ## If a value other than the 'disabled' param is changed, it 
                # came from the editor, otherwise the lister. 
                if key == self.PARAM_DISABLED:
                    conf_key  = util.normalizeBoolean(conf[key], enableStrictMode=True)
                    new_value = util.normalizeBoolean(new_value, enableStrictMode=True)
                    if conf_key != new_value:
                        log_data['action']    = 'disable' if new_value else 'enable'
                        log_data['signature'] = 'Suppression successfully disabled' if new_value else 'Suppression successfully enabled'
                    
                conf[key] = new_value
          
            if key == admin.EAI_ENTRY_ACL:
                for k, v in self.CONF_KEY_MAPPING.iteritems():
                    if k in val and val[k] is not None and len(val[k]) > 0:
                        setattr(conf, v, val[k])
                          
        if conf.namespace is None or len(conf.namespace) == 0:
            conf.namespace = Suppressions.DEFAULT_NAMESPACE
          
        if conf.owner is None or len(conf.owner) == 0:
            conf.owner = Suppressions.DEFAULT_OWNER
            
        try:
            # Check config
            Suppressions.checkConf(conf, name)
                 
        except InvalidConfigException as e:
            e = "The edit attempt for the suppression '%s' produced an invalid configuration: %s" % (name, str(e))
            logger.error(e)
            log_data['status'] = 'failure'
            if log_data['action'] == 'edit':
                log_data['signature'] = 'Unable to save the event suppression'
            elif log_data['action'] == 'enable':
                log_data['signature'] = 'Error occurred while enabling the suppression: ' + str(e)
            else:
                log_data['signature'] = 'Error occurred while disabling the suppression: ' + str(e)
                
            logger.error('SuppressionAudit - suppression={suppression}; action={action}; status={status}; signature={signature}; user={user};'.format(**log_data))
            raise admin.ArgValidationException(e)
        
        # Write out an update to the eventtypes config file
        entity.setEntity(conf, sessionKey=self.getSessionKey())
        
        # Log that the suppression was updated
        logger.info("Successfully updated the '%s' suppression", name)
        
        # Reload suppressions
        self.handleReload()
        
        logger.info('%s completed successfully', actionStr)
        
        logger.info('SuppressionAudit - suppression={suppression}; action={action}; status={status}; signature={signature}; user={user};'.format(**log_data))
    
    def handleRemove(self, confInfo):
        owner = ((self.context == admin.CONTEXT_APP_AND_USER) and self.userName) or "-"
        entity.deleteEntity('configs/conf-eventtypes', self.callerArgs.id, namespace=self.appName, owner=owner, sessionKey=self.getSessionKey())
   
    @staticmethod
    def checkConf(settings, stanza=None, confInfo=None, throwExceptionOnError=False):
        """
        Checks the settings and raises an exception if the configuration is invalid.
        """ 
        # Below is a list of the required fields. The entries in this list will be removed as they
        # are observed. An empty list at the end of the config check indicates that all necessary
        # fields where provided.
        required_fields = Suppressions.REQUIRED_PARAMS[:]
        
        if stanza is not None and confInfo is not None:
            # Add each of the settings
            for key, val in settings.items():
                # Set val to empty if None
                if val is None:
                    val = ''
                    
                if key in Suppressions.VALID_PARAMS:
                    confInfo[stanza].append(key, val)
                    
                # Key is eai; Set meta  
                elif key.startswith(admin.EAI_ENTRY_ACL):
                    confInfo[stanza].setMetadata(key, val)
                            
                # Key is eai; userName/appName
                elif key.startswith(admin.EAI_META_PREFIX):
                    confInfo[stanza].append(key, val)
                    
                # Key is not proper
                else:
                    pass
            
        # Check each of the settings individually
        logger.info("Checking general settings for the '%s' suppression", stanza)
        for key, val in settings.items():
            # Set val to empty if None
            if val is None:
                val = ''
            
            # Check the disabled/selected value
            if key == Suppressions.PARAM_DISABLED:
                try:
                    util.normalizeBoolean(val, enableStrictMode=True)
                    
                    # Remove the field from the list of required fields
                    try:
                        required_fields.remove(key)
                        
                    except ValueError:
                        pass  # Field not available, probably because it is not required
                        
                except ValueError:
                    raise InvalidParameterValueException(key, val, "must be a valid boolean")
                    
            elif key in Suppressions.REQUIRED_PARAMS:
                # Remove the field from the list of required fields
                try:
                    required_fields.remove(key)
                        
                except ValueError:
                    pass  # Field not available, probably because it is not required
                        
            elif key in Suppressions.VALID_PARAMS:
                pass
                                   
            # Key is eai
            elif key.startswith(admin.EAI_META_PREFIX):
                pass
                 
            # Key is not proper
            else:
                if throwExceptionOnError:
                    raise UnsupportedParameterException()
                
                else:
                    logger.warn("The configuration for '%s' contains an unsupported parameter: %s", stanza, key)

        # Error if some of the required fields were not provided
        if len(required_fields) > 0:
            raise InvalidConfigException('The following fields must be defined in the configuration but were not: ' + ', '.join(required_fields).strip())

  
# initialize the handler
admin.init(Suppressions, admin.CONTEXT_APP_AND_USER)