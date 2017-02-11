"""
Copyright (C) 2005 - 2016 Splunk Inc. All Rights Reserved.
"""
import json
import logging
import logging.handlers
import re
import sys

if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)

import splunk.admin as admin
import splunk.entity as entity
import splunk.rest as rest
import splunk.util as util

from splunk    import ResourceNotFound
from shortcuts import NotableOwner
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
from SolnCommon.log     import setup_logger, SHORT_FORMAT
from SolnCommon.kvstore import KvStoreHandler
from SolnCommon.pooling import should_execute

logger = setup_logger('correlationsearches_rest_handler', level=logging.INFO, format=SHORT_FORMAT)


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
        super(InvalidParameterValueException, self).__init__(message)
      
        
class UnsupportedParameterException(InvalidConfigException):
    """
    Describes a config parameter that is unsupported.
    """
    pass


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


class CorrelationSearches(admin.MConfigHandler):
    """
    Set up supported arguments
    """
    # admin.py constants
    REQUESTED_ACTIONS = {'1': 'ACTION_CREATE', '2': 'ACTION_LIST', '4': 'ACTION_EDIT', '8': 'ACTION_REMOVE', '16': 'ACTION_MEMBERS', '32': 'ACTION_RELOAD'}
    # Permissions
    WRITE_CAPABILITY                = 'edit_correlationsearches'
    # Default Params
    PARAM_DISABLED                  = 'disabled'
    PARAM_RULE_NAME                 = 'rule_name'
    PARAM_DESCRIPTION               = 'description'    
    PARAM_SEARCH                    = 'search'
    PARAM_DEPENDENT_SEARCH          = 'related_search_name'
    PARAM_DEPENDENT_SEARCH_0        = 'related_search_name.0'
    PARAM_DEPENDENT_SEARCH_1        = 'related_search_name.1'
    PARAM_DEPENDENT_SEARCH_2        = 'related_search_name.2'
    PARAM_DEPENDENT_SEARCH_3        = 'related_search_name.3'
    PARAM_DEPENDENT_SEARCH_4        = 'related_search_name.4'
    
    PARAM_SECURITY_DOMAIN           = 'security_domain'
    PARAM_SEVERITY                  = 'severity'
    PARAM_RULE_TITLE                = 'rule_title'
    PARAM_RULE_DESCRIPTION          = 'rule_description'
    PARAM_NES_FIELDS                = 'nes_fields'
    PARAM_DRILLDOWN_NAME            = 'drilldown_name'
    PARAM_DRILLDOWN_SEARCH          = 'drilldown_search'
    PARAM_DRILLDOWN_EARLIEST_OFFSET = 'drilldown_earliest_offset'
    PARAM_DRILLDOWN_LATEST_OFFSET   = 'drilldown_latest_offset'
    PARAM_DEFAULT_STATUS            = 'default_status'
    PARAM_DEFAULT_OWNER             = 'default_owner'
    PARAM_NEXT_STEPS                = 'next_steps'
    PARAM_RECOMMENDED_ACTIONS       = 'recommended_actions'
    
    VALID_PARAMS                    = [PARAM_RULE_NAME,
                                       PARAM_DESCRIPTION,
                                       PARAM_SEARCH,
                                       PARAM_DEPENDENT_SEARCH,
                                       PARAM_DEPENDENT_SEARCH_0,
                                       PARAM_DEPENDENT_SEARCH_1,
                                       PARAM_DEPENDENT_SEARCH_2,
                                       PARAM_DEPENDENT_SEARCH_3,
                                       PARAM_DEPENDENT_SEARCH_4,
                                       PARAM_SECURITY_DOMAIN,
                                       PARAM_SEVERITY,
                                       PARAM_RULE_TITLE, 
                                       PARAM_RULE_DESCRIPTION,
                                       PARAM_NES_FIELDS,
                                       PARAM_DRILLDOWN_NAME,
                                       PARAM_DRILLDOWN_SEARCH,
                                       PARAM_DRILLDOWN_EARLIEST_OFFSET,
                                       PARAM_DRILLDOWN_LATEST_OFFSET,
                                       PARAM_DEFAULT_STATUS,
                                       PARAM_DEFAULT_OWNER,
                                       PARAM_NEXT_STEPS,
                                       PARAM_RECOMMENDED_ACTIONS]
    
    ## collections do not support '.' or '$' in params
    ## minus PARAM_DESCRIPTION
    COLLECTION_PARAMS               = [PARAM_RULE_NAME,
                                       PARAM_DESCRIPTION,
                                       PARAM_SECURITY_DOMAIN,
                                       PARAM_SEVERITY,
                                       PARAM_RULE_TITLE, 
                                       PARAM_RULE_DESCRIPTION,
                                       PARAM_NES_FIELDS,
                                       PARAM_DRILLDOWN_NAME,
                                       PARAM_DRILLDOWN_SEARCH,
                                       PARAM_DRILLDOWN_EARLIEST_OFFSET,
                                       PARAM_DRILLDOWN_LATEST_OFFSET,
                                       PARAM_DEFAULT_STATUS,
                                       PARAM_DEFAULT_OWNER,
                                       PARAM_NEXT_STEPS,
                                       PARAM_RECOMMENDED_ACTIONS
                                    ]
    
    REQUIRED_PARAMS                 = [PARAM_RULE_NAME]
  
    IGNORED_PARAMS                  = [PARAM_DISABLED]
  
    # Default Vals
    DEFAULT_NAMESPACE               = 'SA-ThreatIntelligence'
    DEFAULT_OWNER                   = 'nobody'
  
    def setup(self):
        logger.info('Setting up correlationsearches_rest_handler')
        
        self.setWriteCapability(CorrelationSearches.WRITE_CAPABILITY)
         
        if self.requestedAction == admin.ACTION_EDIT or self.requestedAction == admin.ACTION_CREATE:         
            # Fill required params
            for arg in CorrelationSearches.REQUIRED_PARAMS:
                self.supportedArgs.addReqArg(arg)
                
            # Fill valid params
            for arg in CorrelationSearches.VALID_PARAMS:
                if arg not in CorrelationSearches.REQUIRED_PARAMS:
                    self.supportedArgs.addOptArg(arg)

    def handleCreate(self, confInfo):
        """
        Handles creation of a correlation search
        """
        ## Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in CorrelationSearches.REQUESTED_ACTIONS:
            actionStr = CorrelationSearches.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
        
        ## Refresh
        self.handleReload(makeKVS=False)
        
        reviewstatusesDict = self.readConf('reviewstatuses')
        correlationsDict   = self.readConf('correlationsearches')
        # Get list of valid Splunk users
        users = NotableOwner.getOwners(self.getSessionKey())

        name = self.callerArgs.id
        args = self.callerArgs.data
      
        # Make sure the name is not empty
        if not name:
            raise admin.ArgValidationException('The name of the correlation search must not be empty')
      
        # Make sure the item does not already exist
        elif name in correlationsDict:
            raise admin.AlreadyExistsException('A correlation search entry already exists for %s' % name)
        
        # Get the field values (these are written to conf file)
        rule_name                 = _getFieldValue(args, CorrelationSearches.PARAM_RULE_NAME)
        description               = _getFieldValue(args, CorrelationSearches.PARAM_DESCRIPTION)
        search                    = _getFieldValue(args, CorrelationSearches.PARAM_SEARCH)
        related_search_name       = _getFieldValue(args, CorrelationSearches.PARAM_DEPENDENT_SEARCH)
        related_search_name_0     = _getFieldValue(args, CorrelationSearches.PARAM_DEPENDENT_SEARCH_0)
        related_search_name_1     = _getFieldValue(args, CorrelationSearches.PARAM_DEPENDENT_SEARCH_1)
        related_search_name_2     = _getFieldValue(args, CorrelationSearches.PARAM_DEPENDENT_SEARCH_2)
        related_search_name_3     = _getFieldValue(args, CorrelationSearches.PARAM_DEPENDENT_SEARCH_3)
        related_search_name_4     = _getFieldValue(args, CorrelationSearches.PARAM_DEPENDENT_SEARCH_4)
        
        security_domain           = _getFieldValue(args, CorrelationSearches.PARAM_SECURITY_DOMAIN)
        severity                  = _getFieldValue(args, CorrelationSearches.PARAM_SEVERITY)
        rule_title                = _getFieldValue(args, CorrelationSearches.PARAM_RULE_TITLE)
        rule_description          = _getFieldValue(args, CorrelationSearches.PARAM_RULE_DESCRIPTION)
        nes_fields                = _getFieldValue(args, CorrelationSearches.PARAM_NES_FIELDS)
        drilldown_name            = _getFieldValue(args, CorrelationSearches.PARAM_DRILLDOWN_NAME)
        drilldown_search          = _getFieldValue(args, CorrelationSearches.PARAM_DRILLDOWN_SEARCH)
        drilldown_earliest_offset = _getFieldValue(args, CorrelationSearches.PARAM_DRILLDOWN_EARLIEST_OFFSET)
        drilldown_latest_offset   = _getFieldValue(args, CorrelationSearches.PARAM_DRILLDOWN_LATEST_OFFSET)
        default_status            = _getFieldValue(args, CorrelationSearches.PARAM_DEFAULT_STATUS)
        default_owner             = _getFieldValue(args, CorrelationSearches.PARAM_DEFAULT_OWNER)
        next_steps                = _getFieldValue(args, CorrelationSearches.PARAM_NEXT_STEPS)
        recommended_actions       = _getFieldValue(args, CorrelationSearches.PARAM_RECOMMENDED_ACTIONS)
    
        # Add the field values to a configuration dictionary (that will be verified)
        conf           = entity.getEntity('configs/conf-correlationsearches', '_new', sessionKey=self.getSessionKey())
        conf.namespace = self.appName # always save things to SOME app context.
        conf.owner     = ((self.context == admin.CONTEXT_APP_AND_USER) and self.userName) or "-"
        conf['name']   = name
        
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_RULE_NAME, rule_name)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DESCRIPTION, description)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_SEARCH, search)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DEPENDENT_SEARCH, related_search_name)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DEPENDENT_SEARCH_0, related_search_name_0)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DEPENDENT_SEARCH_1, related_search_name_1)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DEPENDENT_SEARCH_2, related_search_name_2)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DEPENDENT_SEARCH_3, related_search_name_3)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DEPENDENT_SEARCH_4, related_search_name_4)
        
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_SECURITY_DOMAIN, security_domain)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_SEVERITY, severity)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_RULE_TITLE, rule_title)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_RULE_DESCRIPTION, rule_description)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_NES_FIELDS, nes_fields)        
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DRILLDOWN_NAME, drilldown_name)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DRILLDOWN_SEARCH, drilldown_search)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DRILLDOWN_EARLIEST_OFFSET, drilldown_earliest_offset)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DRILLDOWN_LATEST_OFFSET, drilldown_latest_offset)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DEFAULT_STATUS, default_status)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_DEFAULT_OWNER, default_owner)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_NEXT_STEPS, next_steps)
        _addToDictIfNonNull(conf, CorrelationSearches.PARAM_RECOMMENDED_ACTIONS, recommended_actions)

        # Check the configuration
        try:
            CorrelationSearches.checkConf(conf, name, users=users, reviewstatuses=reviewstatusesDict)
        
        except InvalidConfigException as e:
            e = "The configuration for the new correlation search '%s' is invalid and could not be created: %s" % (name, str(e))
            logger.error(e)
            raise admin.ArgValidationException(e)
      
        # Write out an update to the reviewstatuses config file
        entity.setEntity(conf, sessionKey=self.getSessionKey())
        logger.info('Successfully added correlation search: %s', name)
        
        # Reload correlationsearches (makeKVS)
        self.handleReload(reloadReviewStatuses=False)

    def handleList(self, confInfo):      
        """
        Handles listing of a review statuses
        """
        ## Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in CorrelationSearches.REQUESTED_ACTIONS:
            actionStr = CorrelationSearches.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
        
        ## Refresh
        self.handleReload(makeKVS=False)
    
        reviewstatusesDict = self.readConf('reviewstatuses')
        correlationsDict   = self.readConfCtx('correlationsearches')
        # Get list of valid Splunk users
        users = NotableOwner.getOwners(self.getSessionKey())
        
        # Get all correlations searches and provide the relevant options
        if correlationsDict:
            # Check each conf
            for stanza, settings in correlationsDict.items():
                if stanza != 'default':
                    try:
                        # Check config
                        CorrelationSearches.checkConf(settings, stanza, confInfo, users=users, reviewstatuses=reviewstatusesDict)
                    except InvalidConfigException as e:
                        logger.error("The configuration for the '%s' correlation search is invalid: %s", stanza, e)
        
        logger.info('%s completed successfully', actionStr)

    def handleReload(self, confInfo=None, makeKVS=True, reloadReviewStatuses=True):
        """
        Handles refresh/reload of the configuration options
        """
        actionStr = str(self.requestedAction)
        if actionStr in CorrelationSearches.REQUESTED_ACTIONS:
            actionStr = CorrelationSearches.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
        logger.info('Refreshing correlationsearches configurations via properties endpoint')
        try:
            entity.refreshEntities('properties/correlationsearches', sessionKey=self.getSessionKey())
        except Exception as e:
            logger.warn('Could not refresh correlationsearches configurations via properties endpoint: %s', e)
        
        ## since we checkConf on reviewstatuses this ensures the latest values
        if reloadReviewStatuses:
            logger.info('Refreshing reviewstatuses configurations via properties endpoint')
            try:
                entity.refreshEntities('properties/reviewstatuses', sessionKey=self.getSessionKey())
            except Exception as e:
                logger.warn('Could not refresh reviewstatuses configurations via properties endpoint: %s', e)            
        
        if makeKVS:
            # Only execute on standalone or on cluster master. 
            exec_status, exec_status_msg = should_execute(session_key=self.getSessionKey())
            logger.info(exec_status_msg)
            if exec_status:
                self.makeKVS()
         
        logger.info('%s completed successfully', actionStr)

    def makeKVS(self, collection='correlationsearches', correlationsDict=None):
        """
        Handles maintenance of correlationsearches kvstore collection
        """
        logger.info('Creating %s collection', collection)
        ## options
        options = {'app': CorrelationSearches.DEFAULT_NAMESPACE, 'owner': CorrelationSearches.DEFAULT_OWNER, 'collection': collection}
        ## get correlationsearches conf
        correlationsDict  = correlationsDict or self.readConf('correlationsearches')
        ## get savedsearches
        savedsearchesDict = self.readConf('savedsearches')
        
        if not correlationsDict:
            logger.error('Correlationsearches dictionary is None; cannot makeKVS')
        else:
            ## get reviewstatuses collection
            gr, gc = KvStoreHandler.get(None, self.getSessionKey(), options)
            
            if gr.status==200:
                existing_keys = [x['_key'] for x in json.loads(gc)]
                correlations = {}
                ## Iterate correlationsearches
                for stanza, settings in correlationsDict.items():
                    if stanza!='default':
                        correlation = {'_key': stanza}
                        for key in CorrelationSearches.COLLECTION_PARAMS:
                            ## kvstore prefers None over empty string
                            correlation[key] = settings.get(key) or None
                        correlations[stanza] = correlation
                ## Iterate savedsearches
                for stanza, settings in savedsearchesDict.items():
                    if re.match('^.*- Rule$', stanza):
                        ## kvstore prefers None over empty string
                        description = settings.get(CorrelationSearches.PARAM_DESCRIPTION) or None
                        if stanza not in correlations:
                            correlations[stanza] = {'_key': stanza}
                        if not correlations[stanza].get(CorrelationSearches.PARAM_DESCRIPTION):
                            correlations[stanza][CorrelationSearches.PARAM_DESCRIPTION] = description
                ## back to list
                correlations = [correlations[x] for x in correlations]

                pr, pc = KvStoreHandler.batch_create(correlations, self.getSessionKey(), options)
                if pr.status!=200:
                    logger.error('Error in upserting records to %s collection: %s', collection, pc)
                
                removed_keys = list(set(existing_keys).difference([x['_key'] for x in correlations])) 
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
    
    def handleEdit(self, confInfo):
        """
        Handles edits to the configuration options
        """
        ## Get requested action
        actionStr = str(self.requestedAction)
        if actionStr in CorrelationSearches.REQUESTED_ACTIONS:
            actionStr = CorrelationSearches.REQUESTED_ACTIONS[actionStr]
            
        logger.info('Entering %s', actionStr)
        
        ## Refresh
        self.handleReload(makeKVS=False)
        
        reviewstatusesDict = self.readConf('reviewstatuses')
        # Get list of valid Splunk users
        users = NotableOwner.getOwners(self.getSessionKey())

        name = self.callerArgs.id
        args = self.callerArgs
        
        if not name:
            raise admin.ArgValidationException('No name provided')
        try:
            conf = entity.getEntity('configs/conf-correlationsearches', name, sessionKey=self.getSessionKey())
        except ResourceNotFound:
            raise admin.NotFoundException("A correlationsearch configuration with the given name '%s' could not be found" % name)
        
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
            conf.namespace = conf[admin.EAI_ENTRY_ACL].get('app', None) or CorrelationSearches.DEFAULT_NAMESPACE
            conf.owner     = conf[admin.EAI_ENTRY_ACL].get('owner', None) or CorrelationSearches.DEFAULT_OWNER
        else:
            conf.namespace = CorrelationSearches.DEFAULT_NAMESPACE
            conf.owner     = CorrelationSearches.DEFAULT_OWNER
        
        try:
            # Check config
            CorrelationSearches.checkConf(conf, name, users=users, reviewstatuses=reviewstatusesDict)
        except InvalidConfigException as e:
            e = "The edit attempt for the correlation search '%s' produced an invalid configuration: %s" % (name, str(e))
            logger.error(e)
            raise admin.ArgValidationException(e)
    
        # Write out an update to the correlationsearches config file
        entity.setEntity(conf, sessionKey=self.getSessionKey())
        
        logger.info("Successfully updated the '%s' correlation search", name)
        
        # Reload correlationsearches (makeKVS)
        self.handleReload(reloadReviewStatuses=False)
        
        logger.info('%s completed successfully', actionStr)
    
    def handleRemove(self, confInfo):
        owner = ((self.context == admin.CONTEXT_APP_AND_USER) and self.userName) or "-"
        entity.deleteEntity('configs/conf-correlationsearches', self.callerArgs.id, namespace=self.appName, owner=owner, sessionKey=self.getSessionKey())

    @staticmethod
    def checkConf(settings, stanza=None, confInfo=None, users=[], reviewstatuses=[], throwExceptionOnError=False):
        """
        Checks the settings and raises an exception if the configuration is invalid.
        """ 
        # Below is a list of the required fields. The entries in this list will be removed as they
        # are observed. An empty list at the end of the config check indicates that all necessary
        # fields where provided.
        required_fields = CorrelationSearches.REQUIRED_PARAMS[:]
              
        if stanza is not None and confInfo is not None:
            # Add each of the settings
            for key, val in settings.items():
                if val is None:
                    val = ''
                    
                if key in CorrelationSearches.VALID_PARAMS:
                    confInfo[stanza].append(key, val)
                                              
                # Key is eai;acl Set meta
                elif key.startswith(admin.EAI_ENTRY_ACL):
                    confInfo[stanza].setMetadata(key, val)
                            
                # Key is eai; userName/appName
                elif key.startswith(admin.EAI_META_PREFIX):
                    confInfo[stanza].append(key, val)
                    
                # Key is not proper
                else:
                    pass
        else:
            pass
                    
        # Check each of the settings
        logger.info("Checking general settings for the '%s' correlation search", stanza)
        for key, val in settings.items():
            ## Set val to empty if None
            if val is None:
                val = ''
                
            # Check earliest/latest offsets
            if (key == CorrelationSearches.PARAM_DRILLDOWN_EARLIEST_OFFSET or key == CorrelationSearches.PARAM_DRILLDOWN_LATEST_OFFSET) and len(val) > 0 and val != ' ':
                # allow $info_min_time$ and $info_max_time$
                if val != '$info_min_time$' and val != '$info_max_time$':
                    try:
                        # allow positive numbers
                        invalid = (int(val, 10) < 0)
                    except (ValueError, TypeError):
                        invalid = True

                    if (invalid):
                        raise InvalidParameterValueException(key, val, 'must be either a positive integer, $info_min_time$, or $info_max_time$')
                
            # Check the DEFAULT_STATUS
            elif key == CorrelationSearches.PARAM_DEFAULT_STATUS and (len(val) > 0 and val != ' '):
                if val not in reviewstatuses:
                    raise InvalidParameterValueException(key, val, 'must be a valid review status')
                
                # Remove the field from the list of required fields
                try:
                    required_fields.remove(key)
                        
                except ValueError:
                    pass  # Field not available, probably because it is not required

            # Check the DEFAULT_OWNER
            elif key == CorrelationSearches.PARAM_DEFAULT_OWNER and (len(val) > 0 and val != ' '):
                if val not in users:
                    raise InvalidParameterValueException(key, val, 'must be a valid Splunk user')
                
                # Remove the field from the list of required fields
                try:
                    required_fields.remove(key)
                        
                except ValueError:
                    pass  # Field not available, probably because it is not required
                
            elif key in CorrelationSearches.REQUIRED_PARAMS:
                # Remove the field from the list of required fields
                try:
                    required_fields.remove(key)
                except ValueError:
                    pass  # Field not available, probably because it is not required
    
            elif key in CorrelationSearches.VALID_PARAMS:
                pass
                    
            # Key is ignored
            elif key in CorrelationSearches.IGNORED_PARAMS:
                pass        
                                   
            # Key is eai
            elif key.startswith('eai'):
                pass
                 
            # Key is not proper
            else:
                if throwExceptionOnError:
                    raise UnsupportedParameterException()
                
                else:
                    logger.warn("The configuration for the '%s' correlation search contains an unsupported parameter: %s", stanza, key)
        
        # Warn if some of the required fields were not provided
        if len(required_fields) > 0:
            raise InvalidConfigException('The following fields must be defined in the configuration but were not: ' + ', '.join(required_fields).strip())
    
# initialize the handler
admin.init(CorrelationSearches, admin.CONTEXT_APP_AND_USER)
