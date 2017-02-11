"""
Copyright (C) 2005 - 2016 Splunk Inc. All Rights Reserved.
"""
import logging
import os
import sys

if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)

import splunk.admin as admin
import splunk.bundle as bundle
import splunk.entity as entity
import splunk.util as util
from splunk import ResourceNotFound

from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
from SolnCommon.log import setup_logger, SHORT_FORMAT

logger = setup_logger('log_review_rest_handler', level=logging.INFO, format=SHORT_FORMAT)


class InvalidConfigException(Exception):
    """
    Describes an invalid configuration.
    """
    pass
    
class InvalidParameterValueException(InvalidConfigException):
    """
    Describes a config parameter that has an invalid value.
    """
    
    def __init__(self, field, value, value_must_be):
        message = "The value for the field '%s' is invalid: %s (was %s)" % (field, value_must_be, value)
        super(InvalidConfigException, self).__init__( message )

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

class LogReview(admin.MConfigHandler):
    
    ## Permissions
    WRITE_CAPABILITY = 'edit_log_review_settings'
    
    ## Default Params
    PARAM_COMMENT_MINIMUM_LENGTH = 'minimum_length'
    PARAM_COMMENT_REQUIRED = 'is_required'
    PARAM_DEBUG = 'debug'
    PARAM_ALLOW_URGENCY_OVERRIDE = 'allow_urgency_override'
    PARAM_TABLE_ATTRIBUTES = 'table_attributes'
    PARAM_EVENT_ATTRIBUTES = 'event_attributes'
    
    VALID_PARAMS = [ PARAM_DEBUG, PARAM_COMMENT_MINIMUM_LENGTH, PARAM_COMMENT_REQUIRED, PARAM_ALLOW_URGENCY_OVERRIDE, PARAM_TABLE_ATTRIBUTES, PARAM_EVENT_ATTRIBUTES ]
    REQUIRED_PARAMS = [ ]
  
    ## Default Vals
    DEFAULT_NAMESPACE = 'SA-ThreatIntelligence'
    DEFAULT_OWNER = 'nobody'
    
    DEFAULT_COMMENT_LENGTH = 8
    DEFAULT_COMMENT_REQUIRED = False
    
    DEFAULT_TABLE_ATTRIBUTES = [{"field": "_time",                       "label": "Time"},
                                {"field": "security_domain",             "label": "Security Domain"},
                                {"field": "rule_title",                  "label": "Title"},
                                {"field": "urgency",                     "label": "Urgency"},
                                {"field": "status_label",                "label": "Status"},
                                {"field": "owner_realname",              "label": "Owner"}
    ]
    
    DEFAULT_EVENT_ATTRIBUTES = [{"field": "action",                      "label": "Action"},
                                {"field": "app",                         "label": "Application"},
                                {"field": "bytes_in",                    "label": "Bytes In"},
                                {"field": "bytes_out",                   "label": "Bytes Out"},
                                {"field": "category",                    "label": "Category"},
                                {"field": "change_type",                 "label": "Change Type"},
                                {"field": "channel",                     "label": "Channel"},
                                {"field": "command",                     "label": "Command"},
                                {"field": "cpu_load_percent",            "label": "CPU Load (%)"},
                                {"field": "creator",                     "label": "Creator"},
                                {"field": "creator_realname",            "label": "Creator Realname"},
                                {"field": "cve",                         "label": "CVE"},
                                {"field": "decoration",                  "label": "Decoration"},
                                {"field": "desc",                        "label": "Description"},
                                {"field": "dest",                        "label": "Destination"},
                                {"field": "dest_threatlist_category",    "label": "Destination Threat List Category"},
                                {"field": "dest_threatlist_description", "label": "Destination Threat List Description"},
                                {"field": "dest_threatlist_name",        "label": "Destination Threat List Name"},
                                {"field": "dest_bunit",                  "label": "Destination Business Unit"},
                                {"field": "dest_category",               "label": "Destination Category"},
                                {"field": "dest_city",                   "label": "Destination City"},
                                {"field": "dest_country",                "label": "Destination Country"},
                                {"field": "dest_dns",                    "label": "Destination DNS"},
                                {"field": "dest_ip",                     "label": "Destination IP Address"},
                                {"field": "dest_is_expected",            "label": "Destination Expected"},
                                {"field": "dest_lat",                    "label": "Destination Latitude"},
                                {"field": "dest_long",                   "label": "Destination Longitude"},
                                {"field": "dest_mac",                    "label": "Destination MAC Address"},
                                {"field": "dest_nt_domain",              "label": "Destination NT Domain"},
                                {"field": "dest_nt_host",                "label": "Destination NT Hostname"},
                                {"field": "dest_owner",                  "label": "Destination Owner"},
                                {"field": "dest_pci_domain",             "label": "Destination PCI Domain"},
                                {"field": "dest_port",                   "label": "Destination Port"},
                                {"field": "dest_record",                 "label": "Destination Record"},
                                {"field": "dest_should_timesync",        "label": "Destination Should Time Synchronize"},
                                {"field": "dest_should_update",          "label": "Destination Should Update"},
                                {"field": "dest_requires_av",            "label": "Destination Requires Antivirus"},
                                {"field": "dest_translated_ip",          "label": "Destination Translated IP Address"},
                                {"field": "dest_translated_port",        "label": "Destination Translated Port"},
                                {"field": "dest_zone",                   "label": "Destination Zone"},
                                {"field": "dhcp_pool",                   "label": "DHCP Pool"},
                                {"field": "direction",                   "label": "Direction"},
                                {"field": "dns",                         "label": "DNS"},
                                {"field": "duration",                    "label": "Duration"},
                                {"field": "dvc",                         "label": "Device"},
                                {"field": "dvc_bunit",                   "label": "Device Business Unit"},
                                {"field": "dvc_category",                "label": "Device Category"},
                                {"field": "dvc_city",                    "label": "Device City"},
                                {"field": "dvc_country",                 "label": "Device Country"},
                                {"field": "dvc_dns",                     "label": "Device DNS"},
                                {"field": "dvc_ip",                      "label": "Device IP Address"},
                                {"field": "dvc_is_expected",             "label": "Device Expected"},
                                {"field": "dvc_lat",                     "label": "Device Latitude"},
                                {"field": "dvc_long",                    "label": "Device Longitude"},
                                {"field": "dvc_mac",                     "label": "Device MAC Address"},
                                {"field": "dvc_nt_host",                 "label": "Device NT Hostname"},
                                {"field": "dvc_owner",                   "label": "Device Owner"},
                                {"field": "dvc_pci_domain",              "label": "Device PCI Domain"},
                                {"field": "dvc_should_timesync",         "label": "Device Should Time Synchronize"},
                                {"field": "dvc_should_update",           "label": "Device Should Update"},
                                {"field": "dvc_requires_av",             "label": "Device Requires Antivirus"},
                                {"field": "end_time",                    "label": "End Time"},
                                {"field": "file_access_time",            "label": "File Access Time"},
                                {"field": "file_create_time",            "label": "File Creation Time"},
                                {"field": "file_hash",                   "label": "File Hash"},
                                {"field": "file_modify_time",            "label": "File Modify Time"},
                                {"field": "file_name",                   "label": "File Name"},
                                {"field": "file_path",                   "label": "File Path"},
                                {"field": "file_permission",             "label": "File Permission"},
                                {"field": "file_size",                   "label": "File Size"},
                                {"field": "FreeMBytes",                  "label": "Free Megabytes"},
                                {"field": "gap",                         "label": "Gap"},
                                {"field": "gid",                         "label": "GID"},
                                {"field": "hash",                        "label": "Hash"},
                                {"field": "http_content_type",           "label": "HTTP Content Type"},
                                {"field": "http_method",                 "label": "HTTP Method"},
                                {"field": "http_referrer",               "label": "HTTP Referrer"},
                                {"field": "http_user_agent",             "label": "HTTP User Agent"},
                                {"field": "ids_type",                    "label": "Intrusion Detection Type"},
                                {"field": "iin_issuer",                  "label": "Issuer Identification Number (IIN)"},
                                {"field": "ip",                          "label": "IP Address"},
                                {"field": "ip_version",                  "label": "Internet Protocol Version"},
                                {"field": "is_interactive",              "label": "Interactive"},
                                {"field": "is_lockout",                  "label": "Is Lockout"},
                                {"field": "is_privileged",               "label": "Is Privileged"},
                                {"field": "isdir",                       "label": "Is Directory"},
                                {"field": "length",                      "label": "Length"},
                                {"field": "location",                    "label": "Location"},
                                {"field": "log_level",                   "label": "Log Level"},
                                {"field": "mac",                         "label": "MAC Address"},
                                {"field": "mem",                         "label": "Total Memory"},
                                {"field": "mem_committed",               "label": "Committed Memory"},
                                {"field": "mem_free",                    "label": "Free Memory"},
                                {"field": "mem_used",                    "label": "Used Memory"},
                                {"field": "mode",                        "label": "Mode"},
                                {"field": "modtime",                     "label": "Modification Time"},
                                {"field": "modify_time",                 "label": "Modification Time"},
                                {"field": "mount",                       "label": "Mount"},
                                {"field": "name",                        "label": "Name"},
                                {"field": "note",                        "label": "Note"},
                                {"field": "nt_host",                     "label": "NT Hostname"},
                                {"field": "object_handle",               "label": "Object Handle"},
                                {"field": "object_name",                 "label": "Object Name"},
                                {"field": "object_type",                 "label": "Object Type"},
                                {"field": "orig_host",                   "label": "Host"},
                                {"field": "orig_host_bunit",             "label": "Host Business Unit"},
                                {"field": "orig_host_category",          "label": "Host Category"},
                                {"field": "orig_host_city",              "label": "Host City"},
                                {"field": "orig_host_country",           "label": "Host Country"},
                                {"field": "orig_host_dns",               "label": "Host DNS"},
                                {"field": "orig_host_ip",                "label": "Host IP Address"},
                                {"field": "orig_host_is_expected",       "label": "Host Expected"},
                                {"field": "orig_host_lat",               "label": "Host Latitude"},
                                {"field": "orig_host_long",              "label": "Host Longitude"},
                                {"field": "orig_host_mac",               "label": "Host MAC Address"},
                                {"field": "orig_host_nt_host",           "label": "Host NT Hostname"},
                                {"field": "orig_host_owner",             "label": "Host Owner"},
                                {"field": "orig_host_pci_domain",        "label": "Host PCI Domain"},
                                {"field": "orig_host_should_timesync",   "label": "Host Should Time Synchronize"},
                                {"field": "orig_host_should_update",     "label": "Host Should Update"},
                                {"field": "orig_host_requires_av",       "label": "Host Requires Av"},
                                {"field": "os",                          "label": "Operating System"},
                                {"field": "os_name",                     "label": "Operating System Name"},
                                {"field": "os_release",                  "label": "Operating System Release"},
                                {"field": "outbound_interface",          "label": "Outbound Interface"},
                                {"field": "package",                     "label": "Package"},
                                {"field": "package_title",               "label": "Package Title"},
                                {"field": "packets_in",                  "label": "Packets In"},
                                {"field": "packets_out",                 "label": "Packets Out"},
                                {"field": "path",                        "label": "Path"},
                                {"field": "PercentFreeSpace",            "label": "Free Space (%)"},
                                {"field": "PercentProcessorTime",        "label": "Processor Time (%)"},
                                {"field": "pid",                         "label": "Process Identifier"},
                                {"field": "pii",                         "label": "Personally Identifiable Information (PII)"},
                                {"field": "port",                        "label": "Port"},
                                {"field": "process",                     "label": "Process"},
                                {"field": "product",                     "label": "Product"},
                                {"field": "product_version",             "label": "Product Version"},
                                {"field": "proto",                       "label": "Internet Protocol"},
                                {"field": "reason",                      "label": "Reason"},
                                {"field": "recipient",                   "label": "Recipient"},
                                {"field": "record_class",                "label": "Record Class"},
                                {"field": "record_type",                 "label": "Record Type"},
                                {"field": "result",                      "label": "Result"},
                                {"field": "rule_number",                 "label": "Rule Identifier"},
                                {"field": "selinux",                     "label": "SELinux"},
                                {"field": "selinuxtype",                 "label": "SELinux Type"},
                                {"field": "sender",                      "label": "Sender"},
                                {"field": "session_id",                  "label": "Session Identifier"},
                                {"field": "setlocaldefs",                "label": "Set Local Definitions"},
                                {"field": "severity_id",                 "label": "Severity Identifier "},
                                {"field": "signature",                   "label": "Signature"},
                                {"field": "signature_id",                "label": "Signature Identifier"},
                                {"field": "signature_version",           "label": "Signature Version"},
                                {"field": "size",                        "label": "Size"},
                                {"field": "src",                         "label": "Source"},
                                {"field": "src_threatlist_category",     "label": "Source Threat List Category"},
                                {"field": "src_threatlist_description",  "label": "Source Threat List Description"},
                                {"field": "src_threatlist_name",         "label": "Source Threat List Name"},
                                {"field": "src_bunit",                   "label": "Source Business Unit"},
                                {"field": "src_category",                "label": "Source Category"},
                                {"field": "src_city",                    "label": "Source City"},
                                {"field": "src_country",                 "label": "Source Country"},
                                {"field": "src_dns",                     "label": "Source DNS"},
                                {"field": "src_ip",                      "label": "Source IP Address"},
                                {"field": "src_is_expected",             "label": "Source Expected"},
                                {"field": "src_lat",                     "label": "Source Latitude"},
                                {"field": "src_long",                    "label": "Source Longitude"},
                                {"field": "src_mac",                     "label": "Source MAC Address"},
                                {"field": "src_nt_domain",               "label": "Source NT Domain"},
                                {"field": "src_nt_host",                 "label": "Source NT Hostname"},
                                {"field": "src_owner",                   "label": "Source Owner"},
                                {"field": "src_pci_domain",              "label": "Source PCI Domain"},
                                {"field": "src_port",                    "label": "Source Port"},
                                {"field": "src_record",                  "label": "Source Record"},
                                {"field": "src_should_timesync",         "label": "Source Should Time Synchronize"},
                                {"field": "src_should_update",           "label": "Source Should Update"},
                                {"field": "src_requires_av",             "label": "Source Requires Antivirus"},
                                {"field": "src_translated_ip",           "label": "Source Translated IP Address"},
                                {"field": "src_translated_port",         "label": "Source Translated Port"},
                                {"field": "src_user",                    "label": "Source User"},
                                {"field": "src_user_group",              "label": "Source User Group"},
                                {"field": "src_user_group_id",           "label": "Source User Group Identifier"},
                                {"field": "src_user_id",                 "label": "Source User Identifier"},
                                {"field": "src_user_privilege",          "label": "Source User Privilege"},
                                {"field": "src_zone",                    "label": "Source Zone"},
                                {"field": "sshd_protocol",               "label": "SSHD Protocol"},
                                {"field": "ssid",                        "label": "Service Set Identifier (SSID)"},
                                {"field": "storage",                     "label": "Total Storage"},
                                {"field": "storage_free",                "label": "Free Storage"},
                                {"field": "storage_free_percent",        "label": "Free Storage (%)"},
                                {"field": "storage_used",                "label": "Used Storage"},
                                {"field": "storage_used_percent",        "label": "Used Storage (%)"},
                                {"field": "start_mode",                  "label": "Start Mode"},
                                {"field": "start_time",                  "label": "Start Time"},
                                {"field": "StartMode",                   "label": "Start Mode"},
                                {"field": "subject",                     "label": "Subject"},
                                {"field": "syslog_facility",             "label": "Syslog Facility"},
                                {"field": "syslog_priority",             "label": "Syslog Priority"},
                                {"field": "SystemUpTime",                "label": "System Uptime"},
                                {"field": "tcp_flags",                   "label": "TCP Flags"},
                                {"field": "threat_ip",                   "label": "Threat IP"},
                                {"field": "tos",                         "label": "Type Of Service"},
                                {"field": "TotalMBytes",                 "label": "Total Megabytes"},
                                {"field": "transaction_id",              "label": "Transaction Identifier"},
                                {"field": "transport",                   "label": "Transport Protocol"},
                                {"field": "ttl",                         "label": "Time To Live"},
                                {"field": "uid",                         "label": "UID"},
                                {"field": "uptime",                      "label": "Uptime"},
                                {"field": "url",                         "label": "URL"},
                                {"field": "UsedMBytes",                  "label": "Used Megabytes"},
                                {"field": "user",                        "label": "User"},
                                {"field": "user_group",                  "label": "User Group"},
                                {"field": "user_group_id",               "label": "User Group Identifier"},
                                {"field": "user_id",                     "label": "User Identifier"},
                                {"field": "user_privilege",              "label": "User Privilege"},
                                {"field": "validity",                    "label": "Validity"},
                                {"field": "vendor",                      "label": "Vendor"},
                                {"field": "vendor_product",              "label": "Vendor/Product"},
                                {"field": "view",                        "label": "View"},
                                {"field": "vlan_id",                     "label": "VLAN Identifier"},
                                {"field": "vlan_name",                   "label": "VLAN Name"},
                                {"field": "threat_category",             "label": "Threat Category"},
                                {"field": "threat_collection",           "label": "Threat Collection"},
                                {"field": "threat_collection_key",       "label": "Threat Collection Key"},
                                {"field": "threat_description",          "label": "Threat Description"},
                                {"field": "threat_group",                "label": "Threat Group"},
                                {"field": "threat_key",                  "label": "Threat Key"},
                                {"field": "threat_match_field",          "label": "Threat Match Field"},
                                {"field": "threat_match_value",          "label": "Threat Match Value"},
                                {"field": "threat_source_id",            "label": "Threat Source ID"},
                                {"field": "threat_source_path",          "label": "Threat Source Path"},
                                {"field": "threat_source_status",        "label": "Threat Source Status"},
                                {"field": "threat_source_type",          "label": "Threat Source Type"},
                                {"field": "malware_alias",               "label": "Malware Alias"}
    ]
       
    '''
    Set up supported arguments
    '''
    def setup(self):
        ## set write capability
        self.setWriteCapability(LogReview.WRITE_CAPABILITY)            
       
        if self.requestedAction == admin.ACTION_EDIT or self.requestedAction == admin.ACTION_CREATE:
              
            for arg in self.REQUIRED_PARAMS:
                self.supportedArgs.addReqArg(arg)
             
            for arg in self.VALID_PARAMS:
                if arg not in self.REQUIRED_PARAMS:
                    self.supportedArgs.addOptArg(arg)

    def handleCreate(self, confInfo):
        logger.debug("In handleCreate")
      
        # Refresh
        self.handleReload()
      
        name = self.callerArgs.id
        args = self.callerArgs.data
      
        # Make sure the name is not empty
        if not name or len(name) == 0:
            raise admin.ArgValidationException("The stanza name must not be empty")
      
        # Make sure the item does not already exist
        if name in self.readConf("log_review"):
            raise admin.AlreadyExistsException("A entry already exists for %s" % (name))
      
        # Get the field values
        # TODO: obtain the values of the fields into Python variables
        
        debug = _getFieldValue( args, self.PARAM_DEBUG, default_value='false' )
        comment_minimum_length = _getFieldValue( args, self.PARAM_COMMENT_MINIMUM_LENGTH, default_value=self.DEFAULT_COMMENT_LENGTH )
        comment_required = _getFieldValue( args, self.PARAM_COMMENT_REQUIRED, default_value=self.DEFAULT_COMMENT_REQUIRED )
        ir_header_labels = _getFieldValue( args, self.PARAM_TABLE_LABELS, default_value=self.DEFAULT_TABLE_LABELS )
        ir_header_fields = _getFieldValue( args, self.PARAM_TABLE_FIELDS, default_value=self.DEFAULT_TABLE_FIELDS )
        ir_attribute_labels = _getFieldValue( args, self.PARAM_ATTRIBUTE_LABELS, default_value=self.DEFAULT_ATTRIBUTE_LABELS )
        ir_attribute_fields = _getFieldValue( args, self.PARAM_ATTRIBUTE_FIELDS, default_value=self.DEFAULT_ATTRIBUTE_FIELDS )
      
        # Add the field values to a configuration dictionary (that will be verified)
        conf = entity.getEntity('configs/conf-log_review', '_new', sessionKey=self.getSessionKey())
        
        conf.namespace = self.appName # always save things to SOME app context.
        conf.owner = self.context == admin.CONTEXT_APP_AND_USER and self.userName or "-"
        
        conf['name'] = name
        
        _addToDictIfNonNull(conf, self.PARAM_DEBUG, debug)
        _addToDictIfNonNull(conf, self.PARAM_COMMENT_MINIMUM_LENGTH, comment_minimum_length)
        _addToDictIfNonNull(conf, self.DEFAULT_COMMENT_REQUIRED, comment_required)
        _addToDictIfNonNull(conf, self.DEFAULT_TABLE_LABELS, ir_header_labels)
        _addToDictIfNonNull(conf, self.DEFAULT_TABLE_FIELDS, ir_header_fields)
        _addToDictIfNonNull(conf, self.DEFAULT_ATTRIBUTE_LABELS, ir_attribute_labels)
        _addToDictIfNonNull(conf, self.DEFAULT_ATTRIBUTE_FIELDS, ir_attribute_fields)
      
        # Check the configuration
        try:
            self.checkConf(conf, name)
        except InvalidConfigException as e:
            logger.error( "The configuration for '%s' is invalid and could not be created: %s" % ( name, str(e)) )
            raise admin.ArgValidationException( str(e) )
      
        # Write out an update to the config file
        entity.setEntity(conf, sessionKey=self.getSessionKey())
      
        # Refresh
        self.handleReload()

    def handleList(self, confInfo):
        """
        Provide the list of configuration options.
        """
        # Refresh
        self.handleReload()
      
        # Get the configuration from log_review.conf
        confDict = self.readConfCtx('log_review')
      
        err_confs = 0
        ok_confs = 0
      
        # Get all the items and provide the relevant options
        if confDict != None: 
          
            # Check each conf
            for stanza, settings in confDict.items():
                if self.checkConfForRule(stanza, settings, confInfo):
                    ok_confs = ok_confs + 1
                else:
                    err_confs = err_confs + 1
                  
        # Print a log message
        if err_confs > 0:
            logger.debug( "LogReview REST handler found bad configuration stanzas, confs_errors=%d, confs_passed=%d" % (err_confs, ok_confs) )
        else:
            logger.debug( "LogReview REST handler loaded all configurations stanzas (no errors found), confs_errors=%d, confs_passed=%d" % (err_confs, ok_confs) )
              
    def handleReload(self, confInfo=None):
        # Refresh the configuration (handles disk based updates)
        refreshInfo = entity.refreshEntities('properties/log_review', sessionKey=self.getSessionKey())

    def handleEdit(self, confInfo):
        """
        Handles edits to the configuration options
        """
        logger.debug("In handleEdit")
        
        # Refresh
        self.handleReload()
      
        name = self.callerArgs.id
        args = self.callerArgs
        
        if name is not None:
            try:
                conf = entity.getEntity('configs/conf-log_review', name, sessionKey=self.getSessionKey())
                
            except ResourceNotFound:
                raise admin.NotFoundException("A log_review setting with the given name '%s' could not be found" % (name))

        else:
            # Stop if no name was provided
            raise admin.ArgValidationException("No name provided")
      
        # Create the resulting configuration that would be persisted if the settings provided are applied
        for key, val in conf.items():
            if key in args.data:
                conf[key] = args[key][0]
            
            if key == admin.EAI_ENTRY_ACL:
                if val.has_key('app') and val['app'] is not None and len(val['app']) > 0:
                    conf.namespace = val['app']
            
                if val.has_key('owner') and val['owner'] is not None and len(val['owner']) > 0:
                    conf.owner = val['owner']
                    
        if conf.namespace is None or len(conf.namespace) == 0:
            conf.namespace = LogReview.DEFAULT_NAMESPACE
            
        if conf.owner is None or len(conf.owner) == 0:
            conf.owner = LogReview.DEFAULT_OWNER
        
        # Check the configuration
        try:
            self.checkConf(conf, name)
        except InvalidConfigException as e:
            logger.error( "The configuration for '%s' is invalid and could not be edited: %s" % ( name, str(e)) )
            raise admin.ArgValidationException( str(e) )
      
        logger.debug("Updating configuration for " + str(name))
      
        entity.setEntity(conf, sessionKey=self.getSessionKey())
        
        ## Reload log_review
        self.handleReload()
      
    def checkConfForRule(self, stanza, settings, confInfo=None):
        """
        Checks the settings for the given stanza (which should be the rule name) and raises an
        exception if the configuration is invalid. Otherwise, the configuration option is added to
        the confInfo object (if not None). Returns true if the item validated, false otherwise.
        """
        
        try:
            self.checkConf(settings, stanza, confInfo)
            return True
        except InvalidConfigException as e:
            logger.error( "The configuration for the '%s' stanza is invalid: %s" % ( stanza, str(e)) )
            return False
              
    @staticmethod
    def checkConf(settings, stanza=None, confInfo=None, onlyCheckProvidedFields=False):
        """
        Checks the settings and raises an exception if the configuration is invalid.
        """
      
        # Add all of the configuration items to the confInfo object so that the REST endpoint lists them (even if they are wrong)
        # We want them all to be listed so that the users can see what the current value is (and hopefully will notice that it is wrong)
        for key, val in settings.items():
        
            # Add the value to the configuration info
            if stanza is not None and confInfo is not None:
            
                # Handle the EAI:ACLs differently than the normal values
                if key == 'eai:acl':
                    confInfo[stanza].setMetadata(key, val)
                elif key in LogReview.VALID_PARAMS:
                    confInfo[stanza].append(key, val)

        # Below is a list of the required fields. The entries in this list will be removed as they
        # are observed. An empty list at the end of the config check indicates that all necessary
        # fields where provided.
        required_fields = LogReview.REQUIRED_PARAMS[:]
      
        # Check each of the settings
        for key, val in settings.items():
          
            # Remove the field from the list of required fields
            try:
                required_fields.remove(key)
            except ValueError:
                pass # Field not available, probably because it is not required
        
            # Debugging level
            if (stanza == 'default' or stanza is None) and key == LogReview.PARAM_DEBUG:
                try:
                    util.normalizeBoolean(val, enableStrictMode=True)
                except ValueError:
                    raise InvalidParameterValueException(key, val, "must be a valid boolean")
              
            # Minimum length parameter
            elif stanza == 'comment' and key == LogReview.PARAM_COMMENT_MINIMUM_LENGTH:
                try:
                    int(val)
                except ValueError:
                    raise InvalidParameterValueException(key, val, "must be a valid integer")
                
            # Is comment required
            elif stanza == 'comment' and key == LogReview.PARAM_COMMENT_REQUIRED:
                try:
                    util.normalizeBoolean(val, enableStrictMode=True)
                except ValueError:
                    raise InvalidParameterValueException(key, val, "must be a valid boolean")
                
            # Is urgency override allowed
            elif (stanza == 'notable_editing' or stanza is None) and key == LogReview.PARAM_ALLOW_URGENCY_OVERRIDE:
                try:
                    util.normalizeBoolean(val, enableStrictMode=True)
                except ValueError:
                    raise InvalidParameterValueException(key, val, "must be a valid boolean")
              
        # Check to make sure the related config options that relate to the given parameters are acceptable
        if stanza != "default" and onlyCheckProvidedFields == False:
          
            # Add checks for field values that depend on the value of other field values here
          
            # Warn if some of the required fields were not provided
            if len(required_fields) > 0:
                raise InvalidConfigException("The following fields must be defined in the configuration but were not: " + ",".join(required_fields) )
              
      
# initialize the handler
admin.init(LogReview, admin.CONTEXT_APP_AND_USER)