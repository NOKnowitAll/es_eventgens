# Copyright (C) 2009-2015 Splunk Inc. All Rights Reserved.
#
# This file contains additional options for an inputs.conf file.  
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#

[threat_intelligence_manager://default]
* Configure a location under $SPLUNK_HOME/etc/apps from which threat 
* intelligence information (in the form of IOC, STIX, TAXII, etc. documents) 
* will be consumed.

directory = <string>
* Define a directory from which to consume threat intelligence. If a full path 
* is specified, the path is expected to already exist. If the value is NOT a 
* full path, the directory is assumed to be under:
*
*	$SPLUNK_HOME/etc/apps/<app>/local/data/<directory>
*
* Relative paths and paths with non-alphanumeric characters (excepting the 
* underscore and space character) are not accepted. This parameter is agnostic
* with respect to the path separator for relative paths; either a back or 
* forward slash can be used. This permits a single configuration file to be 
* used across operating systems.

maxsize = <integer>
* Set the maximum size of an individual threat intelligence source, in bytes.

sinkhole = <boolean>
* If True, the threat intelligence manager will delete threat intelligence
* documents after processing. Defaults to False.

remove_unusable = <boolean>
* If True, the threat intelligence manager deletes a file (after processing it)
* if it does not contain actionable threat intelligence. Defaults to True.

default_weight = <int>
* If set, the threat intelligence manager will use the integer as a default 
* weight for all threat intelligence ingested from this inbox location. A
* weight defined for a specific threat intelligence download will override
* this setting. No default is set for this value.

