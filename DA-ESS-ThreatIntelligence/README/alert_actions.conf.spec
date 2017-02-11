# Copyright (C) 2009-2015 Splunk Inc. All Rights Reserved.
#
# This file contains additional options for an alert_actions.conf file.
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#

[threat_activity]
inline = [1|0]
   * Specifies whether the summary index search command will run as part 
     of the scheduled search or as a follow-on action. This is useful 
     when the results of the scheduled search are expected to be large.
    * Defaults to 1 (true).

_name = <string>
    * The name of the summary index where Splunk will write the events.
    * Defaults to "threat_activity".
    
## Using underscore prepend for risk fields because these are conveniently excluded from the summaryindex markers
## per core implementation of summaryindex alert action in $SPLUNK_HOME/etc/system/default/alert_actions.conf 

_threat_match = <string>
    * The field used to match event data with threat intelligence
    * Defaults to None


[threat_outputlookup]

collections = <comma-delimited-field-list>
   * The list of collections used to populate the threat lookup.
   * Defaults to None