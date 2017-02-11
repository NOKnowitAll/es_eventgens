# Copyright (C) 2009-2015 Splunk Inc. All Rights Reserved.
#
# This file contains all possible options for a correlationsearches.conf file.  Use this file to configure 
# Splunk's correlation search properties.
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#

[default]
rule_name                 =
description               =
search                    =
related_search_name       = 
related_search_name.0     = 
related_search_name.1     = 
related_search_name.2     = 
related_search_name.3     = 
related_search_name.4     =

security_domain           =
severity                  =
rule_title                =
rule_description          =
nes_fields                =
drilldown_name            =
drilldown_search          =
drilldown_earliest_offset = $info_min_time$
drilldown_latest_offset   = $info_max_time$
default_status            =
default_owner             =
next_steps                =
recommended_actions       =

[<stanza name>]
   * Create a stanza name for each correlation search.
   * Stanza name must match stanza in savedsearches.conf
   * Follow the stanza name with any number of the following attribute/value pairs.
   * If you do not specify an attribute, Splunk uses the default.

###### The following settings apply to all correlation searches ######
   
rule_name = <string>
   * Specifies the friendly name of the correlation search as an object.
   * Used to generate statistics per correlation search.
   * Does not support token replacement.
   * Required.
   * Defaults to None.

description = <string>
   * Human readable description of the correlation search as an object.
   * Does not support token replacement.
   * Optional.
   * Defaults to None.
 
search = <json>
   * Deprecated
   * See alert_actions.conf.spec "customsearchbuilder"
   
related_search_name = <string>
   * Name of a saved search that should be enabled when this search is enabled.
   * Optional.
   * Defaults to None.
   
related_search_name.0 = <string>
   * Same as related_search_name (allows for multiple related searches)
   
related_search_name.1 = <string>
   * Same as related_search_name (allows for multiple related searches)
   
related_search_name.2 = <string>
   * Same as related_search_name (allows for multiple related searches)
   
related_search_name.3 = <string>
   * Same as related_search_name (allows for multiple related searches)
   
related_search_name.4 = <string>
   * Same as related_search_name (allows for multiple related searches)

###### The following settings apply to correlation searches that generate notable events ######

security_domain = <access|endpoint|network|threat|identity|audit>
   * Specifies the security domain which this correlation search applies to.
   * Defaults to None.
   
severity = <informational|low|medium|high|critical>
   * Specifies the severity of the correlation search.
   * Defaults to None.

rule_title = <string>
   * Specifies the title for an instance of the correlation search.
   * Used to provide a title for an instance of the correlation search when 
     viewed within the Incident Review dashboard.
   * Supports token ($token$) replacement.
   * Optional.
   * Defaults to None (rule_name).
   
rule_description = <string>
   * A string which describes an instance of the correlation search.
   * Used to provide a description for an instance of the correlation search when 
   viewed within the Incident Review dashboard.
   * Supports token ($token$) replacement.
   * Defaults to None.
   
nes_fields = <comma-delimited-field-list>
  * A list of suggested fields to be used for Notable Event Suppression.
  * The "Suppress Event" modal will select these field-value pairs by default when suppressing.
  * Defaults to None.
   
drilldown_name = <string>
   * A string which providing text for the drilldown hyperlink within the Incident
     Review dashboard.
   * Supports token ($token$) replacement.
   * Defaults to None.

drilldown_search = <string>
   * Actual search terms of the drilldown search.
   * Your search can include macro searches for substitution.
   * Supports token ($token$) replacement.
   * Defaults to None.
   
drilldown_earliest_offset = <$info_min_time$|integer>
   * Number of seconds subtracted from _time.
   * Used to create drilldown_earliest.
   * If $info_min_time$ set drilldown_earliest as info_min_time field value; $info_min_time$ represents the earliest time of the search.
   * See also http://docs.splunk.com/Documentation/Splunk/latest/Searchreference/addinfo
   * Defaults to $info_min_time$.
   
drilldown_latest_offset = <$info_max_time$|integer>
   * Number of seconds added to _time.
   * Used to create drilldown_latest.
   * If $info_max_time$ set drilldown_latest as info_max_time field value; $info_max_time$ represents the latest time of the search.
   * See also http://docs.splunk.com/Documentation/Splunk/latest/Searchreference/addinfo
   * Defaults to $info_max_time$.

default_status = <status_id>
   * Status this correlation search should default to when triggered.
   * Defaults to None.

default_owner = <Splunk user>
   * Splunk user this correlation search should default to when triggered.
   * Defaults to None.

next_steps = <json>
    * A json string that provides the next steps to be performed.
    * See Appendix A for specification.
    * Defaults to None.

recommended_actions = <string>
    * A comma separated list of modular alert actions.
    * Defaults to None.


###### Appendix A: next_steps Specification #######
## Rich text to describe next steps to be executed for notable events.
## Response Action can be referenced within the text by using the following
## notation: [[action|<NameOfAction>]]
# {
#   "version": <version number>,
#   "data":    "<next steps text>"
# }