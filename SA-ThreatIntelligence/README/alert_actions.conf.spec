# Copyright (C) 2009-2015 Splunk Inc. All Rights Reserved.
#
# This file contains additional options for an alert_actions.conf file.
#
# To learn more about configuration files (including precedence) please see the documentation
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#

###### customsearchbuilder ######
[customsearchbuilder]

enabled = [true|false|0|1]
    * Whether or not the search should be driven by custom search builder.
    * This exists so that we are a true noop for scheduled searches.
    * action.customsearchbuilder=0 action.customsearchbuilder.enabled=1
    * Required.
    * Defaults to false.

routine  = [make_correlation_search:makeCorrelationSearch|make_lookup_generating_search:makeLookupGeneratingSearch]
    * The routine to execute when building the custom search
    * This follows a <script:method> notation.
    * Required.
    * Defaults to None.
    
spec     = <json>
    * The json specification for the custom search.
    * Each routine may define it's own specification.
    * See Appendix A for make_correlation_search.
    * See Appendix B for make_lookup_generating_search.
    * Required.
    * Defaults to None.

###### Appendix A: Correlation Search Specification #######
## datamodel/object and inputlookup are used independently from one another
## datamodel/object will win over inputlookup if both were specified
## span is only valid when _time is a splitby attribute
#{
#   "version":                 "<version number>",
#	"searches":              [
#		{
#			"key":          "<Field to use to link searches together>",
#
#			"datamodel":    "<Data Model Name>",
#			"object":       "<Data Model Object Name">,
#			
#			"inputlookup":  {
#				"lookupName": "<Lookup Table Name>",
#				"timeField":  "<Field to use for time based lookups>"
#			},
#
#			"earliest":     "<Earliest Time Specifier>",
#			"latest":       "<Latest Time Specifier>",
#
#			"eventFilter":  "<where clause>",
#
#			"aggregates":   [
#				{
#					"function":  "<sum|dc|etc>",
#					"attribute": "<field input name>",
#					"alias":     "<field output name>"
#				}
#			],
#
#			"splitby":      [
#				{
#					"attribute": "<field input name>",
#					"alias":     "<field output name>",
#                   "span":      "<[seconds|minutes|hours|days|months|(us|ms|cs|ds)]>"
#				}
#			],
#
#			"resultFilter": {
#               "field":      "<field input name>",
#				"comparator": "=|!=|>|>=|<|<=",
#				"value":      "<value>"
#			},
#           "summariesonly":         "[1|0]"
#		}
#	],
#
#	"alert.suppress":        "[1|0]",
#	"alert.suppress.fields": ["<field1>","<field2>",...,"<fieldn>"]
#}


###### Appendix B: Lookup Generating Search Specification #######
## datamodel/object and inputlookup are used independently from one another
## datamodel/object will win over inputlookup if both were specified
## span is only valid when _time is a splitby attribute
#{
#   "version": "<version number>",
#	"search":  {
#			"datamodel":     "<Data Model Name>",
#			"object":        "<Data Model Object Name">,
#			
#			"inputlookup":   {
#				"lookupName": "<Lookup Table Name>",
#				"timeField":  "<Field to use for time based lookups>"
#			},
#
#			"earliest":      "<Earliest Time Specifier>",
#			"latest":        "<Latest Time Specifier>",
#
#			"eventFilter":   "<where clause>",
#
#			"aggregates":    [
#				{
#					"function":  "<sum|dc|etc>",
#					"attribute": "<field input name>",
#					"alias":     "<field output name>"
#				}
#			],
#
#			"splitby":       [
#				{
#					"attribute": "<field input name>",
#					"alias":     "<field output name>",
#                   "span":      "<[seconds|minutes|hours|days|months|(us|ms|cs|ds)]>"
#				}
#			],
#
#           "summariesonly": "[1|0]",
#           "outputlookup":  "<transform name>",
#           "retention":     {
#               "earliestTime": "<relative time specifier>",
#               "timeField":    "<time field name>",
#               "timeFormat":   "<strptime specifier>"
#           }
#		}
#	}
#}


###### nbtstat ######
[nbtstat]
param.host_field = <string>
    * The name of the field representing the value to perform a nbtstat scan on
    * Defaults to None.
    
param.max_results = <int>
    * The number of results to perform a nbtstat scan on
    * Each field value counts as a result
    * Defaults to 1.

param.verbose = [true|false|0|1]
    * Set modular alert action logger to verbose mode
    * Defaults to "false"
    

###### notable ######
[notable]
param.index = <string>
    * The name of the summary index where Splunk will write the events
    * Defaults to "notable"

param.verbose = [true|false|0|1]
    * Set modular alert action logger to verbose mode
    * Defaults to "false"

param.mapfields = <comma-delimited-field-strings>
    * A comma separated strings of notable fields.
    * Fields in this list will be renamed to orig_$field$ when persisting the notable event.
    * For creating a pure adhoc notable event set to empty strying "".
    * Defaults to "rule_name,rule_title,rule_description,security_domain,
    * nes_fields,drilldown_name,drilldown_search,governance,control,
    * status,owner,default_owner,drilldown_earliest_offset,drilldown_latest_offset,
    * recommended_actions"


###### nslookup ######
[nslookup]
param.host_field = <string>
    * The name of the field representing the value to perform a nslookup scan on
    * Defaults to None.
    
param.max_results = <int>
    * The number of results to perform a nslookup scan on
    * Each field value counts as a result
    * Defaults to 1.

param.verbose = [true|false|0|1]
    * Set modular alert action logger to verbose mode
    * Defaults to "false"


###### ping ######
[ping]
param.host_field = <string>
    * The name of the field representing the value to perform a ping scan on
    * Defaults to None.
    
param.max_results = <int>
    * The number of results to perform a ping scan on
    * Each field value counts as a result
    * Defaults to 1.

param.verbose = [true|false|0|1]
    * Set modular alert action logger to verbose mode
    * Defaults to "false"
    

###### risk ######
[risk]

###### Legacy Params ######

_name = <string>
    * The name of the summary index where Splunk will write the events.
    * Defaults to "risk".

## Using underscore prepend for risk fields because these are conveniently excluded from the summaryindex markers
## per core implementation of summaryindex alert action in $SPLUNK_HOME/etc/system/default/alert_actions.conf

_risk_score = <int>
    * The score to apply to risk modifiers generated by the implementation of this action
    * Defaults to 1

_risk_object = <string>
    * The field name to use as the risk_object
    * Field must be available in the result set passed to this action
    * Defaults to None

_risk_object_type = [system|user|<string>|other]
    * The type of risk_object
    * Must be one of "system", "user", arbitrary string, or "other"
    * <string> allows for type extensions
    * Defaults to None

###### Modalert Params ######

param.index = <string>
    * The name of the summary index where Splunk will write the events
    * Defaults to "risk"
    
param._risk_score = <int>
    * The score to apply to risk modifiers generated by the implementation of this action
    * Defaults to 1

param._risk_object = <string>
    * The field name to use as the risk_object
    * Field must be available in the result set passed to this action
    * Defaults to None
    
param._risk_object_type = [system|user|<string>|other]
    * The type of risk_object
    * Must be one of "system", "user", arbitrary string, or "other"
    * <string> allows for type extensions
    * Defaults to None

param.verbose = [true|false|0|1]
    * Set modular alert action logger to verbose mode
    * Defaults to "false"
