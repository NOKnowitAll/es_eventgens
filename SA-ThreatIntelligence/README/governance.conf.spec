# Copyright (C) 2009-2015 Splunk Inc. All Rights Reserved.
#
# This file contains all possible options for a governance.conf file.  Use this file to configure 
# Splunk's governance mappings.
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#

[default]


[<stanza name>]
   * Create a stanza name for each correlation search.
   * Stanza name must match stanza in savedsearches.conf
   * Follow the stanza name with any number of the following attribute/value pairs.
   * If you do not specify an attribute, Splunk uses the default.
   
compliance.<n>.governance = <pci|hipaa|sox|nerc|fisma>
   * IT compliance standard (governance) this correlation search satisfies.
   * 'n' is a number starting at 0, and increasing by 1.
   * Only valid when combined with compliance.<n>.control.
   * Defaults to None.
   
compliance.<n>.control = <string>
   * IT compliance control this correlation search satisfies.
   * 'n' is a number starting at 0, and increasing by 1.
   * Only valid when combined with compliance.<n>.governance.
   * Defaults to None. 
   
compliance.<n>.tag = <string>
   * Tag that must be present in the notable events generated
     in order for <n> governance/control mapping to be valid.
   * 'n' is a number starting at 0, and increasing by 1.
   * Only valid when combined with compliance.<n>.governance and compliance.<n>.control
   * Defaults to None.