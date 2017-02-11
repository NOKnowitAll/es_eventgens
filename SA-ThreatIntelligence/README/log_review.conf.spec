# Copyright (C) 2009-2015 Splunk Inc. All Rights Reserved.
#
# This file contains all possible options for a log_review.conf file.  Use this file to define
# Incident Review and Notable Event Editing properties.
#
# To learn more about configuration files (including precedence) please see the documentation 
# located at http://www.splunk.com/base/Documentation/latest/Admin/Aboutconfigurationfiles
#

[notable_editing]
allow_urgency_override = [1|0]
    * Allow the urgency of a notable event to be edited.
    * Defaults to True.

[comment]
minimum_length = <int>
    * Minimum length of comment if required.
    * Defaults to 20.

is_required    = [1|0]
    * Whether or not a comment is required.
    * Defaults to False.
    
[incident_review]
table_attributes = <json>
    * Ordered list of attributes to display as columns in Incident Review.
    * This is a json array of objects with field/label pairs.
    * See log_review.conf.example

event_attributes = <json>
    * List of attributes to display in the notable event details.
    * This is a json array of objects with field/label pairs.
    * See log_review.conf.example