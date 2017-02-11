# Sophos Technology Add-on 

## About 
    Author: Splunk
    Version: 3.2.0
    Date: 2014-08-22
    Supported product(s): Sophos Endpoint Security and Control up to version 10.3
   
 
## Deployment     
	Source type(s): WinEventLog:Application:sophos
	Input requirements: Data can be received via WinEventLogs, SEC Server logs, or syslog
        
        WinEventLog:Application:
            Data must be imported correctly using Splunk_TA_windows (since Sophos logs are stored in Windows events logs). Once imported, this technology add-on will process the Sophos data
            
        WinEventLog:Sophos Patch:
            There is a sample for monitoring Sophos patch status in:
                $SPLUNK_HOME/etc/apps/Splunk_TA_sophos/default/inputs.conf 
            Edits to that file should only be made here:
                $SPLUNK_HOME/etc/apps/Splunk_TA_sophos/local/inputs.conf
 
        SEC Server Logs Monitor:
            Data can be received via syslog (below) or by monitoring the SEC Server log. If
            monitoring log files directly set the sourcetype to "sophos:sec"
	   
        SEC Server Logs Syslog:
            To receive data over syslog, manually set the sourcetype for the associated data
            input to "sophos:sec". To monitor log files, see the details under "Using this
            Technology Add-on" below

	Has index-time parsing operations: true, this TA needs to be deployed on heavy forwarders and indexers 
    

## Using this Technology Add-on

	Configuration: Automatic
	Ports for automatic configuration: None
	Scripted input setup: Not applicable

	This Add-on can import data directly by monitoring files on the SEC Server or via syslog.
    To monitor the files directly you'll need to set the log file location in the inputs.conf 
    file. Modify the paths appropriately and enable them in $SPLUNK_HOME/etc/apps/Splunk_TA_sophos/local/inputs.conf (do not edit the copy in the default folder). 
    
    To collect from syslog, have Splunk listen on 
        
	1. Create the following file (you may copy pieces from default folder, but one should not 
       edit the default version):
    
            $SPLUNK_HOME/etc/apps/Splunk_TA_sophos/local/inputs.conf
        
	2. These are the SEC server log sourcetypes used by this TA:

            sourcetype = sophos:threats
            sourcetype = sophos:webdata
            sourcetype = sophos:firewall
            sourcetype = sophos:appcontrol
            sourcetype = sophos:devicecontrol
            sourcetype = sophos:tamperprotection
            sourcetype = sophos:datacontrol
            sourcetype = sophos:computerdata

	3. Setting up a syslog receiver is out of scope for this TA. When collecting syslog, 
       a best practice is to use a 3rd party aggregator (e.g. rsyslog or syslog-ng). 
       To have Splunk collect syslog, you would add this inputs.conf stanza in local:
            
            [udp:514]
            sourcetype=sophos:utm:firewall
  
       These are the syslog sourcetypes that should be accounted for in transforms.conf:
            sourcetype::sophos:utm:firewall
            sourcetype::sophos:utm:ips
            sourcetype::sophos:utm:ipsec

Copyright (C) 2005-2014 Splunk Inc. All Rights Reserved.
