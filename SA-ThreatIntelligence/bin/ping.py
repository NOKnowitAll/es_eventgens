'''
Copyright (C) 2009-2016 Splunk Inc. All Rights Reserved.
'''
import json
import logging
import os
import re
import splunk.Intersplunk
import splunk.util as util
import sys
import subprocess
import time
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'Splunk_SA_CIM', 'lib']))

from cim_actions import ModularAction,InvalidResultID

logger = ModularAction.setup_logger('ping_modworkflow')


def handleError(modaction, signature):
    modaction.message(signature, status='failure', level=logging.ERROR)
    results = splunk.Intersplunk.generateErrorResults(signature)
    splunk.Intersplunk.outputResults(results)
    sys.exit(1)


if __name__ == '__main__':
    ## defaults
    ping            = None
    if os.name=='nt':
        ping_switch = '-n 4'
    else:
        ping_switch = '-c 4'

    orig_sid        = None
    orig_rid        = None
    host            = None
    host_field      = None
    MAX_RESULTS     = 1
    max_results     = 1
    host_validation = '^([A-Za-z0-9\.\_\-]+)$'

    the_time        = util.mktimegm(time.gmtime())
    
    ## retrieve results and settings
    results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults()
    logger.debug(settings)
    ## modular action hooks
    modaction_payload     = {'sid':   settings.get('sid', ''),
                             'owner': settings.get('owner'),
                             'app':   settings.get('namespace')}
    modaction             = ModularAction(json.dumps(modaction_payload), logger, action_name="ping")

    ## override defaults w/ opts below
    if len(sys.argv) > 1:
        for a in sys.argv:
            if a.startswith('host=') or a.startswith('dest='):
                where = a.find('=')
                host  = a[where+1:len(a)]
            elif a.startswith('host_field=') or a.startswith('dest_field='):
                where      = a.find('=')
                host_field = a[where+1:len(a)]                
            elif a.startswith('orig_sid='):
                where    = a.find('=')
                orig_sid = a[where+1:len(a)]
            elif a.startswith('orig_rid'):
                where    = a.find('=')
                orig_rid = a[where+1:len(a)]
            elif a.startswith('max_results'):
                where       = a.find('=')
                max_results = a[where+1:len(a)]
    try:
        if int(max_results)>0:
            MAX_RESULTS = int(max_results)
    except:
        pass
    logger.info('max_results setting determined: %s', MAX_RESULTS)   
    ## validate presence of host/host_field                          
    if not host and not host_field:
        signature = 'Must specify either host or host_field'
        handleError(modaction, signature)
    ## set up single result
    if host:            
        host_field = 'host'
        result     = {'host': host}
        if orig_sid and orig_rid:
            result.update({'orig_sid': orig_sid, 'orig_rid': orig_rid})
        results    = [result]
    ## process result(s)
    new_results       = []
    rids              = []
    results_processed = 0
    for num,result in enumerate(results):
        if results_processed>=MAX_RESULTS:
            break
        ## set result id
        result.setdefault('rid', str(num))
        ## update and invoke
        modaction.update(result)   
        modaction.invoke()
        ## validate host_field is present in result
        if host_field not in result:
            signature = 'host_field not present in result set'
            handleError(modaction, signature)
        else:
            ## handle MV
            hosts = result[host_field].split('\n')
        ## iterate hosts (as MV is a possibility)
        for host in hosts:
            if results_processed>=MAX_RESULTS:
                break
            results_processed+=1
            ## validate host value but don't exit    
            if re.match(host_validation, host):
                ## set up new result which will be sent back to splunk
                new_result = {'_time': the_time,
                              'sid':   modaction.sid,
                              'rid':   modaction.rid,
                              'dest':  host
                }
                if modaction.orig_sid and modaction.orig_rid:
                    new_result.update({'orig_sid': modaction.orig_sid, 'orig_rid': modaction.orig_rid})
                ## do ping
                try:
                    ping = subprocess.Popen(['ping', ping_switch, host], stdout=subprocess.PIPE)
                    new_result['_raw'] = ping.communicate()[0]    
                except Exception:
                    signature = 'Exception when executing ping command'
                    handleError(modaction, signature)
                ## add to successful rid list
                rids.append(modaction.rid_ntuple(modaction.orig_sid, modaction.rid, modaction.orig_rid))
                ## add result for intersplunk output
                new_results.append(new_result)
                ## add result for event creation
                modaction.addevent(new_result['_raw'], 'ping')      
            else:
                modaction.message('Invalid characters detected in host input', status='failure', level=logging.WARN)
    
    if len(new_results)>0:
        if modaction.writeevents(index='main', source='ping'):
            modaction.message('Successfully created splunk event', status='success', rids=rids)
        else:
            modaction.message('Failed to create splunk event', status='failure', rids=rids, level=logging.ERROR)
        
    splunk.Intersplunk.outputResults(new_results)
