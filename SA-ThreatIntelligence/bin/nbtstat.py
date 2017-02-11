'''
Copyright (C) 2009-2016 Splunk Inc. All Rights Reserved.
'''
import json
import logging
import os
import re
import splunk.Intersplunk
import splunk.util as util
import subprocess
import sys
import time
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'Splunk_SA_CIM', 'lib']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))

from cim_actions import ModularAction,InvalidResultID

def errorHandler(modaction, outputfile, logger):
    def handleError(signature):
        modaction.message(signature, status='failure', level=logging.ERROR)
        results = splunk.Intersplunk.generateErrorResults(signature)
        splunk.Intersplunk.outputResults(results, outputfile=outputfile)

    return handleError

def do_nbtstat(argv, input_str=None, outputfile=sys.stdout,
        logger=logging.getLogger('dummy')):
    ## defaults
    nbtstat         = None
    orig_sid        = None
    orig_rid        = None
    host            = None
    host_field      = None
    MAX_RESULTS     = 1
    max_results     = 1
    host_validation = '^([A-Za-z0-9\.\_\-]+)$'
    ip_rex          = re.compile('^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$')

    the_time        = util.mktimegm(time.gmtime())

    ## retrieve results and settings
    results, dummyresults, settings = splunk.Intersplunk.getOrganizedResults(input_str)
    logger.debug(settings)
    ## modular action hooks
    modaction_payload     = {'sid':   settings.get('sid', ''),
                             'owner': settings.get('owner'),
                             'app':   settings.get('namespace')}
    modaction             = ModularAction(json.dumps(modaction_payload), logger, action_name="nbtstat")

    ## override defaults w/ opts below
    if len(argv) > 1:
        for a in argv:
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

    handleError = errorHandler(modaction, outputfile, logger)
    ## validate presence of host/host_field
    if not host and not host_field:
        signature = 'Must specify either host or host_field'
        handleError(signature)
        return
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
            handleError(signature)
            return
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
                ip_match = ip_rex.match(host)
                ## set up new result which will be sent back to splunk
                new_result = {'_time': the_time,
                              'sid':   modaction.sid,
                              'rid':   modaction.rid,
                              'dest':  host
                }
                if modaction.orig_sid and modaction.orig_rid:
                    new_result.update({'orig_sid': modaction.orig_sid, 'orig_rid': modaction.orig_rid})
                ## determine nbtstat_cmd
                if os.name=='nt':
                    if ip_match:
                        nbtstat_cmd = ['nbtstat', '-A', host]
                    else:
                        nbtstat_cmd = ['nbtstat', '-a', host]
                elif sys.platform=='darwin':
                    if ip_match:
                        nbtstat_cmd = None
                        modaction.message('Unable to perform reverse netbios lookup', status='failure', level=logging.WARN)
                    else:
                        nbtstat_cmd = ['smbutil', 'lookup', host]
                else:
                    if ip_match:
                        nbtstat_cmd = ['nmblookup', '-A', host]
                    else:
                        nbtstat_cmd = ['nmblookup', host]
                ## do nbtstat
                if nbtstat_cmd:
                    try:
                        nbtstat = subprocess.Popen(nbtstat_cmd, stdout=subprocess.PIPE)
                        new_result['_raw'] = nbtstat.communicate()[0]
                    except Exception:
                        signature = 'Exception when executing nbtstat command'
                        handleError(signature)
                        return
                    ## add to successful rid list
                    rids.append(modaction.rid_ntuple(modaction.orig_sid, modaction.rid, modaction.orig_rid))
                    ## add result for intersplunk output
                    new_results.append(new_result)
                    ## add result for event creation
                    modaction.addevent(new_result['_raw'], 'nbtstat')
            else:
                modaction.message('Invalid characters detected in host input', status='failure', level=logging.WARN)

    if len(new_results)>0:
        if modaction.writeevents(index='main', source='nbtstat'):
            modaction.message('Successfully created splunk event', status='success', rids=rids)
        else:
            modaction.message('Failed to create splunk event', status='failure', rids=rids, level=logging.ERROR)

    splunk.Intersplunk.outputResults(new_results, outputfile=outputfile)

if __name__ == '__main__':
    logger = ModularAction.setup_logger('nbtstat_modworkflow')

    do_nbtstat(sys.argv, logger=logger)
