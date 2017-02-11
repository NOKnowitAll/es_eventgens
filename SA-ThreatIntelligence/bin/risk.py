import csv
import gzip
import json
import logging
import splunk.rest as rest
import sys
import urllib

from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
from cim_actions import ModularAction

logger = ModularAction.setup_logger('risk_modalert')


def normalize_risk_param(modaction, param, default='unknown'):
    ## configuration will have _param
    config_param = '_%s' % param
    ## try result first
    val = result.get(param)
    ## next try modular action param
    if not val:
        val = modaction.configuration.get(config_param)
        ## if risk_object val represents key in result
        if val and param=='risk_object':
            val = result.get(val)
    ## next try legacy param
    if not val:
        try:
            r, c = rest.simpleRequest('saved/searches/%s' % urllib.quote_plus(modaction.search_name),
                                      sessionKey=modaction.session_key,
                                      getargs={'output_mode': 'json'})
            c    = json.loads(c)['entry'][0]['content']
            val  = c.get('action.risk.%s' % config_param)
        except:
            modaction.message('Could not retrieve legacy risk param %s' % config_param, level=logging.WARN)
        ## if risk_object val represents key in result
        if val and param=='risk_object':
            val = result.get(val)
    ## try default
    if not val:
        val = default
    return val
    

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
        sys.exit(1)
    
    try:
        modaction   = ModularAction(sys.stdin.read(), logger, 'risk')
        logger.debug(modaction.settings)
        ## add status info
        modaction.addinfo()
        ## search_name
        search_name = modaction.search_name or 'AdHoc Risk Score'
        ## index
        index       = modaction.configuration.get('index', 'risk')
        
        ## process results
        with gzip.open(modaction.results_file, 'rb') as fh:
            events = []
            for num, result in enumerate(csv.DictReader(fh)):
                ## set rid to row # (0->n) if unset
                result.setdefault('rid', str(num))
                ## risk params
                result['risk_score']       = normalize_risk_param(modaction, 'risk_score', default='1')
                result['risk_object']      = normalize_risk_param(modaction, 'risk_object')
                result['risk_object_type'] = normalize_risk_param(modaction, 'risk_object_type', default='other')
                
                ## for adhoc risk modifiers from incident review, change search_name to event's search_name if available.
                if search_name == 'AdHoc Risk Score' and result.get('search_name'):
                    search_name = result.get('search_name')

                modaction.update(result)
                modaction.invoke()
                modaction.addevent(modaction.result2stash(result, addinfo=True), 'stash')
        
        if modaction.writeevents(index=index, source=search_name):
            modaction.message('Successfully created splunk event', status='success', rids=modaction.rids)
        else:
            modaction.message('Failed to create splunk event', status='failure', rids=modaction.rids, level=logging.ERROR)
        
    except Exception as e:
        ## adding additional logging since adhoc search invocations do not write to stderr
        try:
            modaction.message(e, status='failure', level=logging.CRITICAL)
        except Exception as e:
            logger.critical(e)
        print >> sys.stderr, "ERROR Unexpected error: %s" % e
        sys.exit(3)
