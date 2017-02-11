import csv
import gzip
import json
import logging
import re
import splunk.rest as rest
import sys
import time

from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.util import mktimegm

sys.path.append(make_splunkhome_path(['etc', 'apps', 'Splunk_TA_ueba', 'lib']))
from cim_actions import ModularAction

logger = ModularAction.setup_logger('send2uba_modalert')

ipv4_re = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?$')
# http://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses
ipv6_re = re.compile(r"""^(
                          ([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|
                          ([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|
                          ([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|
                          ([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|
                          ([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|
                          ([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|
                          [0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|
                          :((:[0-9a-fA-F]{1,4}){1,7}|:)|
                          [fF][eE]80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|
                          ::([fF]{4}(:0{1,4}){0,1}:){0,1}
                          ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                          (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|
                          ([0-9a-fA-F]{1,4}:){1,4}:
                          ((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}
                          (25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])
                          )$""", re.X)
mac_re  = re.compile('^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')


def validate_ubaroute(session_key):
    server_defined = False
    
    uri     = '/servicesNS/-/Splunk_TA_ueba/data/outputs/tcp/syslog/ubaroute'
    getargs = {'output_mode': 'json'}
    r, c    = rest.simpleRequest(uri, sessionKey=session_key, getargs=getargs)
    
    if r.status==200:
        c = json.loads(c)['entry'][0]['content']
        server_defined = c.get('server', False)
    
    return server_defined


def make_uba_alarm(modaction, result):
    new_result   = {}
    
    severity_map = {'informational': '1',
                    'low':           '3',
                    'medium':        '5',
                    'high':          '7',
                    'critical':      '9'}
    
    map_keys     = {'bytes_in':      'bytesReceived',
                    'bytes_out':     'bytesSent',
                    'src_port':      'sourcePort',
                    'src_user':      'sourceUser',
                    'dest_port':     'destinationPort',
                    'user':          'destinationUser',
                    'duration':      'sessionDuration',
                    'app':           'application',
                    'file_name':     'filename',
                    'file_path':     'filepath',
                    'file_size':     'filesize',
                    'process_name':  'process',
                    'process_id':    'processId' }
    
    asset_keys   = {'src':   'source',
                    'dest':  'destination',
                    'dvc':   'server' }
    
    ## handle mv by setting the non-mvkey to multival[0]
    mvkeys = [x for x in result if x.startswith('__mv_') and result[x].startswith('$') and result[x].endswith('$')]
    for mvkey in mvkeys:
        key         = mvkey[5:]
        result[key] = result[mvkey][1:-1].split('$;$')[0]
    
    ## timestamp
    new_result['timestamp']  = '%s' % mktimegm(time.gmtime())
    ## dataformat
    new_result['dataformat'] = modaction.configuration.get('dataformat', 'unknown')
    ## evcls
    new_result['evcls']      = modaction.search_name or result.get('search_name') or 'AdHoc UBA Alarm'
    ## evsubctg
    if result.get('signature'):
        new_result['evsubctg'] = result['signature']
    ## severity
    severity = result.get('severity') or modaction.configuration.get('severity') or '5'
    try:
        if severity in severity_map:
            severity = severity_map[severity]
        elif int(severity)<1 or int(severity)>10:
            severity = '5'
    except:
        severity = '5'
    new_result['severity'] = severity
    ## map_keys
    for key in map_keys:
        if key in result:
            new_result[map_keys[key]] = result[key]
    ## src/dest/dvc
    for asset_key in asset_keys:
        ip_determined = False
        ip_sources    = ['%s_ip' % asset_key, asset_key]
        for ip_key in ip_sources:
            possible_ip = result.get(ip_key)
            if possible_ip and (ipv4_re.match(possible_ip) or ipv6_re.match(possible_ip)):
                if not ip_determined:
                    new_result['%sIp' % asset_keys[asset_key]] = possible_ip
                    ip_determined = True

        dns_determined = False
        dns_sources    = ['%s_dns' % asset_key, '%s_nt_host' % asset_key, asset_key]
        for dns_key in dns_sources:
            possible_dns = result.get(dns_key)
            if possible_dns:
                ip_match  = (ipv4_re.match(possible_dns) or ipv6_re.match(possible_dns))
                mac_match = mac_re.match(possible_dns)
                if not ip_match and not mac_match:  
                    if not dns_determined:
                        new_result['%sDns' % asset_keys[asset_key]] = possible_dns
                        dns_determined = True

    return new_result


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
        sys.exit(1)

    try:
        modaction   = ModularAction(sys.stdin.read(), logger, 'send2uba')
        ## validate ubaroute
        if not validate_ubaroute(modaction.session_key):
            raise ValueError('server undefined for ubaroute')
        ## add status info
        modaction.addinfo()
        ## index
        index       = 'ubaroute'
                
        ## process results
        with gzip.open(modaction.results_file, 'rb') as fh:
            events = []
            for num, result in enumerate(csv.DictReader(fh)):
                ## set rid to row # (0->n) if unset
                result.setdefault('rid', str(num))
                modaction.update(result)
                modaction.invoke()
                modaction.addevent(
                    modaction.result2stash(
                        make_uba_alarm(modaction, result),
                        dropexp=None,
                        mapexp=None
                    ),
                    'stash',
                    cam_header=False
                )
        
        if modaction.writeevents(index=index, fext='uba_ubaroute'):
            modaction.message('Successfully created splunk event', status='success', rids=modaction.rids)
        else:
            modaction.message('Failed to create splunk event', status='failure', rids=modaction.rids, level=logging.ERROR)

    except Exception as e:
        ## adding additional logging since adhoc search invocations do not write to stderr
        try:
            modaction.message(e, status='failure', level=logging.CRITICAL)
        except:
            logger.critical(e)
        print >> sys.stderr, "ERROR Unexpected error: %s" % e
        sys.exit(3)
