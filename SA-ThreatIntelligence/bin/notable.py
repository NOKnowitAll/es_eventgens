import csv
import gzip
import json
import logging
import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "Splunk_SA_CIM", "lib"]))
from cim_actions import ModularAction

logger = ModularAction.setup_logger('notable_modalert')


class NotableModularAction(ModularAction):
    
    NOTABLE_MAPS = ['_time', '_raw', 'splunk_server', 'index',
                    'source', 'sourcetype', 'host', 'linecount',
                    'timestartpos', 'timeendpos', 'eventtype',
                    'tag', 'search_name', 'event_hash', 'event_id']
    
    def get_notable_mapexp(self):    
        mapfields = self.configuration.get('mapfields', '')
        ## If it's a pure adhoc case, turn off notable maps.
        if not mapfields:
            return None
        else:
            self.NOTABLE_MAPS.extend(mapfields.split(','))
            return lambda x: (x.startswith('tag::') or
                              x in self.NOTABLE_MAPS)


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
        sys.exit(1)

    try:
        modaction      = NotableModularAction(sys.stdin.read(), logger, 'notable')
        ## add status info
        modaction.addinfo()
        ## search_name
        search_name    = modaction.search_name or 'Manual Notable Event - Rule'
        ## index
        index          = modaction.configuration.get('index', 'notable')
        ## additional fields that need orig_ prepended
        ## For a pure adhoc case, set param.mapfields=''.
        notable_mapexp = modaction.get_notable_mapexp()
        
        ## process results
        with gzip.open(modaction.results_file, 'rb') as fh:
            events = []
            for num, result in enumerate(csv.DictReader(fh)):
                ## set rid to row # (0->n) if unset
                result.setdefault('rid', str(num))
                modaction.update(result)
                modaction.invoke()
                modaction.addevent(
                    modaction.result2stash(result, mapexp=notable_mapexp, addinfo=True),
                    'stash'
                )
        
        if modaction.writeevents(index=index, source=search_name):
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
