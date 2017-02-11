import logging
import sys
import time

import splunk.search

MSG_FMT_INPUT_MSG       = 'msg="A threat intelligence download has failed" stanza="{0}" status="{1}"'

def run(*args, **kwargs):
    """This function searches for failed threat downloads."""
    
    session_key = kwargs.get('sessionKey')
    interval = kwargs.get('interval')
    data = kwargs.get('data')
    
    srch_timeout = 60
    elapsed = 0
    wait_time = 5
    
    # Retrieve last run time.
    if data:
        earliest = int(data.get('last_run')) - 10
    else:
        # Assume 3h interval.
        earliest = '-3h@m'
            
    srch = '''search index=_internal sourcetype=threatintel:download file="threatlist.py:download_*" NOT (status="*starting" OR status="retrying download" OR status="threat list downloaded" OR status="Retrieved document from TAXII feed" OR status="Retrieved documents from TAXII feed") | stats latest(status) as status by stanza'''

    messages = []

    job = splunk.search.dispatch(srch, sessionKey=session_key, earliestTime=earliest)
    while elapsed < srch_timeout:
        if job.isDone:
            if job.resultCount > 0 or job.eventCount > 0:
                for result in job.results:
                    messages.append((logging.ERROR, MSG_FMT_INPUT_MSG.format(
                        result['stanza'], 
                        result['status'])))
            break
        else:
            elapsed += wait_time
            time.sleep(wait_time)

    return messages