import logging
import sys
from urllib import urlencode

import splunk
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.models import CorrelationSearch
from splunk.models.saved_search import SavedSearch

MSG_OK = "No configuration errors found."

# confcheck_related_searches_not_enabled messages
MSG_RELATED_SEARCH_DISABLED  = 'The search "{0}" is related to the correlation search "{1}" but it is not enabled even though the correlation search is; this will cause the correlation to fail'
MSG_RELATED_SEARCH_NOT_FOUND = 'The search "{0}" is related to the correlation search "{1}" but it could not be found'

SAVEDSEARCH_CORRELATION_SEARCH_ERR = 'Audit - Correlations Missing Savedsearches'
SEARCHLINK_CORRELATION_SEARCH_ERR  = '[[app/search/search?' + urlencode({'s': SAVEDSEARCH_CORRELATION_SEARCH_ERR}) + '|here]]'
MSG_CORRELATION_SEARCH_ERR         = 'The correlation search "{0}" in app "{1}" has no corresponding saved searches stanza. Click {2} for details.'


def run(*args, **kwargs):
    """
    This function checks for related searches that are not enabled even though the correlation search is.
    """
    
    sessionKey = kwargs.get('sessionKey')
    correlation_searches = CorrelationSearch.all(sessionKey=sessionKey)
    
    # Determine if the search is enabled
    def isSearchEnabled(searchName, sessionKey):

        try:
            saved_search = SavedSearch.get(SavedSearch.build_id(searchName, None, None), sessionKey)
    
            return not saved_search.is_disabled
        except splunk.ResourceNotFound:
            return None  # Search was not found!
        
    def checkRelatedSearch(main_search, related_search, sessionKey, messages):
        
        if main_search is not None:
            enabled = isSearchEnabled(related_search, sessionKey)
                
            # The related search could not be found
            if enabled is None:
                messages.append((logging.ERROR, MSG_RELATED_SEARCH_NOT_FOUND.format(main_search, related_search)))
                
            # The related search is disabled
            elif not enabled:
                messages.append((logging.ERROR, MSG_RELATED_SEARCH_DISABLED.format(main_search, related_search)))
    
    messages = []
    
    # Check the related searches for each correlation search
    for correlation_search in correlation_searches:
    
        saved_search = None
        # Make sure the correlation search is enabled
        try:
            ## SOLNESS-9934: using owner='nobody' to mitigate false positives as a result of owner differences
            saved_search = SavedSearch.get(SavedSearch.build_id(correlation_search.name, correlation_search.namespace, 'nobody'), sessionKey)
        except splunk.ResourceNotFound:
            ## SOLNESS-7123: Adding exception for the manual notable event correlation search entry
            if correlation_search.name != "Manual Notable Event - Rule":
                # Possibly an orphaned correlationsearches.conf stanza. 
                messages.append((logging.ERROR, MSG_CORRELATION_SEARCH_ERR.format(correlation_search.name, correlation_search.namespace, SEARCHLINK_CORRELATION_SEARCH_ERR)))
    
        if saved_search and not saved_search.is_disabled:
            
            # If the search is enabled, check the related searches to make sure they are enabled too
            for i in ['', '_0', '_1', '_2', '_3', '_4']:
                if getattr(correlation_search, 'related_search_name' + i) is not None:
                    checkRelatedSearch(correlation_search.name, getattr(correlation_search, 'related_search_name' + i), sessionKey, messages)
                
    return messages
