import os
import re
import sys
import json
import hashlib
import logging
import json
import splunk.admin as admin
import splunk.entity as en
import splunk.util as util

from splunk      import AuthenticationFailed, ResourceNotFound
from splunk.rest import simpleRequest
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
from SolnCommon.searchutils import parse_search_string
from SolnCommon.log         import setup_logger, SHORT_FORMAT

# Ensure that shortcuts can be imported.
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-ThreatIntelligence", "bin"]))
from shortcuts import Duration
from shortcuts import Severity
from shortcuts import NotableOwner
# Import the custom search builder
from custom_search_builder.base import CustomSearchBuilderBase
from custom_search_builder.make_correlation_search import makeCorrelationSearch

logger = setup_logger('correlationsearches_base_class', level=logging.DEBUG, format=SHORT_FORMAT)

def error(key):
    '''
    Returns an error message for a given field.
    '''

    # Dictionary of error messages
    error_descriptions = {
        'alert.suppress.fields': "One or more fields must be selected to group by.",
        'alert.suppress.period': "Aggregation window duration must be a positive integer."}

    if key in error_descriptions:
        return 'Invalid value for %s: %s' % (key, error_descriptions[key])
    else:
        return 'Invalid value for %s' % key

class DependentSearchNotFound(Exception):
    pass

class CorrelationSearch:
    """
    Represents a correlation search
    """
    SAVED_SEARCHES_REST_URL         = '/saved/searches/'
    CORRELATION_SEARCHES_REST_URL   = '/alerts/correlationsearches/'
        
    SEGMENT_SEPARATOR               = " - "

    DEFAULT_OWNER            = 'nobody'
    DEFAULT_SECURITY_DOMAIN  = 'Threat'
    DEFAULT_NAMESPACE        = 'SA-ThreatIntelligence'
    VALID_NAMESPACES         = []  # cache for valid namespaces
    INVALID_NAMESPACES       = ['SA-CommonInformationModel', 'SA-Eventgen', 'SA-Utils']
    
    # Base list of fields in correlationsearches.conf.
    SPEC_FIELDS              = {'default_owner',
                                'default_status',
                                'description',
                                'drilldown_name',
                                'drilldown_search',
                                'drilldown_earliest_offset',
                                'drilldown_latest_offset',
                                'rule_description',
                                'rule_name',
                                'rule_title',
                                'search',
                                'security_domain',
                                'severity',
                                'next_steps',
                                'recommended_actions'
                                }
    
    # Alerting parameters for use in UI
    VALID_EMAIL_FORMATS = {'html': 'inline', 'csv': 'as CSV', 'pdf': 'as PDF'}
    # End alerting parameters
    
    def __init__(self, *args, **kwargs):
        self.cron_schedule             = kwargs.get('cron_schedule', None)
        self.realtime_schedule         = util.normalizeBoolean(kwargs.get('realtime_schedule', None))
        self.default_owner             = kwargs.get('default_owner', None)
        self.default_status            = kwargs.get('default_status', None)
        self.description               = kwargs.get('description', None)
        self.domain                    = kwargs.get('domain', CorrelationSearch.DEFAULT_SECURITY_DOMAIN)
        self.drilldown_name            = kwargs.get('drilldown_name', None)
        self.drilldown_search          = kwargs.get('drilldown_search', None)
        self.drilldown_earliest_offset = kwargs.get('drilldown_earliest_offset', None)
        self.drilldown_latest_offset   = kwargs.get('drilldown_latest_offset', None)
        self.end_time                  = kwargs.get('end_time', None)
        self.enabled                   = kwargs.get('enabled', True)
        self.name                      = kwargs.get('name', None)
        self.namespace                 = kwargs.get('namespace', CorrelationSearch.DEFAULT_NAMESPACE)
        self.owner                     = kwargs.get('owner', CorrelationSearch.DEFAULT_OWNER)
        self.rule_description          = kwargs.get('rule_description', None)
        self.rule_title                = kwargs.get('rule_title', None)
        self.search                    = kwargs.get('search', None)
        self.search_spec               = kwargs.get('search_spec', None)
        self.severity                  = Severity.from_readable_severity(kwargs.get('severity', "unknown"))
        self.sid                       = kwargs.get('sid', None)
        self.start_time                = kwargs.get('start_time', None)
        self.gs_service_id             = kwargs.get('gs_service_id', None)
        self.next_steps                = kwargs.get('next_steps', None)
        self.recommended_actions       = kwargs.get('recommended_actions', None)

        if self.sid is not None:
            # This may be an existing search. Namespace and owner get loaded in get_rest_info
            # instead of here, since we need to have the data for static methods as well.
            self.namespace = None
            self.owner     = None

        # Throttling parameters apply to ALL alert actions.
        # Note: aggregate_duration is a Splunk time specifier, so we force the conversion.
        self.aggregate_duration     = str(kwargs.get('aggregate_duration', ''))
        self.group_by               = kwargs.get('group_by', None)

        # Summary index alert action parameters.
        # Default action is to create notable event.
        self.notable_action_enabled = util.normalizeBoolean(kwargs.get('action.notable', True))

        # modular alert settings
        self.alert_actions = { k:v for (k,v) in kwargs.iteritems() if k.startswith('action.') }

    @staticmethod
    def is_search_enabled(settings):
        """
        Determine if the given search is enabled
        """
        
        # Get the disabled flag
        if 'disabled' in settings:
            return not util.normalizeBoolean(settings['disabled'], False)
        
        else:
            return False
            
    @staticmethod
    def enable(search_name, session_key=None):
        """
        Enable the given search.
        """
        
        return CorrelationSearch.set_status(search_name, True, session_key)
    
    @staticmethod
    def disable(search_name, session_key=None):
        """
        Disable the given search.
        """
        
        return CorrelationSearch.set_status(search_name, False, session_key)
    
    @staticmethod
    def enable_related_searches(corr_search_entity, namespace, owner, session_key=None, ignore_missing_searches = False):
        """
        Enables the related searches for the given correlation search entity.
        """
        
        # Make a list of valid related search identifiers
        related_searches_identifiers = ['related_search_name']
        
        for num in range(0,5):
            related_searches_identifiers.append('related_search_name.' + str(num))
            
        # Keep track of how many searches were enabled
        searches_enabled = 0
        
        # Enable the related searches
        for cs_id in related_searches_identifiers:
            
            # See if the related search is available
            if corr_search_entity.get(cs_id, None) is not None:
                
                # Get the search name to enable
                related_search_name = corr_search_entity[cs_id]
                logger.info("Enabling related search=%s, correlation_search=%s", related_search_name, corr_search_entity.name)
                
                # Note that we assume that the dependent search should be in the same app
                try:
                    dependent_search_entity = en.getEntity(CorrelationSearch.SAVED_SEARCHES_REST_URL, related_search_name, sessionKey=session_key)
                    
                except ResourceNotFound:
                    logger.warn("Could not enable related search because it could not be found, related_search=%s, correlation_search=%s", related_search_name, corr_search_entity.name)
                    dependent_search_entity = None
                    
                    if not ignore_missing_searches:
                        raise DependentSearchNotFound("The related search with the given name '%s' could not be found" % (related_search_name))
                
                # Enable the search if we found it
                if dependent_search_entity is not None:
                    
                    # Enable the search
                    dependent_search_entity['disabled'] = False
                    dependent_search_entity.namespace = dependent_search_entity['eai:acl']['app']
                    dependent_search_entity.owner = dependent_search_entity['eai:acl']['owner']
                    
                    en.setEntity(dependent_search_entity, sessionKey=session_key)
                    
                    logger.info("Enabled related search=%s, correlation_search=%s", related_search_name, corr_search_entity.name)
                    searches_enabled = searches_enabled + 1
            else:
                logger.debug("Related search ID does not exist, id=%s, correlation_search=%s", cs_id, corr_search_entity.name)
        
        # Return the number of searches enabled
        return searches_enabled
    
    @staticmethod
    def set_status(search_name, enable, session_key=None):
        """
        Enables/disable the given search. returns true if the search was correctly disabled.
        """
        
        # Create the basic search
        search = CorrelationSearch(sid=search_name)
        
        # Get session key and other information necessary to access the REST endpoint
        session_key, namespace, owner = search.get_rest_info(session_key, None)

        # Get the appropriate entity
        entity = en.getEntity(CorrelationSearch.SAVED_SEARCHES_REST_URL, search_name, namespace=namespace, owner=owner, sessionKey=session_key)
        corr_search_entity = en.getEntity(CorrelationSearch.CORRELATION_SEARCHES_REST_URL, search_name, namespace=namespace, owner=owner, sessionKey=session_key)
        
        # Disable/enable the search
        entity['disabled'] = not enable
        en.setEntity(entity, sessionKey=session_key)
        
        # Enable the related searches (if exists)
        if enable and corr_search_entity is not None:
            CorrelationSearch.enable_related_searches(corr_search_entity, namespace=namespace, owner=owner, session_key=session_key, ignore_missing_searches=False)
        
        return True

    @staticmethod
    def getGroupByAsList(fields):
        """
        Set the list to group by. If a string is provided, then it will be converted to a list.
        """
        
        if fields is not None:

            if isinstance(fields, list) and len(fields) > 0:
                return fields
            elif isinstance(fields, basestring) and len(fields) > 0:
                return [str.strip(i) for i in str(fields).split(",")]
            
        return []
    
    def is_realtime(self):
        """
        Determines if the given correlation search is real-time.
        """
        return CustomSearchBuilderBase.isSearchRT({'earliest': self.start_time or '', 'latest': self.end_time or ''})

    @staticmethod
    def __refresh_savedsearches__(session_key=None):
        en.refreshEntities('properties/savedsearches', sessionKey=session_key)

    @staticmethod
    def __get_session_key__(session_key=None, thrown_exception=True):
        
        # Try to get the session key if not provided
        if session_key is None:
            import splunk
            session_key, unused_sessionSource = splunk.getSessionKey(return_source=True)
        
        # Do not continue if we could not get a session key and the caller wants us to thrown an exception
        if session_key is None and thrown_exception:
            raise AuthenticationFailed("Could not obtain a session key")
        
        # Return the session key
        return session_key

    @staticmethod
    def load(sid, session_key=None, namespace=None, owner=None):
        """
        Load the search with the given name.
        """
        
        # Create the basic search
        search = CorrelationSearch(sid=sid)
        
        # Get the session key and other information necessary to access the REST endpoint
        session_key, namespace, owner = search.get_rest_info(session_key, namespace)

        # Load the information from savedsearches.conf
        search.load_savedsearches_conf(session_key, namespace, owner)
        
        # Load the information from correlationsearches.conf
        search.load_correlationsearches_conf(session_key, namespace, owner)
        
        # Return the resulting search
        return search

    @staticmethod
    def validate_duration_and_group_by(duration, group_by):
        
        # Make sure that:
        #   1) If duration is provided, then at least one group-by field is defined
        if (duration is not None and duration > 0) and group_by is not None and len(group_by) == 0:
            raise ValueError(error('alert.suppress.fields'))
        
        #   2) If a group-by was provided then the duration is not zero
        elif (duration <= 0 or duration is None) and group_by is not None and len(group_by) > 0:
            raise ValueError(error('alert.suppress.fields'))

    def load_savedsearches_conf(self, session_key=None, namespace=None, owner=None):
        """
        Configures the given saved search with the parameters loaded from the related savedsearches.conf
        """
        
        # Refresh savedsearches.conf
        CorrelationSearch.__refresh_savedsearches__(session_key)

        # Get the saved search info
        saved_search            = en.getEntity(CorrelationSearch.SAVED_SEARCHES_REST_URL, self.sid, namespace=namespace, owner=owner, sessionKey=session_key)
        
        self.enabled            = CorrelationSearch.is_search_enabled(saved_search)
        self.start_time         = saved_search.get('dispatch.earliest_time')
        self.end_time           = saved_search.get('dispatch.latest_time')
        self.search             = saved_search.get('search')
        self.cron_schedule      = saved_search.get('cron_schedule')
        self.realtime_schedule  = util.normalizeBoolean(saved_search.get('realtime_schedule', None))

        # Load summary index alert action parameters.
        self.notable_action_enabled = util.normalizeBoolean(saved_search.get('action.notable', None))

        # Load alerts
        self.alert_actions = { k: v  for (k, v) in saved_search.iteritems() if k.startswith('action.') }
        
        # Load app and owner context
        self.namespace           = saved_search.get('eai:acl').get('app')
        self.owner               = saved_search.get('eai:acl').get('owner')
        
        # Load aggregation parameters
        self.group_by            = CorrelationSearch.getGroupByAsList(saved_search.get('alert.suppress.fields', None))
        
        # Set the aggregation to an empty string by default which indicates that no throttling is to be done
        self.aggregate_duration = Duration.duration_from_readable(saved_search.get('alert.suppress.period', ''))

    def load_correlationsearches_conf(self, session_key=None, namespace=None, owner=None):
        """
        Configures the given correlation search with the parameters loaded from the related correlationsearches.conf
        """
        
        # Get the saved search info
        try:
            corr_search = en.getEntity(CorrelationSearch.CORRELATION_SEARCHES_REST_URL, self.sid, namespace=namespace, owner=owner, sessionKey=session_key)
            
            self.description      = corr_search['description']
            self.severity         = corr_search['severity']
            self.default_status   = corr_search['default_status']
            self.default_owner    = corr_search['default_owner']
            self.domain           = corr_search['security_domain']
            self.drilldown_search = corr_search['drilldown_search']
            self.drilldown_name   = corr_search['drilldown_name']
            self.drilldown_earliest_offset = corr_search['drilldown_earliest_offset']
            self.drilldown_latest_offset   = corr_search['drilldown_latest_offset']
            self.name             = corr_search['rule_name']
            self.rule_title       = corr_search['rule_title']
            self.rule_description = corr_search['rule_description']
            self.search_spec      = corr_search['search']
            self.next_steps       = corr_search['next_steps']
            
        except ResourceNotFound:
            pass

    def validate_namespace(self, session_key, namespace=None):
        '''
        Return the namespace of the current search, or the default.
        Raises an exception if an invalid namespace is specified.
        '''

        if not self.VALID_NAMESPACES:
            # Cache value to cut down on REST calls.
            if self.gs_service_id is not None:
                self.VALID_NAMESPACES = CorrelationSearch.get_valid_namespaces(session_key, False)
            else:
                self.VALID_NAMESPACES = CorrelationSearch.get_valid_namespaces(session_key)

        if namespace is None or namespace == '' or len(namespace) == 0:
            namespace = CorrelationSearch.DEFAULT_NAMESPACE
        elif namespace in self.VALID_NAMESPACES:
            pass
        else:
            raise Exception('Unable to load or save search: Invalid application specified (%s).' % (namespace))

        return namespace

    def get_rest_info(self, session_key=None, namespace=None):
        """
        Returns a session key, namespace and owner (in that order). The namespace and owner will be
        populated with default values if they do not have a value already.
        """

        # Try to get the session key if not provided
        session_key = CorrelationSearch.__get_session_key__(session_key)
        
        # If this is an existing search, get the namespace
        if self.sid:
            try:
                saved_search      = en.getEntity(CorrelationSearch.SAVED_SEARCHES_REST_URL, self.sid, sessionKey=session_key)
                namespace         = saved_search.get('eai:acl').get('app')
            except Exception:
                pass

        # Validate the namespace
        namespace = self.validate_namespace(session_key, namespace)
        self.namespace = namespace

        # Force user to "nobody" to permit role-based editing.
        owner = 'nobody' 
        self.owner = owner
        
        return session_key, namespace, owner
    
    def setup_id(self):
        """
        Prepare the id if it is not yet been created
        """
        
        # Setup the rule id if it is not defined yet
        if self.sid is None and (self.domain is not None or self.gs_service_id is not None) and self.name is not None:
            if self.domain is not None:
                self.sid = self.domain + CorrelationSearch.SEGMENT_SEPARATOR + self.name + CorrelationSearch.SEGMENT_SEPARATOR + "Rule"
            else:
                self.sid = self.name + CorrelationSearch.SEGMENT_SEPARATOR + "Rule"
        elif self.sid is None and ((self.domain is not None or self.gs_service_id is not None) or self.name is not None):
            raise Exception("The id of the correlation search is none and cannot be constructed since both domain and name must be defined (%s, %s) respectively" % (self.domain, self.name))

    def save(self, session_key=None):
        """
        Save the correlation search.
        """
        
        # Setup the id if it is not defined yet
        self.setup_id()

        # Get the session key and other information necessary to access the REST endpoint
        session_key, namespace, owner = self.get_rest_info(session_key, self.namespace)

        # Perform the save against the correlation searches endpoint.
        if self.save_correlationsearches_conf(session_key, namespace, owner):
            # Perform the save against the savedsearches endpoint
            # Note: The saved searches entry needs to be saved last since this 
            # will cause Splunk to kick off the search.
            self.save_savedsearches_conf(session_key, namespace, owner)

    @staticmethod
    def none_to_default(value, default=""):
        if value is None:
            return default
        else:
            return value

    @staticmethod
    def blank_to_none(value):
        if value is None:
            return None
        elif len(str(value).strip()) == 0:
            return None

    @staticmethod
    def get_valid_namespaces(session_key, limit_scope=True):
        '''
        Return a list of the valid namespaces for this Splunk instance.
        if limit_scope is set to True:
        Valid namespaces for correlation searches must begin with (DA|SA).
        Otherwise
            return all available scope list
        Static so this can be called in Mako template to populate a dropdown list.
        '''

        apps = en.getEntities('/apps/local/', sessionKey=session_key, count=-1)
        excludes = CorrelationSearch.INVALID_NAMESPACES
        if limit_scope:
            return [i for i in apps if i not in excludes]
        else:
            return apps

    def save_correlationsearches_conf(self, session_key=None, namespace=None, owner=None):
        """
        Save the correlationsearches.conf
        """
        
        # Setup the id if it is not defined yet
        self.setup_id()

        # Is is_new is not defined, then see if it exists already
        corr_search = None
        is_new = False

        try:
            corr_search = en.getEntity(CorrelationSearch.CORRELATION_SEARCHES_REST_URL, self.sid, namespace=namespace, owner=owner, sessionKey=session_key)
        except ResourceNotFound:
            is_new = True
        
        # If new, then create a new entry
        if is_new:
            corr_search = en.getEntity(CorrelationSearch.CORRELATION_SEARCHES_REST_URL, "_new", namespace=namespace, owner=owner, sessionKey=session_key)
            corr_search.owner = CorrelationSearch.DEFAULT_OWNER  # Make sure to force the owner to nobody, otherwise, Splunk will make the entry private
            corr_search['name'] = self.sid
            
        # If existing, then edit the current entry
        else:
            corr_search = en.getEntity(CorrelationSearch.CORRELATION_SEARCHES_REST_URL, self.sid, namespace=namespace, owner=owner, sessionKey=session_key)
        
        # rule name is always included (this forces creation of a correlationsearches.conf stanza for all custom searches).
        corr_search['description']      = CorrelationSearch.none_to_default(self.description)
        corr_search['rule_name']        = CorrelationSearch.none_to_default(self.name)
        corr_search['search']           = CorrelationSearch.none_to_default(self.search_spec)
        if self.notable_action_enabled:
            # Update the correlation search with the relevant fields - notable event search
            corr_search['default_owner']    = CorrelationSearch.none_to_default(self.default_owner)
            corr_search['default_status']   = CorrelationSearch.none_to_default(self.default_status)
            corr_search['drilldown_name']   = CorrelationSearch.none_to_default(self.drilldown_name)
            corr_search['drilldown_search'] = CorrelationSearch.none_to_default(self.drilldown_search)
            corr_search['drilldown_earliest_offset'] = CorrelationSearch.none_to_default(self.drilldown_earliest_offset)
            corr_search['drilldown_latest_offset'] = CorrelationSearch.none_to_default(self.drilldown_latest_offset)
            corr_search['security_domain']  = CorrelationSearch.none_to_default(self.domain).lower()
            corr_search['severity']         = Severity.from_readable_severity(self.severity)
            corr_search['rule_description'] = CorrelationSearch.none_to_default(self.rule_description)
            corr_search['rule_title']       = CorrelationSearch.none_to_default(self.rule_title)
            corr_search['next_steps']       = CorrelationSearch.none_to_default(self.next_steps)
            corr_search['recommended_actions'] = CorrelationSearch.none_to_default(self.recommended_actions)
        else:
            # Update the correlation search with the relevant fields - risk search
            for field in CorrelationSearch.SPEC_FIELDS - {'description', 'rule_name', 'search'}:
                del corr_search.properties[field]
        # Set the entity
        return en.setEntity(corr_search, sessionKey=session_key)

    def remove_rt_from_time(self, search_time):
        
        strip_rt_regex = re.compile("(rt)?(.*)")
        
        m = strip_rt_regex.search(search_time)
        
        if m is not None:
            return m.groups()[1]
        else:
            return search_time

    @staticmethod
    def change_to_realtime(search_name, session_key=None):
        """
        Change the given search to real-time.
        """
        
        # Create the basic search
        search = CorrelationSearch.load(sid=search_name, session_key=session_key)
        
        search.make_realtime()
        search.save()
        
    @staticmethod
    def change_to_non_realtime(search_name, session_key=None):
        """
        Change the given search to scheduled.
        """
        
        # Create the basic search
        search = CorrelationSearch.load(sid=search_name, session_key=session_key)
        
        search.make_non_realtime()
        search.save()

    def isUsingSearchSpec(self):
        if self.search_spec is not None and 'searches' in self.search_spec:
            return True
        else:
            return False

    def update_search_from_spec(self, session_key=None):
        
        # Determine if a search_spec is being used
        if not self.isUsingSearchSpec():
            return
        
        # Parse the search spec
        search_spec_parsed = json.loads(self.search_spec)

        # Update the times accordingly
        if 'inputlookup' in search_spec_parsed['searches'][0]:
            # Inputlookup search.
            # Retain earliest/latest in spec if present
            # Reset dispatch.earliest_time and dispatch.latest_time.
            self.start_time = ''
            self.end_time = '+0s'
        elif len(search_spec_parsed['searches']) > 1:
            # Multimode datamodel search.
            # Retain earliest/latest in spec if present.
            # Reset dispatch.earliest_time and dispatch.latest_time.
            self.start_time = ''
            self.end_time = '+0s'
        elif len(search_spec_parsed['searches']) == 1:
            # Single-mode data model search.
            # dispatch.earliest_time and dispatch.latest_time are used.
            # earliest/latest set to value of the above.
            search_spec_parsed['searches'][0]['earliest'] = self.start_time
            search_spec_parsed['searches'][0]['latest'] = self.end_time
        
        # Update the alert suppress fields
        if self.aggregate_duration is not None and len(str(self.aggregate_duration)) > 0:
            search_spec_parsed['alert.suppress'] = 1
            search_spec_parsed['alert.suppress.fields'] = self.group_by
        else:
            search_spec_parsed['alert.suppress'] = 0
            search_spec_parsed['alert.suppress.fields'] = []
        
        # Update the raw_search
        self.search, unused_parses = makeCorrelationSearch(search_spec_parsed, sessionKey=session_key, logger=logger)
        logger.info("search_spec converted, search= " + self.search)

    def make_non_realtime(self):
        """
        Changes the correlation search from a real-time search to a scheduled one.
        """
        
        self.start_time = self.remove_rt_from_time(self.start_time)
        self.end_time = self.remove_rt_from_time(self.end_time)
        
    def make_realtime(self):
        """
        Changes the correlation search from a scheduled search to a real-time one.
        """
        if not self.is_realtime():
            if self.start_time is not None and not self.start_time.startswith("rt"):
                self.start_time = "rt" + self.start_time
                
            # If blank, add a start time because Splunk requires one for rt
            elif self.start_time is None:
                self.start_time = "rt"
                
            if self.end_time is not None and not self.end_time.startswith("rt"):
                self.end_time = "rt" + self.end_time
                
            # If blank, add a end time because Splunk requires one for rt
            elif self.end_time is None:
                self.end_time = "rt"

    def save_savedsearches_conf(self, session_key=None, namespace=None, owner=None):
        """
        Save the savedsearches.conf
        """
        
        # Setup the id if it is not defined yet
        self.setup_id()
        saved_search = None
        
        try:
            # If existing, then edit the current entry
            saved_search = en.getEntity(CorrelationSearch.SAVED_SEARCHES_REST_URL, self.sid, namespace=namespace, owner=owner, sessionKey=session_key)
        except ResourceNotFound:
            # Create a new entry
            saved_search = en.getEntity(CorrelationSearch.SAVED_SEARCHES_REST_URL, "_new", namespace=namespace, owner=owner, sessionKey=session_key)
            saved_search.owner = CorrelationSearch.DEFAULT_OWNER  # Make sure to force the owner to nobody, otherwise, Splunk will make the entry private
            saved_search['name'] = self.sid

        # If a duration is provided but not a group-by, then assume we are to group-by 'const_dedup_id'
        if self.aggregate_duration is not None and len(str(self.aggregate_duration)) > 0 and len(CorrelationSearch.getGroupByAsList(self.group_by)) == 0:
            self.group_by = ['const_dedup_id']
            
        # Now re-make the search string if a search spec is being used
        self.update_search_from_spec(session_key)
        
        # Make sure that the duration and group-by fields are set right
        CorrelationSearch.validate_duration_and_group_by(Duration.duration_from_readable(self.aggregate_duration), CorrelationSearch.getGroupByAsList(self.group_by))

        # Update the saved search with the relevant fields
        saved_search['dispatch.earliest_time'] = self.start_time
        saved_search['dispatch.latest_time'] = self.end_time
        saved_search['search'] = self.search
        saved_search['cron_schedule'] = self.cron_schedule
        saved_search['realtime_schedule'] = 1 if self.realtime_schedule else 0
        saved_search['is_scheduled'] = 1

        # General alerting parameters.
        saved_search['alert.digest_mode'] = 1
        saved_search['alert.track'] = 0
        
        # Enable the alert suppression if we are using it; otherwise, clear our the related fields
        if self.group_by is None or len(self.group_by) == 0 or self.aggregate_duration == 0 or self.aggregate_duration is None:
            saved_search['alert.suppress'] = 0
            saved_search['alert.suppress.fields'] = ""
            saved_search['alert.suppress.period'] = ""
        else:
            saved_search['alert.suppress'] = 1
            # Convert the group by fields list to a string
            saved_search['alert.suppress.fields'] = ",".join(CorrelationSearch.getGroupByAsList(self.group_by))
            saved_search['alert.suppress.period'] = str(Duration.duration_from_readable(self.aggregate_duration)) + "s"

        # Default alert action set.
        actions = []

        # Notable event alert action parameters
        if self.notable_action_enabled:
            actions.append('notable')
        else:
            # Set no options. Since the action will be disabled in the local conf,
            # other default params may linger if set in default, but should be innocuous.
            pass

        # add actions that are enabled and set configurations for modular alerts
        # name must match '^action\.[^.]$'
        for k, v in self.alert_actions.iteritems():
            terms = k.split('.')
            if terms[0] == 'action':
                if len(terms) == 2 and util.normalizeBoolean(v) == True:
                    actions.append(terms[1])
                elif len(terms) > 2:
                    saved_search[k] = v

        saved_search['actions'] = ','.join(actions)
        if actions:
            saved_search['counttype'] = 'number of events'
            saved_search['quantity'] = 0
            saved_search['relation'] = 'greater than'
        else:
            saved_search['counttype'] = ''
            saved_search['quantity'] = 0
            saved_search['relation'] = ''

        # Set real-time backfill
        saved_search['dispatch.rt_backfill'] = 1

        # Set the entity
        return en.setEntity(saved_search, sessionKey=session_key)

    # get capabilities method    
    @staticmethod
    def getCapabilities4User(user=None, session_key=None):
        roles = []
        capabilities = []
        
        # Get user info              
        if user is not None:
            userDict = en.getEntities('authentication/users/%s' % (user), count=-1, sessionKey=session_key)
        
            for stanza, settings in userDict.items():
                if stanza == user:
                    for key, val in settings.items():
                        if key == 'roles':
                            roles = val
             
        # Get capabilities
        for role in roles:
            roleDict = en.getEntities('authorization/roles/%s' % (role), count=-1, sessionKey=session_key)
            
            for stanza, settings in roleDict.items():
                if stanza == role:
                    for key, val in settings.items():
                        if key == 'capabilities' or key == 'imported_capabilities':
                            capabilities.extend(val)
            
        return capabilities
