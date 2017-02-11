import csv
import httplib
import itertools
import json
import logging
import operator
import re
import sys
import time
import traceback
import urllib

if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)

import splunk.entity as entity
import splunk
import splunk.persistconn.application
import splunk.persistconn.packet
import splunk.rest
import splunk.search
import splunk.util
from splunk.clilib.bundle_paths import make_splunkhome_path
# Persistent connection REST handlers don't add the "bin" directory of the current app to the path.
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-ThreatIntelligence', 'bin']))
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
from shortcuts import NotableOwner
from SolnCommon.kvstore import KvStoreHandler
from SolnCommon.limits import get_limits
from SolnCommon.log import setup_logger
logger = setup_logger('notable_event_update_rest_handler', level=logging.INFO)

csv.field_size_limit(10485760)


class SearchNotFoundException(Exception):
    pass


class NotEventSearchException(Exception):
    pass


class NoRuleIDException(Exception):
    pass


class SearchNotDoneException(Exception):
    pass


def time_function_call(fn):
    """
    Decorator that logs function execution time.

    :param fn : The function being measured.
    """
    def wrapper(*args, **kwargs):
        t1 = time.time()
        r = fn(*args, **kwargs)
        diff = time.time() - t1
        logger.debug("%s, duration=%6fs", fn.__name__, diff)
        return r
    return wrapper


class LogReviewStatus(object):

    def __init__(self, ts, rule_id, owner, urgency, status, comment, user, rule_name, key=None):
        self.time = ts
        self.rule_id = rule_id
        self.owner = owner
        self.urgency = urgency
        self.status = status
        self.comment = comment
        self.user = user
        self.rule_name = rule_name
        # Key of none usually shouldn't be saved as this will result in auto-generation
        # of keys in the KV store. However this is allowed for the construction
        # of temporary objects, usually representing existing statuses.
        self._key = key

    def update_from_existing(self, existing_status=None):
        """Update the current LogReviewStatus object using the status of another object."""
        if isinstance(existing_status, self.__class__):
            self.status = self.status or existing_status.status
            self.owner = self.owner or existing_status.owner
            self.urgency = self.urgency or existing_status.urgency


class LogReviewStatusChanges(object):
    """Class representing the state of changes to Notable Events requested during a REST call."""

    def __init__(self):
        self.success_count = 0
        self.messages = {}

    def incrementFailureCountEx(self, messages_list, count=1):
        for m in messages_list:
            self.incrementFailureCount(m, count)

    def getSuccessCount(self):
        return self.success_count

    def incrementSuccessCount(self, count=1):
        self.success_count += count

    def getFailureCount(self):
        return sum(self.messages.values())

    def incrementFailureCount(self, message, count=1):
        if message in self.messages:
            self.messages[message] += count
        else:
            self.messages[message] = count

    def getMessagesAsString(self, separator="; ", addSuccessInfo=True, errorMessageStart="Unable to change %d events: "):

        msg = None

        # Add the information about the items successfully changed
        if addSuccessInfo:
            if self.success_count > 0:
                msg = "%d events were successfully changed" % self.success_count

        # Add the error message start message
        if errorMessageStart is not None and self.getFailureCount() > 0:
            if msg is None:
                msg = errorMessageStart % (self.getFailureCount())
            else:
                msg = msg + separator + errorMessageStart % (self.getFailureCount())

        # Add the error messages
        errors_msg = None

        for m in self.messages:

            if self.messages[m] == 1:
                m += " (%d event)" % self.messages[m]
            else:
                m += " (%d events)" % self.messages[m]

            if errors_msg is None:
                errors_msg = m
            else:
                errors_msg = errors_msg + separator + m

        # Construct the final message
        if msg is not None and errors_msg is not None:
            return msg + errors_msg
        elif msg is not None:
            return msg
        else:
            return errors_msg


class NotableEventUpdate(splunk.persistconn.application.PersistentServerConnectionApplication):
    """REST handler providing services for modifying the status of notable events."""

    # Below are the column numbers in the incident review csv file
    CSV_INCIDENT_REVIEW_TIME = 0
    CSV_INCIDENT_REVIEW_RULE_ID = 1
    CSV_INCIDENT_REVIEW_OWNER = 2
    CSV_INCIDENT_REVIEW_URGENCY = 3
    CSV_INCIDENT_REVIEW_STATUS = 4
    CSV_INCIDENT_REVIEW_COMMENT = 5
    CSV_INCIDENT_REVIEW_USER = 6

    # The following defines the default status if one is not defined at all
    DEFAULT_NOTABLE_EVENT_STATUS = '0'  # zero corresponds to "Unassigned"
    DEFAULT_STATUS = None

    # The variables below are used when connecting to the REST endpoint
    DEFAULT_NAMESPACE = 'SA-ThreatIntelligence'
    DEFAULT_OWNER = 'nobody'
    LOG_REVIEW_REST_URL = '/alerts/log_review/'
    REVIEW_STATUSES_REST_URL = '/alerts/reviewstatuses/'

    # Options for updating KV store.
    BATCH_SAVE_LIMIT = 0  # Will be obtained from limits.conf upon POST or call to makeChanges. May be overridden.
    DEFAULT_COLLECTION = 'incident_review'
    DEFAULT_OPTIONS = {'app': DEFAULT_NAMESPACE, 'collection': DEFAULT_COLLECTION, 'owner': DEFAULT_OWNER}

    # Default parameters
    DEFAULT_URGENCIES = ['informational', 'low', 'medium', 'high', 'critical']

    # Options for audit record field order (must match definition of transform "kv_for_incident_review").
    DEFAULT_AUDIT_FIELD_ORDER = ['time', 'rule_id', 'rule_name', 'status', 'owner', 'urgency', 'comment', 'user']

    # Rule ID validity
    VALID_RULEID_RX = re.compile(r'^[A-Za-z0-9-]+@@[A-Za-z0-9_.-]+@@[A-Za-z0-9]+$')

    def __init__(self, command_line, command_arg):
        # KV store handler.
        self.kv = KvStoreHandler()
        # The following variables store cached data that can be used to reduce the frequency of REST calls
        self.correlation_searches = None
        self.correlation_search_info = None
        self.status_label_map = None

        super(NotableEventUpdate, self).__init__()

    @staticmethod
    def error(msg, status):
        """
        Return error.

        :param msg: A message describing the problem (a string)
        :type msg: str
        :param status: An integer to be returned as the HTTP status code.
        :type status: int
        """
        logger.error(msg)

        # Payload format is consistent with the previous, non-persistent handler (message content may have changed).
        payload = {
            "success": False,
            "message": msg
        }
        return {'status': status, 'payload': payload}

    def handle(self, args):
        """Main function for REST call.

        :param args: A JSON string representing a dictionary of arguments to the REST call.
        :type args: str

        :return A valid REST response.
        :rtype dict

        - Routing of GET, POST, etc. happens here.
        - All exceptions should be caught here.
        """

        logger.debug('ARGS: %s', args)
        args = json.loads(args)

        try:
            logger.info('Handling %s request.' % args['method'])
            method = 'handle_' + args['method'].lower()
            if callable(getattr(self, method, None)):
                return operator.methodcaller(method, args)(self)
            else:
                return self.error('Invalid method for this endpoint', httplib.METHOD_NOT_ALLOWED)
        except ValueError as e:
            msg = 'ValueError: %s' % e.message
            return self.error(msg, httplib.BAD_REQUEST)
        except splunk.RESTException as e:
            return self.error('RESTexception: %s' % e, httplib.INTERNAL_SERVER_ERROR)
        except Exception as e:
            msg = 'Unknown exception: %s' % e
            logger.exception(msg)
            return self.error(msg, httplib.INTERNAL_SERVER_ERROR)

    def handle_post(self, args):
        """Main function for REST call.

        :param args: A dictionary of arguments to the REST call.
        :type args: dict

        :return A dictionary representing a REST response.
        :rtype dict
        """

        session_key = args['session']['authtoken']
        current_user = args['session']['user']
        post_args = args.get('form', [])

        # Validate parameters (may raise ValueError).
        status, comment, urgency, searchID, newOwner, ruleUIDs = self.validate_parameters(post_args, session_key)

        if not self.BATCH_SAVE_LIMIT:
            self.get_batch_save_limit(session_key)

        self.DEFAULT_STATUS = self.getDefaultStatus(session_key)

        # Make the call
        response_data = self.makeChanges(status, comment, session_key, newOwner, urgency, ruleUIDs, searchID, current_user)

        return {
            'status': httplib.OK,
            'payload': response_data
            }

    @staticmethod
    def is_valid_ruleid(candidate):
        """Validate a rule_id.

        :param value: A candidate rule_id value.
        :type candidate: str

        :return Success status.
        :rtype: bool
        """

        if NotableEventUpdate.VALID_RULEID_RX.match(candidate):
            return True
        return False

    @staticmethod
    def validate_parameters(args, session_key):
        """Validate URI arguments.

        :param args: A dictionary of arguments to the REST call.
        :type args: dict
        :param session_key: A Splunk session key.
        :type session_key: str

        :return A tuple of arguments.
        :rtype tuple

        """

        tmp_args = dict(args)

        status = tmp_args.get('status') or None
        comment = tmp_args.get('comment', '')
        urgency = tmp_args.get('urgency') or None
        searchID = tmp_args.get('searchID')
        newOwner = tmp_args.get('newOwner') or None

        # Populate the ruleUIDs, if provided
        rule_uids = []
            
        # Because ruleUIDs is passed with the name "ruleUIDs[]" from the legacy code as well as ruleUIDs, iterate to retrieve all values.
        for k, v in args:
            if k == 'ruleUIDs[]' or k == 'ruleUIDs':
                if NotableEventUpdate.is_valid_ruleid(v):
                    rule_uids.append(v)
                else:
                    raise ValueError("Invalid rule_id value.")

        if len(rule_uids) == 0:
            # If no valid ruleUID was provided, assume that the user wants to edit all of the events in the search.
            # Set ruleUIDs to None to signal that no filtering of events to edit should be done.
            # Note that if ANY rule_uids were provided, they must have been valid. Thus this should only happen if
            # the "ruleUIDs[]" form value was empty.
            rule_uids = None

        # Urgency
        if urgency is not None and urgency not in NotableEventUpdate.DEFAULT_URGENCIES:
            raise ValueError("Invalid urgency value.")

        # Status
        if status is not None:
            try:
                int(status)
            except ValueError:
                raise ValueError("Invalid status value.")

        # The list of owners can change between requests to this handler, when in persistent mode. Do not cache.
        notable_owners = NotableOwner.getOwners(session_key=session_key)
        if newOwner is not None and newOwner not in notable_owners:
            raise ValueError("Invalid owner value.")

        if not any([comment, status, newOwner, urgency]):
            raise ValueError("One of comment, owner, status, urgency is required.")

        return status, comment, urgency, searchID, newOwner, rule_uids

    @staticmethod
    def get_batch_save_limit(session_key):
        """ Retrieve the chunk size for KV store updates.

        :param session_key: A Splunk session key.
        :type session_key: str

        :return The batch save limit.
        :rtype int
        """
        limits = get_limits('kvstore', session_key)
        NotableEventUpdate.BATCH_SAVE_LIMIT = limits.max_documents_per_batch_save

    @staticmethod
    @time_function_call
    def getCapabilities4User(session_key, user=None):
        """Return a list of capabilities for the given user.

        :param session_key: A Splunk session key.
        :type session_key: str
        :param user: The user to get capabilities for.
        :type user: str
        """

        roles = []
        capabilities = []

        # Get user info
        if user is not None:
            logger.debug('Retrieving role(s) for current user: %s', user)
            userEntities = entity.getEntities('authentication/users/%s' % user, count=-1, sessionKey=session_key)

            for stanza, settings in userEntities.items():
                if stanza == user:
                    for key, val in settings.items():
                        if key == 'roles':
                            logger.debug('Successfully retrieved role(s) for user: %s', user)
                            roles = val

        # Get capabilities
        for role in roles:
            logger.debug('Retrieving capabilities for current user: %s', user)
            roleEntities = entity.getEntities('authorization/roles/%s' % role, count=-1, sessionKey=session_key)

            for stanza, settings in roleEntities.items():
                if stanza == role:
                    for key, val in settings.items():
                        if key == 'capabilities' or key == 'imported_capabilities':
                            logger.debug('Successfully retrieved %s for user: %s', key, user)
                            capabilities.extend(val)

        return capabilities

    @time_function_call
    def refreshStatusLabelMap(self, session_key, force_refresh=False):
        """Return a list of the review statuses in dictionary with the key set to the label (or stanza, if
        label is undefined).

        :param session_key: A Splunk session key.
        :type session_key: str
        :param force_refresh: if False, cached entries will be used is available; otherwise entries will be reloaded.
        :type force_refresh: bool

        :return A dictionary of review statuses.
        :rtype dict
        """
        if force_refresh or self.status_label_map is None:
            logger.debug("Reloading the review statuses list")
            reviewStatusesEntities = entity.getEntities('alerts/reviewstatuses', count=-1, sessionKey=session_key)
            self.status_label_map = {stanza: settings.get("label", stanza) for stanza, settings in reviewStatusesEntities.iteritems()}
            logger.debug("%s review statuses loaded", len(self.status_label_map))

    @staticmethod
    @time_function_call
    def isUrgencyOverrideAllowed(session_key):
        """Return the urgency override state.

        :param session_key: A Splunk session key.
        :type session_key: str

        :return The urgency override state.
        :rtype bool
        """
        notable_en = entity.getEntity(NotableEventUpdate.LOG_REVIEW_REST_URL,
                                      'notable_editing',
                                      namespace=NotableEventUpdate.DEFAULT_NAMESPACE,
                                      owner=NotableEventUpdate.DEFAULT_OWNER,
                                      count=-1,
                                      sessionKey=session_key)

        if 'allow_urgency_override' in notable_en:
            return splunk.util.normalizeBoolean(notable_en['allow_urgency_override'])
        else:
            return True

    @staticmethod
    @time_function_call
    def commentLengthRequired(session_key):
        """Returns the length of the comment required.

        :param session_key: A Splunk session key.
        :type session_key: str

        :return The required comment length (0 if no comment is required).
        :rtype int
        """
        comment_en = entity.getEntity(NotableEventUpdate.LOG_REVIEW_REST_URL,
                                      'comment',
                                      namespace=NotableEventUpdate.DEFAULT_NAMESPACE,
                                      owner=NotableEventUpdate.DEFAULT_OWNER,
                                      sessionKey=session_key,
                                      count=-1)

        # Determine if a comment is required
        is_required = splunk.util.normalizeBoolean(comment_en['is_required'])

        # If a comment is not required then return 0
        if is_required is None or not is_required:
            return 0

        # Determine what length of a comment is required
        if comment_en['minimum_length'] is None:
            return 0
        else:
            minimum_length = comment_en['minimum_length']

            # Convert the length to an integer
            try:
                return int(minimum_length)
            except ValueError:

                # The minimum length is invalid, print an error message
                logger.warn("The value for the minimum length is invalid: %s", minimum_length)
                return 0

    @staticmethod
    @time_function_call
    def getDefaultStatus(session_key):
        """Returns the status ID of the default system-wide review status.

        :param session_key: A Splunk session key.
        :type session_key: str

        :return An integer representing the default status.
        :rtype int
        """

        # Get the list of statuses
        logger.debug("Getting the default status")
        statuses_list = entity.getEntities(NotableEventUpdate.REVIEW_STATUSES_REST_URL,
                                           namespace=NotableEventUpdate.DEFAULT_NAMESPACE,
                                           owner=NotableEventUpdate.DEFAULT_OWNER,
                                           sessionKey=session_key,
                                           count=-1)

        # Get the first status defined a default (there should be only one)
        for status_id in statuses_list:

            # Get the status as a dictionary
            notable_status = statuses_list[status_id]

            # Get the disabled
            if 'disabled' in notable_status:
                disabled = splunk.util.normalizeBoolean(notable_status['disabled'])
            else:
                disabled = False

            # Get the default status
            if 'default' in notable_status:
                default = splunk.util.normalizeBoolean(notable_status['default'])
            else:
                default = False

            # If the status is both enabled and default then return it as the default
            if disabled is False and default:
                return status_id

    @time_function_call
    def getCurrentValues(self, session_key, rule_ids=None):
        """Read the current values from the incident review lookup file.

        :param session_key: A Splunk session key.
        :type session_key: str
        :param rule_ids: A list of events to be modified.
        :type rule_ids: list(str)

        :return A list of LogReviewStatus objects.
        :rtype list(LogReviewStatus)
        """

        existing_statuses = {}

        # Create single instance of maxtime function.
        fn_maxtime = lambda y: y.get('time')

        field_order = ['time', 'rule_id', 'owner', 'urgency', 'status', 'comment', 'user', 'rule_name']

        logger.debug("Getting current incident review statuses from the lookup file...")
        if rule_ids:
            query = {"$or": [{'rule_id': i} for i in rule_ids]}
            response, content = self.kv.query(query, session_key, self.DEFAULT_OPTIONS)
        else:
            response, content = self.kv.get(None, session_key, self.DEFAULT_OPTIONS)

        if response.status == httplib.OK:
            content_as_json = json.loads(content)
            if content_as_json:
                for rule_id, records in itertools.groupby(content_as_json, lambda x: x.get('rule_id')):
                    # Assumes that two edits don't occur at the exact same time
                    # for a given rule_id, we will return whatever "max" returns here.
                    latest_record = max(records, key=fn_maxtime)
                    existing_statuses[rule_id] = LogReviewStatus(*[latest_record.get(field) for field in field_order])
        return existing_statuses

    @time_function_call
    def refreshCorrelationSearches(self, session_key):
        """Refresh the list of correlation searches from splunkd via REST.

        :param session_key: A Splunk session key.
        :type session_key: str

        :return None
        :rtype NoneType
        """
        logger.debug("Reloading the correlation searches")
        self.correlation_searches = entity.getEntities('alerts/correlationsearches', count=-1, sessionKey=session_key)
        self.correlation_search_info = {k: {'rule_name': v['rule_name'], 'default_status': v['default_status']} for k, v in self.correlation_searches.iteritems()}
        logger.debug("%s correlation searches loaded", len(self.correlation_searches))

    @time_function_call
    def getStatus(self, rule_id, correlation_search, existing_statuses, session_key, force_refresh=False):
        """Get the status code for the notable event with the given ID. This function will return the first status it
        can find from the following sources:

         1) The status of the latest notable event per the incident review list
         2) The default status assigned for the given correlation search
         3) The system-wide default status
         4) The status of "Unassigned" (0)

        :param rule_id: The value of the event; used to find if an existing entry exists in the
            incident review lookup table
        :type rule_id: str
        :param correlation_search: The correlation search that the given rule_id corresponds to; used to get
            the default status that is assigned to the given correlation search
        :type correlation_search: str
        :param existing_statuses: Dictionary of existing statuses from the incident review lookup (key being the
            rule_id); used to obtain the current status of the event
        :type existing_statuses: dict
        :param session_key: A Splunk session key.
        :type session_key: str
        :param force_refresh: If true, reload the information about the correlation searches
        :type force_refresh: bool

        :return The default status (string representation of an integer)
        :rtype str
        """

        # Determine if the correlation search has an existing status in incident review
        if rule_id in existing_statuses:
            existing_status_entry = existing_statuses[rule_id]
            logger.debug("Found existing status (%s) for %s", existing_status_entry.status, rule_id)
        else:
            existing_status_entry = None

        # Return the status if it is not blank
        if existing_status_entry is not None and existing_status_entry.status and len(existing_status_entry.status) > 0:
            logger.debug("Returning status from: existing entry, status=%s, rule_id=%s", existing_status_entry.status, rule_id)
            return existing_status_entry.status

        # If a status was not found in the incident review then use the default for the correlation search
        if force_refresh:
            self.refreshCorrelationSearches(session_key)
        status = self.correlation_search_info.get(correlation_search, {}).get('default_status')

        if status is not None:
            logger.debug("Returning status from: correlation search default, status=%s, rule_id=%s", status, rule_id)
            return status
        else:
            logger.debug("Could not find correlation search default status for search '%s', rule_id=%s", correlation_search, rule_id)

        # Use the default status if we could not get a status
        status = self.DEFAULT_STATUS

        if status is not None:
            logger.debug("Returning status from: system default, status=%s, rule_id=%s", status, rule_id)
            return status

        # If we were unable to find a status, then return the default
        logger.debug("Returning status from: module default, status=%s, rule_id=%s", self.DEFAULT_NOTABLE_EVENT_STATUS, rule_id)
        return self.DEFAULT_NOTABLE_EVENT_STATUS

    @time_function_call
    def updateEvents(self, status_records, session_key, existing_statuses=None):
        """
        Update the incident review history for a set of events.

        :param status_records: A list of LogReviewStatus objects.
        :type status_records: list(LogReviewStatus)
        :param session_key: A Splunk session key.
        :type session_key: str
        :param existing_statuses: A dictionary of existing LogReviewStatus objects from the incident review lookup
        :type existing_statuses: dict

        :return The count of updated events
        :rtype int
        """

        for status_record in status_records:
            status_record.update_from_existing(existing_statuses.get(status_record.rule_id))

        # Update.
        unused_response, content = self.kv.batch_create([
            vars(i) for i in status_records], session_key, self.DEFAULT_OPTIONS)

        # Audit.
        audited_bool = self.create_audit_records(status_records, session_key)

        # Note: we DO NOT abort or raise an exception for failure to audit events,
        # to preserve the previous behavior of incident review's former CSV-backed
        # implementation.
        if not audited_bool:
            logger.error('Could not create some audit record for notable event status changes: changed_records="%s"', content)

        # The content object contains a JSON list of the records that were updated,
        # in the format [ <rule_id>_<timestamp>, ... ]
        parsed_content = json.loads(content)
        return len(parsed_content)

    @time_function_call
    def create_audit_records(self, status_records, session_key):
        """
        Create an audit record for a list of updated events.

        :param status_records: A list of LogReviewStatus objects.
        :type status_records: list(LogReviewStatus)
        :param session_key: A Splunk session key.
        :type session_key: str

        :return Success status.
        :rtype bool
        """
        uri = '/services/receivers/simple'
        getargs = {'index': '_audit', 'sourcetype': 'incident_review', 'output_mode': 'json'}
        # Double list-comprehension:
        # a. Comma-separate the fields in each record, replacing "None" with the
        #    empty string
        # b. Newline-separate the records so that the incident_review sourcetype
        #    can pick up the individual audit records via SHOULD_LINEMERGE=false.
        data = '\n'.join([','.join([str(getattr(r, k)) if getattr(r, k) is not None else '' for k in self.DEFAULT_AUDIT_FIELD_ORDER]) for r in status_records])

        response, content = splunk.rest.simpleRequest(uri,
                                                      sessionKey=session_key,
                                                      method='POST',
                                                      getargs=getargs,
                                                      jsonargs=data)

        if response['status'] != str(httplib.OK):
            logger.error('HTTP error when auditing notable events: response="%s"', response)
            return False
        else:
            parsed_content = json.loads(content)
            if len(data) != parsed_content['bytes']:
                # Some audit data was not received.
                logger.error('Audit records could not be created for some notable event updates: content="%s"', content)
                return False

        return True

    @staticmethod
    @time_function_call
    def getSearchResults(searchID, session_key):
        """
        Get the search results for the given search ID.

        :param searchID: A search ID.
        :type searchID: str
        :param session_key: A Splunk session key.
        :type session_key: str

        :return: A Splunk job's events
        """

        job = splunk.search.getJob(searchID, sessionKey=session_key)

        if not job.isDone:
            raise SearchNotDoneException("Search is not done, search must be completed before results can be processed")

        if job.reportSearch:
            logger.warn("The search ID %s is not an event search but one that provides processed results; only an event search can be used for editing notable events", searchID)
            raise NotEventSearchException("Search must be an event search that provides raw events (not results)")

        # Reset the fetch options for faster retrieval.
        job.clearFetchOptions()
        job.setFetchOptions(field_list=['rule_id', 'source'],
                            max_lines=1,
                            output_mode='xml',
                            show_empty_fields=False,
                            time_format='%Y-%m-%dT%H:%M:%S%z')
        return getattr(job, 'events')

    @time_function_call
    def setStatusBySearchID(self, searchID, urgency, status, comment, newOwner, reviewTime, capabilities, session_key, currentUser=None, force_refresh=False, rule_ids_to_change=None, existing_statuses=None):
        """
        Set the status of the events that match a search with the given ID.

        :param searchID: A search ID containing the results that should be modified
        :type searchID: str
        :param urgency: The urgency to set the events to
        :type urgency: str
        :param status: The status to assign the events to
        :type status: str
        :param comment: A comment describing the change
        :type comment: str
        :param newOwner: The owner to assign the events to
        :type newOwner: str
        :param reviewTime: A string representing the review time
        :type reviewTime: str
        :param capabilities: The current user's capability list.
        :type session_key: list(str)
        :param session_key: A Splunk session key.
        :type session_key: str
        :param currentUser: The user performing the changes
        :type currentUser: str
        :param rule_ids_to_change: Rule IDs to be changed. If none, then all events matching the search will be modified.
        :type rule_ids_to_change: list(str)

        :return A LogReviewStatusChanges object representing metadata about the changes.
        :rtype: LogReviewStatusChanges
        """

        # This class instance will record the number of events successfully changed
        status_change_meta = LogReviewStatusChanges()

        # Get the search job (this will throw a splunk.ResourceNotFound exception if the search cannot be found)
        try:
            dataset = self.getSearchResults(searchID, session_key)
        except splunk.ResourceNotFound:
            logger.warn("The search ID %s is no longer accessible, please refresh and try editing the events again", searchID)
            status_change_meta.incrementFailureCountEx(["The search is no longer accessible, please refresh and try editing the events again"])
            return status_change_meta
        except NotEventSearchException:
            status_change_meta.incrementFailureCountEx(["The search is not an event search; searches returning results (instead of events) cannot be used"])
            return status_change_meta
        except SearchNotDoneException:
            status_change_meta.incrementFailureCountEx(["The search is not done; the search must be completed before results can be processed"])
            return status_change_meta

        # Get the existing statuses so that the entries can inherit items as necessary
        if existing_statuses is None:
            existing_statuses = self.getCurrentValues(session_key, rule_ids_to_change)

        # Make sure the comment is the minimum length (if defined)
        minimum_length = self.commentLengthRequired(session_key)
        if len(comment.strip()) < minimum_length:
            status_change_meta.incrementFailureCountEx(["comment length does not meet minimum requirement (must be %d characters long or more)" % (minimum_length)])
            return status_change_meta

        # Determine if urgency changes are allowed
        allowUrgencyChanges = self.isUrgencyOverrideAllowed(session_key)

        # If we are not allowed to change the urgency, then set it to none to indicate that it ought not be changed
        if allowUrgencyChanges is False:
            urgency = None

        # Make a copy of the rules IDs that we are planning to change so that we can exit early from looping through
        # the search results once we get done editing the entries
        rule_ids_to_change_left = None

        if rule_ids_to_change is not None:
            rule_ids_to_change_left = rule_ids_to_change[:]  # Make a copy, we don't want to edit the original

        # Counters
        evaluated = 0

        # Notable events to be edited
        status_records = []

        # Create a status entry for each event
        for event in dataset:

            evaluated += 1

            # Stop processing the events if already handled all of the events we expected to handle
            if rule_ids_to_change_left is not None and len(rule_ids_to_change_left) == 0:
                break

            if 'rule_id' in event:
                rule_id = str(event['rule_id'])

                # Only change the given event if it is in the list to change
                if rule_ids_to_change is not None and rule_id not in rule_ids_to_change:
                    continue

                if 'source' in event:
                    correlation_search = str(event['source'])
                else:
                    correlation_search = None

                rule_name = self.correlation_search_info.get(correlation_search, {}).get('rule_name')

                # Make sure that the user has the capability
                capability_issues = self.checkTransition(rule_id, correlation_search, status, capabilities,
                                                         session_key, existing_statuses, force_refresh)

                # Stop if the permission check failed
                if capability_issues is not None and len(capability_issues) > 0:
                    status_change_meta.incrementFailureCountEx(capability_issues)
                else:
                    # Add the record to the list of records to be saved.
                    status_records.append(LogReviewStatus(reviewTime, rule_id, newOwner, urgency, status, comment,
                                                          currentUser, rule_name, rule_id + '_' + str(reviewTime)))
                    if rule_ids_to_change_left is not None:
                        rule_ids_to_change_left.remove(rule_id)
            else:
                status_change_meta.incrementFailureCount("rule_id field not found in the event")

        logger.debug("Evaluated %i events for editing", evaluated)

        success_count = 0
        # Perform the save in chunks and return status.
        for chunk in [status_records[i:i + self.BATCH_SAVE_LIMIT] for i in range(0, len(status_records), self.BATCH_SAVE_LIMIT)]:
            try:
                success_count += self.updateEvents(chunk, session_key, existing_statuses)
            except Exception as e:
                logger.exception('Exception when updating notable events: %s', e)

        # Update status change metadata.
        # Case 1: updating all events in the search
        # Case 2: updating only selected events
        if (not rule_ids_to_change and success_count == evaluated) or (rule_ids_to_change and len(rule_ids_to_change) == success_count):
            # All successful.
            status_change_meta.incrementSuccessCount(success_count)
        else:
            # Some failures.
            status_change_meta.incrementSuccessCount(success_count)
            status_change_meta.incrementFailureCount('some notable event(s) could not be updated', evaluated - success_count)

        return status_change_meta

    @time_function_call
    def setStatusByIDs(self, rule_ids, urgency, status, comment, newOwner, reviewTime, session_key, currentUser=None, existing_statuses=None):
        """
        Set the status of the events with the given rule IDs


        :param rule_ids: A list of rule IDs.
        :type rule_ids: list(str)
        :param urgency: The urgency to set the events to
        :type urgency: str
        :param status: The status to assign the events to
        :type status: str
        :param comment: A comment describing the change
        :type comment: str
        :param newOwner: The owner to assign the events to
        :type newOwner: str
        :param reviewTime: A string representing the review time
        :type reviewTime: str
        :param session_key: A Splunk session key.
        :type session_key: str
        :param currentUser: The user performing the changes
        :type currentUser: str
        :param existing_statuses: Existing review statuses
        :type existing_statuses: list(LogReviewStatus)

        :return A LogReviewStatusChanges object representing metadata about the changes.
        :rtype: LogReviewStatusChanges
        """

        # This class provides information on the operations performed
        status_change_meta = LogReviewStatusChanges()

        # Make sure the comment is the minimum length (if defined)
        minimum_length = self.commentLengthRequired(session_key)

        if len(comment.strip()) < minimum_length:

            # Return a message noting that the minimum length was not met
            status_change_meta.incrementFailureCountEx(["comment length does not meet minimum requirement (must be %d characters long or more)" % (minimum_length)])
            return status_change_meta

        # Get the existing statuses
        existing_statuses = existing_statuses or self.getCurrentValues(session_key, rule_ids)

        status_records = []
        success_count = 0

        # Append the new entries
        for rule_id in rule_ids:
            status_records.append(LogReviewStatus(reviewTime, rule_id, newOwner, urgency, status, comment, currentUser, None, rule_id + '_' + str(reviewTime)))

        # Perform the save in chunks.
        for chunk in [status_records[i:i + self.BATCH_SAVE_LIMIT] for i in range(0, len(status_records), self.BATCH_SAVE_LIMIT)]:
            try:
                success_count += self.updateEvents(chunk, session_key, existing_statuses)
            except Exception:
                pass

        # Update status change metadata.
        if len(rule_ids) == success_count:
            # All successful.
            status_change_meta.incrementSuccessCount(success_count)
        else:
            # Some failures.
            status_change_meta.incrementSuccessCount(success_count)
            status_change_meta.incrementFailureCount('some notable event(s) could not be updated', len(rule_ids) - success_count)

        return status_change_meta

    @time_function_call
    def setStatuses(self, urgency, status, comment, newOwner, currentUser, ruleUIDs, searchID, reviewTime, existing_statuses, capabilities, session_key):
        """
        Commit the changes to the incident review lookup. Returns a LogReviewStatusChanges instance that describes the
        result of the operation.

        :param urgency: The urgency to set the events to
        :type urgency: str
        :param status: The status to assign the events to
        :type status: str
        :param comment: A comment describing the change
        :type comment: str
        :param newOwner: The owner to assign the events to
        :type newOwner: str
        :param currentUser: The user performing the changes
        :type currentUser: str
        :param ruleUIDs: A list of rule IDs.
        :type ruleUIDs: list(str)
        :param reviewTime: A string representing the review time
        :type reviewTime: str
        :param existing_statuses: Existing review statuses
        :type existing_statuses: dict
        :param capabilities: The current user's capabilities.
        :type capabilities: list(str)
        :param session_key: A Splunk session key.
        :type session_key: str

        :return A LogReviewStatusChanges object representing metadata about the changes.
        :rtype: LogReviewStatusChanges
        """

        # Print a log message noting that an operation is about to happen
        if ruleUIDs is not None and searchID is not None:
            logger.info("About to edit events matching search %s (though only %d events are to be modified)", searchID, len(ruleUIDs))
        if searchID is None and (ruleUIDs is not None and len(ruleUIDs) > 0):
            logger.info("About to edit events by ID (%d events are to be modified)", searchID, len(ruleUIDs))
        else:
            logger.info("About to edit events matching all events matching search %s", searchID)

        # Refresh the correlation searches list so we don't have to later
        self.refreshCorrelationSearches(session_key)

        # Perform the changes
        if searchID is None:
            result = self.setStatusByIDs(ruleUIDs, urgency, status, comment, newOwner, reviewTime, session_key, currentUser, existing_statuses=existing_statuses)
            logger.info("Done editing events")
            return result
        else:
            result = self.setStatusBySearchID(searchID, urgency, status, comment, newOwner, reviewTime, capabilities, session_key, currentUser, force_refresh=False, rule_ids_to_change=ruleUIDs, existing_statuses=existing_statuses)
            logger.info("Done editing events matching search %s", searchID)
            return result

    @time_function_call
    def checkTransition(self, rule_id, correlation_search, status, capabilities, session_key, existing_statuses=None, force_refresh=False):
        """
        Check and make sure that the user can transition the given rules. Returns a list of messages that describes the
        issues found. An empty list indicates that no issues were found.

        :param rule_id: A rule ID.
        :type rule_id: str
        :param correlation_search: A correlation search name.
        :type correlation_search: str
        :param status: The status to assign the events to
        :type status: str
        :param capabilities: A list of capabilities.
        :type capabilities: list(str)
        :param session_key: A Splunk session key.
        :type session_key: str
        :param existing_statuses: Existing review statuses
        :type existing_statuses: dict
        :param force_refresh: If True, cached data will not be used.

        :return Messages about the requested transitions.
        :rtype: list(str)
        """

        # Populate the existing_statuses if not pre-populated
        if existing_statuses is None:
            existing_statuses = self.getCurrentValues(session_key, [rule_id])

        # Below if the list that will contain all of the problems
        messages = []

        # Get the current status of the given notable event
        currentStatus = self.getStatus(rule_id, correlation_search, existing_statuses, session_key, force_refresh)

        # No transition check is needed if we are not changing the status
        if currentStatus == status or status is None or len(status) == 0:
            # No transition checking necessary since we are not changing the status, return the given set of messages
            return messages

        # Get the matching capability
        matchingCapability = "transition_reviewstatus-" + str(currentStatus) + "_to_" + str(status)

        # Generate a warning if the capability is not in the list of allowed transitions
        if matchingCapability not in capabilities:

            newMessage = None

            # If the current status does not, exist, allow the transition.
            try:
                currentStatusLabel = self.status_label_map[currentStatus]
            except (KeyError, TypeError):
                logger.error("Status with ID %s is not valid, transitioning of this event will be allowed", str(currentStatus))
                return messages

            # Get the new label and status
            try:
                newStatusLabel = self.status_label_map[status]
            except (KeyError, TypeError):
                logger.error("Status with ID %s is not valid", str(status))
                newMessage = "No such status could be found with an ID of %s" % str(status)

            # Create the message unless one has already been created (indicating that another check has already failed)
            if newMessage is None:
                newMessage = "transition from %s to %s is not allowed" % (str(currentStatusLabel), str(newStatusLabel))
                logger.info("Transition of event %s from %s to %s is not allowed", rule_id, str(currentStatusLabel), str(newStatusLabel))

            # Append the message if it is not unique
            if newMessage not in messages:
                messages.append(newMessage)
        else:
            logger.info("Capability %s allows transition of event %s from %s to %s", matchingCapability, rule_id, str(currentStatus), str(status))

        # Return the messages
        return messages

    @time_function_call
    def makeChanges(self, status, comment, session_key, newOwner=None, urgency=None, ruleUIDs=None, searchID=None, currentUser=None):
        """
        Make changes to the notable events that are requested.

        :param status: The status to assign the events to
        :type status: str
        :param comment: A comment describing the change
        :type comment: str
        :param session_key: A Splunk session key.
        :type session_key: str
        :param newOwner: The owner to assign the events to
        :type newOwner: str
        :param urgency: The urgency.
        :type urgency: str
        :param ruleUIDs: A list of rule IDs.
        :type ruleUIDs: list(str)
        :param searchID: A string representing a Splunk search ID.
        :type searchID: str
        :param currentUser: The current user.
        :type currentUser: str

        :return A dictionary representing the response to the request.
        :rtype: dict
        """

        response = {}

        try:

            # 0 -- Precondition checks

            #    0.1 -- Make sure the search ID was provided
            if searchID is None and ruleUIDs is None:
                return {"success": False, "message": "No search ID or ruleUIDs were provided."}

            #    0.2 -- Make sure we can retrieve batch size
            if not self.BATCH_SAVE_LIMIT > 0:
                return {"success": False,
                        "message": "Invalid value for max_documents_per_batch_save in limits.conf (must be greater than zero)."}

            # 2 -- Check capabilities

            # if currentStatus is unassigned then what?
            # Do we allow a change to ANY other status?
            # because that seems problematic...
            # Perhaps we treat 'unassigned' as 'new'

            # Get the capabilities for the current user
            capabilities = self.getCapabilities4User(session_key, currentUser)

            # Get the current status label map.
            self.refreshStatusLabelMap(session_key, True)

            # 3 -- Perform the changes
            # Note that reviewTime is always the value of the local time.
            status_change_summary = self.setStatuses(urgency,
                                                     status,
                                                     comment,
                                                     newOwner,
                                                     currentUser,
                                                     ruleUIDs,
                                                     searchID,
                                                     time.time(),
                                                     self.getCurrentValues(session_key, ruleUIDs),
                                                     capabilities,
                                                     session_key)

            # Add additional details that will be used to display additional messages
            response["details"] = status_change_summary.messages
            response["success_count"] = status_change_summary.success_count
            response["failure_count"] = status_change_summary.getFailureCount()

            # Consider the operation a success if some entries were changed so that the view updates
            if status_change_summary.success_count > 0:
                response["success"] = True
            else:
                response["success"] = False

            # If we got some errors, then post them
            if (len(status_change_summary.messages)) > 0:
                error_message = status_change_summary.getMessagesAsString()
                response["message"] = error_message
            else:
                response["message"] = "%s event%s updated successfully" % (
                    status_change_summary.success_count, "s" if status_change_summary.success_count > 1 else '')

            # Return the response
            return response

        except Exception as e:
            # This will be the error message returned
            result = "Error: "

            # Let's get the stacktrace so that debugging is easier
            et, ev, tb = sys.exc_info()

            # Change the result to include a description of the stacktrace
            while tb:
                co = tb.tb_frame.f_code
                filename = "Filename = " + str(co.co_filename)
                line_no = "Error Line # = " + str(traceback.tb_lineno(tb))
                result += str(filename) + str(line_no) + "\n"

                tb = tb.tb_next

            # Add the exception type and value to the message
            result += "\net = " + str(et) + "\nev = " + str(ev)

            # Create the resulting message
            response["success"] = False
            response["message"] = "The update failed:" + str(e)
            response["tb"] = result

            # Also log
            logger.exception(response["message"])

            # Return the response
            return response
