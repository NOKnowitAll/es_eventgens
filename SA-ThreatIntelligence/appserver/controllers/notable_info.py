import cherrypy
import csv
import logging
import json
import sys

import splunk
import splunk.entity as entity
import splunk.appserver.mrsparkle.controllers as controllers
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import jsonresponse
from splunk.appserver.mrsparkle.lib.decorators import expose_page
from splunk.appserver.mrsparkle.lib.routes import route
sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
from shortcuts import NotableOwner

# set the maximum allowable CSV field size 
# 
# The default of the csv module is 128KB; upping to 10MB. See SPL-12117 for 
# the background on issues surrounding field sizes. 
# (this method is new in python 2.5) 
csv.field_size_limit(10485760)

# Setup the logger
logger = logging.getLogger('splunk.appserver.SA-ThreatIntelligence.controllers.NotableInfo')


class Notable(controllers.BaseController):
    """Returns information about notable event urgencies"""

    DEFAULT_NAMESPACE = "SA-ThreatIntelligence"
    DEFAULT_OWNER = 'nobody'
    REVIEW_STATUSES_REST_URL = '/alerts/reviewstatuses/'
    LOG_REVIEW_REST_URL = '/alerts/log_review/'
    URGENCY_ORDER = {
        'informational': 0,
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }
    URGENCY_ORDER_TOP = 5

    def getUrgencies(self):
        file_path = make_splunkhome_path(["etc", "apps", "SA-ThreatIntelligence", "lookups", "urgency.csv"])

        # get the unique urgencies.
        try:
            with open(file_path, "rb") as rFile:
                urgencies = {row["urgency"] for row in csv.DictReader(rFile)}
        except (IOError, csv.Error):
            # Empty lookup table file. This usually indicates an installation error.
            urgencies = set()

        # return them as label,value pairs.
        urgencyDicts = []

        for urg in urgencies:
            order = self.URGENCY_ORDER[urg] if (urg in self.URGENCY_ORDER) else self.URGENCY_ORDER_TOP
            urgencyDicts.append({"value": urg, "order": order, "label": urg.capitalize()})
            
        return urgencyDicts

    def getUsers(self):
        users = NotableOwner.getOwners(cherrypy.session.get('sessionKey'), use_name_as_realname=True)
        result = [{'value': owner, 'label': realname} for owner, realname in users.items()]
        result.sort(key=lambda d: d['label'].lower())
        return result

    def getStatuses(self):
        
        current_user = cherrypy.session['user']['name']   # auth.getCurrentUser()['name']
        session_key = cherrypy.session.get('sessionKey')
            
        try:
            status_entities = entity.getEntities(self.REVIEW_STATUSES_REST_URL, namespace=self.DEFAULT_NAMESPACE, count=500)
        except Exception as e:
            raise e
        
        capabilities = self.getCapabilities4User(current_user, session_key)

        status_dict = {}

        for stanza_name, stanza in status_entities.iteritems():

            for capability in capabilities:
                # If user has at least one transition capability to the status, add the status as an option.
                # Note this does not take into consideration the current status of the notable event
                if capability.startswith('transition_reviewstatus-') and capability.endswith('to_' + stanza_name):
                    status_dict[stanza_name] = stanza
                    break
        
        return self.getSortedStatusArray(status_dict)
    
    def getSortedStatusArray(self, statusEntities):
        sort_order = {"New": 0, "In Progress": 1, "Pending": 2, "Resolved": 3, "Closed": 4}
        default_order = 100

        statuses = [{
                "value": stanzaName,
                "label": stanza['label'],
                "disabled": splunk.util.normalizeBoolean(stanza["disabled"]),
                "order": sort_order.get(stanza['label'], default_order)
            } for stanzaName, stanza in statusEntities.iteritems()]

        return sorted(statuses, key=lambda x: x.get("order"))

    def commentLengthRequired(self):
        """Returns the length of the required comment."""

        session_key = cherrypy.session.get('sessionKey')
        comment_en = entity.getEntity(self.LOG_REVIEW_REST_URL, 'comment', namespace=self.DEFAULT_NAMESPACE, owner=self.DEFAULT_OWNER, sessionKey=session_key, count=-1)

        if splunk.util.normalizeBoolean(comment_en.get('is_required', False)):
            try:
                return int(comment_en.get('minimum_length'))
            except (TypeError, ValueError):
                logger.warn( "The value for the minimum length is invalid: %s", comment_en.get('minimum_length'))
        return 0

    def getCapabilities4User(self, user=None, sessionKey=None):
        """
        Obtains a list of capabilities in an list for the given user.
        
        Arguments:
        user -- The user to get capabilities for (as a string)
        sessionKey -- The session key to be used if it is not none
        """
        
        roles = []
        capabilities = []
        
        # Get user info
        if user is not None:
            logger.debug("Retrieving role(s) for current user: %s", user)
            userEntities = entity.getEntities('authentication/users/%s' % user, count=-1, sessionKey=sessionKey)

            for stanza, settings in userEntities.items():
                if stanza == user:
                    for key, val in settings.items():
                        if key == 'roles':
                            logger.debug("Successfully retrieved role(s) for user: %s", user)
                            roles = val
        
        # Get capabilities
        for role in roles:
            logger.debug("Retrieving capabilities for current user: %s", user)
            roleEntities = entity.getEntities('authorization/roles/%s' % role, count=-1, sessionKey=sessionKey)
          
            for stanza, settings in roleEntities.items():
                if stanza == role:
                    for key, val in settings.items():
                        if key == 'capabilities' or key == "imported_capabilities":
                            logger.debug('Successfully retrieved %s for user: %s' % (key, user))
                            capabilities.extend(val)

        return capabilities
    
    def isUrgencyOverrideAllowed(self):
        """Determines if urgency overrides are allowed."""
        sessionKey = cherrypy.session.get('sessionKey')
        notable_en = entity.getEntity(self.LOG_REVIEW_REST_URL, 'notable_editing', namespace=self.DEFAULT_NAMESPACE, owner=self.DEFAULT_OWNER, count=-1, sessionKey=sessionKey)
        return splunk.util.normalizeBoolean(notable_en.get('allow_urgency_override', True))

    @route('/:incident_review_settings=incident_review_settings')
    @expose_page(must_login=True, methods=['GET'])
    def incidentReviewSettings(self, **kwargs):

        stanza = kwargs.get('stanza', None)
        session_key = cherrypy.session.get('sessionKey')

        if stanza is not None:

            ir_settings = entity.getEntity(self.LOG_REVIEW_REST_URL, stanza, namespace=self.DEFAULT_NAMESPACE, owner=self.DEFAULT_OWNER, sessionKey=session_key, count=-1)

            # Convert the JSON to a list of table labels and fields
            try:
                table_attributes = json.loads(ir_settings.get('table_attributes', '[]'))
            except ValueError:
                cherrypy.response.status = 420
                return self.render_json(_("Table attributes JSON could not be parsed"))

            table_labels = []
            table_fields = []

            for row in table_attributes:
                table_labels.append(row['label'])
                table_fields.append(row['field'])

            # Verify that we got table fields
            if len(table_fields) == 0:
                cherrypy.response.status = 420
                return self.render_json(_("Fields length is zero"))

            # Convert the JSON of attributes
            try:
                event_attributes = json.loads(ir_settings.get('event_attributes', '[]'))
            except ValueError:
                cherrypy.response.status = 420
                return self.render_json(_("Event attributes JSON could not be parsed"))

            attribute_labels = []
            attribute_fields = []

            for row in event_attributes:
                attribute_labels.append(row['label'])
                attribute_fields.append(row['field'])

            # Make sure that number of fields and labels are the same
            if len(attribute_fields) == 0:
                cherrypy.response.status = 420
                return self.render_json(_("Attributes length is zero"))

            return self.render_json({
                'table_labels': table_labels,
                'table_fields': table_fields,
                'attribute_labels': attribute_labels,
                'attribute_fields': attribute_fields
            })

        else:
            cherrypy.response.status = 404
            return self.render_json(_("Stanza argument was not provided"))

    @route('/:all=all')
    @expose_page(must_login=True, methods=['GET'])
    def all(self, **kwargs):
        return self.render_json({
            "users": self.getUsers(),
            "urgencies": self.getUrgencies(),
            "statuses": self.getStatuses(),
            "comment_length_required": self.commentLengthRequired(),
            "urgency_override_allowed": self.isUrgencyOverrideAllowed()
        })
