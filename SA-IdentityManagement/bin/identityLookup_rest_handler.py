"""
Copyright (C) 2005 - 2016 Splunk Inc. All Rights Reserved.
"""
import json
import logging.handlers
import re
import sys

if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)

import splunk
import splunk.admin
import splunk.rest
import splunk.util
from splunk import ResourceNotFound
from splunk.clilib.bundle_paths import make_splunkhome_path
from splunk.appserver.mrsparkle.lib import i18n

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.log import setup_logger, SHORT_FORMAT
logger = setup_logger('identityLookup_rest_handler', level=logging.INFO, format=SHORT_FORMAT)


class IdentityLookup(object):

    # See definitions for convention keys and values in identityLookup.conf.spec.
    CONVENTION_KEY_RX = re.compile(r'^(convention\.(\d+))$')

    REQUIRED_PARAMS = ['exact', 'email', 'email_short', 'convention', 'case_sensitive']
    OPTIONAL_PARAMS = ['convention.*']
    LEGACY_PARAMS = ['match_order']
    VALID_PARAMS = REQUIRED_PARAMS + OPTIONAL_PARAMS + LEGACY_PARAMS

    # Default Values
    DEFAULT_CONF = DEFAULT_STANZA = 'identityLookup'
    DEFAULT_LOOKUP = 'identity_lookup_expanded'
    DEFAULT_NAMESPACE = 'SA-IdentityManagement'
    DEFAULT_OWNER = 'nobody'

    @staticmethod
    def checkConf(settings, stanza, session_key, confInfo=None):
        """1. Checks "settings" for validity.
           2. Raises an exception if the configuration is invalid. Exception
              message is a json dict of invalid keys with error message as value.
           3. Optionally populates the confInfo object by reference (on handleList only). confInfo is used
              when redisplaying stanza information.
        """

        logger.debug('Entering checkConf: stanza: %s', stanza)
        logger.debug('Entering checkConf: settings: %s', settings)
        logger.debug('Entering checkConf: confInfo: %s', confInfo)

        populate = isinstance(confInfo, splunk.admin.ConfigInfo)

        # Validation of identity conventions is dynamic, based on fields in the lookup table.
        identity_fields = IdentityLookup._get_identity_fields(session_key)
        convention_val_rx = re.compile(r'(%s)(\(\d*\))' % '|'.join(identity_fields))
        invalid_keys = {}

        for k in IdentityLookup.REQUIRED_PARAMS:
            if k not in settings:
                invalid_keys[k] = "Required key missing"

        # We populate confInfo with settings at the same time as checking parameter names.
        # confInfo may be None if passed by handleEdit, in which case we do not populate it.
        for key, val in settings.items():

            if val is None:
                val = ''

            if key.startswith(splunk.admin.EAI_ENTRY_ACL):
                # Key is eai:acl. ORDER IS IMPORTANT: eai:acl should be processed before other eai parameters
                # such as eai:appName, eai:userName.
                if populate:
                    confInfo[stanza].setMetadata(key, val)

            elif key.startswith(splunk.admin.EAI_META_PREFIX):
                # Key is eai:<something>
                if populate:
                    confInfo[stanza].append(key, val)

            elif key in IdentityLookup.REQUIRED_PARAMS:
                # Normalize Boolean params (5 params total)
                try:
                    tmp = splunk.util.normalizeBoolean(val, enableStrictMode=True)
                    if populate:
                        confInfo[stanza].append(key, tmp)
                except ValueError:
                    invalid_keys[key] = _("The value is not a valid boolean")

            elif key in IdentityLookup.LEGACY_PARAMS:
                # Ignore legacy parameters.
                logger.info('Ignoring legacy parameter: stanza="%s", key="%s"', stanza, key)

            elif key == 'disabled':
                # Often passed by Splunk REST but not required here.
                logger.info('Ignoring parameter: stanza="%s", key="%s"', stanza, key)

            elif IdentityLookup.CONVENTION_KEY_RX.match(key):
                # Validate conventions.
                match = convention_val_rx.findall(val)

                if len(match):
                    if populate:
                        confInfo[stanza].append(key, val)
                else:
                    # Cannot specify a convention that involves zero fields.
                    invalid_keys[key] = _("No valid convention strings found")

            else:
                # Invalid key - should never get here.
                msg = _('Unsupported parameter: stanza="%s", key="%s"') % (stanza, key)
                logger.error(msg)
                invalid_keys[key] = msg

        if invalid_keys:
            msg = json.dumps(invalid_keys, sort_keys=True)
            if populate:
                confInfo.addErrorMsg(msg)
            raise ValueError(msg)

        logger.debug('Exiting checkConf: stanza: %s', stanza)
        logger.debug('Exiting checkConf: settings: %s', settings)
        logger.debug('Exiting checkConf: confInfo: %s', confInfo)

    @staticmethod
    def _get_identity_fields(session_key):
        """Return the list of fields in the identity lookup table."""

        # Use of data/transforms/lookups endpoint is intentional here because this is the only way to retrieve the
        # fields_list.
        getargs = {'output_mode': 'json'}
        r, c = splunk.rest.simpleRequest('data/transforms/lookups/%s' % IdentityLookup.DEFAULT_LOOKUP,
                                         getargs=getargs,
                                         sessionKey=session_key)
        fields_list = json.loads(c)['entry'][0]['content']['fields_list']
        if isinstance(fields_list, basestring):
            return fields_list.split(',')
        else:
            raise ValueError(_("Empty identity lookup."))


class IdentityLookupRH(splunk.admin.MConfigHandler):

    METHODNAMEMAP = {splunk.admin.ACTION_CREATE: 'ACTION_CREATE',
                     splunk.admin.ACTION_LIST: 'ACTION_LIST',
                     splunk.admin.ACTION_EDIT: 'ACTION_EDIT',
                     splunk.admin.ACTION_REMOVE: 'ACTION_REMOVE',
                     splunk.admin.ACTION_MEMBERS: 'ACTION_MEMBERS',
                     splunk.admin.ACTION_RELOAD: 'ACTION_RELOAD'}

    WRITE_CAPABILITY = 'edit_identitylookup'

    DEFAULT_ARGS = {'output_mode': 'json'}

    GET_URI = '/servicesNS/%s/%s/configs/conf-%s' % (
        IdentityLookup.DEFAULT_OWNER,
        IdentityLookup.DEFAULT_NAMESPACE,
        IdentityLookup.DEFAULT_STANZA
    )

    PUT_URI = '/servicesNS/%s/%s/properties/%s/%s' % (
        IdentityLookup.DEFAULT_OWNER,
        IdentityLookup.DEFAULT_NAMESPACE,
        IdentityLookup.DEFAULT_STANZA,
        IdentityLookup.DEFAULT_STANZA
    )

    def setup(self):
        """Setup REST handler."""
        logger.info('Setting up rest_handler: identityLookup')

        self.setWriteCapability(IdentityLookupRH.WRITE_CAPABILITY)

        if self.requestedAction == splunk.admin.ACTION_EDIT or self.requestedAction == splunk.admin.ACTION_CREATE:

            for arg in IdentityLookup.REQUIRED_PARAMS:
                self.supportedArgs.addReqArg(arg)

            for arg in IdentityLookup.OPTIONAL_PARAMS + IdentityLookup.LEGACY_PARAMS:
                self.supportedArgs.addOptArg(arg)

    def handleList(self, confInfo):
        """List identityLookup stanza."""
        logger.info('Entering %s', self.METHODNAMEMAP[self.requestedAction])
        logger.debug('in %s: confInfo: %s', self.METHODNAMEMAP[self.requestedAction], confInfo)

        self.handleReload()

        try:
            r, c = splunk.rest.simpleRequest(self.GET_URI, getargs=self.DEFAULT_ARGS, sessionKey=self.getSessionKey())
            settings = json.loads(c)['entry'][0]['content']
        except ResourceNotFound:
            raise splunk.admin.NotFoundException("An identityLookup configuration stanza could not be found")

        try:
            IdentityLookup.checkConf(settings, IdentityLookup.DEFAULT_STANZA, self.getSessionKey(), confInfo=confInfo)
        except ValueError as e:
            logger.error("The identityLookup configuration is invalid: %s", e)

        logger.info('Exiting %s', self.METHODNAMEMAP[self.requestedAction])

    def handleReload(self, updateCaseSensitivity=True):
        """Handles refresh/reload of the configuration options"""
        logger.info('Entering %s', self.METHODNAMEMAP[self.requestedAction])

        getargs = self.DEFAULT_ARGS.copy()
        getargs['refresh'] = 1

        # Refresh
        for entity in ['props', 'transforms', 'identityLookup']:
            logger.info('in %s: refreshing %s', self.METHODNAMEMAP[self.requestedAction], entity)
            try:
                uri = 'properties/%s' % entity
                unused_r, unused_c = splunk.rest.simpleRequest(uri, getargs=getargs, sessionKey=self.getSessionKey())
            except Exception:
                logger.exception('in %s: %s refresh failed', self.METHODNAMEMAP[self.requestedAction], entity)

        # Update case sensitivity if requested.
        if updateCaseSensitivity:
            logger.info('in %s: updating transform: %s', self.METHODNAMEMAP[self.requestedAction], IdentityLookup.DEFAULT_LOOKUP)
            identityLookupDict = self.readConf(IdentityLookup.DEFAULT_STANZA)
            stanza = identityLookupDict.get(IdentityLookup.DEFAULT_STANZA, {})
            isCaseSensitive = splunk.util.normalizeBoolean(stanza.get('case_sensitive', False))
            self.updateCaseSensitivity(isCaseSensitive)

        logger.info('Exiting %s', self.METHODNAMEMAP[self.requestedAction])

    def handleEdit(self, confInfo):
        """Handles edits to the configuration options"""
        logger.info('Entering %s', self.METHODNAMEMAP[self.requestedAction])
        logger.debug('in %s: confInfo="%s"', self.METHODNAMEMAP[self.requestedAction], confInfo)
        logger.debug('in %s: callerArgs="%s"', self.METHODNAMEMAP[self.requestedAction], self.callerArgs)

        self.handleReload()

        if self.callerArgs.id != IdentityLookup.DEFAULT_STANZA:
            raise splunk.admin.ArgValidationException("The identityLookup configuration stanza name must be '%s'" % IdentityLookup.DEFAULT_STANZA)

        # Load the existing configuration
        try:
            r, c = splunk.rest.simpleRequest(self.GET_URI, getargs=self.DEFAULT_ARGS, sessionKey=self.getSessionKey())
            settings = json.loads(c)['entry'][0]['content']
        except ResourceNotFound:
            raise splunk.admin.NotFoundException(_("An identityLookup configuration stanza could not be found"))

        # Merge with settings from self.callerArgs
        settings = self.mergeConf(settings)

        # Validate the merged configuration
        try:
            IdentityLookup.checkConf(settings, IdentityLookup.DEFAULT_STANZA, self.getSessionKey())
        except ValueError as exc:
            logger.exception(exc)
            raise splunk.admin.ArgValidationException(exc)

        # Update identityLookup stanza
        postargs = self.DEFAULT_ARGS.copy()
        postargs.update(settings)
        r, c = splunk.rest.simpleRequest(self.PUT_URI, postargs=postargs,
                method='PUT', sessionKey=self.getSessionKey())
        if r.status == 200:
            logger.info("Successfully updated the identityLookup configuration")
        else:
            raise splunk.admin.InternalException(_("Failed to update the identityLookup configuration"))

        # Reload identityLookup
        self.handleReload()

        logger.info('Exiting %s', self.METHODNAMEMAP[self.requestedAction])

    def mergeConf(self, settings):
        """Merge stanza settings with the caller arguments. Simplified implementation here ignores EAI parameters
        because the identityLookup configuration is always a singleton."""
        # if convention.X is not present in callerArgs, remove it
        removed = [key for key in settings if (IdentityLookup.CONVENTION_KEY_RX.match(key) and key not in self.callerArgs)]

        for key in removed:
            del settings[key]

        for key in self.callerArgs:
            if (key in IdentityLookup.REQUIRED_PARAMS or
                    key in IdentityLookup.OPTIONAL_PARAMS or
                    IdentityLookup.CONVENTION_KEY_RX.match(key)):
                settings[key] = self.callerArgs[key][0]
        return settings

    def updateCaseSensitivity(self, isCaseSensitive):
        """Update case sensitivity of identity_lookup_expanded transform to
        match setting in identityLookup.conf."""

        # Note intentional use of properties/transforms here.
        # 1. The case_sensitive_match parameter is not exposed via data/transforms/lookups, cf. SPL-58350, SPL-52305.
        # 2. The data/transforms/lookups endpoint has pathologic behavior, cf. SOLNESS-8576.

        uri = '/servicesNS/%s/%s/properties/transforms/%s/case_sensitive_match' % (
            IdentityLookup.DEFAULT_OWNER,
            IdentityLookup.DEFAULT_NAMESPACE,
            IdentityLookup.DEFAULT_LOOKUP
        )

        r, c = splunk.rest.simpleRequest(uri, sessionKey=self.getSessionKey())

        if splunk.util.normalizeBoolean(c) != isCaseSensitive:
            try:
                r, c = splunk.rest.simpleRequest(uri, postargs={'value': isCaseSensitive}, sessionKey=self.getSessionKey())
                logger.info("Successfully updated transform '%s'", IdentityLookup.DEFAULT_LOOKUP)
            except Exception as e:
                logger.critical("Could not update transform '%s': %s", IdentityLookup.DEFAULT_LOOKUP, e)
        else:
            logger.info("No update required for transform '%s'", IdentityLookup.DEFAULT_LOOKUP)

splunk.admin.init(IdentityLookupRH, splunk.admin.CONTEXT_APP_AND_USER)
