"""
Copyright (C) 2005 - 2016 Splunk Inc. All Rights Reserved.
"""
import httplib
import json
import logging
import sys
import time
import urllib

import splunk
import splunk.rest
import splunk.search
import splunk.util
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-IdentityManagement", "lib"]))
from SolnCommon.log import setup_logger
from SolnCommon.lookup_conversion.lookup_modinput import LookupModularInput
from SolnCommon.metadata import MetadataReader
from SolnCommon.modinput.fields import Field
from identity_generation import get_conventions, generate_search_string
from identity_macros import IdentityCorrelationMacro
from identity_sources import generate_identity_source

import logging
logger = setup_logger('identity_manager', level=logging.INFO)


class IdentityManagerModularInput(LookupModularInput):

    MACRO_AUTOUPDATE_PERMITTED = 'enable_identity_management_autoupdate'
    MACRO_TIMEOUT = 'identity_management_timeout'
    CHECKPOINT_PREFIX = 'identityLookup_conf'
    DEFAULT_TIMEOUT = 30

    def __init__(self):

        scheme_args = {'title': "Identity Management",
                       'description': "Merges asset and identity information into Splunk lookup tables.",
                       'use_external_validation': "true",
                       'streaming_mode': "xml",
                       'use_single_instance': "true"}

        args = [
            Field("category", "Category", """Category of the input lookup table. Must be "asset" or "identity".""", required_on_create=True, required_on_edit=True),
            Field("description", "Description", """Description of the input lookup table.""", required_on_create=True, required_on_edit=True),
            Field("master_host", "Master host", "The master host for this download.", required_on_create=False, required_on_edit=False),
            Field("target", "Target", """Target output destination for this asset or identity table.""", required_on_create=True, required_on_edit=True),
            Field("url", "URL", """Resource locator for the asset or identity table.""", required_on_create=True, required_on_edit=True)]
        
        self._app = 'SA-IdentityManagement'
        self._name = 'IdentityManager'
        self._owner = 'nobody'

        # Target searches will be dispatched IN THE ORDER LISTED.
        self.target_searches = {'asset': ['Identity - Asset String Matches - Lookup Gen',
                                          'Identity - Asset CIDR Matches - Lookup Gen'],
                                'identity': ['Identity - Identity Matches - Lookup Gen']
                                }

        # These searches will be fired once in the order shown if any asset/identity updates occur.
        self.ancillary_searches = ['Identity - Make Categories - Lookup Gen',
                                   'Identity - Make PCI Domains - Lookup Gen']

        super(IdentityManagerModularInput, self).__init__(scheme_args, args)

    def detect_updated_identity_config(self):
        """Compare the previous identityLookup.conf configuration to the current."""
        targets = set()

        try:
            # Refresh and load the identity lookup configuration
            r, c = splunk.rest.simpleRequest('data/transforms/identityLookup/_reload',
                                             getargs={'output_mode': 'json'},
                                             sessionKey=self._input_config.session_key)

            r, c = splunk.rest.simpleRequest('data/transforms/identityLookup/identityLookup',
                                             getargs={'output_mode': 'json'},
                                             sessionKey=self._input_config.session_key)

            parsed = json.loads(c)['entry'][0]['content']
            current_config = {k: v for k, v in parsed.iteritems() if not k.startswith('eai')}
        except Exception:
            logger.exception('status="Exception when retrieving identityLookup.conf"')
            raise
            
        # Retrieve previous configuration.
        prev_config = None
        if self.checkpoint_data_exists(self.CHECKPOINT_PREFIX):
            prev_config = self.get_checkpoint_data(self.CHECKPOINT_PREFIX)

        # Checkpoint the current configuration.
        try:
            self.set_checkpoint_data(self.CHECKPOINT_PREFIX, current_config)
        except Exception as e:
            logger.exception('status="Error when checkpointing identity lookup configuration; next identity merge will be forced"')
        
        # Compare previous to current configuration.
        if prev_config and current_config:
            for key, curr_value in prev_config.iteritems():
                prev_value = prev_config.get(key, None)
                if curr_value != prev_value:
                    logger.info('status="identityLookup.conf configuration changed; identity merge will be forced" key="%s" prev="%s" curr="%s"', key, prev_value, curr_value)
                    targets.add('identity')
        else:
            logger.info('status="identityLookup.conf changes could not be determined. Identity merge will be forced"')
            targets.add('identity')

        return targets

    def detect_updated_search_constructs(self):
        """Detect updated primary saved searches and macros and add the associated targets to the list of merge
        classes."""

        PREVIOUS_SEARCH_CHECKPOINT = 'previous_searches'
        to_merge = set()

        previous = {}
        latest = {}

        if self.checkpoint_data_exists(PREVIOUS_SEARCH_CHECKPOINT):
            previous = self.get_checkpoint_data(PREVIOUS_SEARCH_CHECKPOINT)

        for target, savedsearches in self.target_searches.items():
            for ss in savedsearches:
                prev = previous.get(ss)
                r, c = splunk.rest.simpleRequest(
                    '/servicesNS/nobody/SA-IdentityManagement/properties/savedsearches/%s/search' % urllib.quote(ss),
                    getargs={'output_mode': 'json'},
                    sessionKey=self._input_config.session_key)

                if r.status != httplib.OK:
                    raise ValueError('status="Saved search definition could not be determined" search="%s"', ss)

                latest[ss] = c

                if prev != latest[ss]:
                    logger.info('status="saved searches have been modified" target="%s" savedsearch="%s"', target, ss)
                    to_merge.add(target)

        for macro in [IdentityCorrelationMacro.MACRO_ASSET_SOURCES,
                      IdentityCorrelationMacro.MACRO_IDENTITY_GENERATE,
                      IdentityCorrelationMacro.MACRO_IDENTITY_SOURCES,
                      self.MACRO_AUTOUPDATE_PERMITTED]:
            prev = previous.get(macro)
            r, c = splunk.rest.simpleRequest(
                '/servicesNS/nobody/SA-IdentityManagement/properties/macros/%s/definition' % urllib.quote(macro),
                getargs={'output_mode': 'json'},
                sessionKey=self._input_config.session_key)

            if r.status != httplib.OK:
                raise ValueError('status="Macro definition could not be determined" macro="%s"', macro)

            latest[macro] = c

            if prev != latest[macro]:
                logger.info('status="macro has been modified - all targets will be merged" macro="%s"', macro)
                to_merge.update(['asset', 'identity'])

        # Checkpoint the most recent data.
        self.set_checkpoint_data(PREVIOUS_SEARCH_CHECKPOINT, latest)

        return to_merge

    def get_autoupdate_permitted(self):
        """Return the autoupdate setting as defined in the enable_identity_management_autoupdate macro."""
        r, c = splunk.rest.simpleRequest(
            '/servicesNS/nobody/SA-IdentityManagement/properties/macros/%s/definition' % self.MACRO_AUTOUPDATE_PERMITTED,
            getargs={'output_mode': 'json'},
            sessionKey=self._input_config.session_key)

        if r.status == httplib.OK:
            return splunk.util.normalizeBoolean(c)
        else:
            raise ValueError('status="Macro definition could not be determined" macro="%s"', self.MACRO_AUTOUPDATE_PERMITTED)

    def get_timeout(self):
        """Return the timeout setting as defined in the identity_management_timeout macro."""
        r, c = splunk.rest.simpleRequest(
            '/servicesNS/nobody/SA-IdentityManagement/properties/macros/%s/definition' % self.MACRO_TIMEOUT,
            getargs={'output_mode': 'json'},
            sessionKey=self._input_config.session_key)

        if r.status == httplib.OK:
            try:
                return int(c)
            except ValueError:
                return self.DEFAULT_TIMEOUT
        else:
            logger.warn('status="Timeout value could not be determined; using default" timeout="%s"', self.DEFAULT_TIMEOUT)
            return self.DEFAULT_TIMEOUT


    def monitor(self, jobs, timeout):
        """Monitor jobs for <timeout> seconds until they are complete; warn if not completed."""
        elapsed = 0
        logger.info('status="monitoring for saved search completion" timeout="%s"', timeout)
        while not all([job.isDone for job in jobs]) and elapsed < timeout:
            time.sleep(1)
            elapsed += 1

        for job in jobs:
            if not job.isDone:
                logger.warn('status="saved search did not complete within timeout" search="%s" sid="%s" state="%s"',
                            job.label, job.id, job.dispatchState)
            elif job.isFailed:
                logger.error('status="saved search failed to complete" search="%s" sid="%s" state="%s"',
                             job.label, job.id, job.dispatchState)
            else:
                logger.info('status="saved search completed" search="%s" sid="%s" state="%s"',
                            job.label, job.id, job.dispatchState)

    def run_threads(self, files_by_category, last_run):

        targets = set()

        # Detect forced merging.
        for tgt in self.target_searches:
            if self.checkpoint_data_exists('force_' + tgt):
                logger.info('status="Forcing merge." target=%s', tgt)
                targets.add(tgt)
                if not self.delete_checkpoint_data('force_' + tgt):
                    logger.error('status="Forcing merge (checkpoint file could not be deleted)." target=%s', tgt)
        
        # Detect changes to identityLookup.conf. If identityLookup.conf has changed, force identity lookup generation.
        # targets.update(self.detect_updated_identity_config())
        targets.update(self.detect_updated_identity_config())

        # Detect changes to stanzas, file modification times or file sizes.
        targets.update(self.detect_changes(files_by_category, last_run))

        # Detect saved search and macro modifications.
        targets.update(self.detect_updated_search_constructs())

        # Update search macros if the input stanzas have changed AND auto-update is permitted.
        autoupdate_permitted = self.get_autoupdate_permitted()

        if 'asset' in targets and autoupdate_permitted:
            a_defn = generate_identity_source('asset', self._input_config.session_key)
            IdentityCorrelationMacro.update_macro(IdentityCorrelationMacro.MACRO_ASSET_SOURCES,
                                                  a_defn,
                                                  self._input_config.session_key)

        if 'identity' in targets and autoupdate_permitted:
            i_defn = generate_identity_source('identity', self._input_config.session_key)
            IdentityCorrelationMacro.update_macro(IdentityCorrelationMacro.MACRO_IDENTITY_SOURCES,
                                                  i_defn,
                                                  self._input_config.session_key)

            conventions = get_conventions(self._input_config.session_key)
            g_defn = generate_search_string(*conventions)
            IdentityCorrelationMacro.update_macro(IdentityCorrelationMacro.MACRO_IDENTITY_GENERATE,
                                                  g_defn,
                                                  self._input_config.session_key)

        # Get the timeout value
        timeout = self.get_timeout()

        # Dispatch primary saved searches.
        if targets:
            logger.info('status="running primary saved searches" targets="%s', targets)
            primary_jobs = []
            for target in targets:
                for search in self.target_searches[target]:
                    logger.info('status="dispatching primary saved search" target="%s" search="%s"', target, search)
                    primary_jobs.append(splunk.search.dispatchSavedSearch(search, self._input_config.session_key))
                    logger.info('status="dispatched primary saved search" target="%s" search="%s" sid="%s',
                                target, search, primary_jobs[-1].id)
            # Monitor for completion.
            self.monitor(primary_jobs, timeout)
        else:
            logger.info('status="no action required"')

        # Dispatch ancillary saved searches AFTER completion of the other Lookup Gen searches.
        if targets:
            ancillary_jobs = []
            logger.info('status="running ancillary saved searches"')
            for search in self.ancillary_searches:
                logger.info('status="dispatching ancillary saved search" search="%s"', search)
                ancillary_jobs.append(splunk.search.dispatchSavedSearch(search, self._input_config.session_key))
                logger.info('status="dispatched ancillary saved search" search="%s" sid="%s', search, ancillary_jobs[-1].id)
            # Monitor for completion.
            self.monitor(ancillary_jobs, timeout)

        # Return True here so checkpointing of last_run data completes.
        return True

if __name__ == '__main__':
    logger.info('status="Executing modular input"')
    modinput = IdentityManagerModularInput()
    modinput.execute()
