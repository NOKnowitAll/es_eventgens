'''
Copyright (C) 2005 - 2015 Splunk Inc. All Rights Reserved.
'''
import datetime
import json
import logging
import os
import re
import shutil
import sys
import time

import splunk
import splunk.rest
import splunk.util
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.log import setup_logger
from SolnCommon.lookups import get_temporary_checkpoint_file
from SolnCommon.modinput import ModularInput
from SolnCommon.modinput.fields import Field
from SolnCommon.modinput.fields import IntegerField
from SolnCommon.modinput.fields import RangeField
from SolnCommon.protocols import HttpProtocolHandler
from SolnCommon.protocols import NoopProtocolHandler
from SolnCommon.credentials import CredentialManager

from taxii_client import TaxiiHandler, TaxiiHandlerException


class ThreatlistModularInput(ModularInput):

    def __init__(self):

        self.DEFAULT_INITIAL_DELAY = 300
        self.DEFAULT_RETRIES = 3
        self.DEFAULT_RETRY_INTERVAL = 60
        self.DEFAULT_TIMEOUT_INTERVAL = 30
        self.DEFAULT_SKIP_HEADER_LINES = 0
        self.DEFAULT_THREAD_POOL_SIZE = 5
        self.DEFAULT_THREAD_SLEEP_INTERVAL = 300
        self.DEFAULT_MERGE_THREAD_SLEEP_INTERVAL = 15

        self.HANDLER_HTTP = 'http'
        self.HANDLER_HTTPS = 'https'
        self.HANDLER_LOOKUP = 'lookup'
        self.HANDLER_TAXII = 'taxii'

        # Dictionary of supported protocol handlers.
        self.PROTOCOL_HANDLERS = {self.HANDLER_HTTP: HttpProtocolHandler,
                                  self.HANDLER_HTTPS: HttpProtocolHandler,
                                  self.HANDLER_LOOKUP: NoopProtocolHandler,
                                  self.HANDLER_TAXII: TaxiiHandler}

        # Regex for extracting key=value strings
        self.KV_REGEX = re.compile(r'(\w+)=([\w:$]+|"[^"]+")')
        
        # Regex for extracting interpolated arguments.
        self.ARG_REGEX = re.compile(r'\$([A-Za-z0-9_]+):([A-Za-z0-9_]+)\$')
        
        # Default target directory
        self.THREAT_INTEL_TARGET_PATH = make_splunkhome_path(['etc', 'apps', 'SA-ThreatIntelligence', 'local', 'data', 'threat_intel'])

        # Default exclusions - these are the types of threatlist that don't get
        # written to self.THREAT_INTEL_TARGET_PATH
        self.THREAT_INTEL_EXCLUSIONS = ['alexa', 'asn', 'mozilla_psl', 'tld']

        self.DEPRECATED_STANZAS = ['maxmind_geoip_asn_ipv4', 'maxmind_geoip_asn_ipv6']

        scheme_args = {'title': "Threat Intelligence Downloads",
                       'description': "Downloads threat lists or other threat intelligence feeds from remote hosts.",
                       'use_external_validation': "true",
                       'streaming_mode': "xml",
                       'use_single_instance': "false"}

        args = [
            # General options
            Field("type", "Threatlist Type", """Type of threat list, such as "malware". Must be "taxii" for TAXII feeds.""", required_on_create=True, required_on_edit=True),
            Field("description", "Description", """Description of the threat list.""", required_on_create=True, required_on_edit=True),
            Field("max_age", "Maximum age", "Maximum age for threat content (provided for use by consumers of threat content)", required_on_create=False, required_on_edit=False),
            Field("target", "Target", """Target lookup table.""", required_on_create=False, required_on_edit=False),
            Field("url", "URL", """URL or location of the threatlist.""", required_on_create=True, required_on_edit=True),
            RangeField("weight", "Weight", """Weight for IPs that appear on this threatlist. A higher weight increases an IP's risk score.""", low=1, high=100, required_on_create=True, required_on_edit=True),

            # Download options
            Field("post_args", "POST arguments", """POST arguments to send to the remote URL.""", required_on_create=False, required_on_edit=False),
            IntegerField("retries", "Retries", "the number of times to retry a failed download.  [Defaults to {0}]".format(self.DEFAULT_RETRIES), required_on_create=True, required_on_edit=True),
            IntegerField("retry_interval", "Retry interval", "Interval between attempts to download this threat list, in seconds.  [Defaults to {0}]".format(self.DEFAULT_RETRY_INTERVAL), required_on_create=True, required_on_edit=True),
            Field("site_user", "Remote site user", "The user name for authentication to the remote site, if required. Must correspond to a Splunk stored credential.", required_on_create=False, required_on_edit=False),
            IntegerField("timeout", "Timeout interval", "Time before regarding a download attempt as failed, in seconds.  [Defaults to {0}]".format(self.DEFAULT_TIMEOUT_INTERVAL), required_on_create=True, required_on_edit=True),

            # Proxy options
            RangeField("proxy_port", "Proxy port", "The proxy server port, if required.", low=0, high=65535, required_on_create=False, required_on_edit=False),
            Field("proxy_server", "Proxy server", "The proxy server, if required. Only used by HTTP(S) protocol.", required_on_create=False, required_on_edit=False),
            Field("proxy_user", "Proxy user", "The proxy user name, if required. Must correspond to a Splunk stored credential. Only used by HTTP(s) protocol.", required_on_create=False, required_on_edit=False),

            # Parser options
            Field("delim_regex", "Delimiting regex", "Regular expression used to delimit the input.", required_on_create=False, required_on_edit=False),
            Field("extract_regex", "Extracting regex", "Regular expression used to extract fields from the input.", required_on_create=False, required_on_edit=False),
            Field("fields", "Fields", "The list of fields to extract from the threat list.", required_on_create=False, required_on_edit=False),
            Field("ignore_regex", "Ignoring regex", "Regular expression for lines to be ignored in the threat list.", required_on_create=False, required_on_edit=False),
            Field("skip_header_lines", "Skip header lines", "Number of header lines to skip, if any. [Defaults to {0}]".format(self.DEFAULT_SKIP_HEADER_LINES), required_on_create=False, required_on_edit=False),

            # General processing options - should only be set in default stanza.
            IntegerField("initial_delay", "Initial delay", """Initial delay in seconds before the modular input begins executing, IF not being executed on a cron schedule. Used to alleviate startup load. [Defaults to {0}]""".format(self.DEFAULT_INITIAL_DELAY), required_on_create=False, required_on_edit=False),
            Field("master_host", "Master host", "The master host for this download.", required_on_create=False, required_on_edit=False),
        ]

        self._app = 'SA-ThreatIntelligence'
        self._owner = 'nobody'
        self._name = 'Threatlist'
        
        self._logger = setup_logger(name='threatlist', level=logging.INFO)
        
        super(ThreatlistModularInput, self).__init__(scheme_args, args)

    def get_password(self, user, app, owner):
        credmgr = CredentialManager(self._input_config.session_key)
        return credmgr.get_clear_password(user, '', app, owner)
    
    def get_current_app(self, stanza_name):
        '''Retrieve app for the current stanza.'''

        uri = '/services/data/inputs/threatlist'
        getargs = {'output_mode': 'json', 'search': stanza_name} 
        r, c = splunk.rest.simpleRequest(uri, getargs=getargs, sessionKey=self._input_config.session_key)
        if r.status == 200:
            parsed_content = json.loads(c).get('entry')
            if parsed_content:
                return parsed_content[0]['acl']['app']
            else:
                raise ValueError('Stanza name invalid.')
        else:
            raise ValueError('Could not determine app for current stanza.')
    
    def get_post_args(self, stanza):
        '''Retrieve POST arguments. Right now this is a string expected to
        contain key=value pairs, possibly quoted.
        
        @param stanza: The input stanza.
        '''

        data = {}
        post_args = stanza.get('post_args', {})
        if post_args:
            try:
                data = dict(self.KV_REGEX.findall(post_args))

                # Handle any dynamic POST arguments where we have to retrieve
                # information. Usually this is something like an API key to be
                # retrieved from the secure credential store.
                updated_data = {}

                for post_arg, post_value in data.items():
                    
                    # Strip quotes.
                    if isinstance(post_value, basestring):
                        post_value = post_value.strip('"')
                        updated_data[post_arg] = post_value
                        
                    # Handle form "key=$user:<username>" for API keys where username is not required.
                    arg_match = self.ARG_REGEX.match(post_value)
                    if arg_match:
                        # Right now we only handle custom "user:<username>" arguments.
                        field, value = arg_match.groups()
                        if field == 'user':
                            try:
                                dynamic_value = self.get_password(value, self._app, 'nobody')
                                updated_data[post_arg] = dynamic_value
                            except Exception:
                                self._logger.exception('stanza=%s status="error retrieving user credentials" post_arg="%s" name="%s"', stanza.get('name'), post_arg, value)
                   
                    # Handle simple username retrieval from post_args for TAXII feeds.
                    # If site_user is specified to retrieve a password from an endpoint,
                    # the site_user/site_password combination will be used in preference of this.
                    # This makes it simpler to specify simple "guest" logins.
                    if post_arg == 'taxii_username':
                        if 'taxii_password' not in data:
                            updated_data['taxii_password'] = self.get_password(post_value, self._app, 'nobody')
                            
                    # Handle relative time and timestamp conversions for TAXII feeds.
                    if post_arg == 'earliest' or post_arg == 'latest' and isinstance(post_value, basestring):
                        r, c = splunk.rest.simpleRequest('/services/search/timeparser',
                            getargs={'time': post_value, 
                                     'output_mode': 'json'},
                            sessionKey=self._input_config.session_key)
                        if r.status == 200:
                            updated_data[post_arg] = json.loads(c).get(post_value)
                        else:
                            raise ValueError('Invalid relative time specifier.')

                data.update(updated_data)

            except Exception:
                # Error processing POST arguments. Ignore them.
                self._logger.exception('stanza="%s" status="error processing POST arguments" post_args="%s"', stanza.get('name'), post_args)
    
        return data
    
    def parse_args(self, stanza):
        
        # Get the general arguments.
        args = {'name': stanza.get('name').split('://')[1],
                'retries': stanza.get('retries', self.DEFAULT_RETRIES),
                'retry_interval': stanza.get('retry_interval', self.DEFAULT_RETRY_INTERVAL),
                'type': stanza.get('type'),
                'url': stanza.get('url')
                }

        # handler_args gets the rest of the stanza arguments.
        handler_args = {}
        for k, v in stanza.items():
            if k not in args.keys():
                if isinstance(v, basestring):
                    handler_args[k] = v.strip('"')
                else:
                    handler_args[k] = v

        handler_args['post_data'] = self.get_post_args(stanza)

        # Get the handler.
        if args['type'] == self.HANDLER_TAXII:
            handler_cls = self.PROTOCOL_HANDLERS.get(self.HANDLER_TAXII)
        else:
            handler_cls = self.PROTOCOL_HANDLERS.get(args['url'].split('://')[0])

        # Target filename (only needed for CSV downloads).
        if args['type'] not in self.THREAT_INTEL_EXCLUSIONS:
            # CSV-based threatintel
            args['target_filename'] = os.path.join(self.THREAT_INTEL_TARGET_PATH, args['name'] + '.csv')
        else:
            # Legacy CSV-based threatlists.
            args['target_filename'] = self.gen_checkpoint_filename(args['name'], self._name.lower())

        return handler_cls, args, handler_args

    def download_taxii(self, handler_cls, args, handler_args, checkpoint_data):
        self._logger.info('status="TAXII feed polling starting" stanza="%s"', args['name'])

        handler = handler_cls()

        # Retrieve app name for this stanza in case we need certificates.
        # Unfortunately this requires a REST call.
        handler_args['app'] = self.get_current_app(args['name'])

        if 'last_run' in checkpoint_data:
            # libtaxii requires a tzinfo object for polling.
            handler_args['post_data']['earliest'] = datetime.datetime.fromtimestamp(float(checkpoint_data.get('last_run', 0)), tz=splunk.util.localTZ)

        # This prevents directory traversal attacks since we use the name of the collection as part of the file name.
        if not re.match("[A-Za-z0-9 _.-]+$", handler_args['post_data']['collection']):
            self._logger.error('status="Invalid collection name in TAXII feed specification." stanza="%s"', args['name'])
        else:

            try:
                taxii_message = handler.run(args, handler_args)
                ts = datetime.datetime.now().isoformat().replace(":", "-")
                target_filename = os.path.join(self.THREAT_INTEL_TARGET_PATH, '%s_TAXII_%s_%s.xml' % (args['name'], handler_args['post_data']['collection'], ts))

                try:
                    with open(target_filename, 'w') as f:
                        f.write(taxii_message)
                except IOError:
                    self._logger.exception('status="Exception when writing TAXII document." target_filename="%s"', target_filename)

            except TaxiiHandlerException as e:
                self._logger.exception('status="Exception when polling TAXII feed."')

            self._logger.info('status="Retrieved document from TAXII feed" stanza="%s" collection="%s"', args['name'], handler_args['post_data']['collection'])

    def download_csv(self, handler_cls, args, handler_args):
        '''Download a threat list.
        
        Arguments:
            handler_cls  -  The type of the handler.
            args         - Arguments for the download process
            handler_args - Arguments for the handler.
        '''
        self._logger.info('status="CSV download starting" stanza="%s"', args['name'])
    
        # HTTP handler expects these params:
        # ['site_user', 'app', 'debug', 'owner', 'proxy_port', 'proxy_server', 'proxy_user']

        # The handler's __init__ function will ignore any extraneous parameters.
        # The query must be passed directly to run(), not as a param to __init__.
        # This permits a single handler to be used for multiple HTTP requests.
        handler = handler_cls(self._logger, self._input_config.session_key, **handler_args)
        temp_checkpoint_filehandle = None
        
        retries = args['retries']
        
        while retries >= 0:
            content = handler.run(args['url'], handler_args['post_data'])
            if content:
                try:
                    temp_checkpoint_filehandle = get_temporary_checkpoint_file(args['name'], self._name.lower())                        
                    temp_checkpoint_filehandle.write(content)
                    temp_checkpoint_filehandle.close()
                except IOError:
                    self._logger.exception('stanza="%s" retries_remaining="%s" status="threat list could not be written to temporary file" url="%s"', args['name'], retries, args['url'])
                break
            else:
                self._logger.info('stanza="%s" retries_remaining="%s" status="retrying download" retry_interval="%s" url="%s"', args['name'], retries, args['retry_interval'], args['url'])
                retries -= 1
                time.sleep(args['retry_interval'])
        
        if retries >= 0:
            if temp_checkpoint_filehandle and os.path.isfile(temp_checkpoint_filehandle.name):
                f_stat = os.stat(temp_checkpoint_filehandle.name)
                self._logger.info('stanza="%s" retries_remaining="%s" status="threat list downloaded" file="%s" bytes="%s" url="%s"', args['name'], retries, temp_checkpoint_filehandle.name, f_stat.st_size, args['url'])
                # Move the file into place.
                if os.name in ['nt', 'os2']:
                    try:
                        if os.path.exists(args['target_filename']):
                            os.unlink(args['target_filename'])
                        shutil.move(temp_checkpoint_filehandle.name, args['target_filename'])
                    except Exception:
                        # Catch Exception since this may raise OSError or another WindowsException
                        self._logger.exception('stanza="%s" status="threat list could not be written to disk"', args['name'])
                else:
                    try:
                        shutil.move(temp_checkpoint_filehandle.name, args['target_filename'])
                    except IOError:
                        self._logger.exception('stanza="%s" status="threat list could not be written to disk"', args['name'])
            else:
                # Should never get here.
                self._logger.info('stanza="%s" retries_remaining="%s" status="threat list download succeeded but failed writing to disk" url="%s"', args['name'], retries, args['url'])
        else:
            # File could not be downloaded after multiple retries.
            self._logger.info('stanza="%s" retries_remaining="%s" status="threat list download failed after multiple retries" url="%s"', args['name'], retries, args['url'])

        # Clean any stray checkpoint files.
        try:
            if temp_checkpoint_filehandle and os.path.isfile(temp_checkpoint_filehandle.name):
                os.unlink(temp_checkpoint_filehandle.name)
        except IOError:
            self._logger.exception('stanza="%s" status="temporary threat list file could not be deleted"', args['name'])

    def run(self, stanza, *args, **kwargs):

        self._logger.debug("Entering run method.")
        self._logger.debug("Input configuration: %s", str(self._input_config))
        self._logger.debug("Cleaned parameters: %s", str(stanza))

        # Permit testing from command line.
        if getattr(self, '_alt_session_key', False):
            self._input_config.session_key = self._alt_session_key
        
        # Check for existence of checkpoint directory.
        if not os.path.isdir(self._input_config.checkpoint_dir):
            os.mkdir(self._input_config.checkpoint_dir)

        # Check for existence of target directory
        if not os.path.isdir(self.THREAT_INTEL_TARGET_PATH):
            os.makedirs(self.THREAT_INTEL_TARGET_PATH)

        # Detect if we are the master host.
        # SOLNESS-5856: Threatlist downloads should occur on all hosts in SHC pool.
        # Revert this change if/when modinputs become KV-store aware.
        exec_status = True

        if exec_status and stanza:
            self._logger.debug('status="proceeding" msg="this modinput always executes on all hosts"')

            current_time = time.time()

            if any([d in stanza.get('name', '') for d in self.DEPRECATED_STANZAS]):
                self._logger.info('status="exiting" msg="Ignoring deprecated stanza" name="%s"' % stanza.get('name', 'unknown'))
            elif stanza.get('name') and not re.match("threatlist://[A-Za-z0-9 _-]+$", stanza.get('name')):
                # This avoids path traversals by ignoring processing for stanzas with special characters.
                self._logger.error('status="exiting" msg="Ignoring stanza with invalid name" name="%s"' % stanza.get('name', 'unknown'))
            else:
                self._logger.info('status="continuing" msg="Processing stanza" name="%s"' % stanza.get('name', 'unknown'))
                handler_cls, args, handler_args = self.parse_args(stanza)

                status_filename = args['name'] + '_status'

                # Retrieve last run timestamp (used to scope TAXII feed requests).
                checkpoint_data = self.get_checkpoint_data(status_filename) or {}
                if checkpoint_data:
                    self._logger.info('status="retrieved_checkpoint_data" stanza="%s" last_run="%s"', args['name'], checkpoint_data.get('last_run', 'unknown'))
                else:
                    self._logger.info('status="no_checkpoint_data" stanza="%s"', args['name'])

                if handler_cls == NoopProtocolHandler:
                    # Do nothing. This is a "lookup" based threatlist.
                    return
                elif handler_cls == TaxiiHandler:
                    self.download_taxii(handler_cls, args, handler_args, checkpoint_data)
                elif handler_cls:
                    self.download_csv(handler_cls, args, handler_args)

                # Set checkpoint data.
                self.set_checkpoint_data(status_filename, {'last_run': current_time})

        else:
            # Exit the script if the host is a pool member but not
            # designated as the master host for this input.
            self._logger.info('status="exiting" msg="not master host"')

if __name__ == '__main__':
    modinput = ThreatlistModularInput()
    modinput.execute()
