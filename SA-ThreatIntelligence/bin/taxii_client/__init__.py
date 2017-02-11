import logging
import os
import re
import sys

from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-ThreatIntelligence", "contrib"]))

import libtaxii
import libtaxii.clients as tc
import libtaxii.messages_11 as tm11

logger = logging.getLogger('threatlist')


class TaxiiHandlerException(Exception):
    pass


class TaxiiHandler(object):

    def _clean_taxii_message(self, msg):
        return msg.to_text().replace('\n', ' ').replace('\r', ' ')

    def _poll_taxii_11(self, args):
        '''Poll a TAXII 1.1 feed and return a generator over the content blocks found.
        
        Arguments:
            args - A dictionary of arguments.
        
        '''
        
        app = args.get('app')
        cert_file = args.get('cert_file')
        key_file = args.get('key_file')
        username = args.get('username')
        password = args.get('password')
        

        if app and cert_file and key_file:
            cert_file_path = make_splunkhome_path(["etc", "apps", app, "auth", cert_file])
            key_file_path = make_splunkhome_path(["etc", "apps", app, "auth", key_file])

            if not (os.path.exists(cert_file_path) and os.path.exists(key_file_path)):
                logger.info("Certificate not found - falling back to AUTH_BASIC.")
                cert_file_path = key_file_path = None
        else:
            logger.info("Certificate information incomplete - falling back to AUTH_BASIC.")
            cert_file_path = key_file_path = None

        client = tc.HttpClient()
        client.set_use_https(args.get('use_ssl'))

        # Add proxy parameters if present.
        if 'proxy' in args:
            client.set_proxy(args['proxy'])

        if cert_file_path and key_file_path and username:
            logger.info("Auth Type: AUTH_CERT_BASIC")
            client.set_auth_type(tc.HttpClient.AUTH_CERT_BASIC)
            client.set_auth_credentials({'username': username, 'password': password, 'cert_file': cert_file_path, 'key_file': key_file_path})
        elif cert_file_path and key_file_path:
            logger.info("Auth Type: AUTH_CERT")
            client.set_auth_type(tc.HttpClient.AUTH_CERT)
            client.set_auth_credentials({'cert_file': cert_file_path, 'key_file': key_file_path})
        else:
            logger.info("Auth Type: AUTH_BASIC")
            client.set_auth_type(tc.HttpClient.AUTH_BASIC)
            client.set_auth_credentials({'username': username, 'password': password})
        
        poll_request = tm11.PollRequest(tm11.generate_message_id(),
            collection_name=args.get('collection'),
            exclusive_begin_timestamp_label=args.get('earliest'),
            #inclusive_end_timestamp_label=args.get('latest'),
            poll_parameters=tm11.PollParameters())
    
        poll_xml = poll_request.to_xml()

        http_resp = client.call_taxii_service2(args.get('url'), args.get('service'), tm11.VID_TAXII_XML_11, poll_xml, port=args.get('port'))

        taxii_message = libtaxii.get_message_from_http_response(http_resp, poll_request.message_id)
        if http_resp.getcode() == 200:
            if hasattr(taxii_message, 'content_blocks'):
                return taxii_message.to_xml()
            else:
                raise TaxiiHandlerException('Exception when polling TAXII feed (no content returned): %s' % self._clean_taxii_message(taxii_message))
        else:
            raise TaxiiHandlerException('Exception when polling TAXII feed: %s' % self._clean_taxii_message(taxii_message))

    def _parse_args(self, args, handler_args):
        '''Parse and validate TAXII-specific arguments.
        
        Arguments:
            args         - A dictionary of arguments.
            handler_args - A dictionary of handler-specific arguments.

        Returns:
            The dictionary populated with the arguments.

        Expected arguments:
            
            earliest    - A timestamp representing the earliest time to retrieve from the feed (optional)
            collection  - The TAXII collection (required)
            latest      - A timestamp representing the latest time to retrieve from the feed (optional)
            service     - The TAXII service (required, inferred from URL)
            proxy_port   - A proxy port (optional)
            proxy_server - A proxy server (optional)
            site_password    - A password for authenticating to the remote site (optional)
            site_user    - A user for authenticating to the remote site (optional)
            use_ssl     - Whether to use SSL (required, inferred from URL)
        ''' 

        parsed_args = {}

        # URL
        rx = re.compile('^(?P<proto>http|https)://(?P<url>[^/:]+):?(?P<port>\d{1,5})?/(?P<service>.+)$')

        components = rx.search(args['url'])
        if components:
            c = components.groupdict()
            parsed_args['service'] = c['service'] if c['service'].startswith('/') else '/' + c['service']
            parsed_args['url'] = components.groupdict()['url']
            parsed_args['port'] = components.groupdict()['port']
            parsed_args['use_ssl'] = components.groupdict()['proto'] == 'https'
        else:
            raise TaxiiHandlerException('Invalid arguments for TAXII service (bad URL).')
        
        parsed_args['collection'] = handler_args['post_data'].get('collection', '')
        if not parsed_args['collection']:
            raise TaxiiHandlerException('Invalid arguments for TAXII service (missing collection).')
        
        # TODO: Proxy server support.
        if handler_args.get('proxy_port') and handler_args.get('proxy_server'):
            # Right now only proxy over HTTP is supported, not HTTPS.
            # Also, authenticated proxies are not supported by underlying libtaxii library.
            parsed_args['proxy'] = 'http://%s:%s' % (handler_args['proxy_server'], handler_args['proxy_port'])

        # Remote TAXII authentication.
        if handler_args.get('site_user') and handler_args.get('site_password'):
            parsed_args['username'] = handler_args['site_user']
            parsed_args['password'] = handler_args['site_password']
        elif handler_args['post_data'].get('taxii_username') and handler_args['post_data'].get('taxii_password'):
            parsed_args['username'] = handler_args['post_data']['taxii_username']
            parsed_args['password'] = handler_args['post_data']['taxii_password']
            
        if handler_args['post_data'].get('earliest'):
            parsed_args['earliest'] = handler_args['post_data']['earliest']

        if handler_args['post_data'].get('latest'):
            parsed_args['latest'] = handler_args['post_data']['latest']

        # Certificate authentication for TAXII feeds.
        if handler_args.get('app', ''):
            parsed_args['app'] = handler_args['app']
        if handler_args['post_data'].get('cert_file', ''):
            parsed_args['cert_file'] = handler_args['post_data']['cert_file']
        if handler_args['post_data'].get('key_file', ''):
            parsed_args['key_file'] = handler_args['post_data']['key_file']

#         if parsed_args['earliest'] and 'latest' not in parsed_args:
#             parsed_args['latest'] = datetime.datetime.now()

        return parsed_args
    
    def run(self, args, handler_args):
        parsed_args = self._parse_args(args, handler_args)
        return self._poll_taxii_11(parsed_args)
