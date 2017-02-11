import httplib2
import json
import sys

import splunktalib.rest as sr

import splunktaucclib.common.log as stulog


class APIError(Exception):
    def __init__(self, status, error_code, error_msg):
        self.status = status
        self.error_code = error_code
        self.error_msg = error_msg

    def __str__(self):
        return repr(
            'status={status}, error_code={error_code}, error_msg={error_msg}'.format(
                status=self.status,
                error_code=self.error_code,
                error_msg=self.error_msg))


class SecurityCenter(object):
    def __init__(self,
                 server_url,
                 disable_ssl_certificate_validation,
                 proxy_config=None,
                 pre='rest/',
                 logger_prefix=None):
        self._server_url = server_url
        self._proxy_config = proxy_config
        self._pre = pre
        self._token = None
        self._cookie = None
        self._timeout = 120
        self._disable_ssl_certificate_validation = disable_ssl_certificate_validation
        self._logger_prefix = logger_prefix

    def get_server_url(self):
        return self._server_url

    def login(self, username, password):
        data = {'username': username, 'password': password}
        result = self.perform_request('POST', 'token', data)
        self._token = str(result['token'])

    def logout(self):
        self.perform_request('DELETE', 'token')
        self._token = None
        self._cookie = None

    def analysis(self, limit=sys.maxint - 1, *query_filters, **kwargs):
        self._build_query(query_filters, kwargs)

        received = 0
        step = 1000
        kwargs['query']['startOffset'] = 0
        kwargs['query']['endOffset'] = 0
        total = limit

        while (received < limit) and (received < total):
            # If my endOffset is larger than max, set it to max.
            if received + step > limit:
                kwargs['query']['endOffset'] = limit
            else:
                kwargs['query']['endOffset'] += step

            result = self.perform_request('POST', 'analysis', kwargs)
            received += int(result['returnedRecords'])
            total = int(result['totalRecords'])

            yield result['results']

            kwargs['query']['startOffset'] = kwargs['query']['endOffset']

    def get_vulns(self, scan_id, start_offset, end_offset):
        args = {'type': 'vuln',
                'sourceType': 'individual',
                'scanID': scan_id,
                'query_type': 'vuln',
                'query_tool': 'vulndetails',
                'query_view': 'all'}
        self._build_query(None, args)
        args['query']['startOffset'] = start_offset
        args['query']['endOffset'] = end_offset
        result = self.perform_request('POST', 'analysis', args)
        self._expand_see_also(result['results'])
        self._expand_xref(result['results'])
        return result['results']

    def get_total_records_for_vuln(self, scan_id):
        args = {'type': 'vuln',
                'sourceType': 'individual',
                'scanID': scan_id,
                'query_type': 'vuln',
                'query_tool': 'listvuln',
                'query_view': 'all'}
        self._build_query(None, args)
        args['query']['startOffset'] = 0
        args['query']['endOffset'] = 0
        result = self.perform_request('POST', 'analysis', args)
        return int(result['totalRecords'])

    def get_scan_result(self, scan_id):
        return self.perform_request('GET', 'scanResult/{}'.format(scan_id))

    def perform_request(self, method, path, data=None):
        # build headers
        headers = {'Content-Type': 'application/json'}
        if self._token is not None:
            headers['X-SecurityCenter'] = self._token
        if self._cookie is not None:
            headers['Cookie'] = self._cookie

        # Only convert the data to JSON if there is data.
        if data is not None:
            data = json.dumps(data)

        # make a request
        if self._proxy_config:
            http = sr.build_http_connection(
                config=self._proxy_config,
                timeout=self._timeout,
                disable_ssl_validation=
                self._disable_ssl_certificate_validation)
        else:
            http = httplib2.Http(timeout=self._timeout,
                                 disable_ssl_certificate_validation=
                                 self._disable_ssl_certificate_validation)

        response, content = http.request(
            self._uri(path), method, data, headers)

        if path.find('download') != -1:
            return content

        result = json.loads(content)

        self._error_check(response, result)

        set_cookie = response.get('set-cookie')

        if set_cookie:
            self._cookie = set_cookie[set_cookie.find(',') + 1:].strip()
            stulog.logger.debug('{} set-cookie={}'.format(self._logger_prefix,
                                                          set_cookie))
            stulog.logger.debug('{} self._cookie={}'.format(
                self._logger_prefix, self._cookie))

        return result['response']

    def _uri(self, path):
        if self._server_url.endswith('/'):
            return '{server_url}{pre}{path}'.format(
                server_url=self._server_url,
                pre=self._pre,
                path=path)
        else:
            return '{server_url}/{pre}{path}'.format(
                server_url=self._server_url,
                pre=self._pre,
                path=path)

    @classmethod
    def _expand_see_also(cls, vuln_lst):
        for vuln in vuln_lst:
            see_also = vuln.get('seeAlso')
            if not see_also:
                vuln['seeAlso'] = []
                continue
            else:
                vuln['seeAlso'] = see_also.split()

    @classmethod
    def _expand_xref(cls, vuln_lst):
        for vuln in vuln_lst:
            xref = vuln.get('xref')
            if not xref:
                vuln['xref'] = []
                continue
            else:
                vuln['xref'] = xref.split(',')

    @classmethod
    def _error_check(cls, response, result):
        if response.status != 200 or result['error_code'] != 0:
            raise APIError(response.status, result['error_code'],
                           result['error_msg'])

    @classmethod
    def _build_query(cls, query_filters, kwargs):
        if 'query' not in kwargs:
            kwargs['query'] = {}
            for k, v in kwargs.items():
                if not isinstance(k, str):
                    continue
                if k.find('query_') == 0:
                    kwargs['query'][k[6:]] = v
                    del kwargs[k]
            if not query_filters:
                return
            kwargs['query']['filters'] = [{'filterName': f[0],
                                           'operator': f[1],
                                           'value': f[2]}
                                          for f in query_filters]


def get_security_center(url,
                        disable_ssl_certificate_validation,
                        username,
                        password,
                        proxy_config=None,
                        logger_prefix=None):
    sc = SecurityCenter(url,
                        disable_ssl_certificate_validation,
                        proxy_config,
                        logger_prefix=logger_prefix)
    sc.login(username, password)
    return sc


def return_security_center(sc):
    sc.logout()
