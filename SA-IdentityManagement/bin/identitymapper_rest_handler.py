import collections
import itertools
import logging
import sys
import operator
import json
import httplib
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.clilib.bundle_paths import make_splunkhome_path
import splunk.search

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.log import setup_logger, SHORT_FORMAT
logger = setup_logger('identitymapper', format=SHORT_FORMAT, level=logging.INFO)

if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)


class IdentityMapperErrors(object):
    '''Enum for error strings.'''
    ERR_INVALID_ARG = 'Invalid argument provided'
    ERR_INVALID_ARGC = 'Invalid argument count provided'
    ERR_INVALID_CONSTRAINT_METHOD = 'Invalid constraint method requested'
    ERR_INVALID_CONSTRAINT_FIELD = 'Invalid constraint field requested'


class IdentityMapper(PersistentServerConnectionApplication):
    '''IdentityMapper Controller'''

    CONSTRAINT_METHOD_ASSET = 'reverse_asset_lookup'
    CONSTRAINT_METHOD_IDENTITY = 'reverse_identity_lookup'
    CONSTRAINT_METHOD_DEFAULT = 'string'
    CONSTRAINT_METHODS = [CONSTRAINT_METHOD_ASSET, CONSTRAINT_METHOD_IDENTITY, CONSTRAINT_METHOD_DEFAULT]

    ASSET_SUBJECT_FIELDS = ['src', 'dest', 'dvc', 'host', 'orig_host', 'risk_object', 'threat_match_value']
    ASSET_RESULT_FIELDS = ['ip', 'nt_host', 'dns', 'mac']

    IDENTITY_SUBJECT_FIELDS = ['user', 'src_user', 'risk_object', 'threat_match_value']
    IDENTITY_RESULT_FIELDS = ['identity']

    REVERSE_ASSET_SEARCH_TEMPLATE = '| `reverse_asset_lookup("{}")`'
    REVERSE_IDENTITY_SEARCH_TEMPLATE = '| `reverse_identity_lookup("{}")`'

    RequestTuple = collections.namedtuple('RequestTuple', field_names=['value', 'constraint_method', 'subject_field_sets'])

    def __init__(self, command_line, command_arg):
        super(IdentityMapper, self).__init__()

    def handle(self, in_string):
        args = json.loads(in_string)
        logger.debug('ARGS: %s', args)

        try:
            logger.info('Handling %s request.' % args['method'])
            method = 'handle_' + args['method'].lower()
            if callable(getattr(self, method, None)):
                return operator.methodcaller(method, args)(self)
            else:
                return ('Invalid method for this endpoint', httplib.METHOD_NOT_ALLOWED)

        except ValueError as e:
            msg = 'ValueError: %s' % e.message
            return self.response(msg, httplib.BAD_REQUEST)
        except splunk.RESTException as e:
            return self.response('RESTexception: %s' % e, httplib.INTERNAL_SERVER_ERROR)
        except Exception as e:
            msg = 'Unknown exception: %s' % e
            logger.exception(msg)
            return self.response(msg, httplib.INTERNAL_SERVER_ERROR)

    @staticmethod
    def response(msg, status):
        """
        Return a dict for endpoint REST response.

        Arguments:
        msg -- Result of the request
        status -- HTTP response status
        """

        if status < 400:
            payload = msg
        else:
            # replicate controller's jsonresponse format
            payload = {
                "success": False,
                "offset": 0,
                "count": 0,
                "total": 0,
                "messages": [{'type': 'ERROR', 'message': msg}],
                "data": [],
            }
        return {'status': status, 'payload': payload}

    def result_to_dict(self, resultset):
        '''Take a splunk.search.ResultSet object and turn it into a dictionary
        that has a simple representation.

        Return: A dictionary of field values.
        '''
        result = {}
        for key, multivalued_field in resultset.fields.iteritems():
            result[key] = [str(field) for field in multivalued_field]
        return result

    def get_search_params(self, value, constraint_method):
        '''Return the search template and result fields to be used in search clause generation.

        Arguments:
            value - The value
            constraint_method - A constraint method as defined in self.CONSTRAINT_METHODS.

        Returns:
            A tuple (<search_template>, [result_field, ...])

        Throws:
            ValueError if invalid constraint_method is provided.
        '''

        if constraint_method == self.CONSTRAINT_METHOD_ASSET:
            return self.REVERSE_ASSET_SEARCH_TEMPLATE.format(value), self.ASSET_RESULT_FIELDS
        elif constraint_method == self.CONSTRAINT_METHOD_IDENTITY:
            return self.REVERSE_IDENTITY_SEARCH_TEMPLATE.format(value), self.IDENTITY_RESULT_FIELDS
        elif constraint_method == self.CONSTRAINT_METHOD_DEFAULT:
            return '', ''
        else:
            # Should never get here
            raise ValueError(IdentityMapperErrors.ERR_INVALID_CONSTRAINT_METHOD)

    def run_search(self, request_tuple, session_key=None):
        '''Run reverse lookup searches and return the results.

        Arguments:
            requestTuple - A list of RequestTuple objects.
            constraint_method - A valid constraint method.

        Returns:
            A Python dictionary representing the results for each search.

        Throws:
            splunk.SearchException if the search fails.
        '''

        rv = {'count': 0, 'clauses': [], 'original_value': None, 'records': [], 'success': False}

        if request_tuple.constraint_method in [self.CONSTRAINT_METHOD_ASSET, self.CONSTRAINT_METHOD_IDENTITY]:

            if request_tuple.value:
                rv['original_value'] = request_tuple.value
                search_string, result_fields = self.get_search_params(request_tuple.value, request_tuple.constraint_method)

                srch = splunk.search.dispatch(search_string, sessionKey=session_key)

                for result in srch.results:
                    rv['count'] += 1
                    for subject_field_set in request_tuple.subject_field_sets:
                        # Clauses must be parenthesized.
                        rv['clauses'].append('(' + ' OR '.join(['{}="{}"'.format(s, asset) for k, v in result.fields.iteritems() if k in result_fields for asset in v for s in subject_field_set]) + ')')
                    # Note that the object returned by a search is a ResultSet with ResultField(s).
                    # ResultFields are iterable and thus handle multivalued fields via iteration.
                    # They do not need to be split into strings, although when printed they
                    # appear as CSV strings - this is misleading. Convert to dictionary here.
                    rv['records'].append(self.result_to_dict(result))

        if rv['count'] > 0:
            rv['success'] = True
        else:
            # Either a reverse asset or identity lookup returned no results
            # for a lane, or this is a string expansion request. Return a
            # default search clause for each of the requested lanes.
            # success=true is returned in this case since we do return a
            # valid clause.
            rv['success'] = True
            for subject_field_set in request_tuple.subject_field_sets:
                rv['clauses'].append('(' + ' OR '.join(['{}="{}"'.format(field, request_tuple.value) for field in subject_field_set]) + ')')

        return rv

    def get_subject_fields(self, fields, constraint_method):
        '''Filter the list of fields by validity. Only certain fields known as
        "subject" fields can be included in a reverse lookup search string.

        Arguments:
            fields -- A field or list of fields.
            constraint_method -- The constraint method.

        Returns:
            A tuple ([field, ...], normalized_constraint_method).

        Throws:
            AttributeError, TypeError, or ValueError if the input parameters are ill-formed.
        '''

        # Normalize the input fields to a list, stripping quotes and spaces.
        # Also handle instances where the "fields" parameter is comma-separated.
        # Exceptions here should be caught by the caller.
        if isinstance(fields, basestring):
            # URI had only one "fields" parameter, possibly comma-separated.
            fields = set([field.strip('" ') for field in fields.split(',')])
        elif isinstance(fields, list):
            # URI had multiple "fields" parameters, each possibly comma-separated.
            fields = set([j.strip('" ') for j in [itertools.chain.from_iterable([i.split(',') for i in fields])]])
        else:
            # Should never get here.
            raise ValueError(IdentityMapperErrors.ERR_INVALID_ARG)

        # Normalize the constraint method
        normalized_constraint_method = constraint_method.strip('" ')
        if normalized_constraint_method not in self.CONSTRAINT_METHODS:
            raise ValueError(IdentityMapperErrors.ERR_INVALID_CONSTRAINT_METHOD)

        # For each field, check that the field is not zero-length and is valid for the constraint method.
        # Invalid fields are discarded. Valid fields are returned in subject_fields.
        subject_fields = []
        for field in filter(lambda x: x, fields):

            if normalized_constraint_method == self.CONSTRAINT_METHOD_DEFAULT:
                # Default behavior is to accept all fields. This allows the
                # construction of arbitrary key=value search strings. Templating
                # of the generated search clause is not currently supported.
                subject_fields.append(field)
            else:
                # Validate the fields if a reverse asset or identity lookup was requested.
                # Allow fields in object_name.field format.
                subject_field = field.rsplit('.', 1)[-1]

                if normalized_constraint_method == self.CONSTRAINT_METHOD_ASSET and subject_field in self.ASSET_SUBJECT_FIELDS:
                    subject_fields.append(field)
                elif normalized_constraint_method == self.CONSTRAINT_METHOD_IDENTITY and subject_field in self.IDENTITY_SUBJECT_FIELDS:
                    subject_fields.append(field)
                else:
                    # Invalid constraint field requested for the constraint method.
                    raise ValueError(IdentityMapperErrors.ERR_INVALID_CONSTRAINT_FIELD)

        return subject_fields

    def validate_args(self, value, constraint_method, constraint_fields):
        '''Validate input arguments.

        Arguments:
            values - A value for the reverse entity lookups on.
            constraint_method - A single constraint method.
            constraint_fields - A list of lists of fields (as comma-separated
                strings) to include in the generated search clause.

        Returns:
            An EntityTuple namedtuple containing the valid requests sorted by constraint method.
        '''

        if constraint_fields and isinstance(constraint_fields, basestring):
            constraint_fields = [constraint_fields]
        elif constraint_fields and isinstance(constraint_fields, list):
            pass
        else:
            raise ValueError(IdentityMapperErrors.ERR_INVALID_ARGC)

        if value and isinstance(value, basestring) and constraint_method and isinstance(constraint_method, basestring):
            subject_field_sets = [self.get_subject_fields(cf, constraint_method) for cf in constraint_fields]
        else:
            raise ValueError(IdentityMapperErrors.ERR_INVALID_ARGC)

        return self.RequestTuple(value, constraint_method, subject_field_sets)

    def reverse_lookup(self, value, constraint_fields, constraint_method, session_key=None):
        """
        Arguments:
        values - An identifier or list of identifiers.
        constraint_fields - A list or list of lists of fields to use in the
            generated search.
        constraint_method - The type of reverse lookup (reverse_asset_lookup, reverse_identity_lookup, or string).

        Returns: A JSON object.
        """

        logger.debug('request: value=%s, constraint_fields=%s, constraint_method=%s', value, constraint_fields, constraint_method)

        try:
            request_tuple = self.validate_args(value, constraint_method, constraint_fields)
            logger.debug('request: request_tuple=%s', request_tuple)
        except (AttributeError, TypeError, ValueError) as exc:
            msg = 'Invalid request: value="{}" constraint_fields="{}" constraint_methods="{}" exc="{}"'.format(value, constraint_fields, constraint_method, exc)
            logger.exception(msg)
            return self.response(msg, httplib.BAD_REQUEST)

        try:
            # List comprehension filters out constraint methods that have no corresponding input.
            return self.response(self.run_search(request_tuple, session_key), httplib.OK)
        except Exception as exc:
            msg = 'Reverse lookup failed: value="{}" constraint_fields="{}" constraint_methods="{}" exc="{}"'.format(value, constraint_fields, constraint_method, exc)
            logger.exception(msg)
            return self.response(msg, httplib.INTERNAL_SERVER_ERROR)

    def get_query_params(self, query):
        """
        Constructs hashmap from query params array. Handles multiple values for one param.

        Arguments:
            query - contains key value pairs for query string parameters, extracted from args.get('query')
                          [[key1, val1], [key2, val2], ...]
        Returns
            dict - dict containing params 
                   {key: val} for single value params. 
                   {key: [val1, val2, ...]} for multi-value params.
        """
        params = {}
        for key, val in query:
            if key in params and not isinstance(params[key], list):
                params[key] = [params[key], val]
            elif key in params:
                params[key].append(val)
            else:
                params[key] = val
        return params

    def handle_get(self, args):
        query = self.get_query_params(args.get('query', []))
        try:
            session_key = args["session"]["authtoken"]
        except KeyError:
            return self.response("Failed to obtain auth token", httplib.UNAUTHORIZED)

        required = ["value", "constraint_fields", "constraint_method"]
        missing = [r for r in required if r not in query]
        if missing:
            return self.response("Missing required arguments: %s" % missing, httplib.BAD_REQUEST)

        value = query.pop('value')
        constraint_fields = query.pop('constraint_fields')
        constraint_method = query.pop('constraint_method')
        return self.reverse_lookup(value, constraint_fields, constraint_method, session_key)
