import copy
import httplib
import json
import logging
import re
import sys
import urllib

if sys.platform == "win32":
    import os, msvcrt
    msvcrt.setmode(sys.stdin.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    msvcrt.setmode(sys.stderr.fileno(), os.O_BINARY)

import splunk
import splunk.admin
import splunk.rest
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(['etc', 'apps', 'SA-Utils', 'lib']))
from SolnCommon.log import setup_logger, SHORT_FORMAT
logger = setup_logger('identity_correlation_rest_handler', level=logging.INFO, format=SHORT_FORMAT)


class AutomaticLookup(object):
    """Wrapper class for data/props/lookups, used in creation of automatic lookups."""

    LOOKUP_URI_BASE = '/servicesNS/{owner}/{namespace}/data/props/lookups'
    LOOKUP_URI_FULL = '/servicesNS/{owner}/{namespace}/data/props/lookups/{name}'

    @staticmethod
    def list(owner, namespace, session_key):
        """
        List automatic lookups.

        :param owner: A Splunk user.
        :type owner: str
        :param namespace: A Splunk namespace.
        :type namespace: str
        :param session_key: A Splunk session key.
        :type session_key: str

        :return: A dictionary of automatic lookup definitions by their URL-decoded stanza names.
        :rtype dict
        """

        uri = AutomaticLookup.LOOKUP_URI_BASE.format(owner=owner, namespace=namespace)
        r, c = splunk.rest.simpleRequest(uri, getargs={'output_mode': 'json', 'count': 0}, sessionKey=session_key)
        return {v['name']: v for v in json.loads(c)['entry']}

    @staticmethod
    def fullname(stanza_name, class_name):
        """
        Return the correct identifier for a lookup given the containing stanza name and class name.

        :param stanza_name: The name of the props.conf stanza, e.g. "sourcetype=abcd".
        :type stanza_name: str
        :param class_name:The user-definable portion of the lookup parameter name, e.g. "LOOKUP-<class_name>".
        :type class_name: str

        :return URL-encoded string representing the lookup table identifier.
        :rtype str
        """
        if stanza_name and class_name and isinstance(stanza_name, basestring) and isinstance(class_name, basestring):
            return urllib.quote('%s : LOOKUP-%s' % (stanza_name, class_name))
        else:
            raise ValueError("Lookup table identifier requires non-empty stanza name and class name.")

    @classmethod
    def create(cls, stanza_name, class_name, transform_name, infield, outfields, owner, namespace, session_key, overwrite=False):
        """
        Enable an automatic lookup.
        :param stanza_name: The name of the props.conf stanza, e.g. "sourcetype=abcd".
        :type stanza_name: str
        :param class_name: The user-definable portion of the lookup parameter name, e.g. "LOOKUP-<class_name>".
        :type class_name: str
        :param transform_name: The name of the transform, e.g. "asset_lookup_by_str".
        :type transform_name: str
        :param infield:  An input field name.
        :type infield: str
        :param outfields: A list of output fields.
        :type outfields: list[str]
        :param owner: A Splunk user.
        :type owner: str
        :param namespace: A Splunk app.
        :type namespace: str
        :param session_key: A Splunk session key.
        :type session_key: str
        :param overwrite: If True, use OUTPUT in the lookup definition. If False, use OUTPUTNEW.
        :type overwrite: bool

        :return A tuple (<bool_status>, <response>, <content>)
        :rtype tuple
        """

        uri = cls.LOOKUP_URI_BASE.format(owner=owner, namespace=namespace)
        postargs = {'name': class_name,
                    'transform': transform_name,
                    'overwrite': overwrite,
                    'stanza': stanza_name,
                    'output_mode': 'json'}

        # Add output field arguments. Output field renaming works like this:
        #
        #   'lookup.field.output.ip': 'src_ip'
        #
        # results in:
        #
        #   <lookup_name> ip AS src_ip
        #
        for outfield in outfields:
            postargs["lookup.field.output.%s" % outfield] = "_".join([infield, outfield])

        # Add input field arguments. Input field renaming works like this:
        #
        #   'lookup.field.input.src': 'key'
        #
        # results in:
        #
        #   <lookup_name> key AS src
        #
        postargs["lookup.field.input.key"] = infield

        # Set OUTPUTNEW if necessary:
        #   overwrite == True  --> 0 --> OUTPUT
        #   overwrite == False --> 1 --> OUTPUTNEW
        postargs["overwrite"] = 0 if overwrite else 1

        try:
            r, c = splunk.rest.simpleRequest(uri, sessionKey=session_key, postargs=postargs)
            if r.status == httplib.CONFLICT:
                # 409 error. The automatic lookup already existed. Update with new settings.
                uri = cls.LOOKUP_URI_FULL.format(owner=owner,
                                                 namespace=namespace,
                                                 name=cls.fullname(stanza_name, class_name))
                # Drop unnecessary parameters.
                del postargs['name']
                del postargs['stanza']
                r, c = splunk.rest.simpleRequest(uri, sessionKey=session_key, postargs=postargs, raiseAllErrors=True)
        except splunk.RESTException:
            raise

        return r.status == httplib.CREATED or r.status == httplib.OK, r, c

    @classmethod
    def delete(cls, stanza_name, class_name, owner, namespace, session_key, **ignored_kwargs):
        """
        Delete an automatic lookup.

        :param stanza_name: The name AKA "spec" of the props.conf stanza.
        :type stanza_name: str
        :param class_name: The user-definable portion of the lookup parameter name, e.g. "LOOKUP-<class_name>"
        :type class_name: str
        :param owner: A Splunk user.
        :type owner: str
        :param namespace: A Splunk app.
        :type namespace: str
        :param session_key: A Splunk session key
        :type session_key: str

        :return A tuple (<bool_status>, <response>, <content>)
        :rtype tuple
        """

        uri = cls.LOOKUP_URI_FULL.format(owner=owner,
                                         namespace=namespace,
                                         name=cls.fullname(stanza_name, class_name))
        postargs = {'output_mode': 'json'}

        try:
            # 400 error indicates the lookup does not exist.
            # 403 error indicates invalid authentication OR attempt to delete an automatic lookup that only exists in
            # default/props.conf.
            r, c = splunk.rest.simpleRequest(uri, sessionKey=session_key, postargs=postargs, method="DELETE", raiseAllErrors=True)
        except splunk.RESTException:
            raise

        return r.status == httplib.OK, r, c


class CorrelationSpec(object):
    """Simple container for the information required to create a specific automatic lookup related to asset/identity
    correlation."""

    ID = None
    LOOKUP_STR = None
    LOOKUP_STR_PREFIX = None
    LOOKUP_CIDR = None
    LOOKUP_CIDR_PREFIX = None

    DEFAULT_FIELDS = None
    VALID_INFIELDS = None

    @classmethod
    def class_prefix(cls, use_cidr=False):
        """Return a formatted class name prefix for the automatic lookup specification."""
        return cls.class_name('', use_cidr)

    @classmethod
    def class_name(cls, infield, use_cidr=False):
        """Return a formatted class name for the automatic lookup specification."""
        fmt = '{order}-{lookup}-{infield}'
        if use_cidr:
            return fmt.format(order=cls.LOOKUP_CIDR_PREFIX,
               lookup=cls.LOOKUP_CIDR,
               infield=infield)
        else:
            return fmt.format(order=cls.LOOKUP_STR_PREFIX,
               lookup=cls.LOOKUP_STR,
               infield=infield)

    @classmethod
    def transform_name(cls, use_cidr=False):
        """Return the transform name for the automatic lookup specification.

        :param use_cidr: If True, return the CIDR lookup name (may be None). If False, return the string-based lookup
            table name.
        :type use_cidr: bool

        :return A string representing the name of a lookup table stanza in transforms.conf.
        :rtype str
        """
        return cls.LOOKUP_CIDR if use_cidr else cls.LOOKUP_STR


class AssetCorrelationSpec(CorrelationSpec):
    """Class for holding asset correlation constants."""

    DEFAULT_FIELDS = ("asset_id",
                      "asset_tag",
                      "bunit",
                      "category",
                      "city",
                      "country",
                      "dns",
                      "ip",
                      "is_expected",
                      "lat",
                      "long",
                      "mac",
                      "nt_host",
                      "owner",
                      "pci_domain",
                      "priority",
                      "requires_av",
                      "should_timesync",
                      "should_update")
    ID = "asset"

    LOOKUP_STR = "asset_lookup_by_str"
    LOOKUP_STR_PREFIX = "zu"
    LOOKUP_CIDR = "asset_lookup_by_cidr"
    LOOKUP_CIDR_PREFIX = "zv"

    VALID_INFIELDS = ("dest", "dvc", "src")


class IdentityCorrelationSpec(CorrelationSpec):
    """Class for holding identity correlation constants."""
    DEFAULT_FIELDS = ("bunit",
                      "category",
                      "email",
                      "endDate",
                      "first",
                      "identity",
                      "identity_tag",
                      "last",
                      "managedBy",
                      "nick",
                      "phone",
                      "phone2",
                      "prefix",
                      "priority",
                      "startDate",
                      "suffix",
                      "watchlist",
                      "work_city",
                      "work_country",
                      "work_lat",
                      "work_long")
    ID = "identity"
    LOOKUP_STR = "identity_lookup_expanded"
    LOOKUP_STR_PREFIX = "zy"
    VALID_INFIELDS = ('src_user', 'user')


class AssetCorrelationDefaultFieldsSpec(CorrelationSpec):
    """Class for holding fillnull AKA default field correlation constants for assets."""

    DEFAULT_FIELDS = ("is_expected", "pci_domain", "requires_av", "should_timesync", "should_update")
    ID = "asset_default_fields"
    LOOKUP_STR = "asset_lookup_default_fields"
    LOOKUP_STR_PREFIX = "zz"
    VALID_INFIELDS = AssetCorrelationSpec.VALID_INFIELDS


class IdentityCorrelationDefaultFieldsSpec(CorrelationSpec):
    """Class for holding fillnull AKA default field correlation constants for identities."""

    DEFAULT_FIELDS = ("watchlist",)  # Trailing comma is intentional
    ID = "identity_default_fields"
    LOOKUP_STR = "identity_lookup_default_fields"
    LOOKUP_STR_PREFIX = "zz"
    VALID_INFIELDS = IdentityCorrelationSpec.VALID_INFIELDS


class IdentityCorrelation(object):
    """Class for management of Enterprise Security asset/identity correlation automatic lookup definitions."""

    DEFAULT_NAMESPACE = "SA-IdentityManagement"
    DEFAULT_OWNER = "nobody"

    @staticmethod
    def _get_correlation_type(typ, use_cidr):
        """Get the specifications for the requested correlation type."""

        if typ == AssetCorrelationSpec.ID:
            return AssetCorrelationSpec, AssetCorrelationDefaultFieldsSpec, use_cidr
        elif typ == IdentityCorrelationSpec.ID:
            # Force use_cidr to False for identity correlation as it does not apply.
            return IdentityCorrelationSpec, IdentityCorrelationDefaultFieldsSpec, False
        else:
            raise ValueError('Invalid automatic lookup type requested.')

    @classmethod
    def list_correlations(cls, session_key, stanza_name=None):
        """Parse the active automatic lookups and return a dictionary of the enabled correlations.

        :param session_key: A Splunk session key.
        :type session_key: str
        :param stanza_name: A string representing a props.conf stanza name.
        :type stanza_name: str
        :return A nested dictionary in the following format:

            { <stanza_name>:
                { <type:asset>: [<field_name>, ...]
                  <type:identity>: [<field_name>, ...],
                  attributes: [<attribute_name>, ...]
                }
            }

            Invariants:
            1. The only valid correlations right now are "asset" and "identity".
            2. The "attributes" field will contain a list of the props.conf attributes used for identity correlation,
               for the given stanza_name.
            3. An empty list of field names indicates that the <type> correlation is not enabled for the given
               stanza_name.

            If no stanza name is provided, all identity correlations for all sourcetypes will be listed.

            The keys available in the innermost dictionary may be added to in future releases; consumers of the API
            should not make assumptions about the number or names of keys except as indicated above.

        :rtype dict
        """

        # Retrieve the patterns that match our current correlations. This method assumes that the exact match is enabled
        # for any asset or identity correlation stanza; we do not validate stanza integrity in this method.
        prefixes = {i.class_prefix(): i.ID for i in (AssetCorrelationSpec, IdentityCorrelationSpec)}
        attribute_rx = re.compile("^LOOKUP-(?P<prefix>%s)(?P<field>[A-Za-z0-9_]+)$" % '|'.join(prefixes))

        automatic_lookups = AutomaticLookup.list(cls.DEFAULT_OWNER, cls.DEFAULT_NAMESPACE, session_key)

        default = {i.ID: {'fields': [], 'attribute': []} for i in (AssetCorrelationSpec, IdentityCorrelationSpec)}

        output = {}
        for k, v in automatic_lookups.iteritems():
            stanza = v['content']['stanza']
            attribute = v['content']['attribute']
            match = attribute_rx.match(attribute)
            if match:
                prefix, field = match.groups()
                if stanza_name is None or stanza == stanza_name:
                    curr = output.setdefault(stanza, copy.deepcopy(default))
                    if prefix in prefixes:
                        c_id = prefixes[prefix]
                        curr[c_id]['fields'].append(field)
                        curr[c_id]['attribute'].append(attribute)

        return output

    @classmethod
    def disable_correlation(cls, typ, stanza_name, session_key, infields=None, use_cidr=True):
        return cls._edit_correlation(AutomaticLookup.delete, typ, stanza_name, session_key, infields=infields, use_cidr=use_cidr)

    @classmethod
    def enable_correlation(cls, typ, stanza_name, session_key, infields=None, outfields=None, use_cidr=True):
        return cls._edit_correlation(AutomaticLookup.create, typ, stanza_name, session_key, infields=infields, outfields=outfields, use_cidr=use_cidr)

    @classmethod
    def _edit_correlation(cls, fn, typ, stanza_name, session_key, infields=None, outfields=None, use_cidr=True):
        """Enable correlation for a props.conf stanza.

        :param typ: One of "asset" or "identity".
        :type typ: str
        :param stanza_name: The host, source, or sourcetype identifier of the props.conf stanza.
        :type stanza_name: str
        :param infields: A list of input fields which will have automatic lookups performed on them.
        :type infields: list(str)
        :param session_key: A Splunk session key.
        :type session_key: str
        :param outfields: A list of output field names (defaults to None, which will result in the default output
            field set for the selected correlation.
        :type outfields: list(str)
        :param use_cidr: If True, CIDR correlation will be enabled (used for asset correlation only).
        :type use_cidr: bool

        :return A list of tuples (<bool status>, <HTTP response>, <HTTP content>)
        :rtype tuple
        """

        # Format for exception logging
        exc_fmt = 'msg="Automatic lookup editing failed" typ="{typ}" stanza_name="{stanza_name}" infield="{infield}"'

        spec, spec_fillnull, use_cidr = cls._get_correlation_type(typ, use_cidr)

        # Validate output fields.
        if outfields:
            outfields = [i for i in outfields if i in spec.DEFAULT_FIELDS]
        else:
            outfields = spec.DEFAULT_FIELDS

        # Validate input fields.
        if infields:
            infields = [i for i in infields if i in spec.VALID_INFIELDS]
        else:
            infields = spec.VALID_INFIELDS

        status = []

        for infield in infields:
            # 1. Generate the exact match AKA string-based lookup.
            try:
                success, response, content = fn(stanza_name=stanza_name,
                                                class_name=spec.class_name(infield, use_cidr=False),
                                                transform_name=spec.transform_name(use_cidr=False),
                                                infield=infield,
                                                outfields=outfields,
                                                owner=cls.DEFAULT_OWNER,
                                                namespace=cls.DEFAULT_NAMESPACE,
                                                session_key=session_key,
                                                overwrite=True)
                status.append((success, response, content))
            except splunk.RESTException:
                logger.exception(exc_fmt.format(typ=typ, stanza_name=stanza_name, infield=infield))
                raise

            # 2. Generate the CIDR-based lookup if needed.
            if use_cidr:
                try:
                    success, response, content = fn(stanza_name=stanza_name,
                                                    class_name=spec.class_name(infield, use_cidr=True),
                                                    transform_name=spec.transform_name(use_cidr=True),
                                                    infield=infield,
                                                    outfields=outfields,
                                                    owner=cls.DEFAULT_OWNER,
                                                    namespace=cls.DEFAULT_NAMESPACE,
                                                    session_key=session_key,
                                                    overwrite=True)
                    status.append((success, response, content))
                except splunk.RESTException:
                    logger.exception(exc_fmt.format(typ=typ, stanza_name=stanza_name, infield=infield))
                    raise

            # 3. Generate the default field lookup. Output field selection not supported here.
            try:
                success, response, content = fn(stanza_name=stanza_name,
                                                class_name=spec_fillnull.class_name(infield, use_cidr=False),
                                                transform_name=spec_fillnull.transform_name(False),
                                                infield=infield,
                                                outfields=spec_fillnull.DEFAULT_FIELDS,
                                                owner=cls.DEFAULT_OWNER,
                                                namespace=cls.DEFAULT_NAMESPACE,
                                                session_key=session_key,
                                                overwrite=True)
                status.append((success, response, content))
            except splunk.RESTException as e:
                logger.exception(exc_fmt.format(typ=typ, stanza_name=stanza_name, infield=infield))
                raise

        return status


class IdentityCorrelationRestHandler(splunk.admin.MConfigHandler):
    """REST handler for managing identity correlation settings."""

    METHODMAP = {1: 'ACTION_CREATE',
                 2: "ACTION_LIST",
                 4: "ACTION_EDIT",
                 8: "ACTION_REMOVE",
                 16: "ACTION_MEMBERS",
                 32: "ACTION_RELOAD"}

    BATCH_SAVE_TARGET = 'batch_save'
    DEFAULT_STANZA_NAME = 'default'
    RELOAD_URI = "/servicesNS/{owner}/{namespace}/configs/conf-props/_reload".format(namespace=IdentityCorrelation.DEFAULT_NAMESPACE,
                                                                                     owner=IdentityCorrelation.DEFAULT_OWNER)

    def setup(self):
        """Set up the REST handler."""

        self.setWriteCapability('edit_identitylookup')

        if self.requestedAction in [splunk.admin.ACTION_CREATE, splunk.admin.ACTION_REMOVE]:
            self.supportedArgs.addOptArg('fields')
            self.supportedArgs.addReqArg('type')

        if self.requestedAction in [splunk.admin.ACTION_EDIT]:
            self.supportedArgs.addOptArg('correlations')
            self.supportedArgs.addOptArg('fields')
            self.supportedArgs.addOptArg('type')

    def _has_legacy(self):
        """Raises splunk.admin.ArgValidationException if the current Splunk instance has legacy asset/identity correlation parameters."""
        legacy_lookups = ['LOOKUP-zu_asset_lookup_host_as_str_only',
                          'LOOKUP-zv_asset_lookup_host_as_cidr_only',
                          'LOOKUP-zu_asset_lookup_orig_host_as_str_only',
                          'LOOKUP-zv_asset_lookup_orig_host_as_cidr_only',
                          'LOOKUP-zu_asset_lookup_src_as_str_only',
                          'LOOKUP-zv_asset_lookup_src_as_cidr_only',
                          'LOOKUP-zu_asset_lookup_dest_as_str_only',
                          'LOOKUP-zv_asset_lookup_dest_as_cidr_only',
                          'LOOKUP-zu_asset_lookup_dvc_as_str_only',
                          'LOOKUP-zv_asset_lookup_dvc_as_cidr_only',
                          'LOOKUP-zy_identity_lookup_src_user_only',
                          'LOOKUP-zy_identity_lookup_user_only',
                          'LOOKUP-zz-asset_identity_lookup_default_fields']

        search = ' OR '.join(['name="default : %s"' % i for i in legacy_lookups])

        getargs = {'output_mode': 'json',
                   'count': 0,
                   'search': search}

        uri = AutomaticLookup.LOOKUP_URI_BASE.format(namespace=IdentityCorrelation.DEFAULT_NAMESPACE,
                                                     owner=IdentityCorrelation.DEFAULT_OWNER)
        r, c = splunk.rest.simpleRequest(uri, getargs=getargs, sessionKey=self.getSessionKey())

        msg = 'Legacy identity correlation settings found; identity correlation settings cannot be changed.'
        if r.status == 200:
            parsed_content = json.loads(c)
            if len(parsed_content['entry']) > 0:
                logger.error(msg)
                raise splunk.admin.ArgValidationException(msg)
        else:
            raise splunk.admin.ArgValidationException('Could not determine status of legacy correlation settings.')

    def _validate_sourcetype(self, sourcetype):
        """Validate a sourcetype."""
        # TODO: can we improve this validation?
        valid_rx = re.compile('[A-Za-z0-9_:-]+')
        if valid_rx.match(sourcetype):
            return sourcetype
        else:
            raise splunk.admin.ArgValidationException('Invalid sourcetype for identity correlation.')

    def _validate_batch(self, args):
        """Validate a set of correlation requests.

        Expected format for args (which may be a callerArgs object instead of a pure Python dictionary):

            {'correlations':
                '[
                    {'sourcetype': "sourcetype_string", 'type': [ "(asset|identity)", ...]}
                    { ... }
                 ]'
            }

        """

        correlations = []

        if 'correlations' in args:
            candidates = json.loads(args['correlations'][0])

            for c in candidates:

                spec = None
                name = None

                # Sourcetype handling.
                if 'sourcetype' in c:
                    name = self._validate_sourcetype(c['sourcetype'])
                else:
                    raise splunk.admin.ArgValidationException('Invalid sourcetype in batch_save.')

                if name is None:
                    raise splunk.admin.ArgValidationException('Missing sourcetype in batch save.')

                # Type handling (asset, identity, or both)
                if 'type' in c:

                    for typ in c['type']:
                        if AssetCorrelationSpec.ID == typ:
                            spec = AssetCorrelationSpec
                        elif IdentityCorrelationSpec.ID == typ:
                            spec = IdentityCorrelationSpec
                        else:
                            raise splunk.admin.ArgValidationException('Invalid identity correlation type in batch_save.')

                        if spec is not None:
                            correlations.append((spec.ID, name, spec.VALID_INFIELDS))
                        else:
                            # Should never get here.
                            raise splunk.admin.ArgValidationException('Identity correlation spec invalid.')

                else:
                    raise splunk.admin.ArgValidationException('Missing identity correlation type in batch_save.')

        else:
            raise splunk.admin.ArgValidationException('The "correlations" argument is required for a batch save.')

        return correlations

    def _validate_args(self, args):
        """Validate the arguments."""

        logger.debug('ARGS: %s', args)

        # The self.callerArgs.id parameter should always be defined per EAI protocol definition.
        # Derived from "name" parameter for ACTION_CREATE.
        # Derived from URI for ACTION_LIST, ACTION_EDIT, ACTION_REMOVE.
        name = self._validate_sourcetype(args.id)
        logger.debug('NAME: %s', name)

        is_batch = name == self.BATCH_SAVE_TARGET
        logger.debug('IS_BATCH: %s', is_batch)

        if is_batch:
            correlations = self._validate_batch(args)
            return is_batch, correlations
        else:
            # "type" argument required for ACTION_CREATE, ACTION_EDIT (non-batch), ACTION_REMOVE
            # Note that "type" is a list; we only accept one correlation request at a time.
            if 'type' in args:
                if AssetCorrelationSpec.ID == args['type'][0]:
                    spec = AssetCorrelationSpec
                elif IdentityCorrelationSpec.ID in args['type'][0]:
                    spec = IdentityCorrelationSpec
                else:
                    raise splunk.admin.ArgValidationException('Invalid identity correlation type.')
            else:
                raise splunk.admin.ArgValidationException('Missing identity correlation type.')

            # "fields" argument is optional for ACTION_CREATE, ACTION_EDIT, ACTION_REMOVE
            if "fields" in args:
                if not all([f in spec.VALID_INFIELDS for f in args['fields']]):
                    raise splunk.admin.ArgValidationException('Invalid list of identity correlation fields for class "%s"' % spec.ID)

            # If fields is not specified, default to the complete set.
            return is_batch, [(spec.ID, name, args.get('fields', spec.VALID_INFIELDS))]

    def _clean_dangling_stanzas(self, stanza_name):
        """Clean the stanza if it is empty (i.e., contains no settings that are different from those in a _new
        stanza)."""

        base_uri = '/servicesNS/%s/%s/configs/conf-props/%s'
        new_uri, stanza_uri = [base_uri % (
            IdentityCorrelation.DEFAULT_OWNER,
            IdentityCorrelation.DEFAULT_NAMESPACE,
            i
        ) for i in ['_new', stanza_name]]

        if stanza_name == self.DEFAULT_STANZA_NAME:
            # Unfortunately the "default" stanza header cannot be removed via this method. Ignore the request.
            return True

        # Reload here as for some reason a stanza can become inaccessible if it has just been deleted.
        self.handleReload()

        # Compare stanza contents to _new.
        new_response, new_contents = splunk.rest.simpleRequest(new_uri,
                                                               getargs={'output_mode': 'json'},
                                                               raiseAllErrors=True,
                                                               sessionKey=self.getSessionKey())

        stanza_response, stanza_contents = splunk.rest.simpleRequest(urllib.quote(stanza_uri),
                                                                     getargs={'output_mode': 'json'},
                                                                     raiseAllErrors=True,
                                                                     sessionKey=self.getSessionKey())

        new_parsed = json.loads(new_contents)['entry'][0]['content']
        stanza_parsed = json.loads(stanza_contents)['entry'][0]['content']

        mismatch = False
        missing = False
        for k, v in stanza_parsed.iteritems():
            if not k.startswith('eai') and not k == 'disabled':
                if k in new_parsed:
                    if v != new_parsed[k]:
                        mismatch = True
                else:
                    missing = True

        if not (mismatch or missing):
            # Stanza is dangling: delete it.
            delete_response, delete_content = splunk.rest.simpleRequest(urllib.quote(stanza_uri),
                                                                        getargs={'output_mode': 'json'},
                                                                        raiseAllErrors=True,
                                                                        method="DELETE",
                                                                        sessionKey=self.getSessionKey())
            return delete_response.status == 200
        else:
            return True

    def handleReload(self, confInfo=None):
        """List all available automatic correlations."""
        logger.info('Entering %s', self.METHODMAP[self.requestedAction])

        # check for legacy settings.
        self._has_legacy()

        r, c = splunk.rest.simpleRequest(self.RELOAD_URI,
                                         sessionKey=self.getSessionKey(),
                                         raiseAllErrors=True)

    def handleList(self, confInfo):
        """List all available automatic correlations."""
        logger.info('Entering %s', self.METHODMAP[self.requestedAction])

        # check for legacy settings.
        self._has_legacy()

        correlations = IdentityCorrelation.list_correlations(session_key=self.getSessionKey(), stanza_name=self.callerArgs.id)

        for stanza, lookups in correlations.iteritems():
            for k, v in lookups.iteritems():
                confInfo[stanza].append(k, v['fields'])
                confInfo[stanza].append('attribute', v['attribute'])

    def handleEdit(self, confInfo):
        """Edit an identity correlation."""
        logger.info('Entering %s', self.METHODMAP[self.requestedAction])

        # check for legacy settings.
        self._has_legacy()

        is_batch, entries = self._validate_args(self.callerArgs)

        if is_batch:

            # Disable all currently active correlations
            current_correlations = IdentityCorrelation.list_correlations(session_key=self.getSessionKey())
            for name, settings in current_correlations.iteritems():
                for typ in [AssetCorrelationSpec.ID, IdentityCorrelationSpec.ID]:
                    fields = settings.get(typ, {}).get('fields')
                    if fields:
                        _ = IdentityCorrelation.disable_correlation(typ, name, self.getSessionKey(), fields)
                self._clean_dangling_stanzas(name)

            # Add the new correlations
            for e in entries:
                typ, name, fields = e
                _ = IdentityCorrelation.enable_correlation(typ, name, self.getSessionKey())

        else:

            if not entries:
                raise splunk.admin.NotFoundException('Identity correlation does not exist.')

            # Extract the first (and only) item from the list.
            typ, name, fields = entries[0]

            current_correlations = IdentityCorrelation.list_correlations(session_key=self.getSessionKey(),
                                                                         stanza_name=name)

            # Only one correlation in list.
            existing = current_correlations.get(name, {}).get(typ, {}).get('fields', [])

            to_delete = list(set(existing) - set(fields))
            to_add = list(set(fields) - set(existing))

            if to_delete:
                _ = IdentityCorrelation.disable_correlation(typ, name, self.getSessionKey(), infields=to_delete)
                self._clean_dangling_stanzas(name)
            if to_add:
                _ = IdentityCorrelation.enable_correlation(typ, name, self.getSessionKey(), infields=to_add)

            self.handleReload()

    def handleCreate(self, confInfo):
        """Create an identity correlation."""
        logger.info('Entering %s', self.METHODMAP[self.requestedAction])

        # check for legacy settings.
        self._has_legacy()

        is_batch, entries = self._validate_args(self.callerArgs)
        if is_batch:
            raise splunk.admin.AlreadyExistsException('Batch create requests not accepted by this method.')

        typ, name, fields = entries[0]

        correlations = IdentityCorrelation.list_correlations(session_key=self.getSessionKey(), stanza_name=name)

        if correlations.get(name, {}).get(typ, {}).get('fields'):
            raise splunk.admin.AlreadyExistsException('Identity correlation already defined.')

        _ = IdentityCorrelation.enable_correlation(typ, name, self.getSessionKey(), infields=fields)

        self.handleReload()

    def handleRemove(self, confInfo):
        """Remove an identity correlation."""
        logger.info('Entering %s', self.METHODMAP[self.requestedAction])

        # check for legacy settings.
        self._has_legacy()

        is_batch, entries = self._validate_args(self.callerArgs)
        if is_batch:
            raise splunk.admin.AlreadyExistsException('Batch remove requests not accepted by this method.')

        typ, name, fields = entries[0]

        correlations = IdentityCorrelation.list_correlations(session_key=self.getSessionKey(), stanza_name=name)

        if not correlations:
            raise splunk.admin.NotFoundException('Identity correlation does not exist.')
        else:
            current = correlations.get(name, {}).get(typ, {}).get('fields')

            to_delete = list(set(current) & set(fields))

            if to_delete:
                _ = IdentityCorrelation.disable_correlation(typ, name, self.getSessionKey(), infields=to_delete)
                self._clean_dangling_stanzas(name)
                self.handleReload()
            else:
                raise splunk.admin.NotFoundException('Identity correlation not defined for the specified field .')

splunk.admin.init(IdentityCorrelationRestHandler, splunk.admin.CONTEXT_APP_AND_USER)
