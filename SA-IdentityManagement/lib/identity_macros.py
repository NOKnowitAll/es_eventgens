import splunk
import splunk.rest


class IdentityCorrelationMacro(object):
    """Enum-style class for constants related to identity correlation."""

    MACRO_ASSET_SOURCES = 'asset_sources'
    MACRO_IDENTITY_SOURCES = 'identity_sources'
    MACRO_IDENTITY_GENERATE = 'generate_identities'

    VALID_NAMES = (MACRO_ASSET_SOURCES, MACRO_IDENTITY_SOURCES, MACRO_IDENTITY_GENERATE)
    DEFAULT_APP = 'SA-IdentityManagement'
    DEFAULT_OWNER = 'nobody'

    @classmethod
    def update_macro(cls, name, definition, session_key):
        """Update the given macro with the given definition.

        :param name: The name of the macro.
        :type name: str
        :param definition: The new macro definition.
        :type definition: str
        :param session_key: A Splunk session key.
        :type session_key: str

        :return Success status.
        :rtype bool
        """

        postargs = {'definition': definition, 'output_mode': 'json'}
        uri = '/servicesNS/%s/%s/properties/macros/%s' % (cls.DEFAULT_OWNER, cls.DEFAULT_APP, name)
        if name in cls.VALID_NAMES:
            r, c = splunk.rest.simpleRequest(uri, postargs=postargs, sessionKey=session_key)
            return r.status == 200
        else:
            raise ValueError('This class cannot be used to update the requested macro name.')

