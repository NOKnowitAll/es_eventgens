import json
import splunk
import splunk.auth
import splunk.rest


def generate_identity_source(typ, session_key):
    """Generate a macro that appends together all the lookups defined in enabled identity_manager inputs.conf
    stanzas, e.g:

        | inputlookup append=t <source> | inputlookup append=t <source> | ...

    :param typ: Type of source (asset, identity)
    :type typ: str
    :param session_key: A Splunk session key.
    :type session_key: str

    :return A non-empty string representing a Splunk search
    :rtype str

    Example:
        asset_sources = generate_source_macro('asset', key)
        identity_sources = generate_source_macro('identity', key)
    """

    VALID_TYPES = ['asset', 'identity']
    IDENTITY_MANAGEMENT_URI = 'data/inputs/identity_manager'

    if typ not in VALID_TYPES:
        raise ValueError('Invalid identity correlation source type: must be one of (%s)' % ', '.join(VALID_TYPES))
    else:
        getargs = {'output_mode': 'json',
                   'search': 'target=%s disabled=0' % typ}

    r, c = splunk.rest.simpleRequest(IDENTITY_MANAGEMENT_URI, getargs=getargs, sessionKey=session_key)

    parsed_content = json.loads(c)['entry']
    lookup_tables = [i['content']['url'].replace('lookup://', '') for i in parsed_content]

    if lookup_tables:
        macro_text = ''
        for i in sorted(lookup_tables):
            macro_text += '| inputlookup append=t %s ' % i
        return macro_text.strip("| ")
    else:
        raise ValueError('No enabled identity_manager inputs.conf stanzas found.')