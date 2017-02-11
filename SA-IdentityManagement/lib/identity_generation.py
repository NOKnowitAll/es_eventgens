import json
import re
import splunk
import splunk.auth
import splunk.rest
import splunk.util

# Search-driven identity generation logic relaxes some implicit long-standing constraints on identity values, and
# adds some new constraints.
#
# 1. match_order is now meaningless since MV field are being used for key fields in identity matching, and the KV store
#    is accepted as a valid field. Thus, we can't ensure order of matches at runtime.
# 2. Only certain fields from identity tables are usable in convention strings. These are hardcoded below.

VALID_FIELDS = ['bunit', 'email', 'first', 'middle', 'last', 'nick', 'prefix', 'suffix']

# This regular expression finds all segments corresponding to <fieldname> with a parenthetical clause.
CONVENTION_RX = re.compile(r'(%s)(\([^\)]*\))' % '|'.join(VALID_FIELDS))
FIELD_RX = re.compile(r'%s' % '|'.join(VALID_FIELDS))


def get_conventions(session_key):
    """Retrieve the relevant convention settings from identityLookup.conf.

    :param session_key: A Splunk session key.

    :return a tuple (<email_match_enabled>, <email_short_match_enabled>, <exact_match_enabled>, list(<convention_string>))
    :rtype tuple(bool, bool, bool, list(str))
    """
    getargs = {'output_mode': 'json'}
    r, c = splunk.rest.simpleRequest('/data/transforms/identityLookup', getargs=getargs, sessionKey=session_key)

    # We only use one stanza here; it is an error to specify multiple identityLookup.conf stanzas.
    parsed_content = json.loads(c)['entry'][0]['content']

    if splunk.util.normalizeBoolean(parsed_content['convention']):
        conventions = [v for k, v in parsed_content.iteritems() if k.startswith('convention.')]
    else:
        conventions = []

    return (splunk.util.normalizeBoolean(parsed_content['email']),
            splunk.util.normalizeBoolean(parsed_content['email_short']),
            splunk.util.normalizeBoolean(parsed_content['exact']),
            conventions)


def generate_email_clauses(email, email_short):
    """Generate Splunk eval clause for generating identity values from email addresses.
    :param email: If True, enable generation of email address identity values.
    :type email: bool
    :param email_short: If True, enable generation of short email address identity values sans the @<domain>
    :type email_short: bool

    :return A list of eval search clauses.
    :rtype: list(str)
    """
    clauses = []
    if email:
        clauses.append('eval identity=mvappend(identity,email)')

    if email_short:
        clauses.append('eval identity=mvappend(identity,replace(email,"@.*",""))')

    return clauses


def generate_eval_clause(convention):
    """Generate Splunk eval clause for generating identity values from email addresses.
    :param convention: An identityLookup.conf convention string.
    :type convention: str

    :return A list of eval search clauses.
    :rtype: list(str)
    """
    transform = []
    prev = None
    matched = 0

    for match in reversed(list(CONVENTION_RX.finditer(convention))):
        # We have at least one match.
        matched += 1
        fieldname, candidate_length = match.group(1), match.group(2)
        # Push the remainder of the convention (if any) onto the transformation
        transform.append('"' + convention[match.end():prev] + '"')
        if candidate_length is None:
            # Invalid convention: no length qualifier.
            return None
        elif candidate_length == '()':
            # Use the entire field
            transform.append(fieldname)
        else:
            # We have a candidate parenthesized length clause with a possible integer component, e.g. "(1)"
            candidate_length = candidate_length.strip('()')
            try:
                s = int(candidate_length)
                if s > 0:
                    transform.append('substr(%s,1,%d)' % (fieldname, s))
                else:
                    # Invalid convention - zero in length clause.
                    return None
            except ValueError as e:
                # Invalid convention - non-integer value in length clause.
                return None

        prev = match.start()

    transform.append('"' + convention[:prev] + '"')

    # Filter empty strings and reverse
    transform = reversed([i for i in transform if i != '' and i != '""'])

    # Count the field names found in the convention.

    if matched >= 1 and len(FIELD_RX.findall(convention)) == matched:
        return 'eval identity=mvappend(identity, %s)' % '.'.join(transform)
    else:
        # No valid fields specified in the convention, or a field name was found in the convention without a length
        # qualifier.
        return None


def generate_search_string(email, email_short, exact, conventions):
    """Generate a search string capable of performing identity value conversions, based on the conventions in
    identityLookup.conf.

    :param email: If True, enable generation of email address identity values.
    :type email: bool
    :param email_short: If True, enable generation of short email address identity values sans the @<domain>
    :type email_short: bool
    :param exact: If True, enable generation of exact identity matches.
    :type exact: bool

    :return A Splunk search clause.
    :rtype str
    """
    clauses = []
    # Exact, email, and email_short matching are usually always enabled.

    # exact matching.
    if exact:
        clauses.append('eval identity=split(identity, "|")')

    # email and email_short matching
    clauses.extend(generate_email_clauses(email, email_short))

    # conventions
    for convention in conventions:
        cc = generate_eval_clause(convention)
        if cc:
            clauses.append(cc)

    return ' | '.join(clauses)
