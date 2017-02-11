import sys

import splunk
from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon import ipMath
from SolnCommon.ipMath import IPType


class IPIntelUtils(object):

    @classmethod
    def convert_ip(cls, field_name, field_values, stripchars=' "'):
        '''Convert an input IP address value to a CIDR value compatible
        with a Splunk lookup table.

        Arguments:
            - field_name:   A string representing a field name.
            - field_values: A string representing an IP address or range, or a list of the same
            - stripchars:   A string representing a set of characters to strip from the input.
                            Defaults to stripping whitespace and single quotes.
        
        Several possibilities, not necessarily in order of frequency:
        1. The value is a range where start == end. Convert it to a single IP.
        2. The value is a range where start < end. Convert it to a minimal CIDR
           address set.
        3. The value is an IP. Output it directly.
        4. The value is a CIDR address. If it is an IP in <address>/32 form, 
           treat as in step 1. Otherwise, validate and return it.
        5. The entry is blank. Ignore it.
        6. The entry is invalid in some other way. Return the original value.
           This should not happen due to input validation but is accounted for
           in this code for safety.
        '''

        field_value_list = field_values if isinstance(field_values, list) else [field_values]

        for field_value in field_value_list:
            ip_repr, ip_type = IPType.get(field_value.strip(stripchars))
            
            if ip_type == IPType.IPV4:
                yield field_name, ip_repr
            elif ip_type == IPType.IPV4_RANGE:
                for ip_repr in ipMath.expand_ip_range_to_cidr(ip_repr, clean_single_ips=True):
                    yield field_name, ip_repr
            elif ip_type == IPType.IP_INVALID:
                yield None, None