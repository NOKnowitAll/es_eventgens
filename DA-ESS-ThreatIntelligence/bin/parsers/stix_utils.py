from ip_intel_utils import IPIntelUtils


class STIXFieldUtils(object):
    
    @classmethod
    def parse_address_value(cls, field_name, field_value):
        '''Convert an IP address in the following format to a set of CIDR subnets:
        
            10.0.0.0##comma##10.0.0.100

        Do this by converting the value into a range that can be parsed by the
        existing IPv4 conversion routines.
        '''
        
        # Remember that IPIntelUtils.convert_ip already returns a generator.
        if '##comma##' in field_value:
            return IPIntelUtils.convert_ip(field_name, field_value.replace('##comma##', '-'))
        else:
            return IPIntelUtils.convert_ip(field_name, field_value)
        
    @classmethod
    def parse_certificate_timestamp(cls, field_name, field_value):
        pass
