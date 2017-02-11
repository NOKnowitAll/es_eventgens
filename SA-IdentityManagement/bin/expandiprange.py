import sys

from splunk.clilib.bundle_paths import make_splunkhome_path

sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))

from SolnCommon.ipMath import IPType, expand_ip_range_to_cidr
from SolnCommon.cexe import BaseChunkHandler


class IPExpand(BaseChunkHandler):
    '''Convert fields containing IP address/range into multi-valued IP subnets/addresses'''

    RANGE_DELIM = '-'
    ERR_INVALID_IP_OR_CIDR = "Invalid IP address or CIDR block was specified"

    @classmethod
    def expand_ip(cls, val):
        '''
        Return a list of expanded IPs for a given IP/IP-range string

        Args:
            val (string): an IP or IP-range

        Returns:
            list(string)
        '''

        if val == '':
            return []

        ip_repr, ip_type = IPType.get(val)

        if ip_type == IPType.IPV4:
            return [ip_repr]
        elif ip_type == IPType.IPV4_RANGE:
            return expand_ip_range_to_cidr(ip_repr, clean_single_ips=True)
        elif ip_type == IPType.IP_INVALID:
            raise ValueError("'%s' is not a valid IP address or CIDR block" % val)

    @classmethod
    def expand_multi_ips(cls, vals):
        '''
        Args:
            vals list(string): List of IP/IP-range

        Returns:
            List of IP subnets/addresses
        '''

        if vals == '':
            return vals

        values = vals if isinstance(vals, list) else [vals]
        r = [x for v in values for x in cls.expand_ip(v) if x]
        return r or None

    def handle_getinfo(self, meta, body):
        outmeta = {'type': "streaming"}

        searchinfo = meta['searchinfo']
        arglen = len(searchinfo['args'])
        if arglen == 0:
            self.messages.error('Missing ip-field')
        else:
            outmeta['required_fields'] = searchinfo['args']

        return outmeta, ''

    def handle_execute(self, meta, body):
        fields = self.getinfo['searchinfo']['args']
        header = next(body)
        indices = []
        for f in fields:
            # field "not in list" ValueError bubbles up
            idx = header.index(f)
            # catches mv-field "not in list"
            try:
                mvidx = header.index('__mv_%s' % f)
            except ValueError:
                mvidx = len(header)
                header.append('__mv_%s' % f)

            indices.append((idx, mvidx))

        out = [header]
        headerlen = len(header)
        for row in body:
            for f, mvf in indices:
                if len(row) < headerlen:
                    row.extend([''] * (headerlen - len(row)))

                try:
                    expanded = self.expand_multi_ips(row[f].split("\n"))

                    if isinstance(expanded, list):
                        row[f] = "\n".join(expanded)
                        row[mvf] = "$%s$" % "$;$".join(expanded)
                    else:
                        row[f] = expanded

                except (ValueError, TypeError) as e:
                    self.messages.error("Invalid [%s]: %s", row[f], e)

            out.append(row)

        return meta, out

    def handler(self, meta, body):
        action = meta['action']

        if action == 'getinfo':
            return self.handle_getinfo(meta, body)
        elif action == 'execute':
            return self.handle_execute(meta, body)
        else:
            self.messages.error('Unknown action: %s', action)

        return meta, body


if __name__ == '__main__':
    cmd = IPExpand()
    cmd.run()
