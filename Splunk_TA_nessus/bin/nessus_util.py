import re


def gen_nessus_log_file_name(input_config):
    if input_config.get('metric','') == 'nessus_plugin':
        return "nessus_plugin_{}_{}.ckpt".format(input_config.get('stanza', ''), re.sub(r'\W+', '_',
                                                                                           input_config.get('url', '')))
    elif input_config.get('metric','') == 'nessus_scan':
        return "nessus_scan_{}.ckpt".format(input_config.get('stanza', ''))