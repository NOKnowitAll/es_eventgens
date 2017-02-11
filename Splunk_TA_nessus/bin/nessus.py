#!/usr/bin/python

"""
This is the main entry point for nessus TA
"""
import sys
import os.path as op
sys.path.insert(0, op.join(op.dirname(op.abspath(__file__)), "splunktalib"))

import logging
from datetime import datetime
import traceback
import nessus_data_collector as ndc
import nessus_config
import re

from splunktalib.common import log
from splunktalib.common import util

_LOGGER = log.Logs().get_logger("ta_nessus", level=logging.DEBUG)

util.remove_http_proxy_env_vars()

def do_scheme():
    """
    Feed splunkd the TA's scheme
    """

    print """
    <scheme>
    <title>Splunk Add-on for Nessus</title>
    <description>Splunk Add-on for Nessus</description>
    <use_external_validation>true</use_external_validation>
    <streaming_mode>xml</streaming_mode>
    <use_single_instance>False</use_single_instance>
    <endpoint>
      <args>
        <arg name="name">
        </arg>
        <arg name="metric">
           <required_on_create>1</required_on_create>
           <required_on_edit>1</required_on_edit>
        </arg>
        <arg name="url">
           <required_on_create>1</required_on_create>
           <required_on_edit>1</required_on_edit>
        </arg>
        <arg name="access_key">
           <required_on_create>1</required_on_create>
           <required_on_edit>1</required_on_edit>
        </arg>
        <arg name="secret_key">
           <required_on_create>1</required_on_create>
           <required_on_edit>1</required_on_edit>
        </arg>
        <arg name="page_size">
           <required_on_create>0</required_on_create>
           <required_on_edit>0</required_on_edit>
        </arg>
        <arg name="batch_size">
           <required_on_create>0</required_on_create>
           <required_on_edit>0</required_on_edit>
        </arg>
        <arg name="start_date">
           <required_on_create>1</required_on_create>
           <required_on_edit>1</required_on_edit>
        </arg>
      </args>
    </endpoint>
    </scheme>
    """

def parse_modinput_configs(config_str):
    """
    @config_str: modinput XML configuration feed by splunkd
    """

    import xml.dom.minidom as xdm

    config = {
        "server_host": None,
        "server_uri": None,
        "session_key": None,
        "checkpoint_dir": None,
    }
    root = xdm.parseString(config_str).documentElement
    for tag in config.iterkeys():
        nodes = root.getElementsByTagName(tag)
        if not nodes:
            _LOGGER.error("Invalid config, missing %s section", tag)
            raise Exception("Invalid config, missing %s section", tag)

        if (nodes[0].firstChild and
                nodes[0].firstChild.nodeType == nodes[0].TEXT_NODE):
            config[tag] = nodes[0].firstChild.data
        else:
            _LOGGER.error("Invalid config, expect text ndoe")
            raise Exception("Invalid config, expect text ndoe")

    confs = root.getElementsByTagName("configuration")

    if confs:
        stanzas = confs[0].getElementsByTagName("stanza")
        stanza = stanzas[0]
    else:
        items = root.getElementsByTagName("item")
        stanza = items[0]

    if not stanza:
        _LOGGER.error("Invalid config, missing <item> or <stanza> section")
        raise Exception("Invalid config, missing <item> or <stanza> section")

    stanza_name = stanza.getAttribute("name")
    if not stanza_name:
        _LOGGER.error("Invalid config, missing name")
        raise Exception("Invalid config, missing name")

    config["name"] = stanza_name
    params = stanza.getElementsByTagName("param")
    for param in params:
        name = param.getAttribute("name")
        if (name and param.firstChild and
                param.firstChild.nodeType == param.firstChild.TEXT_NODE):
            config[name] = param.firstChild.data
    return config


def get_nessus_modinput_configs(modinputs):
    try:
        input_config = parse_modinput_configs(modinputs)

        config = nessus_config.NessusConfig(input_config.get("server_uri"),
                    input_config.get("session_key"), input_config.get("checkpoint_dir"))

        config.remove_expired_credentials()
        config.remove_expired_ckpt()

        nessus_conf = config.get_nessus_conf()
        config.update_nessus_conf(nessus_conf)
        # set log level
        loglevel = nessus_conf.get("loglevel", "INFO")
        _LOGGER.info("Set loglevel to %s", loglevel)
        log.Logs().set_level(loglevel)

        # this is a multi-instance TA
        input_name = input_config.get("name").replace("nessus://", "").strip()
        input_conf = config.get_data_input(input_name)

        nessus_conf.update(input_conf)
        nessus_conf["checkpoint_dir"] = input_config.get("checkpoint_dir")

        config.update_data_input_on_disk(input_name, input_conf)

        return nessus_conf
    except Exception as ex:
        _LOGGER.error("Failed to setup config for nessus TA: %s", ex.message)
        _LOGGER.error(traceback.format_exc())
        raise

def log_and_raise_value_exception(msg):
    _LOGGER.error(msg)
    raise ValueError(msg)

def run():
    """
    Main loop. Run this TA for ever
    """

    modinputs = sys.stdin.read(5000)
    nessus_conf = get_nessus_modinput_configs(modinputs)
    if nessus_conf.get("metric") == "nessus_scan":
        collector = ndc.NessusScanCollector(nessus_conf)
        collector.collect_scan_data()
    elif nessus_conf.get("metric") == "nessus_plugin":
        collector = ndc.NessusPluginCollector(nessus_conf)
        collector.collect_plugin_data()

def validate_config():
    """
    Validate inputs.conf
    """

    modinputs = sys.stdin.read(5000)
    if not modinputs:
        return 0

    input_config = parse_modinput_configs(modinputs)

    try:
        limit = int(input_config.get("page_size", '1000').strip())
        assert limit > 0 and limit <= 1000
    except:
        log_and_raise_value_exception("Page size should be an integer between 0 and 1000")

    try:
        ret = int(input_config.get("batch_size", '10000').strip())
        assert ret == 0 or ret >= 1000
    except:
        log_and_raise_value_exception("Batch size should be an integer equals 0, or greater than or equals to 1000")

    try:
        sdate = input_config.get("start_date", "1999/01/01").strip()
        datetime.strptime(sdate, '%Y/%m/%d')
    except:
        log_and_raise_value_exception("start_date format is incorrect.")

    try:
        ret = int(input_config.get("interval", '3600').strip())
        assert ret > 0
    except:
        log_and_raise_value_exception("interval should be an integer")

    metric = input_config.get("metric")
    if metric not in ("nessus_scan", "nessus_plugin"):
        log_and_raise_value_exception("The metric should be nessus_scan or nessus_plugin")
        
    url = input_config.get("url")
    if not url or not re.match(r"^https?\://[\w\-\./%\&\?]+(?::\d{1,5})?$", url):
        log_and_raise_value_exception("url format is incorrect.")

    # config = nessus_config.NessusConfig(input_config.get("server_uri"),
    #             input_config.get("session_key"), input_config.get("checkpoint_dir"))
    # stanza_name = input_config.get("name").replace("nessus://", "").strip()
    #
    # access_key = input_config.get("access_key")
    # secret_key = input_config.get("secret_key")
    # encrypted_keys = config._get_encrypted_keys(stanza_name, check_exist=False) or ""
    # if config.encrypted_display_str in (access_key, secret_key) and not encrypted_keys:
    #     log_and_raise_value_exception("Please input a correctly formatted access_key and secret_key!")

    _LOGGER.info("Finished the validation. No errors.")

    return 0

def usage():
    """
    Print usage of this binary
    """

    hlp = "%s --scheme|--validate-arguments|-h"
    print >> sys.stderr, hlp % sys.argv[0]
    sys.exit(1)

def main():
    """
    Main entry point
    """

    args = sys.argv
    if len(args) > 1:
        if args[1] == "--scheme":
            do_scheme()
        elif args[1] == "--validate-arguments":
            sys.exit(validate_config())
        elif args[1] in ("-h", "--h", "--help"):
            usage()
        else:
            usage()
    else:
        _LOGGER.info("Start nessus TA")
        run()
        _LOGGER.info("End nessus TA")
    sys.exit(0)

if __name__ == "__main__":
    main()
