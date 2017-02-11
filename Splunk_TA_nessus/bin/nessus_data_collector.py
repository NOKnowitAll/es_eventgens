import json
import logging
import os
import re
import time
import traceback
import nessus_rest_client as nrc
import nessus_checkpoint as n_ckpt
from splunktalib.common import log
from datetime import datetime

import splunktalib.common.util as util

_LOGGER = log.Logs().get_logger("ta_nessus", level=logging.DEBUG)

METRICS_INFO = {
    "nessus_scan": {
        "endpoint": "/scans",
        "sourcetype": "nessus:scan"
    },
    "nessus_plugin": {
        "endpoint": "/plugins",
        "sourcetype": "nessus:plugin"
    }
}


class NessusObject(object):
    """
    Nessus base object for modular input output
    """

    def __init__(self, record_time, sourcetype, source, data):
        self.record_time = record_time if record_time else time.time()
        self._data = data
        self._sourcetype = sourcetype
        self._source = source

    def to_string(self, index, host):
        evt_fmt = ("<event><time>{0}</time><source>{1}</source>"
                   "<sourcetype>{2}</sourcetype><host>{3}</host>"
                   "<index>{4}</index><data><![CDATA[ {5} ]]></data></event>")
        data = json.dumps(self._data)
        data = re.sub(r'[\r\n\s]+|\\n+', " ", data)
        data = re.sub(r'\\+', ' ', data)
        return evt_fmt.format(self.record_time, self._source, self._sourcetype,
                              host, index, data)


class NessusBaseCollector(object):
    """
    The base class to collect data
    """

    def __init__(self, config):
        self.config = config
        self._check_exit_handler()
        self._canceled = False
        self.metric = config.get("metric")
        metric_info = METRICS_INFO.get(self.metric.strip().lower())
        self.endpoint = metric_info.get("endpoint")
        self.source = metric_info.get("source")
        self.url = config.get("url")
        self.sourcetype = metric_info.get("sourcetype")
        self.client = nrc.NessusRestClient(self.config)
        self.index = self.config.get("index", "default")
        pattern = re.compile("(?:https?://)?([^ :]+)(?::\d+)?$")
        self.host = pattern.search(self.config.get("url").lower()).groups()[0]

    def _exit_handler(self, signum, frame=None):
        self._canceled = True
        _LOGGER.info("cancellation received. sign num=%s", signum)
        if os.name == 'nt':
            return True

    def _check_exit_handler(self):
        try:
            if os.name == 'nt':
                import win32api
                win32api.SetConsoleCtrlHandler(self._exit_handler, True)
            else:
                import signal
                signal.signal(signal.SIGTERM, self._exit_handler)
                signal.signal(signal.SIGINT, self._exit_handler)
        except Exception as ex:
            _LOGGER.warn("Fail to set signal, skip this step: %s: %s",
                         type(ex).__name__, ex)
            _LOGGER.error(traceback.format_exc())

    def _print_stream(self, entry):
        print entry.to_string(self.index, self.host)

    def _get_batch_size(self):
        batch_size = self.config.get("batch_size", 100000)
        try:
            batch_size = int(batch_size)
        except:
            _LOGGER.error(
                "Cannot convert Batch Size %s to integer, use 100000 by default.",
                batch_size)
            batch_size = 100000
        finally:
            return batch_size

    def _get_page_size(self):
        page_size = self.config.get("page_size", 1000)
        try:
            page_size = int(page_size)
        except:
            _LOGGER.error(
                "Cannot convert Page Size %s to integer, use 1000 by default.",
                page_size)
            page_size = 1000
        finally:
            return page_size


class NessusScanCollector(NessusBaseCollector):
    """
    The subclass of NessusBaseCollector to collect nessus scan data.
    """

    def __init__(self, config):
        super(NessusScanCollector, self).__init__(config)
        self.ckpt = n_ckpt.NessusScanCheckpoint(config)

    def _collect_scans(self):
        """
        The method to collect the outline info of all the scans.
        """
        response = self.client.request(self.endpoint)
        if response.get("content"):
            records = response.get("content")
            return records.get("scans", [])
        return []


    def _collect_scan_history(self, scan_results_content):
        """
        The method to get the history_id of an scan.
        The history_id is the largest id.
        """

        histories = scan_results_content.get('history', None)
        if not histories:
            return None, None
        for his in histories[::-1]:
            if util.is_true(self.config.get("index_events_for_unsuccessful_scans", True)):
                if his.get("status").lower().strip() not in ('running', 'paused'):
                    return his, histories[-1]
            else:
                if his.get("status").lower().strip() == 'completed':
                    return his, histories[-1]
        return None, histories[-1]

    def _collect_scan_info(self, scan_results_content):
        """
        The method to get the scan_info part in the scan_results_content.
        It removes the 'acls' part and the field with null value which is not needed.
        """
        scan_info = scan_results_content.get("info", {})

        if 'acls' in scan_info:
            del scan_info['acls']
        for (k, v) in scan_info.items():
            if v is None:
                del scan_info[k]
        return scan_info

    def _collect_one_host_scan_info(self, host_id, sid, scan_info):
        """
        The method to collect all the vulnerabilities of one host and generate the event data.
        """
        count = 0
        host_uri = self.endpoint + '/' + str(sid) + '/hosts/' + str(host_id)
        result = self.client.request(host_uri).get("content")
        # if there is exception in request, return None
        if result is None:
            _LOGGER.info("There is exception in request, return None")
            return None
        else:
            host_info = result.get("info", {})
            host_end_time = host_info.get("host_end", "")
            if self.ckpt.is_new_host_scan(host_end_time,
                                          self.config.get("start_date")):
                self.source = self.url + self.endpoint + '/' + str(
                    sid) + '/hosts/' + str(host_id)
                for vuln in result.get("vulnerabilities", []):
                    vuln["sid"] = sid
                    vuln["host_id"] = host_id

                    # get the port info
                    plugin_id = vuln.get("plugin_id", "")
                    port_info = []
                    if plugin_id:
                        plugin_uri = "{}/plugins/{}".format(host_uri,
                                                            plugin_id)
                        plugin_outputs = self.client.request(plugin_uri).get(
                            "content", {}).get("outputs")
                        ports = []
                        for output in plugin_outputs:
                            ports.extend(output.get("ports", {}).keys())
                        for port in ports:
                            port_elem = {}
                            port_items = re.split(r"\s*/\s*", port)
                            port_elem["port"] = int(port_items[0])
                            if port_items[1]:
                                port_elem["transport"] = port_items[1]
                            if port_items[2]:
                                port_elem["protocol"] = port_items[2]
                            port_info.append(port_elem)

                    vuln = dict(vuln, **scan_info)
                    vuln = dict(vuln, **host_info)
                    if port_info:
                        vuln["ports"] = port_info
                    entry = NessusObject(
                        vuln.get("timestamp"), self.sourcetype, self.source,
                        vuln)
                    self._print_stream(entry)
                    count += 1
        return count

    def _collect_scan_data_of_one_scan(self, sid, scan_info, page_size):
        """
        The method to collect events of one scan id.
        """
        hosts = self.ckpt.contents[self.url]["scans"][str(sid)]["hosts"]
        count = 0
        while len(hosts) > 0:
            if self._canceled:
                _LOGGER.info("Stop this data input since splunk exits")
                self.ckpt.write()
                return 0
            host_id = hosts[-1]
            result_of_one_host = self._collect_one_host_scan_info(host_id, sid,
                                                                  scan_info)
            # if result_of_one_host is None, which means there is exception when request, then the host_id is not popped
            if result_of_one_host is not None:
                hosts.pop()
                count += result_of_one_host
                if count >= page_size:
                    return count
        self.ckpt.write()
        return count

    def _collect_scan_data(self, page_size):
        """
        The method to collect scan events at the size of page_size
        """
        count = 0
        self.ckpt.read()
        for (sid, ascan) in self.ckpt.contents.get(self.url,
                                                   {}).get("scans").items():
            try:
                scan_results = self.client.request(self.endpoint + '/' + sid)
                scan_results_content = scan_results.get('content', {})

                his, last_his = self._collect_scan_history(scan_results_content)
                hid = his.get('history_id') if his else None
                if hid and self.ckpt.is_new_scan(sid, hid):
                    self.ckpt.contents[self.url]["scans"][str(sid)] = {}
                    self.ckpt.contents[self.url]["scans"][str(sid)][
                        "history_id"] = hid
                    if last_his.get('status') in ('running', 'paused'):
                        self.ckpt.contents[self.url]["scans"][str(sid)]["hosts"]=[]
                    elif util.is_true(self.config.get("index_events_for_unsuccessful_scans", True)) or last_his.get(
                            'status') \
                            =='completed':
                        self.ckpt.contents[self.url]["scans"][str(sid)]["hosts"] = [
                            ahost.get("host_id")
                            for ahost in scan_results_content.get("hosts", [])
                        ]
                    else:
                        self.ckpt.contents[self.url]["scans"][str(sid)]["hosts"]=[]
                    self.ckpt.write()

                scan_info = self._collect_scan_info(scan_results_content)
                if not scan_info:
                    continue

                count += self._collect_scan_data_of_one_scan(sid, scan_info,
                                                             page_size)

                if count > page_size:
                    self.ckpt.write()
                    return count
            except Exception:
                _LOGGER.error(traceback.format_exc())
        self.ckpt.write()
        return count

    def collect_scan_data(self):
        """
        The entrance method to collect scan report data.
        """
        batch_size = self._get_batch_size()
        page_size = self._get_page_size()

        self.ckpt.read()

        if self.ckpt.contents.get(self.url,
                                  {}).get("start_date") != self.config.get(
                                      "start_date", "1999/01/01"):
            self.ckpt.delete_ckpt_file()
            self.ckpt = n_ckpt.NessusScanCheckpoint(self.config)

        ckpt_scans = self.ckpt.contents.get(self.url, {}).get("scans")
        is_hosts_empty = True
        for (sid, ascan) in ckpt_scans.items():
            if len(ascan.get("hosts", {})) > 0:
                is_hosts_empty = False
                break

        if is_hosts_empty:
            scans = self._collect_scans()
            if not scans:
                _LOGGER.info("The scans is None.")
                for sid in self.ckpt.contents[self.url]["scans"].keys():
                    del self.ckpt.contents[self.url]["scans"][sid]
                self.ckpt.write()
            else:
                sid_set = list(set([str(scan.get("id")) for scan in scans]))

                # remove the sids which are not existed currently.
                for sid in self.ckpt.contents[self.url]["scans"].keys():
                    if sid not in sid_set:
                        del self.ckpt.contents[self.url]["scans"][sid]

                for sid in sid_set:
                    scan_results = self.client.request(self.endpoint + '/' + sid)
                    scan_results_content = scan_results.get('content', {})

                    his, last_his = self._collect_scan_history(scan_results_content)
                    hid = his.get('history_id') if his else None
                    if hid and self.ckpt.is_new_scan(sid, hid):
                        self.ckpt.contents[self.url]["scans"][str(sid)] = {}
                        self.ckpt.contents[self.url]["scans"][str(sid)][
                            "history_id"] = hid
                        if last_his.get('status') in ('running', 'paused'):
                            self.ckpt.contents[self.url]["scans"][str(sid)]["hosts"]=[]
                        elif util.is_true(self.config.get("index_events_for_unsuccessful_scans", True)) or last_his.get(
                            'status') \
                                =='completed':
                            self.ckpt.contents[self.url]["scans"][str(sid)]["hosts"] = [
                                ahost.get("host_id")
                                for ahost in scan_results_content.get("hosts", [])
                            ]
                        else:
                            self.ckpt.contents[self.url]["scans"][str(sid)]["hosts"]=[]
                self.ckpt.write()

        total = 0
        while total < batch_size or batch_size == 0:
            print "<stream>"
            count = self._collect_scan_data(page_size)
            print "</stream>"
            if count > 0:
                total += count
            else:
                break
        _LOGGER.info("Totally get %i scan vulnerability events.", total)
        return total


class NessusPluginCollector(NessusBaseCollector):
    """
    The subclass of NessusBaseCollector to collect nessus plugin data.
    """

    def __init__(self, config):
        super(NessusPluginCollector, self).__init__(config)
        self.plugin_ckpt = n_ckpt.NessusPluginCheckpoint(config)
        self.mv_fields = ("bid", "cve", "osvdb", "xref", "msft", "cert")

    def _collect_plugin_families(self):
        """
        the method to collect all of the plugin families.
        """
        response = self.client.request(self.endpoint + "/families")
        plugin_family_id_set = set()
        if response.get("content"):
            records = response.get("content")
            if records.get("families"):
                for plugin_family in records.get("families"):
                    plugin_family_id_set.add(plugin_family.get("id"))
        return plugin_family_id_set

    def _collect_plugin_id(self, plugin_family_id_set):
        """
        :param plugin_family_id_set: the set of plugin family ids.
        :return:  a list of plugin_ids. The type is list.
        """
        plugin_set = set()
        for plugin_family_id in plugin_family_id_set:
            response = self.client.request(self.endpoint + "/families/" + str(
                plugin_family_id))
            if response.get("content"):
                records = response.get("content")
                plugins = records.get("plugins", [])
                # to deal with the issue: "plugins":null
                if not plugins:
                    continue
                for plugin in plugins:
                    plugin_set.add(plugin.get("id"))
            else:
                return None
        return list(plugin_set)

    def _collect_plugin_info(self, plugin_id):
        """
        :param plugin_id:
        :return: the detail info of the plugin with id  plugin_id
        """
        result = {}
        response = self.client.request(self.endpoint + "/plugin/" + str(
            plugin_id))
        if response.get("content"):
            record = response.get("content")
            if record.get("id"):
                result["id"] = record.get("id")
            if record.get("family_name"):
                result["family_name"] = record.get("family_name")
            if record.get("attributes"):
                attributes_set = record.get("attributes")
                for attribute in attributes_set:
                    attribute_name = attribute.get("attribute_name").replace(
                        '"', "'").lower().strip()
                    attribute_value = attribute.get("attribute_value").replace(
                        '"', "'").lower().strip()

                    # split "see_also" to mv
                    if attribute_name == "see_also":
                        result["see_also"] = re.split(r"[\n\r\s]+",
                                                      attribute_value)
                        continue

                    # split "cpe" to mv, and see if has multiple cpe fields originally
                    if attribute_name == "cpe":
                        if "cpe" not in result:
                            result["cpe"] = []
                        values = re.split(r"[\n\r\s]+", attribute_value)
                        result["cpe"].extend(values)
                        continue

                    if attribute_name in result:
                        if isinstance(result[attribute_name],
                                      list) and attribute_value not in result[
                                          attribute_name]:
                            result[attribute_name].append(attribute_value)
                        elif result[attribute_name] != attribute_value:
                            result[attribute_name] = [result[attribute_name],
                                                      attribute_value]
                    elif attribute_name in self.mv_fields:
                        result[attribute_name] = [attribute_value]
                    else:
                        result[attribute_name] = attribute_value
            else:
                _LOGGER.warn("The id %i with no content", plugin_id)
            return result
        # if there is exception in request, return None
        else:
            _LOGGER("There is exception in request, return None")
            return None

    def _collect_plugin_data(self, page_size):
        """
        The method to collect plugin data at the size of page_size.
        """
        self.plugin_ckpt.read()
        is_plugin_ids_empty = False
        event_count = 0
        req_count = 0
        for req_x in range(page_size):
            if self._canceled:
                _LOGGER.info("Stop this data input since splunk exits")
                self.plugin_ckpt.write()
                return (0, 0, True)
            if len(self.plugin_ckpt.contents["plugin_ids"]) == 0:
                is_plugin_ids_empty = True
                self.plugin_ckpt.contents[
                    "last_scan_time"] = self.plugin_ckpt.contents[
                        "last_process_time"]
                break
            # plugin_id = self.plugin_ckpt.contents["plugin_ids"].pop()
            plugin_id = self.plugin_ckpt.contents["plugin_ids"][-1]
            plugin_info = self._collect_plugin_info(plugin_id)
            req_count += 1
            # If plugin_info is None, the plugin_id is not popped
            if plugin_info is not None:
                self.plugin_ckpt.contents["plugin_ids"].pop()
                # req_count += 1
                last_modified_time = plugin_info.get(
                    "plugin_modification_date", plugin_info.get(
                        "plugin_publication_date",
                        self.config.get("start_date", "1999/01/01")))
                self.source = self.url + self.endpoint + "/plugin/" + str(
                    plugin_id)
                if self.plugin_ckpt.is_there_updated_plugin(
                        last_modified_time):
                    entry = NessusObject(time.time(), self.sourcetype,
                                         self.source, plugin_info)
                    self._print_stream(entry)
                    event_count += 1
        self.plugin_ckpt.write()
        if event_count > 0:
            _LOGGER.info("Get %i plugin records returned.", event_count)
        else:
            _LOGGER.info("No plugin records returned.")
        return (event_count, req_count, is_plugin_ids_empty)

    def collect_plugin_data(self):
        """
        The entrance method to collect plugin data.
        """

        batch_size = self._get_batch_size()
        page_size = self._get_page_size()
        total_event = 0
        total_request = 0

        self.plugin_ckpt.read()
        if self.plugin_ckpt.contents.get("start_date") != self.config.get(
                "start_date", "1999/01/01"):
            self.plugin_ckpt.delete_ckpt_file()
            self.plugin_ckpt = n_ckpt.NessusPluginCheckpoint(self.config)

        if len(self.plugin_ckpt.contents.get("plugin_ids", [])) == 0:
            plugin_families = self._collect_plugin_families()
            plugin_id_set = self._collect_plugin_id(plugin_families)
            if plugin_id_set is None:
                _LOGGER.error("Exception when request plugin_ids")
                return (0, 0)
            self.plugin_ckpt.contents["plugin_ids"] = plugin_id_set
            self.plugin_ckpt.contents[
                "last_scan_time"] = self.plugin_ckpt.contents[
                    "last_process_time"]
            self.plugin_ckpt.contents["last_process_time"] = datetime.utcnow(
            ).date().strftime("%Y/%m/%d")
            self.plugin_ckpt.write()

        while total_request < batch_size or batch_size == 0:
            print "<stream>"
            (event_count, req_count,
             is_plugin_ids_empty) = self._collect_plugin_data(page_size)
            print "</stream>"
            total_event += event_count
            total_request += req_count
            if is_plugin_ids_empty:
                break

        _LOGGER.info("Totally request plugin %i times, get %i events.",
                     total_request, total_event)
        return (total_event, total_request)
