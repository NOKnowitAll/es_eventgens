import json
import logging
import os
import re
import traceback

import nessus_util
from splunktalib.common import log
from datetime import datetime

_LOGGER = log.Logs().get_logger("ta_nessus", level=logging.DEBUG)

class NessusBaseCheckpoint(object):
    """
    The base class of Nessus checkpoint
    """
    def __init__(self, config):
        self.config = config
        self.url = config.get('url')
        self.contents = {}
        self._fname = self._get_fname(self._gen_fname())
        self._reset_check_point()


    def _gen_fname(self):
        """
        The method to generate the file name of checkpoint file.
        """
        return nessus_util.gen_nessus_log_file_name(self.config)

    def _get_fname(self, fname):
        """
        The method to get the file path and filename of the checkpoint file.
        """
        return os.path.join(self.config.get("checkpoint_dir"), fname)

    def _reset_check_point(self):
        """
        The method to reset the checkpoint
        """
        raise NotImplementedError("Derived class shall implement the function")

    def _get_content(self):
        """
        The method to get the content of the checkpoint.
        """
        return self.contents

    def read(self):
        """
        The method to read the checkpoint.
        """
        _LOGGER.info("Read Checkpoint from file {}".format(self._fname))
        try:
            if not os.path.isfile(self._fname):
                raise ValueError("Checkpoint file doesn't exist")
            with open(self._fname, "r") as f:
                content = f.read().strip()
                if not content:
                    raise ValueError("Empty checkpoint content")
                ckpt = json.loads(content)
                self.contents = ckpt
        except ValueError as ex:
            _LOGGER.info(
                "Checkpoint file format is incorrect. %s", ex)
            self._reset_check_point()
        except Exception as ex:
            _LOGGER.warn(
                "Failed to read Checkpoint from file %s, err: %s, will reset checkpoint",
                self._fname, ex)
            self._reset_check_point()

    def write(self):
        """
        The method to write checkpoint file.
        """
        if (not self._fname) or (not self._get_content()):
            _LOGGER.info("No checkpoint")
            return None
        _LOGGER.info("Write Checkpoint to file %s.", self._fname)
        with open(self._fname + ".new", "w") as f:
            json.dump(self.contents, f, indent=4)
        try:
            os.rename(self._fname, self._fname + ".old")
        except (OSError, IOError):
            _LOGGER.info(traceback.format_exc())
        os.rename(self._fname + ".new", self._fname)
        try:
            os.remove(self._fname + ".old")
        except (OSError, IOError):
            _LOGGER.info(traceback.format_exc())

    def delete_ckpt_file(self):
        """
        The method to delete checkpoint file
        """
        try:
            os.remove(self._fname)
        except (OSError, IOError):
            _LOGGER.info(traceback.format_exc())

class NessusScanCheckpoint(NessusBaseCheckpoint):
    """
    The class of Nessus Scan Checkpoint.
    The name of the checkpoint is "nessus_scan_<-the stanza of the input->.ckpt"
    The formate of checkpoint file is :
    {
        url_1:{
            "start_date": xxxxxxx,
            "scans": {
                scan_id_i:{
                    "history_id": history_id_i,
                    "hosts": [host_id_1, host_id_2, ..., host_id_k]
                    },

                scan_id_j:{
                    "history_id": history_id_j,
                    "hosts": [host_id_1, host_id_2, ..., host_id_x]
                },
            ...
        },
        ...
    }
    """
    def __init__(self, config):
        super(NessusScanCheckpoint, self).__init__(config)

    def _reset_check_point(self):
        self.contents[self.url] = {}
        self.contents[self.url]["scans"] = {}
        self.contents[self.url]["start_date"] = self.config.get("start_date")

    def is_new_scan(self, s_id, cur_h_id):
        """
        Check if there is a new scan.
        If the h_id of current scan is larger than the one in the checkpoint, it is a new scan.
        """
        if cur_h_id is not None and self.url in self.contents:
            ckpt_of_this_url = self.contents[self.url]
            if str(s_id) in ckpt_of_this_url.get("scans", {}):
                his_id = ckpt_of_this_url.get("scans", {}).get(str(s_id), {}).get("history_id")
                return cur_h_id > his_id
        elif cur_h_id is None:
            return False
        return True

    def is_new_host_scan(self, last_scan_end_time, start_date):
        """
        Check if there is new scan occured on the host. 
        If the last_scan_end_time is later than the one in the checkpoint, it's a new host scan.
        """
        if last_scan_end_time=="":
            return True
        last_scan_end_time = datetime.strptime(last_scan_end_time, "%a %b %d %H:%M:%S %Y")
        start_date =  datetime.strptime(start_date, "%Y/%m/%d")
        return last_scan_end_time >= start_date

class NessusPluginCheckpoint(NessusBaseCheckpoint):
    """
    The class of Plugin Checkpoint.
    The name of the checkpoint is "nessus_plugin_<-the url->.ckpt"
    The format of checkpoint file is:
    {
        "start_date":xxxxxxx,
        "last_scan_time": xxxxxxx,
        "last_process_time": xxxxxxx,
        "plugin_ids":[plugin_id_1,plugin_id_2,...plugin_id_n]
    }
    """
    def __init__(self, config):
        super(NessusPluginCheckpoint, self).__init__(config)

    def _reset_check_point(self):
        self.contents["last_scan_time"] = None
        self.contents["last_process_time"] = None
        self.contents["plugin_ids"] = []
        self.contents["start_date"] = self.config.get("start_date")

    def is_there_updated_plugin(self, last_modified_time):
        """
        The method to check whether is there any plugin updated after the last scan.
        """
        ls_time = self.contents["last_scan_time"]
        st_time = self.contents["start_date"]
        if ls_time is None:
            return True
        st_time = datetime.strptime(st_time, '%Y/%m/%d')
        ls_time = datetime.strptime(ls_time, '%Y/%m/%d')
        lm_time = datetime.strptime(last_modified_time, '%Y/%m/%d')
        return lm_time >= ls_time and lm_time >= st_time

