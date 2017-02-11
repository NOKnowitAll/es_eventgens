from splunktalib.conf_manager.conf_manager import ConfManager
from splunktalib.credentials import CredentialManager

import logging
import os
from splunktalib.common import log
import nessus_util

_LOGGER = log.Logs().get_logger("ta_nessus", level=logging.DEBUG)


class NessusConfigException(Exception):
    "Exception for Nessus config manager errors"
    pass


def check_conf_mgr_result(success, msg):
    """
    Check the result and throw exception if needed
    """
    if success:
        return
    _LOGGER.error(msg)
    raise NessusConfigException(msg)


class NessusConfig(object):
    def __init__(self, splunk_uri, session_key, checkpoint_dir):
        self.conf_mgr = ConfManager(splunk_uri,
                                    session_key,
                                    app_name="Splunk_TA_nessus")
        self.cred_mgr = CredentialManager(session_key=session_key,
                                          splunkd_uri=splunk_uri,
                                          app="Splunk_TA_nessus")
        self.checkpoint_dir = checkpoint_dir

        self.data_input_type = "nessus"
        self.conf_file_name = "nessus"
        self.conf_proxy_stanza_name = "nessus_proxy"
        self.conf_log_stanza_name = "nessus_loglevel"
        self.conf_scan_stanza_name = "nessus_scan"
        self.cred_proxy_stanza_name = "__Splunk_TA_nessus_proxy__"

        self.encrypted_display_str = "********"

        self.fields_proxy = ("proxy_enabled", "proxy_username", "proxy_type",
                             "proxy_password", "proxy_url", "proxy_port",
                             "proxy_rdns")

        self.fields_log = ("loglevel")

        self.fields_scan = ("index_events_for_unsuccessful_scans")

        self.fields_data_input = ("metrics", "page_size", "start_date", "url",
                                  "access_key", "secret_key", "disabled",
                                  "interval", "source", "sourcetype", "index",
                                  "host", "batch_size")

    def get_cred_stanza_name(self, name):
        check_conf_mgr_result(name, "The stanza name is None.")
        return "".join(("__Splunk_TA_nessus_inputs_", name))

    def update_nessus_conf(self, key_values):
        _LOGGER.info("Update nessus.conf")
        key_values = key_values.copy()
        self._encrypt_nessus_conf(key_values)

        self._set_raw_stanza(self.conf_proxy_stanza_name, key_values)

    def get_nessus_conf(self):
        conf_stanza_proxy = self._get_raw_stanza(self.conf_proxy_stanza_name)
        conf_stanza_log = self._get_raw_stanza(self.conf_log_stanza_name)
        conf_stanza_scan = self._get_raw_stanza(self.conf_scan_stanza_name)

        username = conf_stanza_proxy.get("proxy_username", "")
        password = conf_stanza_proxy.get("proxy_password", "")

        _LOGGER.info("Try to get encrypted proxy username & password")

        if self.encrypted_display_str in (username, password):
            encrypted_proxy_user_pwd = self._get_raw_stanza(
                self.cred_proxy_stanza_name,
                stanza_type="cred")
            decrypted_username = encrypted_proxy_user_pwd.get(
                self.cred_proxy_stanza_name)['proxy_username']
            decrypted_password = encrypted_proxy_user_pwd.get(
                self.cred_proxy_stanza_name)['proxy_password']
            conf_stanza_proxy["proxy_username"] = decrypted_username \
                if username == self.encrypted_display_str else username
            conf_stanza_proxy["proxy_password"] = decrypted_password \
                if password == self.encrypted_display_str else password

        conf_stanza_proxy.update(conf_stanza_log)
        conf_stanza_proxy.update(conf_stanza_scan)
        return conf_stanza_proxy

    def update_data_input_on_disk(self, name, key_values, check_success=True):
        _LOGGER.info("Update data input [%s]", name)

        if key_values.get('raw_access_key',
                          '') != self.encrypted_display_str or key_values.get(
                              'raw_secret_key',
                              '') != self.encrypted_display_str:
            key_values = key_values.copy()
            success = self._encrypt_data_input(name, key_values, check_success)
            if not success:
                if check_success:
                    msg = "Failed to encrypt access_key or secret_key for data input [{}]".format(
                        name)
                    check_conf_mgr_result(False, msg)
                else:
                    return False

            if key_values.get("eai:acl"):
                app_name = key_values.get("eai:acl").get("app")
            else:
                app_name = "Splunk_TA_nessus"

            update_cnt = {
                'metric': key_values.get('metric'),
                'url': key_values.get('url'),
                'access_key': self.encrypted_display_str,
                'secret_key': self.encrypted_display_str,
                'start_date': key_values.get('start_date')
            }

            try:
                self.conf_mgr.update_data_input("nessus", name, update_cnt,
                                                app_name)
            except Exception:
                _LOGGER.error(
                    'Failed to update the token of the stanza {} in inputs.conf'.format(
                        name))
                return False
        return True

    def remove_expired_credentials(self):
        inputs = self._get_raw_stanza(stanza_type="data_input",
                                      check_exist=False) or ()
        creds = self._get_raw_stanza(stanza_type="cred", check_exist=False)
        input_names = set(self.get_cred_stanza_name(data_input.get("stanza")) \
            for data_input in inputs)
        for name in creds:
            if name.startswith(
                    "__Splunk_TA_nessus_inputs") and name not in input_names:
                _LOGGER.info(
                    "Remove credential %s since related data input has been deleted",
                    name)
                self._delete_credential(name)

    def remove_expired_ckpt(self):
        inputs = self._get_raw_stanza(stanza_type="data_input",
                                      check_exist=False)

        ckpt_names = set(nessus_util.gen_nessus_log_file_name(data_input)
                         for data_input in inputs)
        files = os.listdir(self.checkpoint_dir)
        for name in files:
            ckpt_path = os.path.join(self.checkpoint_dir, name)
            if name.startswith("nessus_") and name.endswith(".ckpt") and \
               name not in ckpt_names and os.path.isfile(ckpt_path):
                _LOGGER.info(
                    "Remove checkpoint %s since related data input has been deleted",
                    ckpt_path)
                try:
                    os.remove(ckpt_path)
                except:
                    _LOGGER.error("Cannot remove checkpoint file %s",
                                  ckpt_path)

    def get_data_input(self, name):
        _LOGGER.info("Get data input by name %s", name)
        input_stanza = self._get_raw_stanza(name, stanza_type="data_input")
        input_stanza["url"] = input_stanza.get("url", "").strip().lower()

        access_key = input_stanza.get("access_key", "")
        secret_key = input_stanza.get("secret_key", "")
        input_stanza["raw_access_key"] = access_key
        input_stanza["raw_secret_key"] = secret_key

        if self.encrypted_display_str in (access_key, secret_key):
            encrypted_keys = self._get_encrypted_keys(name, check_exist=False)
            if not encrypted_keys:
                check_conf_mgr_result(False, "Cannot get the encrypted keys.")
            decrypted_access_key = encrypted_keys.get("access_key")
            decrypted_secret_key = encrypted_keys.get("secret_key")

            input_stanza["access_key"] = decrypted_access_key if \
                access_key == self.encrypted_display_str else access_key
            input_stanza["secret_key"] = decrypted_secret_key if \
                secret_key == self.encrypted_display_str else secret_key

        return input_stanza

    def _encrypt_nessus_conf(self, key_values):
        _LOGGER.info("Encrypt the proxy username & password")
        user = key_values.get("proxy_username", "")
        pwd = key_values.get("proxy_password", "")

        if not user:
            key_values["proxy_username"] = ""
            key_values["proxy_password"] = ""
            _LOGGER.info(
                "Proxy username is empty. Try to delete the encrypted proxy username & password")
            self._delete_credential(self.cred_proxy_stanza_name)
            return

        self._set_raw_stanza(self.cred_proxy_stanza_name,
                             {
                                 'proxy_username': user,
                                 'proxy_password': pwd
                             },
                             stanza_type="cred")

        _LOGGER.info("Finish encryption. Set them to %s",
                     self.encrypted_display_str)
        key_values["proxy_username"] = self.encrypted_display_str
        key_values["proxy_password"] = self.encrypted_display_str

    def _delete_credential(self, name):
        return self.cred_mgr.delete(name)

    def _encrypt_data_input(self, name, key_values, check_success=True):
        access_key = key_values.get("access_key", "")
        secret_key = key_values.get("secret_key", "")

        if not access_key or not secret_key:
            return False

        name = self.get_cred_stanza_name(name)
        success = self._set_raw_stanza(name,
                                       {"access_key": access_key,
                                        "secret_key": secret_key},
                                       stanza_type="cred",
                                       check_success=check_success)

        key_values["access_key"] = self.encrypted_display_str
        key_values["secret_key"] = self.encrypted_display_str

        return success

    def _get_encrypted_keys(self, name, check_exist=True):
        name = self.get_cred_stanza_name(name)
        decrypt = self._get_raw_stanza(name,
                                       stanza_type="cred",
                                       check_exist=check_exist)
        if decrypt:
            access_key = decrypt.get(name).get("access_key")
            secret_key = decrypt.get(name).get("secret_key")
            return {"access_key": access_key, "secret_key": secret_key}
        return None

    def _get_raw_stanza(self,
                        stanza_name=None,
                        stanza_type="conf",
                        check_exist=True):
        stanza_type = stanza_type.strip().lower()
        if stanza_type == "conf":
            stanza = self.conf_mgr.get_conf(self.conf_file_name, stanza_name)
        elif stanza_type == "data_input":
            stanza = self.conf_mgr.get_data_input(self.data_input_type,
                                                  stanza_name)
        else:
            stanza = self.cred_mgr.get_clear_password(stanza_name)

        if check_exist:
            check_conf_mgr_result(
                stanza, "Failed to get stanza {} by {} manager.".format(
                    stanza_name, stanza_type))
        return stanza

    def _set_raw_stanza(self,
                        stanza_name,
                        key_values,
                        stanza_type="conf",
                        app_name=None,
                        check_success=True):
        app_name = app_name or "Splunk_TA_nessus"
        stanza_type = stanza_type.strip().lower()

        new_values = {}
        if stanza_type == "conf":
            for k, v in key_values.items():
                if v is not None and (
                    (k in self.fields_log and
                     stanza_name == self.conf_log_stanza_name) or
                    (k in self.fields_proxy and
                     stanza_name == self.conf_proxy_stanza_name) or (
                         k in self.fields_scan and
                         stanza_name == self.conf_scan_stanza_name)):
                    new_values[k] = v
            success = self.conf_mgr.set_stanza(self.conf_file_name,
                                               stanza_name, new_values)
        elif stanza_type == "data_input":
            for k, v in key_values.items():
                if v is not None and k in self.fields_data_input:
                    new_values[k] = v
            success = self.conf_mgr.set_data_input_stanza(
                self.data_input_type, stanza_name, new_values, app_name)
        else:
            success = self.cred_mgr.update({stanza_name: key_values})

        if check_success:
            check_conf_mgr_result(
                success, "Failed to update stanza {} by {} manager.".format(
                    stanza_name, stanza_type))

        return success
