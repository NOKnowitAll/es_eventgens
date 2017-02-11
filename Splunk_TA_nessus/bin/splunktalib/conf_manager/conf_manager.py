"""
This module hanles configuration related stuff
"""

import os.path as op

from splunktalib.common import log
from splunktalib.common.util import is_true
import splunktalib.conf_manager.conf_endpoints as scmc
import splunktalib.conf_manager.data_input_endpints as scmdi
import splunktalib.conf_manager.property_endpoints as scmp

_LOGGER = log.Logs().get_logger("ta_util_conf_manager")


def conf_file2name(conf_file):
    conf_name = op.basename(conf_file)
    if conf_name.endswith(".conf"):
        conf_name = conf_name[:-5]
    return conf_name


class ConfManager(object):
    def __init__(self, splunkd_uri, session_key, owner='nobody', app_name='-'):
        self.splunkd_uri = splunkd_uri
        self.session_key = session_key
        self.owner = owner
        self.update_owner = 'nobody' if owner == '-' else owner
        self.app_name = app_name

    def reload_conf(self, conf_name):
        return scmc.reload_conf(self.splunkd_uri, self.session_key,
                              self.app_name, conf_name)

    def create_stanza(self, conf_name, stanza, key_values=None):
        if key_values is None:
            key_values = {}
        return scmc.create_stanza(self.splunkd_uri, self.session_key,
                                self.update_owner, self.app_name,
                                conf_name, stanza, key_values)

    def get_conf(self, conf_name, stanza=None, do_reload=False):
        if do_reload:
            self.reload_conf(conf_name)
        return scmc.get_conf(self.splunkd_uri, self.session_key,
                           self.owner, self.app_name,
                           conf_name, stanza)

    def stanza_exist(self, conf_name, stanza):
        return scmc.stanza_exist(self.splunkd_uri, self.session_key,
                                     self.owner, self.app_name,
                                     conf_name, stanza)

    def update_stanza(self, conf_name, stanza, key_values):
        return scmc.update_stanza(self.splunkd_uri, self.session_key,
                                self.update_owner, self.app_name,
                                conf_name, stanza, key_values)

    def delete_stanza(self, conf_name, stanza):
        return scmc.delete_stanza(self.splunkd_uri, self.session_key,
                                self.update_owner, self.app_name,
                                conf_name, stanza)

    def create_properties(self, conf_name, stanza):
        return scmp.create_properties(self.splunkd_uri, self.session_key,
                                    self.owner, self.app_name,
                                    conf_name, stanza)

    def update_properties(self, conf_name, stanza, key_values):
        return scmp.update_properties(self.splunkd_uri, self.session_key,
                                    self.owner, self.app_name,
                                    conf_name, stanza, key_values)

    def get_property(self, conf_name, stanza, key, do_reload=False):
        if do_reload:
            self.reload_conf(conf_name)
        return scmp.get_property(self.splunkd_uri, self.session_key,
                               self.owner, self.app_name,
                               conf_name, stanza, key)

    def delete_stanzas(self, conf_name, stanzas):
        """
        :param stanzas: list of stanzas
        :return: list of failed stanzas
        """
        failed_stanzas = []
        for stanza in stanzas:
            if not self.delete_stanza(conf_name, stanza):
                failed_stanzas.append(stanza)
        return failed_stanzas

    def set_stanza(self, conf_name, stanza, key_values, clear_old=False):
        if clear_old:
            self.delete_stanza(conf_name, stanza)
            return self.create_stanza(conf_name, stanza, key_values)

        if self.create_stanza(conf_name, stanza, key_values):
            return True
        return self.update_stanza(conf_name, stanza, key_values)

    def all_stanzas(self, conf_name, do_reload=False, ret_metadata=False):
        """
        @return: a list of dict stanza objects if successful.
                 Otherwise return None
        """
        stanzas = self.get_conf(conf_name, None, do_reload)
        if stanzas:
            if not ret_metadata:
                for stanza in stanzas:
                    del stanza['eai:acl']
            return stanzas
        else:
            return []

    def get_stanza(self, conf_name, stanza, do_reload=False,
                   ret_metadata=False):

        stanza = self.get_conf(conf_name, stanza, do_reload)
        if not stanza:
            return {}
        if not ret_metadata:
            del stanza['eai:acl']
        return stanza

    # data input management

    def create_data_input(self, input_type, name, key_values=None, app_name=None):
        app_name = app_name or self.app_name
        return scmdi.create_data_input(self.splunkd_uri, self.session_key,
                                    self.update_owner, self.app_name,
                                    input_type, name, key_values)

    def update_data_input(self, input_type, name, key_values, app_name=None):
        app_name = app_name or self.app_name
        return scmdi.update_data_input(self.splunkd_uri, self.session_key,
                                    self.update_owner, app_name,
                                    input_type, name, key_values)

    def delete_data_input(self, input_type, name):
        return scmdi.delete_data_input(self.splunkd_uri, self.session_key,
                                    self.update_owner, self.app_name,
                                    input_type, name)

    def get_data_input(self, input_type, name=None, do_reload=False):
        if do_reload:
            self.reload_data_input(input_type)
        return scmdi.get_data_input(self.splunkd_uri, self.session_key,
                                 self.update_owner, self.app_name,
                                 input_type, name)

    def reload_data_input(self, input_type):
        return scmdi.reload_data_input(self.splunkd_uri, self.session_key,
                                    self.update_owner, self.app_name,
                                    input_type)

    def enable_data_input(self, input_type, name):
        return scmdi.operate_data_input(self.splunkd_uri, self.session_key,
                                     self.update_owner, self.app_name,
                                     input_type, name, 'enable')

    def disable_data_input(self, input_type, name):
        return scmdi.operate_data_input(self.splunkd_uri, self.session_key,
                                     self.update_owner, self.app_name,
                                     input_type, name, 'disable')

    def data_input_exist(self, input_type, name):
        result = self.get_data_input(input_type, name)
        return result is not None

    def set_data_input_stanza(self, input_type, name, key_values, app_name):
        if self.create_data_input(input_type, name, key_values):
            return True

        disable = False
        if 'disabled' in key_values:
            disable = is_true(key_values['disabled'])
            del key_values['disabled']

        if not self.update_data_input(input_type, name, key_values, app_name):
            return False

        if disable:
            return self.disable_data_input(input_type, name)
        else:
            return self.enable_data_input(input_type, name)

    def all_data_input_stanzas(self, input_type, do_reload=False,
                               ret_metadata=False):
        stanzas = self.get_data_input(input_type, None, do_reload)
        if stanzas:
            if not ret_metadata:
                for stanza in stanzas:
                    for key in stanza.keys():
                        if key.startswith('eai:'):
                            del stanza[key]
            return stanzas
        else:
            return []

    def get_data_input_stanza(self, input_type, name, do_reload=False,
                              ret_metadata=False):

        stanza = self.get_data_input(input_type, name, do_reload)
        if not stanza:
            return {}
        if not ret_metadata:
            for key in stanza.keys():
                if key.startswith('eai:'):
                    del stanza[key]
        return stanza

    def delete_data_input_stanzas(self, input_type, names):
        """
        :param stanzas: list of stanzas
        :return: list of failed stanzas
        """
        failed_names = []
        for name in names:
            if not self.delete_data_input(input_type, name):
                failed_names.append(name)
        return failed_names
