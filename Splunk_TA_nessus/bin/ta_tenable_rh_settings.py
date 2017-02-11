"""Test global setting REST handler
"""

import ta_tenable_import_declare

import splunk.admin as admin

from splunktaucclib.rest_handler import base, multimodel, normaliser, validator
from splunktaucclib.rest_handler.cred_mgmt import CredMgmt
from splunktaucclib.rest_handler.error_ctl import RestHandlerError as RH_Err
from splunktalib.common import util

util.remove_http_proxy_env_vars()


class NessusCredMgmt(CredMgmt):
    def context(self, stanzaName, data=None):
        return ('Splunk_TA_nessus', '__Splunk_TA_nessus_proxy__', '', )


class NessusSettingsHandler(multimodel.MultiModelRestHandler):
    def setModel(self, name):
        """Get data model for specified object.
        """
        # get model for object
        if name not in self.modelMap:
            RH_Err.ctl(404,
                       msgx='object={name}'
                       .format(name=name,
                               handler=self.__class__.__name__))
        self.model = self.modelMap[name]

        # load attributes from model
        obj = self.model()
        attrs = {attr: getattr(obj, attr, None)
                 for attr in dir(obj)
                 if not attr.startswith('__') and attr not in
                 ('endpoint', 'rest_prefix', 'cap4endpoint', 'cap4get_cred')}
        self.__dict__.update(attrs)

        # credential fields
        self.encryptedArgs = set([(self.keyMap.get(arg) or arg)
                                  for arg in self.encryptedArgs])
        user, app = self.user_app()
        self._cred_mgmt = NessusCredMgmt(sessionKey=self.getSessionKey(),
                                         user=user,
                                         app=app,
                                         endpoint=self.endpoint,
                                         encryptedArgs=self.encryptedArgs, )
        return


class Logging(base.BaseModel):
    requiredArgs = {'loglevel'}
    defaultVals = {'loglevel': 'INFO'}
    validators = {'loglevel': validator.Enum(('WARN', 'INFO', 'ERROR'))}
    outputExtraFields = ('eai:acl', 'acl', 'eai:attributes', 'eai:appName',
                         'eai:userName')


class Proxy(base.BaseModel):
    requiredArgs = {'proxy_enabled', }
    optionalArgs = {'proxy_url', 'proxy_port', 'proxy_username',
                    'proxy_password', 'proxy_rdns', 'proxy_type'}
    encryptedArgs = {'proxy_username', 'proxy_password'}
    defaultVals = {
        'proxy_enabled': 'false',
        'proxy_rdns': 'false',
        'proxy_type': 'http',
    }
    validators = {
        'proxy_enabled': validator.RequiredIf(
            ('proxy_url', 'proxy_port'), ('1', 'true', 'yes')),
        'proxy_url': validator.AllOf(validator.Host(),
                                     validator.RequiredIf(('proxy_port', ))),
        'proxy_port': validator.AllOf(validator.Port(),
                                      validator.RequiredIf(('proxy_url', ))),
        'proxy_type':
        validator.Enum(("socks4", "socks5", "http", "http_no_tunnel")),
    }
    normalisers = {'proxy_enabled': normaliser.Boolean(), }
    outputExtraFields = ('eai:acl', 'acl', 'eai:attributes', 'eai:appName',
                         'eai:userName')


class TenableScSettings(base.BaseModel):
    defaultVals = {'disable_ssl_certificate_validation': '0', }
    outputExtraFields = ('eai:acl', 'acl', 'eai:attributes', 'eai:appName',
                         'eai:userName', 'disable_ssl_certificate_validation')


class Setting(multimodel.MultiModel):
    endpoint = "configs/conf-nessus"
    modelMap = {
        'nessus_loglevel': Logging,
        'nessus_proxy': Proxy,
        'tenable_sc_settings': TenableScSettings
    }
    cap4endpoint = ''
    cap4get_cred = ''


if __name__ == "__main__":
    admin.init(
        multimodel.ResourceHandler(Setting,
                                   handler=NessusSettingsHandler),
        admin.CONTEXT_APP_AND_USER, )
