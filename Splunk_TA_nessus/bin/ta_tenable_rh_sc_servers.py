
import ta_tenable_import_declare

import splunk.admin as admin

from splunktaucclib.rest_handler import base, normaliser
from splunktalib.common import util

util.remove_http_proxy_env_vars()


class Servers(base.BaseModel):
    """REST Endpoint of Server in Splunk Add-on UI Framework.
    """
    rest_prefix = 'ta_tenable'
    endpoint = "configs/conf-tenable_sc_servers"
    requiredArgs = {'url', 'username', 'password'}
    encryptedArgs = {'password'}
    cap4endpoint = ''
    cap4get_cred = ''


if __name__ == "__main__":
    admin.init(base.ResourceHandler(Servers), admin.CONTEXT_APP_AND_USER)
