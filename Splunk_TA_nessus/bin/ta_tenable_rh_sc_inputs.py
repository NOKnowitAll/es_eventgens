import ta_tenable_import_declare

import splunk.admin as admin

from splunktaucclib.rest_handler import base, normaliser
from splunktalib.common import util

import ta_tenable_util

util.remove_http_proxy_env_vars()


class DefaultInputs(base.BaseModel):
    """REST Endpoint of Server in Splunk Add-on UI Framework.
    """
    rest_prefix = 'ta_tenable'
    endpoint = "configs/conf-tenable_sc_inputs"
    requiredArgs = {'server', 'data', 'index', 'interval'}
    optionalArgs = {'start_time', 'batch_size'}
    normalisers = {"disabled": normaliser.Boolean()}

    defaultVals = {'data': 'sc_vulnerability', 'batch_size': 10000}

    cap4endpoint = ''
    cap4get_cred = ''


class DefaultHandler(base.BaseRestHandler):
    def __init__(self, *args, **kwargs):
        base.BaseRestHandler.__init__(self, *args, **kwargs)
        session_key = self.getSessionKey()
        self.defaultVals.update({
            'start_time': ta_tenable_util.get_30_days_ago_local_time(
                session_key)
        })


if __name__ == "__main__":
    admin.init(
        base.ResourceHandler(DefaultInputs,
                             handler=DefaultHandler),
        admin.CONTEXT_APP_AND_USER)
