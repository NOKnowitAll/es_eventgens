
import ta_tenable_import_declare

import splunk.admin as admin

from splunktaucclib.rest_handler import datainput, normaliser, validator
from splunktalib.common import util

util.remove_http_proxy_env_vars()


class NessusInputs(datainput.DataInputModel):
    """REST Endpoint of Server in Splunk Add-on UI Framework.
    """
    rest_prefix = 'ta_tenable'
    dataInputName = "nessus"
    requiredArgs = [
        'url',
        'access_key',
        'secret_key',
        'metric',
    ]

    optionalArgs = [
        'batch_size',
        'start_date',
        'index',
        'interval',
    ]

    defaultVals = {
        'batch_size': '100000',
        'start_date': '1999/01/01',
        'index': 'default',
        'interval': '86400',
    }

    validators = {
        'metric': validator.Enum(("nessus_scan", "nessus_plugin"))
    }

    normalisers = {
      'disabled': normaliser.Boolean(),
    }

    cap4endpoint = ''
    cap4get_cred = ''

if __name__ == "__main__":
    admin.init(
        datainput.ResourceHandler(NessusInputs),
        admin.CONTEXT_APP_AND_USER
    )
