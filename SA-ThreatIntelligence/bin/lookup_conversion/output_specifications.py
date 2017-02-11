'''
Copyright (C) 2005 - 2013 Splunk Inc. All Rights Reserved.
'''
import sys
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.lookup_conversion.output import LookupOutputSpec


class ThreatlistManagerAlexaOutputSpec(LookupOutputSpec):
    def __init__(self):
        super(ThreatlistManagerAlexaOutputSpec, self).__init__(default_lookup="alexa_lookup_by_str")

class ThreatlistManagerMozilla_pslOutputSpec(LookupOutputSpec):
    def __init__(self):
        super(ThreatlistManagerMozilla_pslOutputSpec, self).__init__(default_lookup="mozilla_public_suffix_lookup")

class ThreatlistManagerTldOutputSpec(LookupOutputSpec):
    def __init__(self):
        super(ThreatlistManagerTldOutputSpec, self).__init__(default_lookup="cim_http_tld_lookup")
