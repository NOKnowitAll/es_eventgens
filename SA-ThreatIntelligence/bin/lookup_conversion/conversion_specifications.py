"""
Copyright (C) 2005 - 2016 Splunk Inc. All Rights Reserved.
"""
import sys
from splunk.clilib.bundle_paths import make_splunkhome_path
sys.path.append(make_splunkhome_path(["etc", "apps", "SA-Utils", "lib"]))
from SolnCommon.lookup_conversion.conversion import LookupConversionSpec
from SolnCommon.lookup_conversion.fields import DomainFieldMapping
from SolnCommon.lookup_conversion.fields import FieldMapping
from SolnCommon.lookup_conversion.fields import LengthFieldMapping
from SolnCommon.lookup_conversion.fields import RegistrableLengthFieldMapping


class ThreatlistManagerAlexaConversionSpec(LookupConversionSpec):
    """Class defining a specification used to convert a set of threat lists into
    a static Splunk lookup table."""
 
    def __init__(self, *args, **kwargs):
         
        fieldmap = {'rank': FieldMapping('description'),
                    'domain': DomainFieldMapping('domain', is_key_field=True)}

        super(ThreatlistManagerAlexaConversionSpec, self).__init__(fieldmap,
            allow_custom=False,
            allow_mv_keys=False,
            merge_fields=[],
            mv_key_fields=[])

class ThreatlistManagerTldConversionSpec(LookupConversionSpec):
    """Class defining a specification used to convert a set of threat lists into
    a static Splunk lookup table."""
 
    def __init__(self, *args, **kwargs):

        fieldmap = {'tld': DomainFieldMapping('tld', is_key_field=True)}

        super(ThreatlistManagerTldConversionSpec, self).__init__(fieldmap,
            allow_custom=False,
            allow_mv_keys=False,
            merge_fields=[],
            mv_key_fields=[])


class ThreatlistManagerMozilla_pslConversionSpec(LookupConversionSpec):
    """Class defining a specification used to convert a set of threat lists into
    a static Splunk lookup table."""
 
    def __init__(self, *args, **kwargs):

        fieldmap = {'length': RegistrableLengthFieldMapping('length', requires=["rule", "domain"], delim=".", is_generated=True),
            'domain': DomainFieldMapping('domain', is_key_field=True),
            'segments': LengthFieldMapping('segments', requires=["domain"], delim=".", is_generated=True),
            }

        super(ThreatlistManagerMozilla_pslConversionSpec, self).__init__(fieldmap,
            allow_custom=False,
            allow_mv_keys=False,
            merge_fields=[],
            mv_key_fields=[])
