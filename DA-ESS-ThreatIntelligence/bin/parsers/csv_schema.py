from parsers import AbstractThreatIntelligenceSchema
from parsers import Collection
from parsers import Field
from parsers.ip_intel_utils import IPIntelUtils
from parsers.utils import FieldUtils


class CSVSchemaSpecification(AbstractThreatIntelligenceSchema):
        
    def __init__(self):

        # Note that this schema is different from others in that we expect input
        # fields to be single-valued. This requires IPIntelUtils.convert_ip
        # to handle both list and string input.
        
        super(CSVSchemaSpecification, self).__init__()
        
        self._default_fields = [Field('description', ['description'], FieldUtils.str_gen),
                                Field('weight', ['weight'], FieldUtils.str_gen)]
        
        self._collection_list = []

        # certificate_intel
        self._certificate_threatlist_fields = [
            Field('certificate_issuer', ['certificate_issuer'], FieldUtils.safe_str_gen),
            Field('certificate_issuer_email', ['certificate_issuer_email'], FieldUtils.safe_str_gen),
            Field('certificate_issuer_organization', ['certificate_issuer_organization'], FieldUtils.safe_str_gen),
            Field('certificate_issuer_unit', ['certificate_issuer_unit'], FieldUtils.safe_str_gen),
            Field('certificate_serial', ['certificate_serial'], FieldUtils.safe_str_gen),
            Field('certificate_subject', ['certificate_subject'], FieldUtils.safe_str_gen),
            Field('certificate_subject_email', ['certificate_subject_email'], FieldUtils.safe_str_gen),
            Field('certificate_subject_organization', ['certificate_subject_organization'], FieldUtils.safe_str_gen),
            Field('certificate_subject_unit', ['certificate_subject_unit'], FieldUtils.safe_str_gen),
        ] + self._default_fields
        self._collection_list.append(Collection('certificate_issuer', 'certificate_intel', {i.infield: i for i in self._certificate_threatlist_fields}))
        self._collection_list.append(Collection('certificate_issuer_email', 'certificate_intel', {i.infield: i for i in self._certificate_threatlist_fields}))
        self._collection_list.append(Collection('certificate_issuer_organization', 'certificate_intel', {i.infield: i for i in self._certificate_threatlist_fields}))
        self._collection_list.append(Collection('certificate_issuer_unit', 'certificate_intel', {i.infield: i for i in self._certificate_threatlist_fields}))
        self._collection_list.append(Collection('certificate_serial', 'certificate_intel', {i.infield: i for i in self._certificate_threatlist_fields}))
        self._collection_list.append(Collection('certificate_subject', 'certificate_intel', {i.infield: i for i in self._certificate_threatlist_fields}))
        self._collection_list.append(Collection('certificate_subject_email', 'certificate_intel', {i.infield: i for i in self._certificate_threatlist_fields}))
        self._collection_list.append(Collection('certificate_subject_organization', 'certificate_intel', {i.infield: i for i in self._certificate_threatlist_fields}))
        self._collection_list.append(Collection('certificate_subject_unit', 'certificate_intel', {i.infield: i for i in self._certificate_threatlist_fields}))

        # email_intel 
        self._email_threatlist_fields = [
            Field('src_user', ['src_user'], FieldUtils.safe_str_gen),
            Field('subject', ['subject'], FieldUtils.safe_str_gen)
        ] + self._default_fields
        self._collection_list.append(Collection('src_user', 'email_intel', {i.infield: i for i in self._email_threatlist_fields}))
        self._collection_list.append(Collection('subject', 'email_intel', {i.infield: i for i in self._email_threatlist_fields}))

        # file_intel
        self._file_threatlist_fields = [
            Field('file_hash', ['file_hash'], FieldUtils.safe_str_gen),
            Field('file_name', ['file_name'], FieldUtils.safe_str_gen),
        ] + self._default_fields
        self._collection_list.append(Collection('file_hash', 'file_intel', {i.infield: i for i in self._file_threatlist_fields}))
        self._collection_list.append(Collection('file_name', 'file_intel', {i.infield: i for i in self._file_threatlist_fields}))

        # http_intel
        self._http_threatlist_fields = [
            Field('http_referrer', ['http_referrer'], FieldUtils.safe_str_gen),
            Field('http_user_agent', ['http_user_agent'], FieldUtils.safe_str_gen),
            Field('url', ['url'], FieldUtils.safe_str_gen)
        ] + self._default_fields
        self._collection_list.append(Collection('http_referrer', 'http_intel', {i.infield: i for i in self._http_threatlist_fields}))
        self._collection_list.append(Collection('http_user_agent', 'http_intel', {i.infield: i for i in self._http_threatlist_fields}))
        self._collection_list.append(Collection('url', 'http_intel', {i.infield: i for i in self._http_threatlist_fields}))

        # ip_intel by domain
        self._domain_threatlist_fields = [
            Field('domain', ['domain'], FieldUtils.safe_str_gen)
        ] + self._default_fields
        self._collection_list.append(Collection('domain', 'ip_intel', {i.infield: i for i in self._domain_threatlist_fields}))

        # ip_intel by ip
        self._ip_threatlist_fields = [
            Field('ip', ['ip'], IPIntelUtils.convert_ip)
        ] + self._default_fields
        self._collection_list.append(Collection('ip', 'ip_intel', {i.infield: i for i in self._ip_threatlist_fields}))

        # process_intel
        self._process_threatlist_fields = [
            Field('process', ['process'], FieldUtils.str_gen),
            Field('process_file_name', ['process_file_name'], FieldUtils.str_gen)
        ] + self._default_fields
        self._collection_list.append(Collection('process', 'process_intel', {i.infield: i for i in self._process_threatlist_fields}))
        self._collection_list.append(Collection('process_file_name', 'process_intel', {i.infield: i for i in self._process_threatlist_fields}))

        # registry_intel
        self._registry_threatlist_fields = [
            Field('registry_path', ['registry_path'], FieldUtils.str_gen),
            Field('registry_value_name', ['registry_value_name'], FieldUtils.str_gen),
            Field('registry_value_text', ['registry_value_text'], FieldUtils.str_gen)
        ] + self._default_fields
        self._collection_list.append(Collection('registry_path', 'registry_intel', {i.infield: i for i in self._registry_threatlist_fields}))
        self._collection_list.append(Collection('registry_value_name', 'registry_intel', {i.infield: i for i in self._registry_threatlist_fields}))
        self._collection_list.append(Collection('registry_value_text', 'registry_intel', {i.infield: i for i in self._registry_threatlist_fields}))

        # service_intel
        self._service_threatlist_fields = [
            Field('service', ['service'], FieldUtils.str_gen),
            Field('service_file_hash', ['service_file_hash'], FieldUtils.str_gen),
            Field('service_dll_file_hash', ['service_dll_file_hash'], FieldUtils.str_gen),
        ] + self._default_fields
        self._collection_list.append(Collection('service', 'service_intel', {i.infield: i for i in self._service_threatlist_fields}))
        self._collection_list.append(Collection('service_file_hash', 'service_intel', {i.infield: i for i in self._service_threatlist_fields}))
        self._collection_list.append(Collection('service_dll_file_hash', 'service_intel', {i.infield: i for i in self._service_threatlist_fields}))

        # user_intel
        self._user_threatlist_fields = [
            Field('user', ['user'], FieldUtils.str_gen)
        ] + self._default_fields
        self._collection_list.append(Collection('user', 'user_intel', {i.infield: i for i in self._user_threatlist_fields}))

        # Make the spec addressable by field name.
        self._collection_spec = {i.name: i for i in self._collection_list}
