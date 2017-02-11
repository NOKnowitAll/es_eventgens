import functools
from parsers import AbstractThreatIntelligenceSchema
from parsers import Collections
from parsers import Fieldmap
from parsers import RoutedField
from parsers.utils import FieldUtils
from parsers.stix_utils import STIXFieldUtils


class STIXParserSpecification(AbstractThreatIntelligenceSchema):
    
    def __init__(self):
        
        super(STIXParserSpecification, self).__init__()

        self._addressobject_fields = [
            RoutedField('address_value', ['ip'], Collections.IP_INTEL, STIXFieldUtils.parse_address_value)
        ]
        
        self._domainnameobject_fields = [
            RoutedField('value', ['domain'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._emailmessageobject_fields = [
            RoutedField('header.bcc.address_value', ['recipient'], Collections.EMAIL_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('header.cc.address_value', ['recipient'], Collections.EMAIL_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('header.date', ['received_time'], Collections.EMAIL_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('header.from.address_value', ['src_user'], Collections.EMAIL_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('header.sender.address_value', ['src_user'], Collections.EMAIL_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('header.subject', ['subject'], Collections.EMAIL_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('header.to.address_value', ['recipient'], Collections.EMAIL_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('raw_body', ['body'], Collections.EMAIL_INTEL, FieldUtils.iter_to_str_gen),
            # TODO: Attachments and Links - how are these references presented?
        ]

        self._dnsrecordobject_fields = [
            RoutedField('ip_address.address_value', ['ip'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('domain_name', ['domain'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._fileobject_fields = [
            RoutedField('hashes.simple_hash_value', ['file_hash'], Collections.FILE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('file_name', ['file_name'], Collections.FILE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('file_extension', ['file_extension'], Collections.FILE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('file_path', ['file_path'], Collections.FILE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('full_path', ['file_path', 'file_name'], Collections.FILE_INTEL, functools.partial(FieldUtils.parse_path, prefix='file_')),
            #Field('HexBinary', ['file_hash'], Collections.FILE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('size_in_bytes', ['file_size'], Collections.FILE_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._httpsessionobject_fields = [
            RoutedField('http_request_response.http_client_request.http_request_line.version', ['http_version'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_provisional_server_response.http_status_line.version', ['http_version'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_server_response.http_status_line.version', ['http_version'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_client_request.http_request_line.http_method', ['http_method'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_client_request.http_request_header.parsed_header.content_type', ['http_content_type'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_provisional_server_response.http_response_header.parsed_header.content_type', ['http_content_type'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_server_response.http_response_header.parsed_header.content_type', ['http_content_type'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_client_request.http_request_header.parsed_header.referer', ['http_referrer'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_client_request.http_request_header.parsed_header.user_agent', ['http_user_agent'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_provisional_server_response.http_status_line.status_code', ['status'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_server_response.http_status_line.status_code', ['status'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_client_request.http_request_header.parsed_header.cookie', ['cookie'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_client_request.http_request_header.raw_header', ['header'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_provisional_server_response.http_response_header.raw_header', ['header'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_server_response.http_response_header.raw_header', ['header'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_client_request.http_request_line', ['uri_path'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('http_request_response.http_client_request.http_request_header.parsed_header.host.domain_name', ['domain'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._networkconnectionobject_fields = [
            RoutedField('source_socket_address.ip_address', ['ip'], Collections.HTTP_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._networksocketobject_fields = [
            RoutedField('local_address.ip_address.address_value', ['ip'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('remote_address.ip_address.address_value', ['ip'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('domain', ['domain'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._processobject_fields = [
            RoutedField('name', ['process'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('image_info.path', ['process_file_path'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('image_info.file_name', ['process_file_name'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('argument_list', ['process_arguments'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('network_connection_list.source_socket_address.ip_address', ['src'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('network_connection_list.source_socket_address.port', ['src_port'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('network_connection_list.destination_socket_address.ip_address', ['dest'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('network_connection_list.destination_socket_address.port', ['dest_port'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._socketaddressobject_fields = [
            RoutedField('ip_address.address_value', ['ip'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen)
        ]
        
        self._uriobject_fields = [
            RoutedField('value', ['url'], Collections.HTTP_INTEL, functools.partial(FieldUtils.iter_to_str_gen, lstrip_chars=' ":'))
        ]

        self._useraccountobject_fields = [
            RoutedField('username', ['user'], Collections.USER_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('fullname', ['full_name'], Collections.USER_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('description', ['description'], Collections.USER_INTEL, FieldUtils.iter_to_str_gen),
        ]

        self._whoisobject_fields = [
            RoutedField('ip_address.address_value', ['ip'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('domain_name', ['domain'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('contact_info.address', ['address'], Collections.IP_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._windowsprocessobject_fields = self._processobject_fields + [
            RoutedField('handle_list.name', ['process_handle_name'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('handle_list.type', ['process_handle_type'], Collections.PROCESS_INTEL, FieldUtils.iter_to_str_gen),
        ]
        
        self._windowsregistrykeyobject_fields = [
            RoutedField('hive', ['registry_hive'], Collections.REGISTRY_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('key', ['registry_key'], Collections.REGISTRY_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('values.name', ['registry_value_name'], Collections.REGISTRY_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('values.data', ['registry_value_data'], Collections.REGISTRY_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('values.datatype', ['registry_value_type'], Collections.REGISTRY_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('modified_time', ['registry_modified_time'], Collections.REGISTRY_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._windowsserviceobject_fields = [
            RoutedField('service_name', ['service'], Collections.SERVICE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('display_name', ['descriptive_name'], Collections.SERVICE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('description_list', ['description'], Collections.SERVICE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('service_status', ['status'], Collections.SERVICE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('service_type', ['service_type'], Collections.SERVICE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('startup_type', ['start_mode'], Collections.SERVICE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('service_dll', ['service_dll_file_path'], Collections.SERVICE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('service_dll_hashes.simple_hash_value', ['service_dll_file_hash'], Collections.SERVICE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('service_dll_certificate_issuer', ['certificate_issuer'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('service_dll_certificate_subject', ['certificate_subject'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen)
        ]
        self._windowsuseraccountobject_fields = self._useraccountobject_fields + [
            RoutedField('group_list.name', ['group_name'], Collections.USER_INTEL, FieldUtils.iter_to_str_gen)
        ]

        # TODO: Time field parsing: from format - 2011-03-07T01:13:05+00:00
        self._x509certificateobject_fields = [
            RoutedField('certificate.version', ['certificate_version'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('certificate.issuer', ['certificate_issuer'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('certificate.subject_public_key.public_key_algorithm', ['certificate_publickey_algorithm'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('certificate.serial_number', ['certificate_serial'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('certificate.signature_algorithm', ['certificate_signature_algorithm'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('certificate.subject', ['certificate_subject'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('certificate.validity.not_after', ['certificate_end_time'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen),
            RoutedField('certificate.validity.not_before', ['certificate_start_time'], Collections.CERTIFICATE_INTEL, FieldUtils.iter_to_str_gen)
        ]

        self._collection_list = []
        # Add field handlers to the collection, making the fields addressable by "infield".
        self._collection_list.append(Fieldmap('AddressObjectType', {i.input_field: i for i in self._addressobject_fields}))
        self._collection_list.append(Fieldmap('DomainNameObjectType', {i.input_field: i for i in self._domainnameobject_fields}))
        self._collection_list.append(Fieldmap('DNSRecordObjectType', {i.input_field: i for i in self._dnsrecordobject_fields}))
        self._collection_list.append(Fieldmap('EmailMessageObjectType', {i.input_field: i for i in self._emailmessageobject_fields}))
        self._collection_list.append(Fieldmap('FileObjectType', {i.input_field: i for i in self._fileobject_fields}))
        self._collection_list.append(Fieldmap('HTTPSessionObjectType', {i.input_field: i for i in self._httpsessionobject_fields}))
        self._collection_list.append(Fieldmap('NetworkConnectionObjectType', {i.input_field: i for i in self._networkconnectionobject_fields}))
        self._collection_list.append(Fieldmap('NetworkSocketObjectType', {i.input_field: i for i in self._networksocketobject_fields}))
        self._collection_list.append(Fieldmap('ProcessObjectType', {i.input_field: i for i in self._processobject_fields}))
        self._collection_list.append(Fieldmap('SocketAddressObjectType', {i.input_field: i for i in self._socketaddressobject_fields}))
        self._collection_list.append(Fieldmap('URIObjectType', {i.input_field: i for i in self._uriobject_fields}))
        self._collection_list.append(Fieldmap('UserAccountObjectType', {i.input_field: i for i in self._useraccountobject_fields}))
        self._collection_list.append(Fieldmap('WindowsProcessObjectType', {i.input_field: i for i in self._windowsprocessobject_fields}))
        self._collection_list.append(Fieldmap('WindowsRegistryKeyObjectType', {i.input_field: i for i in self._windowsregistrykeyobject_fields}))
        self._collection_list.append(Fieldmap('WindowsUserAccountObjectType', {i.input_field: i for i in self._windowsuseraccountobject_fields}))
        self._collection_list.append(Fieldmap('WindowsServiceObjectType', {i.input_field: i for i in self._windowsserviceobject_fields}))
        self._collection_list.append(Fieldmap('WhoisObjectType', {i.input_field: i for i in self._whoisobject_fields}))
        self._collection_list.append(Fieldmap('X509CertificateObjectType', {i.input_field: i for i in self._x509certificateobject_fields}))

        # Make the spec addressable by IndicatorItem name, e.g. "FileItem".
        self._collection_spec = {i.name: i for i in self._collection_list}
