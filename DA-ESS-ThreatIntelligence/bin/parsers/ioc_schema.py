import functools
from parsers import AbstractThreatIntelligenceSchema
from parsers import Collection
from parsers import Field
from parsers.ioc_utils import IOCParserUtils 
from parsers.utils import FieldUtils


class IOCParserSpecification(AbstractThreatIntelligenceSchema):
    
    def __init__(self):

        super(IOCParserSpecification, self).__init__()

        self._dnsentryitem_fields = [Field('DnsEntryItem/RecordData/Host', ['domain'], FieldUtils.iter_to_str_gen),
            Field('DnsEntryItem/RecordData/IPv4Address', ['ip'], FieldUtils.iter_to_str_gen)]

        self._email_fields = [Field('Email/Attachment/MIMEType', ['attachment_type'], FieldUtils.iter_to_str_gen),
            Field('Email/Attachment/Name', ['file_name'], FieldUtils.iter_to_str_gen),
            Field('Email/Attachment/SizeInBytes', ['file_size'], FieldUtils.iter_to_str_gen),
            Field('Email/Body', ['body'], FieldUtils.iter_to_str_gen),
            Field('Email/From', ['src_user'], FieldUtils.iter_to_str_gen),
            Field('Email/Received', ['received_time'], FieldUtils.iter_to_str_gen),
            Field('Email/ReceivedFromIP', ['src'], FieldUtils.iter_to_str_gen),
            Field('Email/Subject', ['subject'], FieldUtils.iter_to_str_gen),
            Field('Email/To', ['recipient'], FieldUtils.iter_to_str_gen)]
        
        self._fileitem_fields = [Field('FileItem/FileExtension', ['file_extension'], FieldUtils.iter_to_str_gen),
            Field('FileItem/FileName', ['file_name'], FieldUtils.iter_to_str_gen),
            Field('FileItem/FilePath', ['file_extension', 'file_name', 'file_path'], functools.partial(IOCParserUtils.parse_path, prefix='file_')),
            Field('FileItem/FullPath', ['file_extension', 'file_name', 'file_path'], functools.partial(IOCParserUtils.parse_path, prefix='file_')),
            Field('FileItem/Md5sum', ['file_hash'], FieldUtils.iter_to_str_gen),
            Field('FileItem/Sha1sum', ['file_hash'], FieldUtils.iter_to_str_gen),
            Field('FileItem/Sha256sum', ['file_hash'], FieldUtils.iter_to_str_gen),
            Field('FileItem/SizeInBytes', ['file_size'], FieldUtils.iter_to_str_gen)]

        self._networkitem_fields = [Field('Network/HTTP_Referr', ['http_referrer'], FieldUtils.iter_to_str_gen),
            Field('Network/UserAgent', ['http_user_agent'], FieldUtils.iter_to_str_gen),
            Field('Network/String', ['data'], FieldUtils.iter_to_str_gen),
            Field('Network/URI', ['url'], FieldUtils.iter_to_str_gen),
            Field('Network/DNS', ['domain'], FieldUtils.iter_to_str_gen)]

        self._processitem_fields = [Field('ProcessItem/arguments', ['process_arguments'], FieldUtils.iter_to_str_gen),
            Field('ProcessItem/HandleList/Handle/Name', ['process_handle_name'], FieldUtils.iter_to_str_gen),
            Field('ProcessItem/HandleList/Handle/Type', ['process_handle_type'], FieldUtils.iter_to_str_gen),
            Field('ProcessItem/Name', ['process'], FieldUtils.iter_to_str_gen),
            Field('ProcessItem/path', ['process_file_path', 'process_file_name'], functools.partial(IOCParserUtils.parse_path, prefix='process_file_')),
            Field('ProcessItem/PortList/PortItem/localIP', ['src'], FieldUtils.iter_to_str_gen),
            Field('ProcessItem/PortList/PortItem/localPort', ['src_port'], FieldUtils.iter_to_str_gen),
            Field('ProcessItem/PortList/PortItem/remoteIP', ['dest'], FieldUtils.iter_to_str_gen),
            Field('ProcessItem/PortList/PortItem/remotePort', ['dest_port'], FieldUtils.iter_to_str_gen)]

        self._registryitem_fields = [Field('RegistryItem/Hive', ['registry_hive'], FieldUtils.iter_to_str_gen),
            Field('RegistryItem/Path', ['registry_path'], FieldUtils.iter_to_str_gen),
            Field('RegistryItem/KeyPath', ['registry_path'], FieldUtils.iter_to_str_gen),
            Field('RegistryItem/Modified', ['registry_modified_time'], FieldUtils.iter_to_str_gen),
            Field('RegistryItem/Text', ['registry_value_text'], FieldUtils.iter_to_str_gen),
            Field('RegistryItem/Type', ['registry_value_type'], FieldUtils.iter_to_str_gen),
            Field('RegistryItem/Username', ['user'], FieldUtils.iter_to_str_gen),
            Field('RegistryItem/Value', ['registry_value_data'], FieldUtils.iter_to_str_gen),
            Field('RegistryItem/ValueName', ['registry_value_name'], FieldUtils.iter_to_str_gen)]
        
        self._serviceitem_fields = [Field('ServiceItem/description', ['description'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/descriptiveName', ['descriptive_name'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/mode', ['start_mode'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/name', ['service'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/path', ['service_file_path', 'service_file_name'], functools.partial(IOCParserUtils.parse_path, prefix='service_file_')),
            Field('ServiceItem/pathmd5sum', ['service_file_hash'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/pathsha1sum', ['service_file_hash'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/pathsha256sum', ['service_file_hash'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/serviceDLL', ['service_dll_file_path', 'service_dll_file_name'], functools.partial(IOCParserUtils.parse_path, prefix='service_dll_file_')),
            Field('ServiceItem/serviceDLLmd5sum', ['service_dll_file_hash'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/serviceDLLsha1sum', ['service_dll_file_hash'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/serviceDLLsha256sum', ['service_dll_file_hash'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/status', ['status'], FieldUtils.iter_to_str_gen),
            Field('ServiceItem/type', ['service_type'], FieldUtils.iter_to_str_gen)]
        
        self._useritem_fields = [Field('UserItem/description', ['description'], FieldUtils.iter_to_str_gen),
            Field('UserItem/Username', ['user'], FieldUtils.iter_to_str_gen),
            Field('UserItem/fullname', ['full_name'], FieldUtils.iter_to_str_gen),
            #Field('UserItem/groupname', ['group_name'], FieldUtils.iter_to_str_gen),  # TODO
            Field('UserItem/grouplist', ['group_name'], FieldUtils.iter_to_str_gen)]
            
        self._collection_list = []
        # Add field handlers to the collection, making the fields addressable by "infield".
        self._collection_list.append(Collection('DnsEntryItem', 'ip_intel', {i.infield: i for i in self._dnsentryitem_fields}))
        self._collection_list.append(Collection('Email', 'email_intel', {i.infield: i for i in self._email_fields}))
        self._collection_list.append(Collection('FileItem', 'file_intel', {i.infield: i for i in self._fileitem_fields}))
        self._collection_list.append(Collection('NetworkItem', 'http_intel', {i.infield: i for i in self._networkitem_fields}))
        self._collection_list.append(Collection('ProcessItem', 'process_intel', {i.infield: i for i in self._processitem_fields}))
        self._collection_list.append(Collection('RegistryItem', 'registry_intel', {i.infield: i for i in self._registryitem_fields}))
        self._collection_list.append(Collection('ServiceItem', 'service_intel', {i.infield: i for i in self._serviceitem_fields}))
        self._collection_list.append(Collection('UserItem', 'user_intel', {i.infield: i for i in self._useritem_fields}))

        # Make the spec addressable by IndicatorItem name, e.g. "FileItem".
        self._collection_spec = {i.name: i for i in self._collection_list}

