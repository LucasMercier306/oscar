from dataclasses import dataclass
from ecs_client.models.bucket import Bucket
from typing import List

from dataclasses import dataclass
import xml.etree.ElementTree as ET

@dataclass
class NamespaceData:
    creation_time: int
    id: str
    inactive: bool
    link_rel: str
    link_href: str
    name: str
    default_bucket_block_size: int
    block_size_in_count: int
    block_size: int
    is_compliance_enabled: bool
    is_encryption_enabled: bool
    is_stale_allowed: bool
    root_user_name: str
    root_user_password: str
    is_object_lock_with_ado_allowed: bool
    notification_size_in_count: int
    notification_size: int
    default_data_services_vpool: str

    @staticmethod
    def from_xml(xml_data: bytes) -> 'NamespaceData':
        root = ET.fromstring(xml_data)

        def get_bool(text: str) -> bool:
            return text.lower() == 'true'

        return NamespaceData(
            creation_time=int(root.find('creation_time').text),
            id=root.find('id').text,
            inactive=get_bool(root.find('inactive').text),
            link_rel=root.find('link').attrib['rel'],
            link_href=root.find('link').attrib['href'],
            name=root.find('name').text,
            default_bucket_block_size=int(root.find('default_bucket_block_size').text),
            block_size_in_count=int(root.find('blockSizeInCount').text),
            block_size=int(root.find('blockSize').text),
            is_compliance_enabled=get_bool(root.find('is_compliance_enabled').text),
            is_encryption_enabled=get_bool(root.find('is_encryption_enabled').text),
            is_stale_allowed=get_bool(root.find('is_stale_allowed').text),
            root_user_name=root.find('root_user_name').text,
            root_user_password=root.find('root_user_password').text,
            is_object_lock_with_ado_allowed=get_bool(root.find('is_object_lock_with_ado_allowed').text),
            notification_size_in_count=int(root.find('notificationSizeInCount').text),
            notification_size=int(root.find('notificationSize').text),
            default_data_services_vpool=root.find('default_data_services_vpool').text
        )

@dataclass
class Namespace:
    name: str
    buckets: List[Bucket]