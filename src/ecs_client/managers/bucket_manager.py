import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from requests import Response

from ecs_client.ecs_request import ECSClient
from ecs_client.models.bucket import BucketInfo


class BucketRequest:
    """
    Manage ECS S3 buckets via ECS Management REST API.
    """

    def __init__(self, client: ECSClient):
        self.client = client

    def create(
        self,
        bucket: str,
        namespace: str,
        file_system_enabled: bool = False,
        quota: Optional[int] = None,
        retention_days: Optional[int] = None,
        autocommit_period: Optional[int] = None,
        default_data_services_vpool: Optional[str] = None,
        immutable: bool = False
    ) -> Response:
        """
        Create a bucket.
        If immutable=True, retention_days (en jours) est requis.
        """
        if immutable and retention_days is None:
            raise ValueError("Immutable buckets require a retention period in days.")

        root = ET.Element("object_bucket_create")
        ET.SubElement(root, "name").text = bucket
        ET.SubElement(root, "namespace").text = namespace

        if file_system_enabled:
            ET.SubElement(root, "fileSystemEnabled").text = "true"
            ET.SubElement(root, "read_only_tso").text = "true"
        if quota is not None:
            ET.SubElement(root, "quota").text = str(quota)
        if retention_days is not None:
            ET.SubElement(root, "retention").text = str(retention_days)
        if autocommit_period is not None:
            ET.SubElement(root, "autocommit_period").text = str(autocommit_period)
        if default_data_services_vpool:
            ET.SubElement(root, "defaultDataServicesVpool").text = default_data_services_vpool

        xml_body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        headers = {"Content-Type": "application/xml"}
        return self.client.post(
            "/object/bucket", data=xml_body, headers=headers,
            params={"namespace": namespace}
        )

    def delete(self, bucket: str, namespace: str) -> Response:
        """
        Delete an existing bucket.
        """
        return self.client.delete(
            f"/object/bucket/{bucket}",
            params={"namespace": namespace}
        )

    def list(self, namespace: str) -> List[BucketInfo]:
        """
        List all buckets in a namespace.
        """
        resp = self.client.get(
            "/object/bucket", params={"namespace": namespace}
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        buckets = []
        for elem in root.findall('bucket'):
            buckets.append(BucketInfo.from_xml(elem))
        return buckets

    def get(self, bucket: str, namespace: str) -> BucketInfo:
        """
        Retrieve details of a single bucket.
        """
        resp = self.client.get(
            f"/object/bucket/{bucket}", params={"namespace": namespace}
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        return BucketInfo.from_xml(root)

    def get_bucket_metadata(self, bucket: str, namespace: str) -> Dict[str, str]:
        """
        Retrieve all metadata associated with a bucket.
        Retourne un dict tag->valeur.
        """
        resp = self.client.get(
            f"/object/bucket/{bucket}/info", params={"namespace": namespace}
        )
        resp.raise_for_status()
        root = ET.fromstring(resp.text)
        return {child.tag: child.text or '' for child in root}

    def set_owner(self, bucket: str, namespace: str, new_owner: str) -> Response:
        """
        Update bucket owner via Management REST API.
        """
        root = ET.Element("bucket")
        ET.SubElement(root, "owner").text = new_owner
        xml_body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        headers = {"Content-Type": "application/xml"}
        return self.client.put(
            f"/object/bucket/{bucket}", data=xml_body,
            headers=headers, params={"namespace": namespace}
        )

    def calculate_size(
        self,
        bucket: str,
        namespace: str,
        metadata_filter: Optional[Dict[str, str]] = None
    ) -> int:
        """
        Compute total size (en bytes) of all objects in a bucket.
        Optionnellement filtre par métadonnées utilisateurs.
        """
        total_size = 0
        # Example: List all objects via S3Request, then filter
        from ecs_client.s3_request import S3Request
        s3 = S3Request(self.client.config)
        paginator = s3.list_objects(bucket, namespace)
        for obj in paginator:
            if metadata_filter:
                obj_meta = s3.head_object(bucket, namespace, obj['Key'])
                tags = obj_meta.get('Metadata', {})
                if not all(tags.get(k) == v for k, v in metadata_filter.items()):
                    continue
            total_size += int(obj['Size'])
        return total_size

    def lock_object(
        self,
        bucket: str,
        namespace: str,
        object_key: str,
        retention_days: int
    ) -> Response:
        """
        Lock an object to make it immutable for a retention period.
        Utilise l’en-tête x-emc-retention-period (secondes).
        """
        from ecs_client.s3_request import S3Request
        s3 = S3Request(self.client.config)
        retention_seconds = retention_days * 86400
        return s3.put_object_retention(
            bucket, namespace, object_key,
            headers={'x-emc-retention-period': str(retention_seconds)}
        )