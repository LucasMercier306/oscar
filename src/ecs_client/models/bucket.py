import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from urllib.parse import quote_plus

from requests import Response

from ecs_client import ConfigEMC
from ecs_client.ecs_request import ECSClient
from ecs_client.managers.namespace_manager import NamespaceRequest
from ecs_client.models.bucket import BucketInfo


class BucketRequest:
    """
    Manage buckets via the ECS Management REST API.
    """

    def __init__(self, emc_config: ConfigEMC):
        # ECSClient handles authentication and stores EMC configuration
        self.client = ECSClient(emc_config)

    def get(self, bucket: str, namespace: str) -> BucketInfo:
        """
        Retrieve properties of an existing bucket as a BucketInfo dataclass.

        :param bucket: Name of the bucket.
        :param namespace: Namespace to which the bucket belongs. Required.
        :raises ValueError: If namespace is empty.
        :raises HTTPError: If the HTTP response status is >= 400.
        """
        if not namespace:
            raise ValueError("The 'namespace' parameter is required for get_bucket")

        qp_bucket = quote_plus(bucket)
        resp: Response = self.client.get(
            f"/object/bucket/{qp_bucket}/info",
            params={"namespace": namespace}
        )
        resp.raise_for_status()
        return BucketInfo.from_xml(resp.text)

    def create(
        self,
        bucket: str,
        namespace: str,
        file_system_enabled: bool = False,
        quota: Optional[int] = None,
        retention: Optional[int] = None,
        autocommit_period: Optional[int] = None,
        default_data_services_vpool: Optional[str] = None,
        immutable: bool = False,
    ) -> Response:
        """
        Create a new bucket in a given namespace with extended options.

        :param bucket: Name of the bucket to create.
        :param namespace: Namespace in which to create the bucket.
        :param file_system_enabled: Enable file system access if True.
        :param quota: Quota in bytes, if set.
        :param retention: Retention period in days, if set.
        :param autocommit_period: Autocommit interval in seconds, if set.
        :param default_data_services_vpool: Default data services vPool. If None, fetched from namespace.
        :param immutable: Set bucket data immutability if True.
        :raises HTTPError: If the HTTP response status is >= 400.
        """
        # Determine default vPool if not provided
        if default_data_services_vpool is None:
            ns_data = NamespaceRequest(self.client.emc_config).get(namespace)
            default_data_services_vpool = getattr(
                ns_data,
                "default_data_services_vpool",
                None
            )

        # Build XML payload
        root = ET.Element("object_bucket_create")
        ET.SubElement(root, "name").text = bucket
        ET.SubElement(root, "namespace").text = namespace

        if file_system_enabled:
            # CamelCase tag for JSON compatibility
            ET.SubElement(root, "fileSystemEnabled").text = "true"
            # Underscore tag for TSO activation
            ET.SubElement(root, "read_only_tso").text = "true"

        if quota is not None:
            ET.SubElement(root, "quota").text = str(quota)
        if retention is not None:
            ET.SubElement(root, "retention").text = str(retention)
        if autocommit_period is not None:
            ET.SubElement(root, "autocommit_period").text = str(autocommit_period)
        if default_data_services_vpool:
            ET.SubElement(root, "defaultDataServicesVpool").text = (
                default_data_services_vpool
            )
        if immutable:
            # Enable data immutability at bucket creation
            ET.SubElement(root, "data_immutable").text = "true"

        xml_body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        headers = {"Content-Type": "application/xml"}
        return self.client.post(
            "/object/bucket",
            data=xml_body,
            headers=headers
        )

    def delete(self, bucket: str, namespace: str) -> Response:
        """
        Delete an existing bucket.
        """
        qp_bucket = quote_plus(bucket)
        qp_ns = quote_plus(namespace)
        return self.client.delete(
            f"/object/bucket/{qp_bucket}?namespace={qp_ns}"
        )

    def set_metadata(
        self,
        bucket: str,
        namespace: str,
        head_type: str,
        metadata: List[Dict[str, str]],
    ) -> Response:
        """
        Update bucket metadata.

        :param bucket: Bucket name.
        :param namespace: Bucket namespace.
        :param head_type: HEAD type (e.g., 'metadata').
        :param metadata: List of dicts with 'name' and 'value' keys.
        :raises ValueError: If namespace is empty.
        :raises HTTPError: If the HTTP response status is >= 400.
        """
        if not namespace:
            raise ValueError("The 'namespace' parameter is required for set_metadata")

        qp_bucket = quote_plus(bucket)
        payload = {
            "head_type": head_type,
            "metadata": [
                {"name": m["name"], "value": m["value"]} for m in metadata
            ],
        }
        return self.client.put(
            f"/object/bucket/{qp_bucket}/metadata",
            params={"namespace": namespace},
            json=payload,
        )