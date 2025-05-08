import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
from urllib.parse import quote_plus

from requests import Response

from ecs_client import ConfigEMC
from ecs_client.ecs_request import ECSClient
from ecs_client.models.namespace import NamespaceData


class NamespaceRequest:

    def __init__(self, emc_config: ConfigEMC):
        self.client = ECSClient(emc_config)

    def list(self) -> List[Dict[str, str]]:

        resp = self.client.get("/object/namespaces")
        resp.raise_for_status()
        text = resp.text
        root = ET.fromstring(text)
        namespaces = []
        for n in root.findall(".//namespace"):
            entry = {}
            for child in n:
                entry[child.tag] = child.text
            namespaces.append(entry)
        return namespaces

    def get(self, namespace: str) -> Response:
        resp = self.client.get(
            f"/object/namespaces/namespace/{quote_plus(namespace)}"
        )
        return NamespaceData.from_xml(resp.content)

    def create(
        self,
        namespace: str,
        default_replication_group: Optional[str] = None,
        namespace_admins: Optional[List[str]] = None,
        quota: Optional[Dict[str, int]] = None,
        encryption: bool = False,
    ) -> Response:
        # Construction du XML pour la création
        root = ET.Element("namespace")
        ET.SubElement(root, "id").text = namespace
        if default_replication_group:
            ET.SubElement(root, "defaultReplicationGroup").text = (
                default_replication_group
            )
        if namespace_admins:
            admins = ET.SubElement(root, "namespaceAdmins")
            for u in namespace_admins:
                ET.SubElement(admins, "user").text = u
        if quota:
            q = ET.SubElement(root, "quota")
            for k, v in quota.items():
                ET.SubElement(q, k).text = str(v)
        ET.SubElement(root, "encryption").text = str(encryption).lower()

        xml_body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        headers = {"Content-Type": "application/xml"}
        return self.client.post(
            "/object/namespaces", data=xml_body, headers=headers
        )
