import base64
import hashlib
import xml.etree.ElementTree as ET
from typing import List

import requests

from ecs_client import ConfigS3
from ecs_client.s3_request import Authenticator, S3Signer


def _build_lifecycle_config(rules: List[ET.Element]) -> bytes:
    """Helper function to build lifecycle configuration XML."""
    root = ET.Element("LifecycleConfiguration")
    for rule in rules:
        root.append(rule)
    return ET.tostring(root, encoding="utf-8")


def build_rule_with_date(
    rule_id: str, prefix: str, date_str: str
) -> ET.Element:
    """Build a lifecycle rule with expiration by date."""
    rule = ET.Element("Rule")
    id_elem = ET.SubElement(rule, "ID")
    id_elem.text = rule_id
    prefix_elem = ET.SubElement(rule, "Prefix")
    prefix_elem.text = prefix
    status = ET.SubElement(rule, "Status")
    status.text = "Enabled"
    expiration = ET.SubElement(rule, "Expiration")
    date_elem = ET.SubElement(expiration, "Date")
    date_elem.text = date_str
    return rule


def build_rule_with_days(rule_id: str, prefix: str, days: int) -> ET.Element:
    """Build a lifecycle rule with expiration by days."""
    rule = ET.Element("Rule")
    id_elem = ET.SubElement(rule, "ID")
    id_elem.text = rule_id
    prefix_elem = ET.SubElement(rule, "Prefix")
    prefix_elem.text = prefix
    status = ET.SubElement(rule, "Status")
    status.text = "Enabled"
    expiration = ET.SubElement(rule, "Expiration")
    days_elem = ET.SubElement(expiration, "Days")
    days_elem.text = str(days)
    return rule


class LifecycleRequest:
    """
    Gestion des lifecycles S3 inspirée de ecs-s3-manager.
    Passe en path-style pour ECS Test Drive.
    """

    def __init__(self, s3_config: ConfigS3):
        self.auth = Authenticator(s3_config)

    def get_lifecycle(self, bucket: str) -> str:
        """
        Récupère la configuration lifecycle en XML pour un bucket S3 ECS.
        Path-style URL: https://<endpoint>/<bucket>?lifecycle
        + Header x-emc-namespace.
        """
        endpoint = self.auth.endpoint.rstrip("/")
        url = f"{endpoint}/{bucket}?lifecycle"

        # Header namespace + signature V2
        hdrs = {"x-emc-namespace": self.auth.namespace}
        signed_headers = S3Signer.sign_request_v2(
            "GET",
            url,
            hdrs.copy(),
            self.auth.access_key,
            self.auth.secret_key,
            b"",
        )

        resp = requests.get(url, headers=signed_headers, verify=False)
        if resp.status_code == 404:
            return ""
        resp.raise_for_status()
        return resp.text

    def list_rules(self, bucket: str) -> List[str]:
        xml = self.get_lifecycle(bucket)
        if not xml:
            return []
        root = ET.fromstring(xml)
        return [rule.find("ID").text for rule in root.findall("Rule")]

    def apply_rules(
        self, bucket: str, rules: List[ET.Element]
    ) -> requests.Response:
        """
        Applique un nouveau LifecycleConfiguration (remplace l’existant).
        Path-style URL: https://<endpoint>/<bucket>?lifecycle
        + Header x-emc-namespace, Content-MD5, Content-Length.
        """
        xml_body = _build_lifecycle_config(rules)
        md5_b64 = base64.b64encode(hashlib.md5(xml_body).digest()).decode(
            "utf-8"
        )

        endpoint = self.auth.endpoint.rstrip("/")
        url = f"{endpoint}/{bucket}?lifecycle"

        headers = {
            "x-emc-namespace": self.auth.namespace,
            "Content-MD5": md5_b64,
            "Content-Type": "application/xml",
            "Content-Length": str(len(xml_body)),
        }

        signed_headers = S3Signer.sign_request_v2(
            "PUT",
            url,
            headers.copy(),
            self.auth.access_key,
            self.auth.secret_key,
            xml_body,
        )

        resp = requests.put(
            url, headers=signed_headers, data=xml_body, verify=False
        )
        resp.raise_for_status()
        return resp

    def create_rule_with_date(
        self, bucket: str, rule_id: str, prefix: str, date_str: str
    ) -> requests.Response:
        rule = build_rule_with_date(rule_id, prefix, date_str)
        return self.apply_rules(bucket, [rule])

    def create_rule_with_days(
        self, bucket: str, rule_id: str, prefix: str, days: int
    ) -> requests.Response:
        rule = build_rule_with_days(rule_id, prefix, days)
        return self.apply_rules(bucket, [rule])
