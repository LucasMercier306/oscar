from typing import Dict, Optional, Tuple, List
from urllib.parse import urljoin, quote_plus
import paramiko
import requests
from paramiko import SSHClient
from requests import Response
import hashlib
import base64
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth

from ecs_client import ConfigECS, ConfigS3, ConfigEMC, ConfigECSClient, logger
from ecs_client.exceptions import ECSCLientBadCredential, ECSCLientRequestError


### ECS REQUEST SIMPLE SSH TUNNEL ###
class ECSRequest:
    def __init__(self, ecs_config: ConfigECS, jump_host: Optional["ECSRequest"] = None):
        self.name = ecs_config.name
        self.cluster = ecs_config.name  # Assuming cluster name is the same as ECS name

        # SSH
        self.ssh_host_name = ecs_config.host_name
        self.ssh_port = ecs_config.ssh_port
        self.jump_host = jump_host

        self.ssh_username = ecs_config.username
        self.ssh_password = ecs_config.password

        # API
        self.api_username = ecs_config.username
        self.api_password = ecs_config.password
        self.verify = ecs_config.verify

        self.api_mgt_url = (
            f"{ecs_config.protocol}://{ecs_config.host_name}:{ecs_config.api_port}"
        )
        self.base_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.ssh_client = None
        self.token = None

    # SSH
    def login_ssh(self):
        if self.jump_host:
            logger.info(f"{self.name} has {self.jump_host.name} as jump host...")
            if not self.jump_host.ssh_client:
                self.jump_host.login_ssh()
            self.ssh_client = self.jump_host.ssh_client
            return
        logger.info(f"Opening ssh connection on host {self.name}...")
        self.ssh_client = SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh_client.connect(
            hostname=self.ssh_host_name,
            username=self.ssh_username,
            password=self.ssh_password,
        )
        logger.info(f"Ssh connection opened on host {self.name}.")

    def logout_ssh(self):
        if not self.ssh_client or self.jump_host:
            return
        logger.info(f"Closing ssh connection on host {self.name}...")
        self.ssh_client.close()
        logger.info(f"Ssh connection closed on host {self.name}.")

    def run_command_on_host(self, command: str, *, log_command: bool = True, stdin: str = "") -> Tuple[str, str]:
        if not self.ssh_client or not self.ssh_client.get_transport().is_active():
            self.login_ssh()

        if log_command:
            logger.info(f"On host {self.name}, running command: {command}")
        if self.jump_host:
            command = f'ssh {self.ssh_host_name} "{command}"'
            return self.jump_host.run_command_on_host(command)

        ssh_stdin, ssh_stdout, ssh_stderr = self.ssh_client.exec_command(command)
        if stdin:
            ssh_stdin.write(stdin)
            ssh_stdin.flush()
        std_err: str = ssh_stderr.read().decode()
        if std_err:
            logger.error(f"Host {self.name} ssh response error: {std_err}")

        return ssh_stdout.read().decode(), std_err

    # API
    def login_api(self, **kwargs) -> Response:
        headers: Dict[str, str] = self.base_headers.copy()
        headers.pop("X-SDS-AUTH-TOKEN", None)
        logger.info(f"Sending logging request to ECS {self.name}...")
        uri: str = urljoin(self.api_mgt_url, "/login")
        response = requests.request(
            "GET",
            uri,
            headers=headers,
            verify=self.verify,
            auth=(self.api_username, self.api_password),
        )

        if response.status_code == 401:
            raise ECSCLientBadCredential(response.text)
        if response.status_code >= 400:
            raise ECSCLientRequestError(response.text)

        logger.info(f"Logging succeed to: {self.name}")
        self.token = response.headers.get("X-SDS-AUTH-TOKEN")
        self.base_headers["X-SDS-AUTH-TOKEN"] = self.token
        return response

    def _request(self, method: str, endpoint: str, **kwargs) -> Response:
        if not hasattr(self, 'token') or not self.token:
            self.login_api()
        uri: str = urljoin(self.api_mgt_url, endpoint)

        if method == "GET":
            logger.debug(f"Sending {method} request at {uri}...")
        else:
            logger.info(f"Sending {method} request at {uri}...")

        base_headers = self.base_headers.copy()
        if "headers" in kwargs:
            base_headers.update(kwargs.get("headers"))
        if "json" in kwargs:
            logger.info(f'With body: {kwargs.get("json")}')

        response: Response = requests.request(
            method, uri, verify=self.verify, headers=base_headers, **kwargs
        )
        logger.debug(f"Responded with status code {response.status_code}")

        if response.status_code == 401:
            self.login_api()
            return self._request(method, endpoint, **kwargs)
        if response.status_code >= 400:
            raise ECSCLientRequestError(response.text)

        logger.debug(f"Request response: {response.text}")
        return response

    def get(self, endpoint: str, **kwargs) -> Response:
        return self._request("GET", endpoint, **kwargs)

    def post(self, endpoint: str, **kwargs) -> Response:
        return self._request("POST", endpoint, **kwargs)

    def put(self, endpoint: str, **kwargs) -> Response:
        return self._request("PUT", endpoint, **kwargs)

    def delete(self, endpoint: str, **kwargs) -> Response:
        return self._request("DELETE", endpoint, **kwargs)

    def logout_api(self) -> Optional[Response]:
        if not hasattr(self, 'token') or not self.token:
            return None
        response: Response = self.get("/logout")
        del self.base_headers["X-SDS-AUTH-TOKEN"]
        self.token = ""
        return response


### END ECS REQUEST SIMPLE SSH TUNNEL ###
### S3 AUTHENTICATION ###
class S3Signer:
    @staticmethod
    def sign_request_v2(method, url, headers, access_key, secret_key, payload):
        # … implémentation existante …
        pass


class Authenticator:
    def __init__(
            self,
            s3_config: ConfigS3,
            method: str = 'v2'
    ):
        self.access_key = s3_config.access_key
        self.secret_key = s3_config.secret_key
        self.namespace = s3_config.namespace
        self.endpoint = s3_config.endpoint.rstrip('/')
        self.region = s3_config.region
        self.auth_method = method.lower()

    def sign(
            self,
            method: str,
            bucket: Optional[str] = None,
            object_key: Optional[str] = None,
            subresource: Optional[str] = None,
            headers: Dict[str, str] = None,
            payload: bytes = b'',
    ) -> Tuple[Dict[str, str], str]:
        """
        Sign the request for S3 operations. Retourne (signed_headers, url).
        """
        if headers is None:
            headers = {}
            
        url = self.endpoint
        if bucket:
            url += f"/{bucket}"
        if object_key:
            url += f"/{object_key}"
        if subresource:
            url += subresource

        if self.auth_method == 'v2':
            signed_headers = S3Signer.sign_request_v2(
                method, url, headers, self.access_key, self.secret_key, payload
            )
            return signed_headers, url
        else:
            raise NotImplementedError("Only v2 authentication is supported at this time.")


### END S3 AUTHENTICATION ###

### EMC AUTHENTICATION ###
class ECSAuth:
    def __init__(self, emc_config: ConfigEMC):
        self.base_url = emc_config.endpoint.rstrip('/')
        self.username = emc_config.username
        self.password = emc_config.password
        self.session = requests.Session()

    def login(self) -> requests.Session:
        auth = HTTPBasicAuth(self.username, self.password)
        resp = self.session.post(f"{self.base_url}/login", auth=auth)
        resp.raise_for_status()
        return self.session

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, path: str, **kwargs) -> Response:
        return self.session.get(self._url(path), **kwargs)

    def post(self, path: str, json=None, **kwargs) -> Response:
        return self.session.post(self._url(path), json=json, **kwargs)

    def put(self, path: str, json=None, **kwargs) -> Response:
        return self.session.put(self._url(path), json=json, **kwargs)

    def delete(self, path: str, **kwargs) -> Response:
        return self.session.delete(self._url(path), **kwargs)


### END EMC AUTHENTICATION ###

class ECSClient:
    def __init__(self, emc_config: ConfigEMC):
        auth = ECSAuth(emc_config)
        self.base_url = emc_config.endpoint.rstrip('/')
        self.session = auth.login()

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, path: str, **kwargs) -> Response:
        return self.session.get(self._url(path), **kwargs)

    def post(self, path: str, json=None, **kwargs) -> Response:
        return self.session.post(self._url(path), json=json, **kwargs)

    def put(self, path: str, json=None, **kwargs) -> Response:
        return self.session.put(self._url(path), json=json, **kwargs)

    def delete(self, path: str, **kwargs) -> Response:
        return self.session.delete(self._url(path), **kwargs)


### NOUVELLES CLASSES DE REQUÊTES REST ###

class NamespaceRequest:
    """
    Gérez les namespaces via l'API Management ECS.
    - List/Create: GET|POST /object/namespaces
    - Get/Update/Delete: GET|PUT|DELETE /object/namespaces/namespace/{namespace}
    """
    def __init__(self, emc_config: ConfigEMC):
        self.client = ECSClient(emc_config)

    def list(self) -> Response:
        return self.client.get("/object/namespaces")

    def get(self, namespace: str) -> Response:
        return self.client.get(f"/object/namespaces/namespace/{quote_plus(namespace)}")

    def create(
        self,
        namespace: str,
        default_replication_group: Optional[str] = None,
        namespace_admins: Optional[List[str]] = None,
        quota: Optional[Dict[str, int]] = None,
        encryption: bool = False
    ) -> Response:
        payload: Dict = {"namespace": namespace}
        if default_replication_group:
            payload["defaultReplicationGroup"] = default_replication_group
        if namespace_admins:
            payload["namespaceAdmins"] = namespace_admins
        if quota:
            payload["quota"] = quota
        payload["encryption"] = encryption
        return self.client.post("/object/namespaces", json=payload)

    def update(self, namespace: str, **kwargs) -> Response:
        return self.client.put(f"/object/namespaces/namespace/{quote_plus(namespace)}", json=kwargs)

    def delete(self, namespace: str) -> Response:
        return self.client.delete(f"/object/namespaces/namespace/{quote_plus(namespace)}")


class BucketRequest:
    """
    Gérez les buckets via l'API Management ECS.
    - List/Create: GET|POST /object/bucket
    - Get/Update/Delete: GET|PUT|DELETE /object/bucket/{bucketName}
    - Metadata: POST /object/bucket/{bucketName}/metadata
    """
    def __init__(self, emc_config: ConfigEMC):
        self.client = ECSClient(emc_config)

    def list(self, namespace: Optional[str] = None) -> Response:
        params = {}
        if namespace:
            params["namespace"] = namespace
        return self.client.get("/object/bucket", params=params)

    def get(self, bucket: str) -> Response:
        return self.client.get(f"/object/bucket/{quote_plus(bucket)}")

    def create(
        self,
        bucket: str,
        namespace: Optional[str] = None,
        file_system_enabled: bool = False,
        quota: Optional[int] = None,
        retention: Optional[int] = None
    ) -> Response:
        payload: Dict = {"bucket": bucket}
        if namespace:
            payload["namespace"] = namespace
        if file_system_enabled:
            payload["fileSystemEnabled"] = True
        if quota is not None:
            payload["quota"] = quota
        if retention is not None:
            payload["retention"] = retention
        return self.client.post("/object/bucket", json=payload)

    def update(self, bucket: str, **kwargs) -> Response:
        return self.client.put(f"/object/bucket/{quote_plus(bucket)}", json=kwargs)

    def delete(self, bucket: str) -> Response:
        return self.client.delete(f"/object/bucket/{quote_plus(bucket)}")

    def set_metadata(self, bucket: str, metadata: Dict[str, str]) -> Response:
        return self.client.post(f"/object/bucket/{quote_plus(bucket)}/metadata", json=metadata)


def _build_lifecycle_config(rules: List[ET.Element]) -> bytes:
    """Helper function to build lifecycle configuration XML."""
    root = ET.Element('LifecycleConfiguration')
    for rule in rules:
        root.append(rule)
    return ET.tostring(root, encoding='utf-8')


def build_rule_with_date(rule_id: str, prefix: str, date_str: str) -> ET.Element:
    """Build a lifecycle rule with expiration by date."""
    rule = ET.Element('Rule')
    id_elem = ET.SubElement(rule, 'ID')
    id_elem.text = rule_id
    prefix_elem = ET.SubElement(rule, 'Prefix')
    prefix_elem.text = prefix
    status = ET.SubElement(rule, 'Status')
    status.text = 'Enabled'
    expiration = ET.SubElement(rule, 'Expiration')
    date_elem = ET.SubElement(expiration, 'Date')
    date_elem.text = date_str
    return rule


def build_rule_with_days(rule_id: str, prefix: str, days: int) -> ET.Element:
    """Build a lifecycle rule with expiration by days."""
    rule = ET.Element('Rule')
    id_elem = ET.SubElement(rule, 'ID')
    id_elem.text = rule_id
    prefix_elem = ET.SubElement(rule, 'Prefix')
    prefix_elem.text = prefix
    status = ET.SubElement(rule, 'Status')
    status.text = 'Enabled'
    expiration = ET.SubElement(rule, 'Expiration')
    days_elem = ET.SubElement(expiration, 'Days')
    days_elem.text = str(days)
    return rule


class LifecycleRequest:
    """
    Gestion des lifecycles S3 inspirée de ecs-s3-manager.
    """
    def __init__(self, s3_config: ConfigS3):
        self.auth = Authenticator(s3_config)

    def get_lifecycle(self, bucket: str) -> str:
        headers, url = self.auth.sign('GET', bucket=bucket, subresource='?lifecycle')
        resp = requests.get(url, headers=headers)
        if resp.status_code == 404:
            return ""
        resp.raise_for_status()
        return resp.text

    def list_rules(self, bucket: str) -> List[str]:
        xml = self.get_lifecycle(bucket)
        if not xml:
            return []
        root = ET.fromstring(xml)
        return [rule.find('ID').text for rule in root.findall('Rule')]

    def apply_rules(self, bucket: str, rules: List[ET.Element]) -> Response:
        xml_body = _build_lifecycle_config(rules)
        digest = hashlib.md5(xml_body).digest()
        md5_b64 = base64.b64encode(digest).decode('utf-8')
        hdrs = {
            'Content-Type': 'application/xml',
            'Content-MD5': md5_b64,
            'Content-Length': str(len(xml_body))
        }
        signed, url = self.auth.sign('PUT', bucket=bucket, subresource='?lifecycle', headers=hdrs, payload=xml_body)
        resp = requests.put(url, headers=signed, data=xml_body)
        resp.raise_for_status()
        return resp

    def create_rule_with_date(self, bucket: str, rule_id: str, prefix: str, date_str: str) -> Response:
        rule = build_rule_with_date(rule_id, prefix, date_str)
        return self.apply_rules(bucket, [rule])

    def create_rule_with_days(self, bucket: str, rule_id: str, prefix: str, days: int) -> Response:
        rule = build_rule_with_days(rule_id, prefix, days)
        return self.apply_rules(bucket, [rule])