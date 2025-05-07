from typing import Dict, Optional, Tuple, List
from urllib.parse import urljoin, quote_plus
import paramiko
import requests
from ecs_client.models import namespace
from paramiko import SSHClient
from requests import Response
from datetime import datetime
import hashlib
import hmac
import base64
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth

from ecs_client import ConfigECS, ConfigS3, ConfigEMC, ConfigECSClient, logger
from ecs_client.exceptions import ECSCLientBadCredential, ECSCLientRequestError
import pickle
from ecs_client.models.namespace import NamespaceData
from xml.etree.ElementTree import Element, SubElement, tostring
from ecs_client.models.bucket import BucketInfo
from urllib.parse import urlparse
import hashlib
import base64




### ECS REQUEST SIMPLE SSH TUNNEL ###
class ECSRequest:
    def __init__(self, ecs_config: ConfigECS, jump_host: Optional["ECSRequest"] = None):
        self.name = ecs_config.name
        self.cluster = ecs_config.name

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
        return self._request("GET", endpoint, **kwargs, verify=False)

    def post(self, endpoint: str, **kwargs) -> Response:
        return self._request("POST", endpoint, **kwargs, verify=False)

    def put(self, endpoint: str, **kwargs) -> Response:
        return self._request("PUT", endpoint, **kwargs, verify=False)

    def delete(self, endpoint: str, **kwargs) -> Response:
        return self._request("DELETE", endpoint, **kwargs, verify=False)

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
    def sign_request_v2(
        method: str,
        url: str,
        headers: Dict[str, str],
        access_key: str,
        secret_key: str,
        payload: bytes
    ) -> Dict[str, str]:
        """
        AWS Signature V2 compatible pour ECS S3.
        """
        # 1. Date
        if "Date" not in headers:
            headers["Date"] = datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        # 2. MD5 et Content-Type
        content_md5 = headers.get("Content-MD5", "")
        content_type = headers.get("Content-Type", "")
        # 3. Canonicalized x-emc- / x-amz- headers
        amz = {
            k.lower(): v
            for k, v in headers.items()
            if k.lower().startswith("x-emc-") or k.lower().startswith("x-amz-")
        }
        canonical_amz = "".join(f"{k}:{amz[k]}\n" for k in sorted(amz))
        # 4. Canonicalized resource
        from urllib.parse import urlparse
        parsed = urlparse(url)
        resource = parsed.path
        if parsed.query:
            resource += "?" + parsed.query
        # 5. String to sign
        string_to_sign = (
            f"{method}\n"
            f"{content_md5}\n"
            f"{content_type}\n"
            f"{headers['Date']}\n"
            f"{canonical_amz}"
            f"{resource}"
        )
        # 6. Calcul de la signature
        sig = base64.b64encode(
            hmac.new(secret_key.encode(), string_to_sign.encode(), hashlib.sha1).digest()
        ).decode()
        headers["Authorization"] = f"AWS {access_key}:{sig}"
        return headers

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
    def __init__(self, emc_config):
        self.base_url = emc_config.endpoint.rstrip('/')
        self.username = emc_config.username
        self.password = emc_config.password
        self.session = requests.Session()
        self.cookie_file = 'cookiefile.pkl'

    def login(self):
        login_url = f"{self.base_url}/login?using-cookies=true"
        auth = HTTPBasicAuth(self.username, self.password)
        resp = self.session.get(login_url, auth=auth, verify=False)
        logger.info(resp.content)
        resp.raise_for_status()

        # Save cookies to a file using pickle
        with open(self.cookie_file, 'wb') as f:
            pickle.dump(self.session.cookies, f)

        return self.session

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, path: str, **kwargs) -> requests.Response:
        kwargs.setdefault('headers', {}).update(self._get_auth_headers())
        return self.session.get(self._url(path), **kwargs, verify=False)

    def post(self, path: str, json=None, **kwargs) -> requests.Response:
        kwargs.setdefault('headers', {}).update(self._get_auth_headers())
        return self.session.post(self._url(path), json=json, **kwargs, verify=False)

    def put(self, path: str, json=None, **kwargs) -> requests.Response:
        kwargs.setdefault('headers', {}).update(self._get_auth_headers())
        return self.session.put(self._url(path), json=json, **kwargs, verify=False)

    def delete(self, path: str, **kwargs) -> requests.Response:
        kwargs.setdefault('headers', {}).update(self._get_auth_headers())
        return self.session.delete(self._url(path), **kwargs, verify=False)

    def _get_auth_headers(self):
        token = self.session.cookies.get('auth_token')
        if not token:
            logger.error("Authentication token not found in cookies.")
            raise ValueError("Authentication token not found.")
        return {"Authorization": token}

### END EMC AUTHENTICATION ###

class ECSClient:
    def __init__(self, emc_config):

        self.emc_config = emc_config
        auth = ECSAuth(emc_config)
        self.base_url = emc_config.endpoint.rstrip('/')
        self.session = auth.login()

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(self._url(path), **kwargs, verify=False)

    def post(self, path: str, json=None, **kwargs) -> requests.Response:
        return self.session.post(self._url(path), json=json, **kwargs, verify=False)

    def put(self, path: str, json=None, **kwargs) -> requests.Response:
        return self.session.put(self._url(path), json=json, **kwargs, verify=False)

    def delete(self, path: str, **kwargs) -> requests.Response:
        return self.session.delete(self._url(path), **kwargs, verify=False)
    
class NamespaceRequest:
    """
    Gérez les namespaces via l'API Management ECS.
    """
    def __init__(self, emc_config: ConfigEMC):
        self.client = ECSClient(emc_config)

    def list(self) -> List[Dict[str, str]]:
        """
        Liste les namespaces via l’API Management ECS,
        retourne une liste de dicts {'id': ..., 'defaultReplicationGroup': ..., …}
        """
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
        resp = self.client.get(f"/object/namespaces/namespace/{quote_plus(namespace)}")
        return NamespaceData.from_xml(resp.content)

    def create(
        self,
        namespace: str,
        default_replication_group: Optional[str] = None,
        namespace_admins: Optional[List[str]] = None,
        quota: Optional[Dict[str, int]] = None,
        encryption: bool = False
    ) -> Response:
        # Construction du XML pour la création
        root = ET.Element("namespace")
        ET.SubElement(root, "id").text = namespace
        if default_replication_group:
            ET.SubElement(root, "defaultReplicationGroup").text = default_replication_group
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
        return self.client.post("/object/namespaces", data=xml_body, headers=headers)



class BucketRequest:
    """
    Gérez les buckets via l'API Management ECS.
    """
    def __init__(self, emc_config: ConfigEMC):
        # Le client gère déjà l'authentification et stocke emc_config
        self.client = ECSClient(emc_config)

    def get(self, bucket: str, namespace: str) -> BucketInfo:
        """
        Récupère les propriétés d'un bucket et renvoie un BucketInfo.
        
        :param bucket: le nom du bucket
        :param namespace: namespace auquel il appartient (obligatoire)
        :raises ValueError si namespace vide
        :raises HTTPError si le statut HTTP >= 400
        """
        if not namespace:
            raise ValueError("Le paramètre 'namespace' est obligatoire pour get_bucket")

        qp_bucket = quote_plus(bucket)
        # L'API Management REST s'attend à /info?namespace=<ns>
        resp: Response = self.client.get(
            f"/object/bucket/{qp_bucket}/info",
            params={"namespace": namespace}
        )
        resp.raise_for_status()
        # Transforme le XML brut en dataclass BucketInfo
        return BucketInfo.from_xml(resp.text)


    def create(
        self,
        bucket: str,
        namespace: str,
        file_system_enabled: bool = False,
        quota: Optional[int] = None,
        retention: Optional[int] = None,
        autocommit_period: Optional[int] = None,
        default_data_services_vpool: Optional[str] = None
    ) -> Response:
        """
        Création de bucket via l’API Management ECS (XML).
        Si default_data_services_vpool n'est pas fourni, on le récupère depuis le namespace.
        """
        # 1) Récupérer le vpool si absent
        if default_data_services_vpool is None:
            ns_data = NamespaceRequest(self.client.emc_config).get(namespace)
            default_data_services_vpool = getattr(
                ns_data, "default_data_services_vpool", None
            )

        # 2) Construire le XML selon la spec REST
        root = ET.Element("object_bucket_create")
        ET.SubElement(root, "name").text = bucket
        ET.SubElement(root, "namespace").text = namespace

        if file_system_enabled:
            # tag camelCase pour JSON compatibility
            ET.SubElement(root, "fileSystemEnabled").text = "true"
            # tag underscore pour TSO activation
            ET.SubElement(root, "read_only_tso").text = "true"

        if quota is not None:
            ET.SubElement(root, "quota").text = str(quota)
        if retention is not None:
            ET.SubElement(root, "retention").text = str(retention)
        if autocommit_period is not None:
            ET.SubElement(root, "autocommit_period").text = str(autocommit_period)
        if default_data_services_vpool:
            ET.SubElement(
                root, "defaultDataServicesVpool"
            ).text = default_data_services_vpool

        xml_body = ET.tostring(root, encoding="utf-8", xml_declaration=True)

        # 3) Envoi de la requête
        headers = {"Content-Type": "application/xml"}
        return self.client.post("/object/bucket", data=xml_body, headers=headers)

    def delete(self, bucket: str, namespace: str) -> Response:
        qp_bucket = quote_plus(bucket)
        qp_ns = quote_plus(namespace)
        return self.client.delete(f"/object/bucket/{qp_bucket}?namespace={qp_ns}")

    def set_metadata(
        self,
        bucket: str,
        namespace: str,
        head_type: str,
        metadata: List[Dict[str, str]]
    ) -> Response:
        """
        Déploie la secure bucket metadata (HDFS) sur un bucket via ECS Management REST API.
        Exige un JSON de la forme :
        {
          "head_type": "...",
          "metadata": [
            {"name":"...", "value":"..."},
            ...
          ]
        }
        """
        if not namespace:
            raise ValueError("Le paramètre 'namespace' est obligatoire pour set_metadata")

        qp_bucket = quote_plus(bucket)
        # Construction du payload JSON
        payload = {
            "head_type": head_type,
            "metadata": [
                {"name": m["name"], "value": m["value"]} for m in metadata
            ]
        }
        # Envoi en PUT sur /object/bucket/{bucket}/metadata?namespace=...
        return self.client.put(
            f"/object/bucket/{qp_bucket}/metadata",
            params={"namespace": namespace},
            json=payload
        )


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
    Utilise le path-style pour ECS Test Drive : get, create, delete lifecycles.
    """

    def __init__(self, s3_config: ConfigS3):
        self.auth = Authenticator(s3_config)

    def get_lifecycle(self, bucket: str) -> str:
        """
        Récupère la configuration lifecycle en XML pour un bucket S3 ECS.
        Path-style: https://<endpoint>/<bucket>?lifecycle
        + Header x-emc-namespace
        """
        endpoint = self.auth.endpoint.rstrip('/')
        url = f"{endpoint}/{bucket}?lifecycle"

        # Header namespace + signature V2
        headers = {"x-emc-namespace": self.auth.namespace}
        signed_headers = S3Signer.sign_request_v2(
            "GET", url, headers.copy(),
            self.auth.access_key, self.auth.secret_key, b""
        )

        resp = requests.get(url, headers=signed_headers, verify=False)
        if resp.status_code == 404:
            return ""
        resp.raise_for_status()
        return resp.text

    def list_rules(self, bucket: str) -> List[str]:
        """
        Renvoie la liste des IDs de règles lifecycle.
        """
        xml = self.get_lifecycle(bucket)
        if not xml:
            return []
        root = ET.fromstring(xml)
        return [rule.find('ID').text for rule in root.findall('Rule')]

    def apply_rules(self, bucket: str, rules: List[ET.Element]) -> requests.Response:
        """
        Applique un nouveau LifecycleConfiguration (remplace l’existant).
        Path-style: https://<endpoint>/<bucket>?lifecycle
        + Headers x-emc-namespace, Content-MD5, Content-Length, Content-Type.
        """
        xml_body = _build_lifecycle_config(rules)
        md5_b64 = base64.b64encode(hashlib.md5(xml_body).digest()).decode("utf-8")

        endpoint = self.auth.endpoint.rstrip('/')
        url = f"{endpoint}/{bucket}?lifecycle"

        headers = {
            "x-emc-namespace": self.auth.namespace,
            "Content-MD5":     md5_b64,
            "Content-Type":    "application/xml",
            "Content-Length":  str(len(xml_body)),
        }

        signed_headers = S3Signer.sign_request_v2(
            "PUT", url, headers.copy(),
            self.auth.access_key, self.auth.secret_key, xml_body
        )

        resp = requests.put(url, headers=signed_headers, data=xml_body, verify=False)
        resp.raise_for_status()
        return resp

    def create_rule_with_date(self, bucket: str, rule_id: str, prefix: str, date_str: str) -> requests.Response:
        """
        Crée et applique une règle expiration par date.
        """
        rule = build_rule_with_date(rule_id, prefix, date_str)
        return self.apply_rules(bucket, [rule])

    def create_rule_with_days(self, bucket: str, rule_id: str, prefix: str, days: int) -> requests.Response:
        """
        Crée et applique une règle expiration par nombre de jours.
        """
        rule = build_rule_with_days(rule_id, prefix, days)
        return self.apply_rules(bucket, [rule])

    def delete_lifecycle(self, bucket: str) -> requests.Response:
        """
        Supprime la configuration lifecycle du bucket.
        Path-style: https://<endpoint>/<bucket>?lifecycle
        + Header x-emc-namespace.
        """
        endpoint = self.auth.endpoint.rstrip('/')
        url = f"{endpoint}/{bucket}?lifecycle"

        headers = {"x-emc-namespace": self.auth.namespace}
        signed_headers = S3Signer.sign_request_v2(
            "DELETE", url, headers.copy(),
            self.auth.access_key, self.auth.secret_key, b""
        )

        resp = requests.delete(url, headers=signed_headers, verify=False)
        resp.raise_for_status()
        return resp
