from typing import Dict, Optional, Tuple
from urllib.parse import urljoin, quote_plus, urlparse
import paramiko
import requests
from paramiko import SSHClient
from requests import Response
import hashlib
import hmac
import base64
import datetime
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
        if not self.token:
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
            return self._request(method, uri, **kwargs)
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
        if not self.token:
            return
        response: Response = self.get("/logout")
        del self.base_headers["X-SDS-AUTH-TOKEN"]
        self.token = ""
        return response
### END ECS REQUEST SIMPLE SSH TUNNEL ###


### S3 AUTHENTICATION ###

class S3Signer:
    @staticmethod
    def sign_request_v2(method: str, url: str, headers: dict, access_key: str, secret_key: str, payload: bytes = b'') -> dict:
        parsed = urlparse(url)
        path = parsed.path or '/'
        canonical_resource = path
        if parsed.query:
            canonical_resource += '?' + parsed.query

        now = datetime.datetime.utcnow()
        date_str = now.strftime('%a, %d %b %Y %H:%M:%S GMT')
        headers['Date'] = headers.get('Date', date_str)

        amz_headers = {}
        for k, v in headers.items():
            lk = k.lower()
            if lk.startswith('x-amz-') or lk.startswith('x-emc-'):
                amz_headers[lk] = ' '.join(v.split())
        canonical_amz = ''.join(f"{k}:{amz_headers[k]}\n" for k in sorted(amz_headers))

        content_md5 = headers.get('Content-MD5', '')
        content_type = headers.get('Content-Type', '')

        string_to_sign = "\n".join([
            method,
            content_md5,
            content_type,
            headers['Date'],
            canonical_amz + canonical_resource
        ])

        sig = hmac.new(secret_key.encode('utf-8'),
                       string_to_sign.encode('utf-8'),
                       hashlib.sha1).digest()
        signature_b64 = base64.b64encode(sig).decode('utf-8')

        headers['Authorization'] = f"AWS {access_key}:{signature_b64}"
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
            bucket: str = '',
            object_name: str = '',
            subresource: str = '',
            headers: dict = None,
            payload: bytes = b''
    ) -> (dict, str):
        headers = headers.copy() if headers else {}
        headers['x-emc-namespace'] = self.namespace

        path = f"/{bucket}" if bucket else '/'
        if object_name:
            path += f"/{quote_plus(object_name)}"
        url = self.endpoint + path
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
        self.cert = None
        self.session = requests.Session()

    def login(self):
        auth = HTTPBasicAuth(self.username, self.password)
        resp = self.session.post(f"{self.base_url}/login", auth=auth)
        resp.raise_for_status()
        return self.session

    def logout(self):
        resp = self.session.post(f"{self.base_url}/logout")
        resp.raise_for_status()

    def get_session(self):
        return self.login()

class ECSClient:
    def __init__(self, emc_config: ConfigEMC):
        auth = ECSAuth(emc_config)
        self.base_url = emc_config.endpoint.rstrip('/')
        self.session = auth.get_session()

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, path: str, **kwargs):
        breakpoint()
        return self.session.get(self._url(path), **kwargs)

    def post(self, path: str, json=None, **kwargs):
        return self.session.post(self._url(path), json=json, **kwargs)

    def put(self, path: str, json=None, **kwargs):
        return self.session.put(self._url(path), json=json, **kwargs)

    def delete(self, path: str, **kwargs):
        return self.session.delete(self._url(path), **kwargs)
### END EMC AUTHENTICATION ###
