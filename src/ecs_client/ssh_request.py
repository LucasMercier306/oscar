from typing import Dict, Optional, Tuple
from urllib.parse import urljoin

import paramiko
import requests
from paramiko import SSHClient
from requests import Response

from ecs_client import ConfigECS, logger
from ecs_client.exceptions import ECSCLientBadCredential, ECSCLientRequestError


class ECSRequest:
    def __init__(
        self, ecs_config: ConfigECS, jump_host: Optional["ECSRequest"] = None
    ):
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

        self.api_mgt_url = f"{ecs_config.protocol}://{ecs_config.host_name}:{ecs_config.api_port}"
        self.base_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        self.ssh_client = None
        self.token = None

    # SSH
    def login_ssh(self):
        if self.jump_host:
            logger.info(
                f"{self.name} has {self.jump_host.name} as jump host..."
            )
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

    def run_command_on_host(
        self, command: str, *, log_command: bool = True, stdin: str = ""
    ) -> Tuple[str, str]:
        if (
            not self.ssh_client
            or not self.ssh_client.get_transport().is_active()
        ):
            self.login_ssh()

        if log_command:
            logger.info(f"On host {self.name}, running command: {command}")
        if self.jump_host:
            command = f'ssh {self.ssh_host_name} "{command}"'
            return self.jump_host.run_command_on_host(command)

        ssh_stdin, ssh_stdout, ssh_stderr = self.ssh_client.exec_command(
            command
        )
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
        if not hasattr(self, "token") or not self.token:
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
        if not hasattr(self, "token") or not self.token:
            return None
        response: Response = self.get("/logout")
        del self.base_headers["X-SDS-AUTH-TOKEN"]
        self.token = ""
        return response
