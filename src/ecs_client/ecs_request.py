import pickle

import requests
from requests.auth import HTTPBasicAuth

from ecs_client import logger


class ECSAuth:
    def __init__(self, emc_config):
        self.base_url = emc_config.endpoint.rstrip("/")
        self.username = emc_config.username
        self.password = emc_config.password
        self.session = requests.Session()
        self.cookie_file = "cookiefile.pkl"

    def login(self):
        login_url = f"{self.base_url}/login?using-cookies=true"
        auth = HTTPBasicAuth(self.username, self.password)
        resp = self.session.get(login_url, auth=auth, verify=False)
        logger.info(resp.content)
        resp.raise_for_status()

        # Save cookies to a file using pickle
        with open(self.cookie_file, "wb") as f:
            pickle.dump(self.session.cookies, f)

        return self.session

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, path: str, **kwargs) -> requests.Response:
        kwargs.setdefault("headers", {}).update(self._get_auth_headers())
        return self.session.get(self._url(path), **kwargs, verify=False)

    def post(self, path: str, json=None, **kwargs) -> requests.Response:
        kwargs.setdefault("headers", {}).update(self._get_auth_headers())
        return self.session.post(
            self._url(path), json=json, **kwargs, verify=False
        )

    def put(self, path: str, json=None, **kwargs) -> requests.Response:
        kwargs.setdefault("headers", {}).update(self._get_auth_headers())
        return self.session.put(
            self._url(path), json=json, **kwargs, verify=False
        )

    def delete(self, path: str, **kwargs) -> requests.Response:
        kwargs.setdefault("headers", {}).update(self._get_auth_headers())
        return self.session.delete(self._url(path), **kwargs, verify=False)

    def _get_auth_headers(self):
        token = self.session.cookies.get("auth_token")
        if not token:
            logger.error("Authentication token not found in cookies.")
            raise ValueError("Authentication token not found.")
        return {"Authorization": token}


class ECSClient:
    def __init__(self, emc_config):

        self.emc_config = emc_config
        auth = ECSAuth(emc_config)
        self.base_url = emc_config.endpoint.rstrip("/")
        self.session = auth.login()
    
    def get_bucket_metadata(self, bucket: str, namespace: str) -> Dict[str, str]:
        """
        Retrieve all metadata of the specified bucket.
        Returns a dict of metadata keys and values.
        """
        params = {"namespace": namespace}
        resp = self.get(f"/object/bucket/{bucket}/info", params=params)
        resp.raise_for_status()
        # parse XML into dict
        import xml.etree.ElementTree as ET
        root = ET.fromstring(resp.text)
        return {child.tag: child.text for child in root}

    def set_bucket_owner(self, bucket: str, namespace: str, new_owner: str) -> requests.Response:
        """
        Update the owner of a bucket via ECS Management REST API.
        """
        params = {"namespace": namespace}
        # build XML payload
        import xml.etree.ElementTree as ET
        root = ET.Element("bucket")
        ET.SubElement(root, "owner").text = new_owner
        xml_body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        headers = {"Content-Type": "application/xml"}
        resp = self.put(f"/object/bucket/{bucket}", data=xml_body, headers=headers, params=params)
        resp.raise_for_status()
        return resp

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(self._url(path), **kwargs, verify=False)

    def post(self, path: str, json=None, **kwargs) -> requests.Response:
        return self.session.post(
            self._url(path), json=json, **kwargs, verify=False
        )

    def put(self, path: str, json=None, **kwargs) -> requests.Response:
        return self.session.put(
            self._url(path), json=json, **kwargs, verify=False
        )

    def delete(self, path: str, **kwargs) -> requests.Response:
        return self.session.delete(self._url(path), **kwargs, verify=False)
