import base64
import hashlib
import hmac
from datetime import datetime
from typing import Dict, Optional, Tuple

from ecs_client import ConfigS3


class S3Signer:
    @staticmethod
    def sign_request_v2(
        method: str,
        url: str,
        headers: Dict[str, str],
        access_key: str,
        secret_key: str,
        payload: bytes,
    ) -> Dict[str, str]:
        """
        AWS Signature V2 compatible pour ECS S3.
        """
        # 1. Date
        if "Date" not in headers:
            headers["Date"] = datetime.utcnow().strftime(
                "%a, %d %b %Y %H:%M:%S GMT"
            )
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
            hmac.new(
                secret_key.encode(), string_to_sign.encode(), hashlib.sha1
            ).digest()
        ).decode()
        headers["Authorization"] = f"AWS {access_key}:{sig}"
        return headers


class Authenticator:
    def __init__(self, s3_config: ConfigS3, method: str = "v2"):
        self.access_key = s3_config.access_key
        self.secret_key = s3_config.secret_key
        self.namespace = s3_config.namespace
        self.endpoint = s3_config.endpoint.rstrip("/")
        self.region = s3_config.region
        self.auth_method = method.lower()

    def sign(
        self,
        method: str,
        bucket: Optional[str] = None,
        object_key: Optional[str] = None,
        subresource: Optional[str] = None,
        headers: Dict[str, str] = None,
        payload: bytes = b"",
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

        if self.auth_method == "v2":
            signed_headers = S3Signer.sign_request_v2(
                method, url, headers, self.access_key, self.secret_key, payload
            )
            return signed_headers, url
        else:
            raise NotImplementedError(
                "Only v2 authentication is supported at this time."
            )
