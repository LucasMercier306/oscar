from dataclasses import dataclass
from typing import Optional
import xml.etree.ElementTree as ET

@dataclass
class BucketInfo:
    id: str
    name: str
    namespace: str
    vpool: Optional[str]
    retention: Optional[int]
    auto_commit_period: Optional[int]
    fs_access_enabled: Optional[bool]
    is_tso_read_only: Optional[bool]

    @staticmethod
    def from_xml(xml: str) -> "BucketInfo":
        """
        Parse un payload XML <bucket_info>…</bucket_info> et
        retourne une instance de BucketInfo.
        """
        root = ET.fromstring(xml)

        def get_text(tag: str) -> Optional[str]:
            elem = root.find(tag)
            return elem.text if elem is not None else None

        def get_int(tag: str) -> Optional[int]:
            txt = get_text(tag)
            try:
                return int(txt)  # lève si txt n'est pas un int
            except (TypeError, ValueError):
                return None

        def get_bool(tag: str) -> Optional[bool]:
            txt = get_text(tag)
            if txt is None:
                return None
            return txt.lower() == "true"

        return BucketInfo(
            id=get_text("id") or "",
            name=get_text("name") or "",
            namespace=get_text("namespace") or "",
            vpool=get_text("vpool"),
            retention=get_int("retention"),
            auto_commit_period=get_int("auto_commit_period"),
            fs_access_enabled=get_bool("fs_access_enabled"),
            is_tso_read_only=get_bool("is_tso_read_only"),
        )
