from dataclasses import dataclass
from ecs_client.models.bucket import Bucket
from typing import List


@dataclass
class Namespace:
    name: str
    buckets: List[Bucket]