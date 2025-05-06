from dataclasses import dataclass
from ecs_client.models.metadata import Metadata
from ecs_client.models.lifecycle import Lifecycle

@dataclass
class Bucket:
    name: str
    metadata: Metadata
