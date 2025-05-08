from dataclasses import dataclass
from datetime import datetime


@dataclass
class Lifecycle:
    name: str
    expiration_date: datetime
    filter: str
