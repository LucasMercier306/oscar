from dataclasses import dataclass
from datetime import datetime

@dataclass
class Metadata:
    create_date: datetime
    indicateur: str