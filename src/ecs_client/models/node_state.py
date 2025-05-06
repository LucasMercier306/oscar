from dataclasses import dataclass


@dataclass
class NodeState:
    TotalDTnum: float
    UnreadyDTnum: float
    UnknownDTnum: float
    NodeIP: str
    ActiveConnections: float
