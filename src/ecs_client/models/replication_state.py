from dataclasses import dataclass
from typing import List


@dataclass
class Links:
    datatables: dict
    rglinks: dict
    self: dict


@dataclass
class ReplicationEgressTraffic:
    Bandwidth: str
    t: str


@dataclass
class ReplicationIngressTraffic:
    Bandwidth: str
    t: str


@dataclass
class ReplicationGroup:
    _links: Links
    chunksJournalPendingReplicationTotalSize: str
    chunksPendingXorTotalSize: str
    chunksRepoPendingReplicationTotalSize: str
    id: str
    name: str
    numZones: str
    replicationEgressTrafficCurrent: List[ReplicationEgressTraffic]
    replicationIngressTrafficCurrent: List[ReplicationIngressTraffic]
    replicationRpoTimestamp: str = ""

    @staticmethod
    def from_dict(data: dict) -> "ReplicationGroup":
        replication_egress_traffic = [
            ReplicationEgressTraffic(**item)
            for item in data["replicationEgressTrafficCurrent"]
        ]
        replication_ingress_traffic = [
            ReplicationIngressTraffic(**item)
            for item in data["replicationIngressTrafficCurrent"]
        ]
        replication_rpo_timestamp = data.get("replicationRpoTimestamp", "")
        return ReplicationGroup(
            _links=Links(**data["_links"]),
            chunksJournalPendingReplicationTotalSize=data[
                "chunksJournalPendingReplicationTotalSize"
            ],
            chunksPendingXorTotalSize=data["chunksPendingXorTotalSize"],
            chunksRepoPendingReplicationTotalSize=data[
                "chunksRepoPendingReplicationTotalSize"
            ],
            id=data["id"],
            name=data["name"],
            numZones=data["numZones"],
            replicationEgressTrafficCurrent=replication_egress_traffic,
            replicationIngressTrafficCurrent=replication_ingress_traffic,
            replicationRpoTimestamp=replication_rpo_timestamp,
        )


@dataclass
class ReplicationState:
    _embedded: dict
    _links: dict
    apiChange: str
    title: str

    @staticmethod
    def from_dict(data: dict) -> "ReplicationState":
        replication_groups = []
        if "_embedded" in data and "_instances" in data["_embedded"]:
            replication_groups = [
                ReplicationGroup.from_dict(item)
                for item in data["_embedded"]["_instances"]
            ]
        return ReplicationState(
            _embedded={"_instances": replication_groups},
            _links=data["_links"],
            apiChange=data["apiChange"],
            title=data["title"],
        )
