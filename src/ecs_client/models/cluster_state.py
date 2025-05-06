from dataclasses import dataclass
from typing import List


@dataclass
class Links:
    nodes: dict
    replicationgroups: dict
    rglinksBootstrap: dict
    rglinksFailed: dict
    self: dict
    storagepools: dict


@dataclass
class Count:
    Count: str
    t: str


@dataclass
class Space:
    Space: str
    t: str


@dataclass
class Percent:
    Percent: str
    t: str


@dataclass
class Capacity:
    Capacity: str
    t: str


@dataclass
class ClusterState:
    BootstrapProgressPercent: str
    _links: Links
    alertsNumUnackCritical: List[Count]
    alertsNumUnackError: List[Count]
    alertsNumUnackInfo: List[Count]
    alertsNumUnackWarning: List[Count]
    allocatedCapacityForecast: List
    apiChange: str
    chunksEcApplicableTotalSealSizeCurrent: List[Space]
    chunksEcCodedRatioCurrent: List[Percent]
    chunksEcCodedTotalSealSizeCurrent: List[Space]
    chunksEcRateCurrent: List[dict]
    chunksGeoCacheCount: str
    chunksGeoCacheTotalSize: str
    chunksGeoCopyAvgSize: str
    chunksGeoCopyNumber: str
    chunksGeoCopyTotalSize: str
    chunksJournalPendingReplicationTotalSize: str
    chunksL0BtreeAvgSize: str
    chunksL0BtreeNumber: str
    chunksL0BtreeTotalSize: str
    chunksL0JournalAvgSize: str
    chunksL0JournalNumber: str
    chunksL0JournalTotalSize: str
    chunksL1BtreeAvgSize: str
    chunksL1BtreeNumber: str
    chunksL1BtreeTotalSize: str
    chunksL1JournalAvgSize: str
    chunksL1JournalNumber: str
    chunksL1JournalTotalSize: str
    chunksRepoAvgSealSize: str
    chunksRepoNumber: str
    chunksRepoPendingReplicationTotalSize: str
    chunksRepoTotalSealSize: str
    chunksXorNumber: str
    chunksXorTotalSize: str
    diskSpaceAllocatedCurrent: List[Space]
    diskSpaceAllocatedGeoCacheCurrent: List[Capacity]
    diskSpaceAllocatedGeoCopyCurrent: List[Capacity]
    diskSpaceAllocatedLocalProtectionCurrent: List[Capacity]
    diskSpaceAllocatedSystemMetadataCurrent: List[Capacity]
    diskSpaceAllocatedUserDataCurrent: List[Capacity]
    diskSpaceFreeCurrent: List[Space]
    diskSpaceOfflineTotalCurrent: List[Space]
    diskSpaceReservedCurrent: List[Space]
    diskSpaceTotalCurrent: List[Space]
    gcCombinedPendingCurrent: List[Capacity]
    gcCombinedReclaimedCurrent: List[Capacity]
    gcCombinedTotalDetectedCurrent: List[Capacity]
    gcCombinedUnreclaimableCurrent: List[Capacity]
    gcSystemMetadataIsEnabled: str
    gcSystemPendingCurrent: List[Capacity]
    gcSystemReclaimedCurrent: List[Capacity]
    gcSystemTotalDetectedCurrent: List[Capacity]
    gcSystemUnreclaimableCurrent: List[Capacity]
    gcUserDataIsEnabled: str
    gcUserPendingCurrent: List[Capacity]
    gcUserReclaimedCurrent: List[Capacity]
    gcUserTotalDetectedCurrent: List[Capacity]
    gcUserUnreclaimableCurrent: List[Capacity]
    id: str
    name: str
    numBadDisks: str
    numBadNodes: str
    numDisks: str
    numGoodDisks: str
    numGoodNodes: str
    numMaintenanceDisks: str
    numMaintenanceNodes: str
    numNodes: str
    numReadyToReplaceDisks: str
    recoveryBadChunksTotalSizeCurrent: List[Space]
    recoveryRateCurrent: List[dict]
    replicationEgressTrafficCurrent: List[dict]
    replicationIngressTrafficCurrent: List[dict]
    replicationRpoTimestamp: str

    @staticmethod
    def from_dict(data: dict) -> "ClusterState":
        return ClusterState(
            BootstrapProgressPercent=data["BootstrapProgressPercent"],
            _links=Links(**data["_links"]),
            alertsNumUnackCritical=[
                Count(**item) for item in data["alertsNumUnackCritical"]
            ],
            alertsNumUnackError=[
                Count(**item) for item in data["alertsNumUnackError"]
            ],
            alertsNumUnackInfo=[
                Count(**item) for item in data["alertsNumUnackInfo"]
            ],
            alertsNumUnackWarning=[
                Count(**item) for item in data["alertsNumUnackWarning"]
            ],
            allocatedCapacityForecast=data["allocatedCapacityForecast"],
            apiChange=data["apiChange"],
            chunksEcApplicableTotalSealSizeCurrent=[
                Space(**item)
                for item in data["chunksEcApplicableTotalSealSizeCurrent"]
            ],
            chunksEcCodedRatioCurrent=[
                Percent(**item) for item in data["chunksEcCodedRatioCurrent"]
            ],
            chunksEcCodedTotalSealSizeCurrent=[
                Space(**item)
                for item in data["chunksEcCodedTotalSealSizeCurrent"]
            ],
            chunksEcRateCurrent=data["chunksEcRateCurrent"],
            chunksGeoCacheCount=data["chunksGeoCacheCount"],
            chunksGeoCacheTotalSize=data["chunksGeoCacheTotalSize"],
            chunksGeoCopyAvgSize=data["chunksGeoCopyAvgSize"],
            chunksGeoCopyNumber=data["chunksGeoCopyNumber"],
            chunksGeoCopyTotalSize=data["chunksGeoCopyTotalSize"],
            chunksJournalPendingReplicationTotalSize=data[
                "chunksJournalPendingReplicationTotalSize"
            ],
            chunksL0BtreeAvgSize=data["chunksL0BtreeAvgSize"],
            chunksL0BtreeNumber=data["chunksL0BtreeNumber"],
            chunksL0BtreeTotalSize=data["chunksL0BtreeTotalSize"],
            chunksL0JournalAvgSize=data["chunksL0JournalAvgSize"],
            chunksL0JournalNumber=data["chunksL0JournalNumber"],
            chunksL0JournalTotalSize=data["chunksL0JournalTotalSize"],
            chunksL1BtreeAvgSize=data["chunksL1BtreeAvgSize"],
            chunksL1BtreeNumber=data["chunksL1BtreeNumber"],
            chunksL1BtreeTotalSize=data["chunksL1BtreeTotalSize"],
            chunksL1JournalAvgSize=data["chunksL1JournalAvgSize"],
            chunksL1JournalNumber=data["chunksL1JournalNumber"],
            chunksL1JournalTotalSize=data["chunksL1JournalTotalSize"],
            chunksRepoAvgSealSize=data["chunksRepoAvgSealSize"],
            chunksRepoNumber=data["chunksRepoNumber"],
            chunksRepoPendingReplicationTotalSize=data[
                "chunksRepoPendingReplicationTotalSize"
            ],
            chunksRepoTotalSealSize=data["chunksRepoTotalSealSize"],
            chunksXorNumber=data["chunksXorNumber"],
            chunksXorTotalSize=data["chunksXorTotalSize"],
            diskSpaceAllocatedCurrent=[
                Space(**item) for item in data["diskSpaceAllocatedCurrent"]
            ],
            diskSpaceAllocatedGeoCacheCurrent=[
                Capacity(**item)
                for item in data["diskSpaceAllocatedGeoCacheCurrent"]
            ],
            diskSpaceAllocatedGeoCopyCurrent=[
                Capacity(**item)
                for item in data["diskSpaceAllocatedGeoCopyCurrent"]
            ],
            diskSpaceAllocatedLocalProtectionCurrent=[
                Capacity(**item)
                for item in data["diskSpaceAllocatedLocalProtectionCurrent"]
            ],
            diskSpaceAllocatedSystemMetadataCurrent=[
                Capacity(**item)
                for item in data["diskSpaceAllocatedSystemMetadataCurrent"]
            ],
            diskSpaceAllocatedUserDataCurrent=[
                Capacity(**item)
                for item in data["diskSpaceAllocatedUserDataCurrent"]
            ],
            diskSpaceFreeCurrent=[
                Space(**item) for item in data["diskSpaceFreeCurrent"]
            ],
            diskSpaceOfflineTotalCurrent=[
                Space(**item) for item in data["diskSpaceOfflineTotalCurrent"]
            ],
            diskSpaceReservedCurrent=[
                Space(**item) for item in data["diskSpaceReservedCurrent"]
            ],
            diskSpaceTotalCurrent=[
                Space(**item) for item in data["diskSpaceTotalCurrent"]
            ],
            gcCombinedPendingCurrent=[
                Capacity(**item) for item in data["gcCombinedPendingCurrent"]
            ],
            gcCombinedReclaimedCurrent=[
                Capacity(**item) for item in data["gcCombinedReclaimedCurrent"]
            ],
            gcCombinedTotalDetectedCurrent=[
                Capacity(**item)
                for item in data["gcCombinedTotalDetectedCurrent"]
            ],
            gcCombinedUnreclaimableCurrent=[
                Capacity(**item)
                for item in data["gcCombinedUnreclaimableCurrent"]
            ],
            gcSystemMetadataIsEnabled=data["gcSystemMetadataIsEnabled"],
            gcSystemPendingCurrent=[
                Capacity(**item) for item in data["gcSystemPendingCurrent"]
            ],
            gcSystemReclaimedCurrent=[
                Capacity(**item) for item in data["gcSystemReclaimedCurrent"]
            ],
            gcSystemTotalDetectedCurrent=[
                Capacity(**item)
                for item in data["gcSystemTotalDetectedCurrent"]
            ],
            gcSystemUnreclaimableCurrent=[
                Capacity(**item)
                for item in data["gcSystemUnreclaimableCurrent"]
            ],
            gcUserDataIsEnabled=data["gcUserDataIsEnabled"],
            gcUserPendingCurrent=[
                Capacity(**item) for item in data["gcUserPendingCurrent"]
            ],
            gcUserReclaimedCurrent=[
                Capacity(**item) for item in data["gcUserReclaimedCurrent"]
            ],
            gcUserTotalDetectedCurrent=[
                Capacity(**item) for item in data["gcUserTotalDetectedCurrent"]
            ],
            gcUserUnreclaimableCurrent=[
                Capacity(**item) for item in data["gcUserUnreclaimableCurrent"]
            ],
            id=data["id"],
            name=data["name"],
            numBadDisks=data["numBadDisks"],
            numBadNodes=data["numBadNodes"],
            numDisks=data["numDisks"],
            numGoodDisks=data["numGoodDisks"],
            numGoodNodes=data["numGoodNodes"],
            numMaintenanceDisks=data["numMaintenanceDisks"],
            numMaintenanceNodes=data["numMaintenanceNodes"],
            numNodes=data["numNodes"],
            numReadyToReplaceDisks=data["numReadyToReplaceDisks"],
            recoveryBadChunksTotalSizeCurrent=[
                Space(**item)
                for item in data["recoveryBadChunksTotalSizeCurrent"]
            ],
            recoveryRateCurrent=data["recoveryRateCurrent"],
            replicationEgressTrafficCurrent=data[
                "replicationEgressTrafficCurrent"
            ],
            replicationIngressTrafficCurrent=data[
                "replicationIngressTrafficCurrent"
            ],
            replicationRpoTimestamp=data["replicationRpoTimestamp"],
        )
