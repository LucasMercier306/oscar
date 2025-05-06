from dataclasses import dataclass


@dataclass
class NodeInfo:
    data2_ip: str
    data_ip: str
    geo_ip: str
    ip: str
    isLocal: bool
    mgmt_ip: str
    nodeid: str
    nodename: str
    private_ip: str
    rackId: str
    version: str

    @staticmethod
    def from_dict(data: dict) -> "NodeInfo":
        return NodeInfo(
            data2_ip=data["data2_ip"],
            data_ip=data["data_ip"],
            geo_ip=data["geo_ip"],
            ip=data["ip"],
            isLocal=data["isLocal"],
            mgmt_ip=data["mgmt_ip"],
            nodeid=data["nodeid"],
            nodename=data["nodename"],
            private_ip=data["private_ip"],
            rackId=data["rackId"],
            version=data["version"],
        )
