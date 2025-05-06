from typing import Dict, List

from requests import Response

from ecs_client.managers.base_manager import BaseManagerAPI
from ecs_client.models import NodeInfo


class NodeInfoManager(BaseManagerAPI):
    def get_all(self, nodes: List[str]) -> Dict[str, NodeInfo | List[str]]:
        res: Dict[str, NodeInfo | List[str]] = {"errors": []}
        for ecs_name, ecs_request in self.ecs_requests.items():
            if ecs_name not in nodes:
                continue
            with self.ecs_error_handler(ecs_name, res["errors"]):
                response: Response = ecs_request.get(
                    "/vdc/nodes",
                    params={"dataType": "current"},
                )
                for node_info_raw in response.json()["node"]:
                    try:
                        ecs = next(
                            iter(
                                ecs
                                for ecs in self.ecs_requests.values()
                                if node_info_raw["nodename"]
                                in ecs.ssh_host_name
                            )
                        )
                        res[ecs.name] = NodeInfo.from_dict(node_info_raw)
                    except StopIteration:
                        res["errors"].append(
                            f"ECS {node_info_raw['nodename']} not in the "
                            f"configuration"
                        )

        return res
