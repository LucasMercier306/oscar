from typing import Dict, List

from requests import Response

from ecs_client.managers.base_manager import BaseManagerAPI
from ecs_client.models import ClusterState


class ClusterStateManager(BaseManagerAPI):
    def get_all(self, nodes: list[str]) -> Dict[str, ClusterState | List[str]]:
        res: Dict[str, ClusterState | List[str]] = {"errors": []}
        for ecs_name, ecs_request in self.ecs_requests.items():
            if ecs_name not in nodes:
                continue
            with self.ecs_error_handler(ecs_name, res["errors"]):
                response: Response = ecs_request.get(
                    "/dashboard/zones/localzone",
                    params={"dataType": "current"},
                )
                res[ecs_name] = ClusterState.from_dict(response.json())

        return res
