from typing import Dict, List

from requests import Response

from ecs_client.managers.base_manager import BaseManagerAPI
from ecs_client.models import NodeState


class NodeStateManager(BaseManagerAPI):
    def get_all(self) -> Dict[str, NodeState | List[str]]:
        raise NotImplementedError("Need to access node:9101 API.")
        res: Dict[str, NodeState | List[str]] = {"errors": []}
        for ecs_name, ecs_request in self.ecs_requests.items():
            try:
                response: Response = ecs_request.get(
                    "/stats/dt/DTInitStat",  # Certainly another base url
                    params={"dataType": "current"},
                )
                res[ecs_name] = NodeState(**response.json())
            except Exception as e:
                res["errors"].append(f"On ECS {ecs_name}: {e}")

        return res
