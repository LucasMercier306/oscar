from typing import Dict, List

from requests import Response

from ecs_client.managers.base_manager import BaseManagerAPI
from ecs_client.models import ReplicationState


class ReplicationStateManager(BaseManagerAPI):
    def get_all(self) -> Dict[str, ReplicationState | List[str]]:
        res: Dict[str, ReplicationState | List[str]] = {"errors": []}
        for ecs_name, ecs_request in self.ecs_requests.items():
            with self.ecs_error_handler(ecs_name, res["errors"]):
                response: Response = ecs_request.get(
                    "/dashboard/zones/localzone/replicationgroups",
                    params={"dataType": "current"},
                )
                res[ecs_name] = ReplicationState.from_dict(response.json())

        return res
