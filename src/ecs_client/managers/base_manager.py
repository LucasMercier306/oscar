import traceback
from contextlib import contextmanager
from typing import Dict, List, Tuple

from ecs_client import logger
from ecs_client.request import ECSRequest


class BaseManagerSSH:
    ecs_requests: Dict[str, ECSRequest]
    nodes_by_cluster: Dict[str, List[str]]

    def __init__(self, ecs_requests: Dict[str, ECSRequest]):
        self.ecs_requests = ecs_requests
        nodes_by_cluster: Dict[str, List[str]] = {}
        for name, ecs_request in ecs_requests.items():
            cluster: str = ecs_request.cluster
            if cluster not in nodes_by_cluster:
                nodes_by_cluster[cluster] = [name]
            else:
                nodes_by_cluster[cluster].append(name)
        self.nodes_by_cluster = nodes_by_cluster

    def execute_command_on_hosts(
        self, command: str
    ) -> Dict[str, str | List[str]]:
        res: Dict[str, str | List[str]] = {"errors": []}
        for ecs_name, ecs_request in self.ecs_requests.items():
            try:
                stdout, stderr = ecs_request.run_command_on_host(command)
                logger.debug(f"\n{stdout}")
                if not stderr:
                    res[ecs_request.name] = stdout
                else:
                    res["errors"].append(f"{ecs_name}: {stderr}")
            except Exception as e:
                res["errors"].append(f"{ecs_name}: {e}")

        return res

    def execute_command_on_host(
        self, host: str, command: str
    ) -> Tuple[str, str]:
        ecs_request = self.ecs_requests[host]
        stdout, stderr = ecs_request.run_command_on_host(command)
        logger.debug(f"\n{stdout}")
        return stdout, stderr

    @staticmethod
    @contextmanager
    def ecs_error_handler(ecs_name: str, errors: List[str]):
        try:
            yield errors
        except Exception as e:
            errors.append(f"On ECS {ecs_name}: {e}")
            logger.error(f"On ECS {ecs_name}: {e}")
            logger.debug(traceback.format_exc())


class BaseManagerAPI:
    ecs_requests: Dict[str, ECSRequest]

    def __init__(self, ecs_requests: Dict[str, ECSRequest]):
        self.ecs_requests = ecs_requests

    @staticmethod
    @contextmanager
    def ecs_error_handler(ecs_name: str, errors: List[str]):
        try:
            yield errors
        except Exception as e:
            errors.append(f"On ECS {ecs_name}: {e}")
            logger.error(f"On ECS {ecs_name}: {e}")
            logger.debug(traceback.format_exc())
