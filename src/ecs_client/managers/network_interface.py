from typing import Dict, List

from ecs_client.exceptions import ECSClientSSHCommandError
from ecs_client.managers.base_manager import BaseManagerSSH
from ecs_client.models import NetworkInterface


class NetworkInterfaceManager(BaseManagerSSH):
    def get_all_by_cluster(
        self,
    ) -> Dict[str, List[NetworkInterface] | List[str]]:
        network_interfaces: Dict[str, List[NetworkInterface] | List[str]] = {
            "errors": []
        }
        for cluster in self.nodes_by_cluster.keys():
            with self.ecs_error_handler(cluster, network_interfaces["errors"]):
                node_name = next(iter(self.nodes_by_cluster[cluster]))
                res, err = self.execute_command_on_host(
                    node_name, "svc_network show int"
                )
                if err:
                    raise ECSClientSSHCommandError(err)
                network_interfaces[cluster] = (
                    NetworkInterface.build_from_bash_output(res)
                )
        return network_interfaces
