from code import interact
from contextlib import contextmanager
from typing import Dict, List, Optional, Tuple

from ecs_client import ConfigECSClient, logger
from ecs_client.managers import (
    ClusterStateManager,
    NetworkInterfaceManager,
    NodeInfoManager,
    PowerSupplyManager,
    ReplicationStateManager,
    TemperatureManager,
    NamespaceManager
)
from ecs_client.managers.base_manager import BaseManagerSSH
from ecs_client.models import (
    ClusterState,
    NetworkInterface,
    NodeInfo,
    PowerSupply,
    ReplicationState,
    Temperature,
)
from ecs_client.request import ECSRequest
from ecs_client.request import Authenticator as S3Client
from ecs_client.request import ECSClient as EMCClient


class ECSClient:
    client_config: ConfigECSClient
    #ssh
    ecs_requests: Dict[str, ECSRequest]
    #emc
    emc_client: EMCClient

    def __init__(
        self,
        client_config: ConfigECSClient,
        ecs_requests: Dict[str, ECSRequest],
        emc_client: EMCClient,
    ):
        self.client_config = client_config
        self.ecs_requests = ecs_requests
        self.emc_client = emc_client

    def interactive(self):
        manager = BaseManagerSSH(self.ecs_requests)
        interact(local=locals())

    def execute_command_on_hosts(
        self, command: str, print_res: bool = True
    ) -> Dict[str, str | List[str]]:
        manager = BaseManagerSSH(self.ecs_requests)
        results: Dict[str, str | List[str]] = manager.execute_command_on_hosts(
            command
        )
        if print_res:
            for ecs_name, result in results.items():
                print(f"{ecs_name}:")
                print(result)
        else:
            return manager.execute_command_on_hosts(command)

    def execute_command_on_host(
        self, host: str, command: str, print_res: bool = True
    ) -> Tuple[str, str]:
        manager = BaseManagerSSH(self.ecs_requests)
        stdout, stderr = manager.execute_command_on_host(host, command)
        if print_res:
            print(stdout)
        else:
            return stdout, stderr

    def get_cluster_state(
        self, nodes: List[str]
    ) -> Dict[str, ClusterState | List[str]]:
        logger.info("Getting clusters state...")
        cluster_state_manager = ClusterStateManager(self.ecs_requests)
        clusters_state = cluster_state_manager.get_all(nodes)
        logger.info("Clusters state collected.")
        return clusters_state

    def get_nodes_info(
        self, nodes: List[str]
    ) -> Dict[str, NodeInfo | List[str]]:
        logger.info("Getting nodes info...")
        node_info_manager = NodeInfoManager(self.ecs_requests)
        nodes_info = node_info_manager.get_all(nodes)
        logger.info("Nodes info collected.")
        return nodes_info

    # def get_nodes_state(self) -> Dict[str, NodeState]:
    #     logger.info("Getting nodes state...")
    #     node_state_manager = NodeStateManager(self.ecs_requests)
    #     nodes_state = node_state_manager.get_all()
    #     logger.info("Nodes state collected.")
    #     return nodes_state

    def get_replications_state(
        self,
    ) -> Dict[str, ReplicationState | List[str]]:
        logger.info("Getting replications state...")
        replication_state_manager = ReplicationStateManager(self.ecs_requests)
        replications_state = replication_state_manager.get_all()
        logger.info("Replications state collected.")
        return replications_state

    def get_network_interfaces_by_cluster(
        self,
    ) -> Dict[str, List[NetworkInterface] | List[str]]:
        logger.info("Getting network interfaces...")
        network_interface_manager = NetworkInterfaceManager(self.ecs_requests)
        network_int = network_interface_manager.get_all_by_cluster()
        logger.info("Network interfaces collected.")
        return network_int

    def get_power_supplies(self) -> Dict[str, List[PowerSupply] | List[str]]:
        logger.info("Getting power supplies...")
        power_supply_manager = PowerSupplyManager(self.ecs_requests)
        power_supplies = power_supply_manager.get_all()
        logger.info("Power supplies collected.")
        return power_supplies

    def get_temperatures(self) -> Dict[str, List[Temperature] | List[str]]:
        logger.info("Getting temperatures...")
        temperature_manager = TemperatureManager(self.ecs_requests)
        temperatures = temperature_manager.get_all()
        logger.info("Temperatures collected.")
        return temperatures

    #####new lines ################

    #def get_namespaces(self) :
    #    logger.info("Getting namespaces...")
    #    namespace_manager = NamespaceManager(self.emc_client)
    #    namespaces = namespace_manager.get_all()
    #    logger.info("namespaces collected.")
    #    return namespaces

    def get_namespace_by_name(self, name: str):
        logger.info("Getting namespace...")
        namespace_manager = NamespaceManager(self.emc_client)
        namespace = namespace_manager.get(name)
        logger.info("namespace collected.")
        return namespace


    @staticmethod
    @contextmanager
    def session(client_config: ConfigECSClient) -> "ECSClient":
        ecs_client: Optional[ECSClient] = None
        try:
            ecs_requests: Dict[str, ECSRequest] = {}
            emc_client: Optional[EMCClient] = None
            for ecs_config in client_config.configs_ecs:
                jump_host: Optional[ECSRequest] = None
                if ecs_config.ssh_jump_host:
                    jump_host = ecs_requests[ecs_config.ssh_jump_host]
                ecs_requests[ecs_config.name] = ECSRequest(
                    ecs_config, jump_host
                )
            ecs_client = ECSClient(client_config, ecs_requests, emc_client)
            yield ecs_client
        finally:
            logger.info("ECS logout...")
            if not ecs_client:
                return
            for name, ecs_request in ecs_client.ecs_requests.items():
                try:
                    ecs_request.logout_ssh()
                    ecs_request.logout_api()
                except Exception as e:
                    logger.error(f"Error while ssh logout of host {name}: {e}")
