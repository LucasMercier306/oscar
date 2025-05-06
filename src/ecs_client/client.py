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
from ecs_client.request import (
    ECSRequest,                
    Authenticator as S3Client,
    ECSClient as EMCClient,
    NamespaceRequest,
    BucketRequest,
    LifecycleRequest
)


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

    def list_namespaces(self) -> List[Dict]:
        logger.info("Listing namespaces...")
        resp = NamespaceRequest(self.client_config.config_emc).list()
        resp.raise_for_status()
        return resp.json()

    def get_namespace(self, name: str) -> Dict:
        logger.info(f"Getting namespace {name}...")
        resp = NamespaceRequest(self.client_config.config_emc).get(name)
        resp.raise_for_status()
        return resp.json()

    def create_namespace(
        self,
        name: str,
        default_replication_group: Optional[str] = None,
        namespace_admins: Optional[List[str]] = None,
        quota: Optional[Dict[str, int]] = None,
        encryption: bool = False
    ) -> Dict:
        logger.info(f"Creating namespace {name}...")
        resp = NamespaceRequest(self.client_config.config_emc).create(
            namespace=name,
            default_replication_group=default_replication_group,
            namespace_admins=namespace_admins,
            quota=quota,
            encryption=encryption
        )
        resp.raise_for_status()
        return resp.json()

    def update_namespace(self, name: str, **kwargs) -> Dict:
        logger.info(f"Updating namespace {name} with {kwargs}...")
        resp = NamespaceRequest(self.client_config.config_emc).update(name, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def delete_namespace(self, name: str) -> bool:
        logger.info(f"Deleting namespace {name}...")
        resp = NamespaceRequest(self.client_config.config_emc).delete(name)
        resp.raise_for_status()
        return resp.status_code == 204

    ###### Méthodes REST pour buckets ######

    def list_buckets(self, namespace: Optional[str] = None) -> List[Dict]:
        logger.info("Listing buckets...")
        resp = BucketRequest(self.client_config.config_emc).list(namespace)
        resp.raise_for_status()
        return resp.json()

    def get_bucket(self, bucket: str) -> Dict:
        logger.info(f"Getting bucket {bucket}...")
        resp = BucketRequest(self.client_config.config_emc).get(bucket)
        resp.raise_for_status()
        return resp.json()

    def create_bucket(
        self,
        bucket: str,
        namespace: Optional[str] = None,
        file_system_enabled: bool = False,
        quota: Optional[int] = None,
        retention: Optional[int] = None
    ) -> Dict:
        logger.info(f"Creating bucket {bucket}...")
        resp = BucketRequest(self.client_config.config_emc).create(
            bucket=bucket,
            namespace=namespace,
            file_system_enabled=file_system_enabled,
            quota=quota,
            retention=retention
        )
        resp.raise_for_status()
        return resp.json()

    def update_bucket(self, bucket: str, **kwargs) -> Dict:
        logger.info(f"Updating bucket {bucket} with {kwargs}...")
        resp = BucketRequest(self.client_config.config_emc).update(bucket, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def delete_bucket(self, bucket: str) -> bool:
        logger.info(f"Deleting bucket {bucket}...")
        resp = BucketRequest(self.client_config.config_emc).delete(bucket)
        resp.raise_for_status()
        return resp.status_code == 204

    def set_bucket_metadata(self, bucket: str, metadata: Dict[str, str]) -> Dict:
        logger.info(f"Setting metadata on bucket {bucket}...")
        resp = BucketRequest(self.client_config.config_emc).set_metadata(bucket, metadata)
        resp.raise_for_status()
        return resp.json()

    ###### Méthodes S3 pour les lifecycles ######

    def list_lifecycle_rules(self, bucket: str) -> List[str]:
        logger.info(f"Listing lifecycle rules for bucket {bucket}...")
        s3_cfg = self.client_config.configs_s3[0]
        return LifecycleRequest(s3_cfg).list_rules(bucket)

    def create_lifecycle_rule_with_date(
        self,
        bucket: str,
        rule_id: str,
        prefix: str,
        date_str: str
    ) -> None:
        logger.info(f"Creating lifecycle rule {rule_id} on {bucket} expiring at {date_str}...")
        s3_cfg = self.client_config.configs_s3[0]
        LifecycleRequest(s3_cfg).create_rule_with_date(bucket, rule_id, prefix, date_str)

    def create_lifecycle_rule_with_days(
        self,
        bucket: str,
        rule_id: str,
        prefix: str,
        days: int
    ) -> None:
        logger.info(f"Creating lifecycle rule {rule_id} on {bucket} expiring after {days} days...")
        s3_cfg = self.client_config.configs_s3[0]
        LifecycleRequest(s3_cfg).create_rule_with_days(bucket, rule_id, prefix, days)


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