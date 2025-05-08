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
)
from ecs_client.managers.base_manager import BaseManagerSSH
from ecs_client.managers.bucket_manager import BucketRequest
from ecs_client.managers.lifecycle_manager import LifecycleRequest
from ecs_client.managers.namespace_manager import NamespaceRequest
from ecs_client.ssh_request import ECSRequest
from requests import Response


class ECSClient:
    """
    Client principal pour interagir avec :
    - Les clusters ECS via SSH/API (managers)
    - L’API Management EMC pour namespaces et buckets
    - Les opérations S3 (lifecycle, etc.)
    """

    def __init__(
        self,
        client_config: ConfigECSClient,
        ecs_requests: Dict[str, ECSRequest],
    ):
        self.client_config = client_config
        self.ecs_requests = ecs_requests

    # -------------- SSH / CLI interactif --------------
    def interactive(self):
        manager = BaseManagerSSH(self.ecs_requests)
        interact(local=locals())

    def execute_command_on_hosts(
        self, command: str, print_res: bool = True
    ) -> Dict[str, str | List[str]]:
        manager = BaseManagerSSH(self.ecs_requests)
        results = manager.execute_command_on_hosts(command)
        if print_res:
            for name, res in results.items():
                print(f"{name}:\n{res}")
        return results

    def execute_command_on_host(
        self, host: str, command: str, print_res: bool = True
    ) -> Tuple[str, str]:
        manager = BaseManagerSSH(self.ecs_requests)
        stdout, stderr = manager.execute_command_on_host(host, command)
        if print_res:
            print(stdout)
        return stdout, stderr

    # -------------- Managers ECS --------------
    def get_cluster_state(self, nodes: List[str]) -> Dict[str, object]:
        logger.info("Getting cluster state...")
        mgr = ClusterStateManager(self.ecs_requests)
        result = mgr.get_all(nodes)
        logger.info("Cluster state collected.")
        return result

    def get_nodes_info(self, nodes: List[str]) -> Dict[str, object]:
        logger.info("Getting nodes info...")
        mgr = NodeInfoManager(self.ecs_requests)
        result = mgr.get_all(nodes)
        logger.info("Nodes info collected.")
        return result

    def get_replications_state(self) -> Dict[str, object]:
        logger.info("Getting replications state...")
        mgr = ReplicationStateManager(self.ecs_requests)
        result = mgr.get_all()
        logger.info("Replications state collected.")
        return result

    def get_network_interfaces_by_cluster(self) -> Dict[str, object]:
        logger.info("Getting network interfaces...")
        mgr = NetworkInterfaceManager(self.ecs_requests)
        result = mgr.get_all_by_cluster()
        logger.info("Network interfaces collected.")
        return result

    def get_power_supplies(self) -> Dict[str, object]:
        logger.info("Getting power supplies...")
        mgr = PowerSupplyManager(self.ecs_requests)
        result = mgr.get_all()
        logger.info("Power supplies collected.")
        return result

    def get_temperatures(self) -> Dict[str, object]:
        logger.info("Getting temperatures...")
        mgr = TemperatureManager(self.ecs_requests)
        result = mgr.get_all()
        logger.info("Temperatures collected.")
        return result

    # -------------- Namespaces (EMC Management API) --------------
    def list_namespaces(self) -> List[Dict[str, str]]:
        logger.info("Listing namespaces...")
        return NamespaceRequest(
            self.client_config.config_emc
        ).list()

    def get_namespace(self, name: str) -> Dict:
        logger.info(f"Getting namespace {name}...")
        resp = NamespaceRequest(
            self.client_config.config_emc
        ).get(name)
        resp.raise_for_status()
        return resp.json()

    def create_namespace(
        self,
        name: str,
        default_replication_group: Optional[str] = None,
        namespace_admins: Optional[List[str]] = None,
        quota: Optional[Dict[str, int]] = None,
        encryption: bool = False,
    ) -> Dict:
        logger.info(f"Creating namespace {name}...")
        resp = NamespaceRequest(
            self.client_config.config_emc
        ).create(
            namespace=name,
            default_replication_group=default_replication_group,
            namespace_admins=namespace_admins,
            quota=quota,
            encryption=encryption,
        )
        resp.raise_for_status()
        return resp.json()

    def update_namespace(self, name: str, **kwargs) -> Dict:
        logger.info(f"Updating namespace {name} with {kwargs}...")
        resp = NamespaceRequest(
            self.client_config.config_emc
        ).update(name, **kwargs)
        resp.raise_for_status()
        return resp.json()

    # -------------- Buckets (EMC Management API) --------------
    def list_buckets(self, namespace: str) -> List[Dict]:
        logger.info(f"Listing buckets in namespace {namespace}...")
        return BucketRequest(
            self.client_config.config_emc
        ).list(namespace)

    def get_bucket(self, bucket: str, namespace: str) -> Dict:
        logger.info(f"Getting bucket {bucket} in namespace {namespace}...")
        resp = BucketRequest(
            self.client_config.config_emc
        ).get(bucket, namespace)
        resp.raise_for_status()
        return resp.json()

    def create_bucket(
        self,
        bucket: str,
        namespace: str,
        file_system_enabled: bool = False,
        quota: Optional[int] = None,
        retention: Optional[int] = None,
        immutable: bool = False,
    ) -> Dict:
        """
        Create a bucket; if immutable=True, retention (in days) is required.
        """
        logger.info(
            f"Creating bucket {bucket} in namespace {namespace}... "
            f"immutable={immutable}, retention_days={retention}"
        )
        resp = BucketRequest(
            self.client_config.config_emc
        ).create(
            bucket=bucket,
            namespace=namespace,
            file_system_enabled=file_system_enabled,
            quota=quota,
            retention_days=retention,
            immutable=immutable,
        )
        resp.raise_for_status()
        return resp.json()

    def update_bucket_owner(
        self, bucket: str, namespace: str, new_owner: str
    ) -> Dict:
        """
        Set or update the owner of a bucket.
        """
        logger.info(
            f"Updating owner of bucket {bucket} to {new_owner}..."
        )
        resp = BucketRequest(
            self.client_config.config_emc
        ).set_owner(bucket, namespace, new_owner)
        resp.raise_for_status()
        return resp.json()

    def get_bucket_metadata(
        self, bucket: str, namespace: str
    ) -> Dict[str, str]:
        """
        Retrieve all metadata of the specified bucket.
        """
        logger.info(
            f"Retrieving metadata for bucket {bucket}..."
        )
        return BucketRequest(
            self.client_config.config_emc
        ).get_bucket_metadata(bucket, namespace)

    def calculate_bucket_size(
        self,
        bucket: str,
        namespace: str,
        metadata_filter: Optional[Dict[str, str]] = None,
    ) -> int:
        """
        Compute total size (in bytes) of objects in a bucket.
        Optionally filter by object metadata.
        """
        logger.info(
            f"Calculating size for bucket {bucket}..."
        )
        return BucketRequest(
            self.client_config.config_emc
        ).calculate_size(bucket, namespace, metadata_filter)

    def lock_object(
        self,
        bucket: str,
        namespace: str,
        object_key: str,
        retention_days: int,
    ) -> Response:
        """
        Lock an object to make it immutable for a retention period.
        """
        logger.info(
            f"Locking object {object_key} in bucket {bucket} "
            f"for {retention_days} days..."
        )
        return BucketRequest(
            self.client_config.config_emc
        ).lock_object(bucket, namespace, object_key, retention_days)

    def delete_bucket(self, bucket: str, namespace: str) -> bool:
        logger.info(f"Deleting bucket {bucket} in namespace {namespace}...")
        resp = BucketRequest(
            self.client_config.config_emc
        ).delete(bucket, namespace)
        resp.raise_for_status()
        return resp.status_code == 204

    # -------------- Gestion des lifecycles S3 --------------
    def list_lifecycle_rules(self, bucket: str) -> List[str]:
        logger.info(f"Listing lifecycle rules for bucket {bucket}...")
        s3_cfg = self.client_config.configs_s3[0]
        return LifecycleRequest(s3_cfg).list_rules(bucket)

    def create_lifecycle_rule_with_date(
        self, bucket: str, rule_id: str, prefix: str, date_str: str
    ) -> None:
        logger.info(
            f"Creating lifecycle rule {rule_id} "
            f"on {bucket} expiring at {date_str}..."
        )
        s3_cfg = self.client_config.configs_s3[0]
        LifecycleRequest(s3_cfg).create_rule_with_date(
            bucket, rule_id, prefix, date_str
        )

    def create_lifecycle_rule_with_days(
        self, bucket: str, rule_id: str, prefix: str, days: int
    ) -> None:
        logger.info(
            f"Creating lifecycle rule {rule_id} "
            f"on {bucket} expiring after {days} days..."
        )
        s3_cfg = self.client_config.configs_s3[0]
        LifecycleRequest(s3_cfg).create_rule_with_days(
            bucket, rule_id, prefix, days
        )

    # -------------- Contexte de session --------------
    @staticmethod
    @contextmanager
    def session(client_config: ConfigECSClient) -> "ECSClient":
        ecs_client = None
        try:
            ecs_requests: Dict[str, ECSRequest] = {}
            for ecs_cfg in client_config.configs_ecs:
                jump = (
                    ecs_requests.get(ecs_cfg.ssh_jump_host)
                    if ecs_cfg.ssh_jump_host
                    else None
                )
                ecs_requests[ecs_cfg.name] = ECSRequest(ecs_cfg, jump)
            ecs_client = ECSClient(client_config, ecs_requests)
            yield ecs_client
        finally:
            logger.info("ECS logout...")
            if ecs_client:
                for name, req in ecs_client.ecs_requests.items():
                    try:
                        req.logout_ssh()
                        req.logout_api()
                    except Exception as e:
                        logger.error(f"Error during logout of {name}: {e}")
