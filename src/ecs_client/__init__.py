import logging
from dataclasses import dataclass
from os import environ as env
from typing import List, Optional
import yaml

__all__ = ["logger", "ConfigECSClient", "ConfigECS", "ConfigS3", "ConfigEMC", "load_config"]

# Logger setup
def configure_logger(verbose: int) -> logging.Logger:
    logger = logging.getLogger("ecs_client")
    level = logging.DEBUG if verbose > 0 else logging.INFO
    logger.setLevel(level)

    formatter = logging.Formatter(
        "[%(asctime)s] - [%(levelname)s] - ECS client - %(message)s"
    )

    file_handler = logging.FileHandler("ecs_client.log")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

@dataclass
class ConfigS3:
    name: str
    endpoint: str
    access_key: str
    secret_key: str
    namespace: str
    region: str
    prefix_list: List[str]

@dataclass
class ConfigEMC:
    username: str
    password: str
    endpoint: str

@dataclass
class ConfigECS:
    name: str
    username: str
    password: str
    host_name: str

    ssh_jump_host: Optional[str] = None
    ssh_port: str = "22"

    protocol: str = "https"
    api_port: str = "4443"
    verify: bool = True

@dataclass
class ConfigECSClient:
    configs_ecs: List[ConfigECS]
    configs_s3: List[ConfigS3]
    config_emc: ConfigEMC
    verbose: int = 0

    def __post_init__(self):
        if self.verbose > 0:
            logger.setLevel(logging.DEBUG)

def load_config() -> ConfigECSClient:
    ecs_client_config_file_path = env.get("ECS_CONFIG_PATH", "./.config/ecs_client.yaml")
    ecs_client_secrets_config_file_path = env.get("ECS_SECRETS_CONFIG_PATH", "./.config/ecs_client-secrets.yaml")

    try:
        with open(ecs_client_config_file_path, "r") as yamlfile:
            config_client = yaml.load(yamlfile, Loader=yaml.FullLoader)

        with open(ecs_client_secrets_config_file_path, "r") as yamlfile:
            config_client_secrets = yaml.load(yamlfile, Loader=yaml.FullLoader)

    except FileNotFoundError as e:
        logger.error(f"Configuration file not found: {e}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML file: {e}")
        raise

    configs_ecs = [
        ConfigECS(
            name=ecs_name,
            username=ecs_config["username"],
            password=config_client_secrets.get("ecs", {}).get(ecs_name, {}).get("password", ""),
            host_name=ecs_config["host_name"],
        )
        for ecs_name, ecs_config in config_client.get("ecs", {}).items()
    ]

    configs_s3 = [
        ConfigS3(
            name=s3_name,
            endpoint=s3_config["endpoint"],
            access_key=s3_config["access_key"],
            secret_key=config_client_secrets.get("s3", {}).get(s3_name, {}).get("secret_key", ""),
            namespace=s3_config["namespace"],
            region=s3_config["region"],
            prefix_list=s3_config.get("prefix_list", []),
        )
        for s3_name, s3_config in config_client.get("s3", {}).items()
    ]

    config_emc = ConfigEMC(
        username=config_client.get("ecs-emc", {}).get("username", ""),
        password=config_client_secrets.get("ecs-emc", {}).get("password", ""),
        endpoint=config_client.get("ecs-emc", {}).get("endpoint", ""),
    )

    config_ecs_client = ConfigECSClient(
        configs_ecs=configs_ecs,
        configs_s3=configs_s3,
        config_emc=config_emc,
        verbose=config_client.get("ecs_client", {}).get("verbose", 0),
    )

    # Configure logger based on verbosity
    configure_logger(config_ecs_client.verbose)

    return config_ecs_client

# Initialize logger
logger = configure_logger(verbose=0)
