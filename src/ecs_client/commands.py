from fire import Fire

from ecs_client import ConfigECSClient, load_config, logger
from ecs_client.client import ECSClient


def run():
    logger.info("ECS client run command.")
    config_client: ConfigECSClient = load_config()

    with ECSClient.session(config_client) as ecs_client:
        Fire(ecs_client)
