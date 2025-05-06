from typing import Dict, List

from ecs_client.managers.base_manager import BaseManagerSSH
from ecs_client.models import Temperature


class TemperatureManager(BaseManagerSSH):
    def get_all(self) -> Dict[str, List[Temperature] | List[str]]:
        temperatures: Dict[str, List[Temperature] | List[str]] = {}

        res: Dict[str, str | List[str]] = self.execute_command_on_hosts(
            "cs_hal sensors temp"
        )
        temperatures["errors"] = res.pop("errors")
        temperatures.update(
            {
                name: Temperature.from_bash_output(res_node)
                for name, res_node in res.items()
            }
        )
        return temperatures
