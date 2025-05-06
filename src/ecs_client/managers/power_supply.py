from typing import Dict, List

from ecs_client.managers.base_manager import BaseManagerSSH
from ecs_client.models import PowerSupply


class PowerSupplyManager(BaseManagerSSH):
    def get_all(self) -> Dict[str, List[PowerSupply] | List[str]]:
        power_supplies: Dict[str, List[PowerSupply] | List[str]] = {}

        res: Dict[str, str | List[str]] = self.execute_command_on_hosts(
            "cs_hal sensors psu"
        )
        power_supplies["errors"] = res.pop("errors")
        power_supplies.update(
            {
                name: PowerSupply.build_from_bash_output(res_node)
                for name, res_node in res.items()
            }
        )
        return power_supplies
