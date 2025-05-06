from dataclasses import dataclass
from typing import List


@dataclass
class PowerSupply:
    entity: str
    type: str
    label: str
    status: str
    info: str

    @staticmethod
    def build_from_bash_output(bash_output: str) -> List["PowerSupply"]:
        power_supplies = []
        lines = bash_output.splitlines()

        # Skip the header lines
        for line in lines[2:]:
            if line.strip() == "" or line.startswith("NOTE:"):
                continue

            parts = line.split()
            entity = " ".join(parts[0:2])
            type_ = parts[2]
            label = " ".join(parts[3:-2])
            status = parts[-2]
            info = parts[-1] if parts[-1] != "-" else ""

            power_supply = PowerSupply(
                entity=entity,
                type=type_,
                label=label,
                status=status,
                info=info,
            )
            power_supplies.append(power_supply)

        return power_supplies
