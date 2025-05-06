from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Temperature:
    entity: str
    type: str
    label: str
    status: str
    celcius: Optional[int] = None

    @staticmethod
    def from_bash_output(bash_output: str) -> List["Temperature"]:
        lines = bash_output.strip().split("\n")
        temperatures = []

        for line in lines:
            parts = [word for word in line.split("  ") if word]
            if (
                len(parts) < 4
                or parts[0].startswith("Entity")
                or parts[0].startswith("--")
            ):
                # Skip header or invalid lines
                continue

            # Extract the fields
            entity = parts[0]
            type = parts[1]
            label = " ".join(parts[2].split())
            status = " ".join(parts[3].split())
            celcius = (
                int(parts[4].strip("Degrees Celsius"))
                if "Degrees Celsius" in line
                else None
            )

            temperature = Temperature(entity, type, label, status, celcius)
            temperatures.append(temperature)

        return temperatures
