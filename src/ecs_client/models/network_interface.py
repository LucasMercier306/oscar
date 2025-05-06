from dataclasses import dataclass
from typing import List, Optional


@dataclass
class NetworkInterface:
    node: str
    interface_name: str
    ip_addr: Optional[str]
    subnet_mask: Optional[str]
    vlan: Optional[int]
    mtu: int
    link_state: str
    admin_state: str
    peer_switch_name: Optional[str]
    peer_switch_port: Optional[str]

    @staticmethod
    def build_from_bash_output(bash_output: str) -> List["NetworkInterface"]:
        interfaces = []
        lines = bash_output.splitlines()
        current_node = None

        for line in lines:
            if line.startswith("Node:"):
                current_node = line.split()[1]
            elif line.strip() and not (
                line.startswith("Interface")
                or line.startswith("Name")
                or line.startswith("\x1b[93mName")
            ):
                parts = line.split()
                if len(parts) >= 9:
                    interface_name = parts[0]
                    ip_addr = parts[1] if parts[1] != "-" else None
                    subnet_mask = parts[2] if parts[2] != "-" else None
                    vlan = int(parts[3]) if parts[3] != "-" else None
                    mtu = int(parts[4])
                    link_state = parts[5]
                    admin_state = parts[6]
                    peer_switch_name = parts[7] if parts[7] != "-" else None
                    peer_switch_port = parts[8] if parts[8] != "-" else None

                    interface = NetworkInterface(
                        node=current_node,
                        interface_name=interface_name,
                        ip_addr=ip_addr,
                        subnet_mask=subnet_mask,
                        vlan=vlan,
                        mtu=mtu,
                        link_state=link_state,
                        admin_state=admin_state,
                        peer_switch_name=peer_switch_name,
                        peer_switch_port=peer_switch_port,
                    )
                    interfaces.append(interface)

        return interfaces
