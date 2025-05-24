"""Main file"""

import argparse
import asyncio
import ipaddress
from typing import List

from scans import ack, fin, fragmented_tcp_scan, null, syn, tcp_scan, udp, xmas
from utils import async_mass_scan

SCAN_TYPES = {
    "S": syn,
    "F": fin,
    "N": null,
    "X": xmas,
    "T": tcp_scan,
    "A": ack,
    "U": udp,
    "FR": fragmented_tcp_scan,
}


def parse_ports(port_str: str) -> List[int]:
    """Парсинг портов: 80 / 80,443 / 1-100"""
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports


def parse_targets(target_str: str) -> List[str]:
    """Парсинг целей: 192.168.1.1 / 192.168.1.1,192.168.1.2 / 192.168.1.0/24"""
    targets = []
    for part in target_str.split(","):
        if "/" in part:
            network = ipaddress.ip_network(part, strict=False)
            targets.extend([str(host) for host in network.hosts()])
        else:
            targets.append(part)
    return targets


async def main():
    parser = argparse.ArgumentParser(description="Python OpenPortsFinder")
    parser.add_argument(
        "-p", "--ports", required=True, help="Порты: 80 / 80,443 / 1-100"
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Цель: 192.168.1.1 / 192.168.1.1,2 / 192.168.1.0/24",
    )
    parser.add_argument(
        "-s",
        "--scan-type",
        default="S",
        choices=SCAN_TYPES.keys(),
        help="Тип сканирования: sS (SYN), sF (FIN), sU (UDP)",
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
        targets = parse_targets(args.target)
        scan_func = SCAN_TYPES[args.scan_type]

        print(
            f"Сканирование {args.target} (порты: {args.ports}) с использованием метода {args.scan_type}..."
        )
        await async_mass_scan(targets, ports, scan_func)

    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    asyncio.run(main())
