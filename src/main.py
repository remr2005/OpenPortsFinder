"""Main entry point for Python OpenPortsFinder - массовый асинхронный сканер портов с множеством методов."""

import argparse
import asyncio
import ipaddress
from typing import List

from scans import (
    ack,
    fin,
    fragmented_tcp_scan,
    icmp_address_mask_scan,
    icmp_echo_scan,
    icmp_timestamp_scan,
    idle,
    null,
    scan_network,
    source_port_manipulation,
    syn,
    tcp_scan,
    udp,
    xmas,
)
from utils import async_mass_scan, async_mass_scan_ICMP

SCAN_TYPES = {
    "S": syn,
    "F": fin,
    "N": null,
    "X": xmas,
    "T": tcp_scan,
    "A": ack,
    "U": udp,
    "ID": idle,
    "SP": source_port_manipulation,
    "FR": fragmented_tcp_scan,
    "IE": icmp_echo_scan,
    "IM": icmp_address_mask_scan,
    "IT": icmp_timestamp_scan,
    "CVE": scan_network,
}


def parse_ports(port_str: str) -> List[int]:
    """
    Разбирает строку с портами в список чисел.

    Поддерживаются форматы:
    - Один порт: "80"
    - Список портов через запятую: "80,443"
    - Диапазон портов: "1-100"

    Args:
        port_str (str): Строка с портами.

    Returns:
        List[int]: Список портов.
    """
    ports = []
    for part in port_str.split(","):
        if "-" in part:
            start, end = map(int, part.split("-"))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    return ports


def parse_targets(target_str: str) -> List[str]:
    """
    Разбирает строку с IP-адресами или подсетями в список отдельных IP.

    Поддерживаются форматы:
    - Одиночный IP: "192.168.1.1"
    - Несколько IP через запятую: "192.168.1.1,192.168.1.2"
    - Подсеть: "192.168.1.0/24"

    Args:
        target_str (str): Строка с целями.

    Returns:
        List[str]: Список IP-адресов.
    """
    targets = []
    for part in target_str.split(","):
        if "/" in part:
            network = ipaddress.ip_network(part, strict=False)
            targets.extend([str(host) for host in network.hosts()])
        else:
            targets.append(part)
    return targets


async def main():
    """
    Основная асинхронная функция для запуска сканирования.

    Разбирает аргументы командной строки, настраивает параметры сканирования
    и запускает соответствующий асинхронный метод сканирования.

    Обрабатывает разные типы сканирования, включая ICMP и TCP/UDP.
    """
    parser = argparse.ArgumentParser(description="Python OpenPortsFinder")
    parser.add_argument(
        "-p", "--ports", required=False, help="Порты: 80 / 80,443 / 1-100"
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
        help="Тип сканирования: S (SYN), F (FIN), U (UDP) и др.",
    )
    parser.add_argument(
        "--detect-os", action="store_true", help="Включить определение ОС"
    )
    parser.add_argument(
        "--send-rst",
        action="store_true",
        help="Отправлять RST-пакеты в ответ для уменьшения подозрительности",
    )
    parser.add_argument(
        "--zombi-ip",
        default="",
        help="IP зомби-хоста для idle-сканирования",
    )
    parser.add_argument(
        "--false-port",
        default="53",
        help="Ложный порт для сканирования с манипуляцией портом",
    )

    args = parser.parse_args()

    try:
        targets = parse_targets(args.target)
        scan_func = SCAN_TYPES[args.scan_type]
        dargs = []

        if args.zombi_ip:
            dargs.append(args.zombi_ip)
        elif args.false_port:
            dargs.append(args.false_port)

        if args.scan_type == "S":
            dargs = [args.send_rst, args.detect_os]

        print(
            f"Сканирование {args.target} (порты: {args.ports}) с использованием метода {args.scan_type}..."
        )

        if args.scan_type in ["IE", "IM", "IT", "CVE"]:
            await async_mass_scan_ICMP(targets, scan_func)
        else:
            ports = parse_ports(args.ports)
            await async_mass_scan(targets, ports, scan_func, dargs)

    except Exception as e:
        print(f"Ошибка: {e}")


if __name__ == "__main__":
    asyncio.run(main())
