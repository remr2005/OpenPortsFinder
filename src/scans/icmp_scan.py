"""
ICMP-сканирование
"""

import asyncio

from scapy.all import ICMP, IP, conf, sr1

conf.verb = 0


async def icmp_echo_scan(target_ip: str) -> tuple[str, bool]:
    """
    Выполняет ICMP Echo сканирование (ping).

    Отправляет ICMP Echo Request (тип 8) на указанный IP.
    Если получен Echo Reply (тип 0), хост считается доступным.

    Args:
        target_ip (str): IP-адрес цели.

    Returns:
        tuple[str, bool]:
            - IP-адрес цели,
            - True, если получен ответ, иначе False.
    """
    pkt = IP(dst=target_ip) / ICMP()
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))

    if response is not None:
        print(f"[+] {target_ip} — отвечает на Echo Request", flush=True)

    return target_ip, response is not None


async def icmp_timestamp_scan(target_ip: str) -> tuple[str, bool]:
    """
    Выполняет ICMP Timestamp сканирование.

    Отправляет ICMP Timestamp Request (тип 13) и ожидает Timestamp Reply (тип 14).
    Используется для определения доступности узла и его настроек времени.

    Args:
        target_ip (str): IP-адрес цели.

    Returns:
        tuple[str, bool]:
            - IP-адрес цели,
            - True, если получен ответ, иначе False.
    """
    pkt = IP(dst=target_ip) / ICMP(type=13)
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))

    if response is not None:
        print(f"[+] {target_ip} — отвечает на Timestamp Request", flush=True)

    return target_ip, response is not None


async def icmp_address_mask_scan(target_ip: str) -> tuple[str, bool]:
    """
    Выполняет ICMP Address Mask сканирование.

    Отправляет ICMP Address Mask Request (тип 17), ожидается ответ типа 18.
    Используется редко, но может показать, что устройство работает под старой ОС или нестандартной конфигурацией.

    Args:
        target_ip (str): IP-адрес цели.

    Returns:
        tuple[str, bool]:
            - IP-адрес цели,
            - True, если получен ответ, иначе False.
    """
    pkt = IP(dst=target_ip) / ICMP(type=17)
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))

    if response is not None:
        print(f"[+] {target_ip} — отвечает на Address Mask Request", flush=True)

    return target_ip, response is not None
