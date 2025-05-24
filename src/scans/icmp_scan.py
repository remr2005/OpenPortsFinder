"""
ICMP скан
"""

import asyncio

from scapy.all import ICMP, IP, conf, sr1

conf.verb = 0


async def icmp_echo_scan(target_ip: str) -> tuple[str, bool]:
    pkt = IP(dst=target_ip) / ICMP()
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))
    return target_ip, response is not None


async def icmp_timestamp_scan(target_ip: str) -> tuple[str, bool]:
    pkt = IP(dst=target_ip) / ICMP(type=13)  # Timestamp Request
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))
    return target_ip, response is not None


async def icmp_address_mask_scan(target_ip: str) -> tuple[str, bool]:
    pkt = IP(dst=target_ip) / ICMP(type=17)  # Address Mask Request
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))
    return target_ip, response is not None
