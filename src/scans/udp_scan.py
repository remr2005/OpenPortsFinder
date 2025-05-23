import asyncio

from scapy.all import ICMP, IP, UDP, conf, sr1

conf.verb = 0


async def udp(target_ip: str, port: int) -> tuple[str, int, bool]:
    pkt = IP(dst=target_ip) / UDP(dport=port)
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=3, verbose=0))
    if response is None:
        return target_ip, port, True
    elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3:
        return target_ip, port, False
    return target_ip, port, True
