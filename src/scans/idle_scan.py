import asyncio

from scapy.all import IP, TCP, conf, sr1

conf.verb = 0


async def idle(target_ip: str, zombie_ip: str, port: int) -> bool:
    ip_id_pkt = IP(dst=zombie_ip) / TCP(dport=80, flags="A")
    loop = asyncio.get_running_loop()
    resp1 = await loop.run_in_executor(None, lambda: sr1(ip_id_pkt, timeout=2))
    if not resp1:
        return False
    ip_id_before = resp1.id

    spoofed_syn = IP(src=zombie_ip, dst=target_ip) / TCP(dport=port, flags="S")
    await loop.run_in_executor(None, lambda: sr1(spoofed_syn, timeout=2))

    resp2 = await loop.run_in_executor(None, lambda: sr1(ip_id_pkt, timeout=2))
    if not resp2:
        return False
    ip_id_after = resp2.id

    return ip_id_after > ip_id_before
