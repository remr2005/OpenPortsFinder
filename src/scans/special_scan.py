import asyncio

from scapy.all import IP, TCP, conf, fragment, sr1

conf.verb = 0


async def fragmented_tcp_scan(target_ip: str, port: int | str) -> tuple[str, int, bool]:
    port = int(port)
    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    fragments = fragment(pkt, fragsize=8)
    loop = asyncio.get_running_loop()
    for frag in fragments:
        await loop.run_in_executor(None, lambda: sr1(frag, timeout=1, verbose=0))
    return target_ip, port, True


async def source_port_manipulation(
    target_ip: str, port: str | int, spoofed_sport: int | str = 53
) -> tuple[str, int, bool]:
    port = int(port)
    pkt = IP(dst=target_ip) / TCP(dport=port, sport=spoofed_sport, flags="S")
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))
    if response and response.haslayer(TCP):
        return target_ip, port, response.getlayer(TCP).flags == 0x12
    return target_ip, port, False
