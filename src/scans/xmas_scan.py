import asyncio

from scapy.all import ICMP, IP, TCP, conf, sr1

conf.verb = 0


async def xmas(
    target_ip: str,
    port: str | int,
    print_console: bool = True,
) -> tuple[str, str | int, bool]:
    """
    XMAS сканирование — флаги FIN, PSH, URG
    """
    port = int(port)
    ip = IP(dst=target_ip)
    xmas_pkt = TCP(dport=port, flags="FPU", sport=12345, seq=1000)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(ip / xmas_pkt, timeout=2))

    if response is None:
        if print_console:
            print(f"[!] Порт {port} — открыт или фильтруется (XMAS)")
        return target_ip, port, True
    elif response.haslayer(ICMP):
        icmp_layer = response.getlayer(ICMP)
        if icmp_layer.type == 3 and icmp_layer.code in {1, 2, 3, 9, 10, 13}:
            if print_console:
                print(
                    f"[!] Порт {port} — фильтруется (ICMP Type 3 Code {icmp_layer.code})"
                )
            return target_ip, port, True
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
        return target_ip, port, False
    return target_ip, port, False
