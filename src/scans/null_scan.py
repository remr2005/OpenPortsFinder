import asyncio

from scapy.all import ICMP, IP, TCP, conf, sr1

conf.verb = 0


async def null(
    target_ip: str,
    port: str | int,
    print_console: bool = True,
) -> tuple[str, str | int, bool]:
    """
    NULL сканирование — отправка TCP-пакета без флагов
    """
    port = int(port)
    ip = IP(dst=target_ip)
    null_pkt = TCP(dport=port, flags=0, sport=12345, seq=1000)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(ip / null_pkt, timeout=2))

    if response is None:
        if print_console:
            print(f"[!] Порт {port} — открыт или фильтруется (NULL)")
        return target_ip, port, True
    elif response.haslayer(ICMP):
        icmp_layer = response.getlayer(ICMP)
        if icmp_layer.type == 3 and icmp_layer.code in {1, 2, 3, 9, 10, 13}:
            if print_console:
                print(
                    f"[!] Порт {port} — фильтруется (ICMP Type 3 Code {icmp_layer.code})"
                )
            return target_ip, port, True

    return target_ip, port, False
