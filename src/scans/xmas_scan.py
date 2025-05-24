"""
XMAS-скан
"""

import asyncio

from scapy.all import ICMP, IP, TCP, conf, sr1

conf.verb = 0


async def xmas(
    target_ip: str,
    port: str | int,
    print_console: bool = True,
) -> tuple[str, str | int, bool]:
    """
    Выполняет XMAS TCP-сканирование указанного IP-адреса и порта.

    В XMAS-сканировании отправляется TCP-пакет с установленными флагами FIN, PSH и URG.
    Это необычное сочетание флагов может привести к разному поведению со стороны различных систем.
    Стандартное поведение:
    - Нет ответа: порт вероятно **открыт** или **фильтруется**.
    - Ответ TCP с флагом RST (0x14): порт **закрыт**.
    - Ответ ICMP Type 3 (Destination Unreachable): порт **фильтруется**.

    Args:
        target_ip (str): IP-адрес цели.
        port (int | str): Номер порта, подлежащий сканированию.
        print_console (bool): Если True — выводит результат в консоль.

    Returns:
        tuple[str, str | int, bool]:
            - IP-адрес цели,
            - номер порта,
            - True, если порт открыт или фильтруется, иначе False (порт закрыт).
    """
    port = int(port)
    ip = IP(dst=target_ip)
    xmas_pkt = TCP(dport=port, flags="FPU", sport=12345, seq=1000)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(ip / xmas_pkt, timeout=2))

    if response is None:
        if print_console:
            print(
                f"[!] Порт {port} по ip {target_ip} — открыт или фильтруется (XMAS)",
                flush=True,
            )
        return target_ip, port, True
    elif response.haslayer(ICMP):
        icmp_layer = response.getlayer(ICMP)
        if icmp_layer.type == 3 and icmp_layer.code in {1, 2, 3, 9, 10, 13}:
            if print_console:
                print(
                    f"[!] Порт {port} по ip {target_ip} — фильтруется (ICMP Type 3 Code {icmp_layer.code})",
                    flush=True,
                )
            return target_ip, port, True
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:  # RST-ACK
        if print_console:
            print(
                f"[-] Порт {port} по ip {target_ip} — закрыт (RST получен)",
                flush=True,
            )
        return target_ip, port, False

    return target_ip, port, False
