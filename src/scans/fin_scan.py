"""
FIN-скан
"""

import asyncio

from scapy.all import ICMP, IP, TCP, conf, sr1

conf.verb = 0


async def fin(
    target_ip: str,
    port: str | int,
    print_console: bool = True,
) -> tuple[str, int, bool]:
    """
    Выполняет FIN-сканирование TCP-порта на указанном IP-адресе.

    FIN-сканирование отправляет TCP-пакет с установленным флагом FIN и анализирует ответ:
    - Отсутствие ответа (timeout) обычно означает, что порт открыт или фильтруется.
    - Ответ ICMP с типом 3 и кодом из {1, 2, 3, 9, 10, 13} означает, что порт фильтруется.
    - Ответ TCP с флагами RST+ACK (0x14) указывает, что порт закрыт.

    Args:
        target_ip (str): Целевой IP-адрес для сканирования.
        port (str | int): Целевой TCP-порт (число или строка с числом).
        print_console (bool, optional): Если True, выводит результат в консоль. По умолчанию True.

    Returns:
        tuple[str, int, bool]: Кортеж с IP, портом и булевым значением, указывающим,
            открыт ли порт (True — открыт/фильтруется, False — закрыт).
    """
    port = int(port)
    ip = IP(dst=target_ip)
    fin_pkt = TCP(dport=port, flags="F", sport=12345, seq=1000)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(ip / fin_pkt, timeout=2))

    if response is None:
        if print_console:
            print(
                f"[!] Порт {port} по ip {target_ip} — открыт или фильтруется (FIN)",
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
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
        # 0x14 = RST+ACK
        return target_ip, port, False
    return target_ip, port, False
