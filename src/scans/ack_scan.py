"""
Скан для нахождения открытых или фильтруемых портов
"""

import asyncio

from scapy.all import ICMP, IP, TCP, conf, sr1  # type: ignore

conf.verb = 0


async def ack(
    target_ip: str,
    port: str | int,
    print_console: bool = True,
) -> tuple[str, int, bool]:
    """
    Выполняет ACK-сканирование TCP-порта для определения фильтрации.

    ACK-сканирование отправляет TCP-пакет с установленным флагом ACK и анализирует ответ:
    - Отсутствие ответа (timeout) или ICMP с типом 3 и кодом из {1,2,3,9,10,13} указывает на фильтрацию порта.
    - Ответ TCP с флагами RST+ACK (0x14) указывает, что порт не фильтруется.
    - В остальных случаях считается, что порт не фильтруется.

    Args:
        target_ip (str): Целевой IP-адрес.
        port (str | int): Целевой TCP-порт (число или строка с числом).
        print_console (bool, optional): Если True, выводит информацию в консоль. По умолчанию True.

    Returns:
        tuple[str, int, bool]: Кортеж с IP, портом и булевым значением,
            где True означает, что порт фильтруется, False — не фильтруется.
    """
    port = int(port)
    ip = IP(dst=target_ip)
    ack_pkt = TCP(dport=port, flags="A", sport=12345, seq=1000, ack=1001)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(ip / ack_pkt, timeout=2))

    if response is None:
        if print_console:
            print(f"[!] Порт {port} по ip {target_ip} — фильтруется (ACK)", flush=True)
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
        # 0x14 = RST+ACK, порт не фильтруется
        return target_ip, port, False
    return target_ip, port, False
