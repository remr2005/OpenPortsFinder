"""
Фрагментированный скан и скан с манипулированием порта.

Модуль реализует два метода TCP-сканирования:
1. fragmented_tcp_scan — использует фрагментацию IP-пакетов для обхода фильтров.
2. source_port_manipulation — маскирует сканирование, подставляя доверенный source port (например, 53).

Оба метода полезны при обходе систем обнаружения вторжений и брандмауэров.
"""

import asyncio

from scapy.all import IP, TCP, conf, fragment, sr1

conf.verb = 0


async def fragmented_tcp_scan(
    target_ip: str, port: int | str, print_console: bool = True
) -> tuple[str, int, bool]:
    """
    Выполняет TCP SYN-сканирование с фрагментацией IP-пакета (evading firewall/IDS).

    Отправляет IP-пакет, разделённый на фрагменты, для обхода фильтрации и анализа.
    Считается, что некоторые IDS/IPS могут не собирать фрагменты полностью и пропустить атаку.

    Args:
        target_ip (str): IP-адрес цели.
        port (int | str): Целевой порт для сканирования.
        print_console (bool): Если True — печатает результат в консоль.

    Returns:
        tuple[str, int, bool]: Кортеж из (IP-адрес, порт, открыт ли порт).
    """
    port = int(port)
    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    fragments = fragment(pkt, fragsize=8)
    loop = asyncio.get_running_loop()

    response = None
    for frag in fragments:
        reply = await loop.run_in_executor(
            None, lambda: sr1(frag, timeout=2, verbose=0)
        )
        if reply:
            response = reply
            break

    is_open = (
        response is not None
        and response.haslayer(TCP)
        and response.getlayer(TCP).flags == 0x12  # SYN-ACK
    )

    if is_open and print_console:
        print(f"[+] Порт {port} по ip {target_ip} — открыт", flush=True)

    return target_ip, port, is_open


async def source_port_manipulation(
    target_ip: str,
    port: str | int,
    spoofed_sport: int | str = 53,
    print_console: bool = True,
) -> tuple[str, int, bool]:
    """
    Выполняет TCP SYN-сканирование, подменяя source port на доверенный (например, 53/UDP DNS).

    Метод используется для обхода фильтрации, которая допускает трафик только с определённых портов (например, DNS/HTTP).
    Отправляется SYN-пакет с подделанным исходным портом, и анализируется ответ от цели.

    Args:
        target_ip (str): IP-адрес цели.
        port (int | str): Целевой порт для сканирования.
        spoofed_sport (int | str): Подставляемый исходный порт (по умолчанию 53).
        print_console (bool): Если True — выводит результат в консоль.

    Returns:
        tuple[str, int, bool]: Кортеж из (IP-адрес, порт, открыт ли порт).
    """
    port = int(port)
    pkt = IP(dst=target_ip) / TCP(dport=port, sport=int(spoofed_sport), flags="S")
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))
    if response and response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            if print_console:
                print(f"[+] Порт {port} по ip {target_ip} — открыт ", flush=True)
            return target_ip, port, True
    return target_ip, port, False
