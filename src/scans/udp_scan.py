"""
UDP-скан
"""

import asyncio

from scapy.all import ICMP, IP, UDP, conf, sr1

conf.verb = 0


async def udp(
    target_ip: str, port: int, print_console: bool = True
) -> tuple[str, int, bool]:
    """
    Асинхронное UDP сканирование порта.

    Отправляет UDP пакет на указанный порт и анализирует ответ для определения статуса порта.

    Parameters:
        target_ip (str): IP-адрес цели сканирования
        port (int): Номер порта для сканирования
        print_console (bool, optional): Флаг вывода результатов в консоль. По умолчанию True.

    Returns:
        tuple[str, int, bool]: Кортеж содержащий:
            - target_ip (str): IP-адрес цели
            - port (int): Номер проверенного порта
            - status (bool): Результат проверки (True если порт считается открытым)

    Examples:
        >>> asyncio.run(udp("192.168.1.1", 53))
        ('192.168.1.1', 53, True)

        >>> asyncio.run(udp("10.0.0.1", 123, print_console=False))
        ('10.0.0.1', 123, False)

    Notes:
        - Для работы требует root-прав в Linux/MacOS
        - Открытым считается порт, если получен ICMP-ответ "port unreachable"
        - Может давать ложноположительные результаты для фильтруемых портов
    """
    pkt = IP(dst=target_ip) / UDP(dport=port)
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=3, verbose=0))
    if response is None:
        if print_console:
            print(f"[+] Порт {port} — открыт ", flush=True)
        return target_ip, port, True
    elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3:
        return target_ip, port, False
    return target_ip, port, False
