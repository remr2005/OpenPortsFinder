"""Syn scan function"""

import asyncio

from scapy.all import IP, TCP, conf, sr1

from utils import detect_os

conf.verb = 0


async def syn(
    target_ip: str,
    port: str | int,
    answer: bool = True,
    scan_os: bool = False,
    print_console: bool = True,
) -> tuple[str, str | int, bool, str]:
    """
    Выполняет TCP SYN-сканирование (полуоткрытое сканирование) заданного IP и порта.

    SYN-сканирование заключается в отправке TCP-пакета с флагом SYN на целевой порт.
    Если в ответ приходит SYN-ACK (флаг 0x12), значит порт открыт.
    После получения SYN-ACK может быть отправлен RST для сброса соединения, чтобы не завершать 3-way handshake.
    Дополнительно может производиться определение ОС по ответу TCP/IP.

    Args:
        target_ip (str): IP-адрес цели.
        port (int | str): Целевой порт, который требуется просканировать.
        answer (bool): Если True — отправляется TCP RST после получения SYN-ACK (для избежания установления соединения).
        scan_os (bool): Если True — запускается определение операционной системы по ответу.
        print_console (bool): Если True — выводит результат сканирования в консоль.

    Returns:
        tuple[str, str | int, bool, str]: Кортеж вида:
            - IP-адрес цели,
            - номер порта,
            - флаг, открыт ли порт,
            - имя операционной системы (если определено, иначе пустая строка).
    """
    OS_name = ""
    port = int(port)
    ip = IP(dst=target_ip)
    syn = TCP(dport=port, flags="S", sport=12345, seq=1000)

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(None, lambda: sr1(ip / syn, timeout=2))
    except OSError as e:
        if print_console:
            print(
                f"[!] Ошибка отправки пакета на порт {port} по ip {target_ip}: {e}",
                flush=True,
            )
        return target_ip, port, False, OS_name

    if response is None:
        if print_console:
            print(
                f"[?] Порт {port} по ip {target_ip} — фильтруется (нет ответа)",
                flush=True,
            )
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN-ACK
            if scan_os:
                OS_name = (await detect_os(response))[0][0]
            if print_console:
                print(
                    f"[+] Порт {port} по ip {target_ip} — открыт " + OS_name, flush=True
                )

            if answer:
                rst = TCP(
                    dport=port, sport=12345, flags="R", seq=1001, ack=response.ack
                )
                try:
                    await loop.run_in_executor(None, lambda: sr1(ip / rst, timeout=1))
                except OSError as e:
                    print(
                        f"[!] Ошибка отправки RST на порт {port} по ip {target_ip}: {e}"
                    )
            return target_ip, port, True, OS_name
    else:
        if print_console:
            print(f"[!] Порт {port} по ip {target_ip} — неожиданный ответ", flush=True)

    return target_ip, port, False, OS_name
