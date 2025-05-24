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
    SYN сканирование
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
            print(f"[!] Ошибка отправки пакета на порт {port}: {e}")
        return target_ip, port, False, OS_name

    if response is None and print_console:
        print(f"[?] Порт {port} — фильтруется (нет ответа)")
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:
            if scan_os:
                OS_name = (await detect_os(response))[0][0]
            if print_console:
                print(f"[+] Порт {port} — открыт " + OS_name)

            if answer:
                rst = TCP(
                    dport=port, sport=12345, flags="R", seq=1001, ack=response.ack
                )
                try:
                    await loop.run_in_executor(None, lambda: sr1(ip / rst, timeout=1))
                except OSError as e:
                    print(f"[!] Ошибка отправки RST на порт {port}: {e}")
            return target_ip, port, True, OS_name
    elif print_console:
        print(f"[!] Порт {port} — неожиданный ответ")
    return target_ip, port, False, OS_name
