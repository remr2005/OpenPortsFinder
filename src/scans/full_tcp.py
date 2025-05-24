"""
TCP сканирование (полное соединение)
"""

import socket
from typing import Tuple


def tcp_scan(target_ip: str, port: int, timeout: float = 2.0) -> Tuple[str, int, bool]:
    """
    Выполняет TCP Connect-сканирование (аналог nmap -sT).

    Попытка установить полное TCP-соединение с целью:
    - Если соединение успешно — порт открыт.
    - Если соединение отказано — порт закрыт.
    - Если нет ответа — порт фильтруется или хост недоступен.

    Args:
        target_ip (str): IP-адрес цели.
        port (int): Порт для проверки.
        timeout (float): Таймаут в секундах.

    Returns:
        Tuple[str, int, bool]:
            - IP-адрес цели,
            - номер порта,
            - True если порт открыт, иначе False.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"[+] Порт {port} по IP {target_ip} — открыт", flush=True)
            return target_ip, port, True
        else:
            print(
                f"[-] Порт {port} по IP {target_ip} — закрыт или фильтруется",
                flush=True,
            )
            return target_ip, port, False

    except socket.timeout:
        print(
            f"[?] Порт {port} по IP {target_ip} — таймаут (возможно фильтрация)",
            flush=True,
        )
        return target_ip, port, False

    except socket.error as e:
        print(f"[!] Ошибка при подключении к {target_ip}:{port} — {e}", flush=True)
        return target_ip, port, False

    finally:
        sock.close()
