"""
TCP сканирование
"""

import socket
from typing import Tuple


def tcp_scan(target_ip: str, port: int, timeout: float = 2.0) -> Tuple[str, int, bool]:
    """
    TCP-сканирование с полным подключением (как nmap -sT).
    Возвращает:
        - (True, "open") если порт открыт
        - (False, "closed") если порт закрыт
        - (False, "filtered") если порт фильтруется (нет ответа)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        # Пытаемся подключиться
        result = sock.connect_ex((target_ip, port))

        if result == 0:
            return target_ip, port, True
        else:
            return target_ip, port, False

    except socket.timeout:
        return target_ip, port, False
    except socket.error:
        return target_ip, port, False
    finally:
        sock.close()
