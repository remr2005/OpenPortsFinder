"""
Зомби-скан
"""

import asyncio

from scapy.all import IP, TCP, conf, sr1

conf.verb = 0


async def idle(target_ip: str, port: int, zombie_ip: str) -> tuple[str, int, bool]:
    """
    Выполняет Idle (Zombie) scan с использованием третьего хоста ("зомби") для обнаружения открытых портов без прямого взаимодействия с целью.

    Idle-скан позволяет определить открытые порты **незаметно**, подставляя IP-адрес "зомби"-хоста в качестве источника.
    Метод основан на анализе изменений в поле IP ID у зомби-хоста.

    Алгоритм:
    1. Получаем начальное значение IP ID у зомби.
    2. Отправляем SYN-пакет на целевой порт от имени зомби.
    3. Повторно получаем IP ID у зомби.
    4. Если значение IP ID увеличилось (обычно на 1), это значит, что цель отправила RST в ответ зомби-хосту → **порт открыт**.
       Если IP ID не изменился — цель не ответила → **порт закрыт или фильтруется**.

    Args:
        target_ip (str): IP-адрес цели.
        port (int): Целевой порт.
        zombie_ip (str): IP-адрес зомби-хоста.

    Returns:
        tuple[str, int, bool]:
            - IP-адрес цели,
            - номер проверяемого порта,
            - True, если порт открыт (IP ID увеличился), иначе False.
    """
    ip_id_pkt = IP(dst=zombie_ip) / TCP(dport=80, flags="A")
    loop = asyncio.get_running_loop()

    # Получаем начальный IP ID
    resp1 = await loop.run_in_executor(None, lambda: sr1(ip_id_pkt, timeout=2))
    if not resp1:
        return target_ip, port, False
    ip_id_before = resp1.id

    # Отправляем spoofed SYN от имени зомби на целевой порт
    spoofed_syn = IP(src=zombie_ip, dst=target_ip) / TCP(dport=port, flags="S")
    await loop.run_in_executor(None, lambda: sr1(spoofed_syn, timeout=2))

    # Получаем новый IP ID
    resp2 = await loop.run_in_executor(None, lambda: sr1(ip_id_pkt, timeout=2))
    if not resp2:
        return target_ip, port, False
    ip_id_after = resp2.id

    is_open = ip_id_after > ip_id_before

    if is_open:
        print(f"[+] Порт {port} по ip {target_ip} — открыт (Idle/Zombie)", flush=True)

    return target_ip, port, is_open
