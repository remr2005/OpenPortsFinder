async def null_scan(
    target_ip: str,
    port: str | int,
    print_console: bool = True,
) -> tuple[str, str | int, bool]:
    """
    NULL сканирование — отправка TCP-пакета без флагов
    """
    port = int(port)
    ip = IP(dst=target_ip)
    null_pkt = TCP(dport=port, flags=0, sport=12345, seq=1000)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(ip / null_pkt, timeout=2))

    if response is None:
        if print_console:
            print(f"[?] Порт {port} — открыт или фильтруется (NULL)")
        return target_ip, port, True
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
        if print_console:
            print(f"[-] Порт {port} — закрыт (NULL)")
        return target_ip, port, False
    return target_ip, port, False
async def fin_scan(
    target_ip: str,
    port: str | int,
    print_console: bool = True,
) -> tuple[str, str | int, bool]:
    """
    FIN сканирование — отправка TCP-пакета с флагом FIN
    """
    port = int(port)
    ip = IP(dst=target_ip)
    fin_pkt = TCP(dport=port, flags="F", sport=12345, seq=1000)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(ip / fin_pkt, timeout=2))

    if response is None:
        if print_console:
            print(f"[?] Порт {port} — открыт или фильтруется (FIN)")
        return target_ip, port, True
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
        if print_console:
            print(f"[-] Порт {port} — закрыт (FIN)")
        return target_ip, port, False
    return target_ip, port, False
async def xmas_scan(
    target_ip: str,
    port: str | int,
    print_console: bool = True,
) -> tuple[str, str | int, bool]:
    """
    XMAS сканирование — флаги FIN, PSH, URG
    """
    port = int(port)
    ip = IP(dst=target_ip)
    xmas_pkt = TCP(dport=port, flags="FPU", sport=12345, seq=1000)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(ip / xmas_pkt, timeout=2))

    if response is None:
        if print_console:
            print(f"[?] Порт {port} — открыт или фильтруется (XMAS)")
        return target_ip, port, True
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
        if print_console:
            print(f"[-] Порт {port} — закрыт (XMAS)")
        return target_ip, port, False
    return target_ip, port, False
async def ack_scan(
    target_ip: str,
    port: str | int,
    print_console: bool = True,
) -> tuple[str, str | int, str]:
    """
    ACK сканирование — определение фильтрации
    """
    port = int(port)
    ip = IP(dst=target_ip)
    ack_pkt = TCP(dport=port, flags="A", sport=12345, seq=1000, ack=1001)

    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(ip / ack_pkt, timeout=2))

    if response is None:
        if print_console:
            print(f"[?] Порт {port} — фильтруется (ACK)")
        return target_ip, port, "filtered"
    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
        if print_console:
            print(f"[+] Порт {port} — не фильтруется (ACK)")
        return target_ip, port, "unfiltered"
    return target_ip, port, "unknown"
