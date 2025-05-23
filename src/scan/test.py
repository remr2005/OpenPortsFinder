async def idle_scan(target_ip: str, zombie_ip: str, port: int) -> bool:
    from scapy.all import IP, TCP, sr1
    ip_id_pkt = IP(dst=zombie_ip) / TCP(dport=80, flags="A")
    loop = asyncio.get_running_loop()
    resp1 = await loop.run_in_executor(None, lambda: sr1(ip_id_pkt, timeout=2))
    if not resp1:
        return False
    ip_id_before = resp1.id

    spoofed_syn = IP(src=zombie_ip, dst=target_ip) / TCP(dport=port, flags="S")
    await loop.run_in_executor(None, lambda: sr1(spoofed_syn, timeout=2))

    resp2 = await loop.run_in_executor(None, lambda: sr1(ip_id_pkt, timeout=2))
    if not resp2:
        return False
    ip_id_after = resp2.id

    return ip_id_after > ip_id_before
async def fragmented_tcp_scan(target_ip: str, port: int) -> bool:
    from scapy.all import fragment, sr1
    pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
    fragments = fragment(pkt, fragsize=8)
    loop = asyncio.get_running_loop()
    for frag in fragments:
        await loop.run_in_executor(None, lambda: sr1(frag, timeout=1, verbose=0))
    return True  # Более детальную обработку можно добавить по ICMP ответам
async def source_port_manipulation(target_ip: str, port: int, spoofed_sport: int = 53) -> bool:
    pkt = IP(dst=target_ip) / TCP(dport=port, sport=spoofed_sport, flags="S")
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))
    if response and response.haslayer(TCP):
        return response.getlayer(TCP).flags == 0x12
    return False
async def udp_scan(target_ip: str, port: int) -> str:
    from scapy.all import IP, UDP, sr1, ICMP
    pkt = IP(dst=target_ip) / UDP(dport=port)
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=3, verbose=0))
    if response is None:
        return "Open|Filtered"
    elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3:
        return "Closed"
    return "Open"
async def icmp_echo_scan(target_ip: str) -> bool:
    from scapy.all import IP, ICMP, sr1
    pkt = IP(dst=target_ip) / ICMP()
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))
    return response is not None
async def icmp_timestamp_scan(target_ip: str) -> bool:
    from scapy.all import IP, ICMP, sr1
    pkt = IP(dst=target_ip) / ICMP(type=13)  # Timestamp Request
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))
    return response is not None

async def icmp_address_mask_scan(target_ip: str) -> bool:
    from scapy.all import IP, ICMP, sr1
    pkt = IP(dst=target_ip) / ICMP(type=17)  # Address Mask Request
    loop = asyncio.get_running_loop()
    response = await loop.run_in_executor(None, lambda: sr1(pkt, timeout=2, verbose=0))
    return response is not None
