import asyncio
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor

import vulners

vulners_api = vulners.VulnersApi(
    "KE701P85PZP7VTH6LJ71K9WZI13Z680T50M2QCTVI1SML6222SC727TVK58X9COA"
)

DEFAULT_PORTS = [22, 25, 80, 110, 135, 139, 143, 443, 445]

BANNER_PATTERNS = [
    (r"Server: (\S+)/(.*)", "http"),
    (r"OpenSSH[_/ ](\S+)", "ssh"),
    (r"vsFTPd (\S+)", "ftp"),
    (r"Exim (\S+)", "smtp"),
    (r"Postfix", "smtp"),
    (r"Courier-IMAP (\S+)", "imap"),
    (r"Dovecot (\S+)", "imap"),
    (r"nginx/(\S+)", "http"),
    (r"Apache/(\S+)", "http"),
    (r"ProFTPD (\S+)", "ftp"),
    (r"Microsoft Windows RPC", "rpc"),
    (r"SMB", "smb"),
    (r"NT LM 0.12", "smb"),
]


def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(3)
            s.connect((ip, port))

            if port in [80, 8080, 8000, 443]:
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
            elif port in [25, 587, 465]:
                s.sendall(b"EHLO example.com\r\n")
            elif port == 110:
                s.sendall(b"USER test\r\n")
            elif port == 143:
                s.sendall(b". CAPABILITY\r\n")
            elif port in [139, 445]:
                s.sendall(
                    b"\x00\x00\x00\x85\xffSMB@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                )
            elif port == 135:
                s.sendall(
                    b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00"
                )  # Частичный MSRPC bind

            try:
                banner = s.recv(2048).decode(errors="ignore")
            except socket.timeout:
                return None

            return banner.strip() if banner else None
    except Exception as e:
        print(f"[!] Ошибка на {ip}:{port} — {e}")
        return None


def extract_service_info(banner):
    for pattern, _ in BANNER_PATTERNS:
        match = re.search(pattern, banner or "")
        if match:
            name = match.group(0).split()[0]
            version = match.group(1) if len(match.groups()) >= 1 else ""
            return name.strip(), version.strip()
    return None, None


def search_cve(service, version):
    query = f"{service} {version}" if version else service
    print(query)
    results = vulners_api.search_cpe(query)
    return f"{results['best_match']} | {results['cpe']}"


def scan_host(ip, ports=DEFAULT_PORTS):
    results = []
    for port in ports:
        banner = grab_banner(ip, port)
        if banner:
            service, version = extract_service_info(banner)
            if service:
                cves = search_cve(service, version)
                results.append((port, service, version, cves))
    return results


async def scan_network(target):
    """
    Ищет уязвимости по версии сервисов портов
    """
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print(f"[!] Invalid target: {target}", flush=True)
        return []

    results = []

    def scan_and_collect(ip):
        ip_str = str(ip)
        host_results = scan_host(ip_str)
        if host_results:
            results.append((ip_str, host_results))

    loop = asyncio.get_running_loop()
    # Запускаем в executor, чтобы не блокировать основной поток
    with ThreadPoolExecutor(max_workers=30) as executor:
        await asyncio.gather(
            *[
                loop.run_in_executor(executor, scan_and_collect, ip)
                for ip in net.hosts()
            ]
        )

    return results
