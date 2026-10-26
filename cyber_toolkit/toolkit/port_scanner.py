"""
Lightweight nmap-style TCP port scanner with banner grabbing.
Pure standard-library sockets, multithreaded for speed.
"""

import socket
import time
import concurrent.futures

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

TOP_100_PORTS = sorted(set(list(COMMON_PORTS.keys()) + [
    7, 9, 13, 17, 19, 20, 26, 37, 49, 67, 68, 69, 79, 88, 106, 113, 119,
    123, 137, 138, 158, 179, 199, 389, 427, 465, 500, 514, 515, 543, 544,
    548, 554, 587, 631, 646, 873, 990, 1025, 1026, 1027, 1028, 1029, 1110,
    1433, 1720, 1755, 2000, 2001, 2049, 2121, 2717, 3000, 3001, 3128, 3268,
    3299, 3300, 3986, 4899, 5000, 5001, 5050, 5060, 5101, 5190, 5357, 5631,
    5666, 5800, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8081, 8888, 9100,
    9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]))


def _scan_one(host: str, port: int, timeout: float, grab_banner: bool) -> dict:
    entry = {"port": port, "state": "closed", "service": COMMON_PORTS.get(port, "unknown"), "banner": None}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        conn_result = sock.connect_ex((host, port))
        if conn_result == 0:
            entry["state"] = "open"
            if grab_banner:
                try:
                    sock.settimeout(1.0)
                    if port in (80, 8080, 8000, 8888):
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(256)
                    entry["banner"] = banner.decode(errors="replace").strip()[:200]
                except Exception:
                    pass
    except socket.error:
        pass
    finally:
        sock.close()
    return entry


def scan(host: str, ports=None, timeout: float = 0.6, max_workers: int = 200,
          grab_banner: bool = True, progress_callback=None) -> dict:
    """
    Scan `host` across `ports` (defaults to TOP_100_PORTS).
    progress_callback(done, total, entry) is called after every port check (optional, for live UI updates).
    """
    ports = ports or TOP_100_PORTS
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return {"host": host, "error": f"Could not resolve host: {e}", "open_ports": [], "scanned": 0}

    start = time.time()
    open_ports = []
    total = len(ports)
    done = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_one, resolved_ip, p, timeout, grab_banner): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            entry = future.result()
            done += 1
            if entry["state"] == "open":
                open_ports.append(entry)
            if progress_callback:
                progress_callback(done, total, entry)

    open_ports.sort(key=lambda e: e["port"])
    return {
        "host": host,
        "resolved_ip": resolved_ip,
        "scanned": total,
        "open_ports": open_ports,
        "duration_sec": round(time.time() - start, 2),
    }


if __name__ == "__main__":
    import sys
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    print(f"Scanning {target} ...")
    result = scan(target, ports=list(COMMON_PORTS.keys()))
    print(json.dumps(result, indent=2))
