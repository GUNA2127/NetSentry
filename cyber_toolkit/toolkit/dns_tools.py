"""DNS lookup utilities - A, AAAA, MX, NS, TXT, CNAME, SOA + reverse DNS."""

import socket
import time

try:
    import dns.resolver
    import dns.reversename
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def basic_lookup(hostname: str) -> dict:
    """Fallback lookup using only the standard library (A records + reverse)."""
    result = {"hostname": hostname, "records": {}, "error": None}
    try:
        infos = socket.getaddrinfo(hostname, None)
        addrs = sorted({info[4][0] for info in infos})
        result["records"]["A/AAAA"] = addrs
    except socket.gaierror as e:
        result["error"] = str(e)
    return result


def full_lookup(hostname: str, record_types=None) -> dict:
    """Full DNS lookup across multiple record types. Uses dnspython if available."""
    record_types = record_types or RECORD_TYPES
    start = time.time()
    result = {"hostname": hostname, "records": {}, "errors": {}, "query_time_ms": None}

    if not HAVE_DNSPYTHON:
        basic = basic_lookup(hostname)
        basic["query_time_ms"] = round((time.time() - start) * 1000, 2)
        basic["note"] = "dnspython not installed - showing basic A/AAAA lookup only. Run: pip install dnspython"
        return basic

    resolver = dns.resolver.Resolver()
    for rtype in record_types:
        try:
            answers = resolver.resolve(hostname, rtype, lifetime=5)
            result["records"][rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            result["errors"]["general"] = "Domain does not exist (NXDOMAIN)"
            break
        except Exception as e:
            result["errors"][rtype] = str(e)

    result["query_time_ms"] = round((time.time() - start) * 1000, 2)
    return result


def reverse_lookup(ip: str) -> dict:
    """Reverse DNS (PTR) lookup for an IP address."""
    result = {"ip": ip, "ptr": None, "error": None}
    try:
        if HAVE_DNSPYTHON:
            rev_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(rev_name, "PTR", lifetime=5)
            result["ptr"] = [str(r) for r in answers]
        else:
            host, _, _ = socket.gethostbyaddr(ip)
            result["ptr"] = [host]
    except Exception as e:
        result["error"] = str(e)
    return result


if __name__ == "__main__":
    import sys
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(full_lookup(target), indent=2))
