"""WHOIS lookup - raw socket query to WHOIS servers (no external API needed)."""

import socket
import re

IANA_WHOIS = "whois.iana.org"

# Fallback map for common TLDs in case IANA referral parsing fails
TLD_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org", "io": "whois.nic.io", "co": "whois.nic.co",
    "in": "whois.registry.in", "dev": "whois.nic.google", "app": "whois.nic.google",
    "ai": "whois.nic.ai", "info": "whois.afilias.net", "biz": "whois.biz",
}


def _query(server: str, query: str, timeout: float = 6.0) -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((server, 43))
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            try:
                data = s.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode(errors="replace")


def lookup(domain: str) -> dict:
    domain = domain.strip().lower().lstrip("http://").lstrip("https://").split("/")[0]
    tld = domain.split(".")[-1]
    result = {"domain": domain, "raw": None, "parsed": {}, "error": None}

    server = TLD_SERVERS.get(tld)
    try:
        if not server:
            # Ask IANA which registry handles this TLD
            iana_resp = _query(IANA_WHOIS, tld)
            match = re.search(r"refer:\s*(\S+)", iana_resp)
            server = match.group(1) if match else "whois.iana.org"

        raw = _query(server, domain)

        # Some registries (like verisign) return a referral to the registrar's whois
        referral = re.search(r"Registrar WHOIS Server:\s*(\S+)", raw, re.IGNORECASE)
        if referral and referral.group(1) != server:
            try:
                raw2 = _query(referral.group(1), domain)
                if len(raw2) > 50:
                    raw = raw2
            except Exception:
                pass

        result["raw"] = raw

        fields = {
            "registrar": r"Registrar:\s*(.+)",
            "creation_date": r"Creat(?:ion|ed) Date:\s*(.+)",
            "expiration_date": r"(?:Registry )?Expir\w* Date:\s*(.+)",
            "updated_date": r"Updated Date:\s*(.+)",
            "name_servers": r"Name Server:\s*(.+)",
            "status": r"Domain Status:\s*(.+)",
            "org": r"Registrant Organization:\s*(.+)",
            "country": r"Registrant Country:\s*(.+)",
        }
        for key, pattern in fields.items():
            matches = re.findall(pattern, raw, re.IGNORECASE)
            if matches:
                cleaned = [m.strip() for m in matches]
                result["parsed"][key] = cleaned if len(cleaned) > 1 else cleaned[0]

    except Exception as e:
        result["error"] = str(e)

    return result


if __name__ == "__main__":
    import sys
    import json
    d = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(lookup(d), indent=2))
