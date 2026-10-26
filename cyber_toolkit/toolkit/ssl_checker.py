"""SSL/TLS certificate inspector - expiry, issuer, SANs, protocol/cipher in use."""

import ssl
import socket
import datetime


def check(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    result = {"host": host, "port": port, "error": None}
    ctx = ssl.create_default_context()

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                result["protocol"] = ssock.version()
                result["cipher_suite"] = cipher[0] if cipher else None

                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                result["subject_cn"] = subject.get("commonName")
                result["issuer"] = issuer.get("commonName") or issuer.get("organizationName")

                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                result["valid_from"] = not_before
                result["valid_until"] = not_after

                if not_after:
                    expiry_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry_dt - datetime.datetime.utcnow()).days
                    result["days_until_expiry"] = days_left
                    result["expired"] = days_left < 0
                    if days_left < 0:
                        result["warning"] = "CERTIFICATE EXPIRED"
                    elif days_left < 30:
                        result["warning"] = f"Certificate expires soon ({days_left} days)"

                sans = cert.get("subjectAltName", [])
                result["subject_alt_names"] = [v for k, v in sans if k == "DNS"]

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {e}"
    except socket.timeout:
        result["error"] = "Connection timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


if __name__ == "__main__":
    import sys
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(check(target), indent=2))
