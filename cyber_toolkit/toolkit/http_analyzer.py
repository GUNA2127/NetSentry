"""HTTP response header fetcher + security-header posture check."""

import urllib.request
import urllib.error
import time
import ssl

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
    "Content-Security-Policy": "Mitigates XSS / injection attacks",
    "X-Frame-Options": "Protects against clickjacking",
    "X-Content-Type-Options": "Prevents MIME-sniffing",
    "Referrer-Policy": "Controls referrer information leakage",
    "Permissions-Policy": "Restricts browser feature access",
    "X-XSS-Protection": "Legacy XSS filter (deprecated but still checked)",
}


def analyze(url: str, timeout: float = 8.0) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = {"url": url, "status_code": None, "headers": {}, "security_headers": {},
               "missing_security_headers": [], "response_time_ms": None, "error": None}

    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "NetSentry-Toolkit/1.0"})

    try:
        start = time.time()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["response_time_ms"] = round((time.time() - start) * 1000, 2)
            result["status_code"] = resp.status
            result["headers"] = dict(resp.headers.items())
            result["final_url"] = resp.geturl()

            for h, desc in SECURITY_HEADERS.items():
                if h in result["headers"]:
                    result["security_headers"][h] = result["headers"][h]
                else:
                    result["missing_security_headers"].append({"header": h, "purpose": desc})

    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["headers"] = dict(e.headers.items()) if e.headers else {}
        result["error"] = f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        result["error"] = f"Connection failed: {e.reason}"
    except Exception as e:
        result["error"] = str(e)

    return result


if __name__ == "__main__":
    import sys
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(analyze(target), indent=2))
