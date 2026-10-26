"""Ping & traceroute utilities. Shells out to system ping/traceroute (cross-platform)."""

import platform
import subprocess
import shutil
import re
import socket


def ping(host: str, count: int = 4) -> dict:
    result = {"host": host, "reachable": False, "raw": "", "avg_ms": None, "packet_loss_pct": None, "error": None}
    system = platform.system().lower()

    if system == "windows":
        cmd = ["ping", "-n", str(count), host]
    else:
        cmd = ["ping", "-c", str(count), host]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=count * 4 + 5)
        output = proc.stdout + proc.stderr
        result["raw"] = output
        result["reachable"] = proc.returncode == 0

        loss_match = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s*)?loss", output, re.IGNORECASE)
        if loss_match:
            result["packet_loss_pct"] = float(loss_match.group(1))

        avg_match = re.search(r"(?:avg|Average)\s*=?\s*/?\s*(\d+(?:\.\d+)?)", output)
        # Try multiple formats: "min/avg/max/mdev = 1.1/2.2/3.3/0.1" or Windows "Average = 5ms"
        rtt_match = re.search(r"=\s*[\d.]+/([\d.]+)/[\d.]+", output)
        if rtt_match:
            result["avg_ms"] = float(rtt_match.group(1))
        elif avg_match:
            result["avg_ms"] = float(avg_match.group(1))

    except FileNotFoundError:
        result["error"] = "ping command not found on this system"
    except subprocess.TimeoutExpired:
        result["error"] = "ping timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


def traceroute(host: str, max_hops: int = 30) -> dict:
    result = {"host": host, "hops": [], "raw": "", "error": None}
    system = platform.system().lower()

    if system == "windows":
        binary = "tracert"
        cmd = [binary, "-h", str(max_hops), "-w", "1000", host]
    else:
        binary = shutil.which("traceroute") or shutil.which("tracepath")
        if not binary:
            result["error"] = "traceroute/tracepath not installed on this system"
            return result
        cmd = [binary, "-m", str(max_hops), host] if "traceroute" in binary else [binary, host]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = proc.stdout + proc.stderr
        result["raw"] = output

        for line in output.splitlines():
            line = line.strip()
            hop_match = re.match(r"^\s*(\d+)\s+(.*)", line)
            if hop_match:
                result["hops"].append({"hop": int(hop_match.group(1)), "detail": hop_match.group(2)[:150]})

    except FileNotFoundError:
        result["error"] = f"{binary} not found"
    except subprocess.TimeoutExpired:
        result["error"] = "traceroute timed out"
    except Exception as e:
        result["error"] = str(e)

    return result


def resolve(host: str) -> dict:
    """Quick hostname -> IP resolution with timing info."""
    result = {"host": host, "ip": None, "error": None}
    try:
        result["ip"] = socket.gethostbyname(host)
    except socket.gaierror as e:
        result["error"] = str(e)
    return result


if __name__ == "__main__":
    import sys
    import json
    target = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(json.dumps(ping(target), indent=2))
