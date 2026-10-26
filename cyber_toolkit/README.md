# NetSentry Toolkit

A single, all-in-one network diagnostics & security recon tool that merges the
functionality of `nmap`, `dig`/`nslookup`, `whois`, `ping`/`traceroute`,
an SSL checker, an HTTP-security-header linter, and a live packet sniffer
(Wireshark-style), so one search / one target gives you everything in one
place — as a CLI **and** a real-time web dashboard.

> ⚠️ **Legal & ethical use only.** Run this against systems, domains, and
> networks you **own** or have **explicit written authorization** to test.
> Unauthorized scanning or packet capture can violate computer-crime laws
> (CFAA, Computer Misuse Act, India IT Act §43/66, etc.).

## What's inside

| Module | Replaces | What it does |
|---|---|---|
| `toolkit/dns_tools.py` | `dig` / `nslookup` | A/AAAA/MX/NS/TXT/CNAME/SOA lookups, reverse DNS |
| `toolkit/port_scanner.py` | `nmap` | Multithreaded TCP connect scan + banner grabbing, top-100 or custom ports |
| `toolkit/whois_tool.py` | `whois` | Raw WHOIS queries with registrar/expiry/name-server parsing |
| `toolkit/net_utils.py` | `ping` / `traceroute` | Cross-platform ping & traceroute wrappers |
| `toolkit/ssl_checker.py` | `openssl s_client` | Certificate issuer, expiry countdown, SANs, cipher in use |
| `toolkit/http_analyzer.py` | browser devtools | Fetches headers, flags missing security headers (HSTS, CSP, X-Frame-Options, etc.) |
| `toolkit/packet_sniffer.py` | Wireshark/tcpdump | Live packet capture via `scapy`, protocol breakdown, streams in real time |

## Setup

```bash
cd cyber_toolkit
python3 -m venv venv && source venv/bin/activate      # optional but recommended
pip install -r requirements.txt
```

Live packet capture needs:
- **Linux/macOS:** run with `sudo` (raw sockets require root)
- **Windows:** install [Npcap](https://npcap.com) first, then run as Administrator

If you don't need packet capture, everything else works without `scapy` or root —
those modules just report "capture engine not available" and the rest of the
tool works normally.

## Usage — CLI

```bash
python cli.py dns example.com
python cli.py scan example.com --top 100
python cli.py whois example.com
python cli.py ping 8.8.8.8
python cli.py traceroute example.com
python cli.py ssl example.com
python cli.py http example.com
sudo python cli.py sniff --filter "tcp port 443"
python cli.py all example.com          # full recon report, all modules in one run
```

## Usage — Web dashboard (real-time)

```bash
python web/app.py            # or: sudo python web/app.py  (needed for Live Capture tab)
```

Then open **http://localhost:5000**. One target box runs DNS + WHOIS + ping +
SSL + HTTP + port scan together ("Run full recon"); the Live Capture tab
streams packets over WebSockets as they're captured, with a running
protocol/byte counter — no page refresh needed.

## Notes & limits

- The port scanner does a plain **TCP connect scan** (not raw SYN scanning like
  `nmap -sS`), so it doesn't need root — but it's a bit slower/noisier than a
  SYN scan and will show up in target logs as full connections.
- WHOIS parsing covers the common registry response formats but some TLDs
  return non-standard formats; the raw response is always included alongside
  the parsed fields.
- Packet capture requires elevated privileges by design (raw sockets) —
  this is an OS-level restriction, not a limitation of the tool.
- This toolkit is for authorized diagnostics and learning. It intentionally
  does **not** include exploitation, vulnerability-scanning payloads, or
  anything beyond passive/active recon and traffic visibility.

## Extending it

Each module in `toolkit/` is a plain, importable Python module with a single
clear entry function (`scan()`, `lookup()`, `check()`, `analyze()`, ...), so
you can add new modules (e.g. subdomain enumeration, ARP scanning) the same
way and wire them into both `cli.py` and `web/app.py`.
