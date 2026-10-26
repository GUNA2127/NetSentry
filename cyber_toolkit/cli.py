#!/usr/bin/env python3
"""
NetSentry - All-in-one network diagnostics & security recon CLI.

Examples:
    python cli.py dns example.com
    python cli.py scan example.com --top 100
    python cli.py whois example.com
    python cli.py ping 8.8.8.8
    python cli.py traceroute example.com
    python cli.py ssl example.com
    python cli.py http example.com
    python cli.py sniff                      # requires sudo/root
    python cli.py all example.com             # runs full recon report
"""

import argparse
import json
import sys
import time

from toolkit import dns_tools, port_scanner, whois_tool, net_utils, ssl_checker, http_analyzer

BANNER = r"""
 _   _      _   ____             _              
| \ | | ___| |_/ ___|  ___ _ __ | |_ _ __ _   _  
|  \| |/ _ \ __\___ \ / _ \ '_ \| __| '__| | | | 
| |\  |  __/ |_ ___) |  __/ | | | |_| |  | |_| | 
|_| \_|\___|\__|____/ \___|_| |_|\__|_|   \__, | 
                                           |___/  
  All-in-one recon: DNS * Ports * WHOIS * SSL * HTTP * Packets
  Use only on systems you own or are authorized to test.
"""


def _print_json(data):
    print(json.dumps(data, indent=2, default=str))


def cmd_dns(args):
    _print_json(dns_tools.full_lookup(args.target))


def cmd_reverse(args):
    _print_json(dns_tools.reverse_lookup(args.target))


def cmd_scan(args):
    ports = None
    if args.top == 100:
        ports = port_scanner.TOP_100_PORTS
    elif args.ports:
        ports = [int(p) for p in args.ports.split(",")]

    def progress(done, total, entry):
        bar_len = 30
        filled = int(bar_len * done / total)
        bar = "#" * filled + "-" * (bar_len - filled)
        status = "OPEN" if entry["state"] == "open" else ""
        sys.stdout.write(f"\r[{bar}] {done}/{total}  {('-> port ' + str(entry['port']) + ' ' + status) if status else ''}      ")
        sys.stdout.flush()

    print(f"Scanning {args.target} ...")
    result = port_scanner.scan(args.target, ports=ports, progress_callback=progress)
    print()
    _print_json(result)


def cmd_whois(args):
    _print_json(whois_tool.lookup(args.target))


def cmd_ping(args):
    _print_json(net_utils.ping(args.target, count=args.count))


def cmd_traceroute(args):
    _print_json(net_utils.traceroute(args.target))


def cmd_ssl(args):
    _print_json(ssl_checker.check(args.target, port=args.port))


def cmd_http(args):
    _print_json(http_analyzer.analyze(args.target))


def cmd_sniff(args):
    from toolkit.packet_sniffer import LiveSniffer, HAVE_SCAPY
    if not HAVE_SCAPY:
        print("scapy is not installed. Run: pip install scapy")
        return

    def on_pkt(entry):
        proto = entry["proto"]
        src = f"{entry['src']}:{entry['sport']}" if entry["sport"] else entry["src"]
        dst = f"{entry['dst']}:{entry['dport']}" if entry["dport"] else entry["dst"]
        print(f"[{proto:5}] {src or '?':22} -> {dst or '?':22} {entry['length']}B")

    sniffer = LiveSniffer(iface=args.iface, bpf_filter=args.filter, on_packet=on_pkt)
    print(f"Starting live capture (filter={args.filter or 'none'}). Ctrl+C to stop.")
    sniffer.start()
    try:
        while True:
            time.sleep(1)
            if sniffer.error:
                print(f"\nError: {sniffer.error}")
                break
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()
        print("\n--- Summary ---")
        _print_json(sniffer.snapshot()["stats"])


def cmd_all(args):
    target = args.target
    print(BANNER)
    print(f"=== Full recon report for {target} ===\n")

    print(">> DNS records")
    _print_json(dns_tools.full_lookup(target))

    print("\n>> WHOIS")
    _print_json(whois_tool.lookup(target))

    print("\n>> Ping")
    _print_json(net_utils.ping(target, count=3))

    print("\n>> TLS/SSL certificate")
    _print_json(ssl_checker.check(target))

    print("\n>> HTTP security headers")
    _print_json(http_analyzer.analyze(target))

    print("\n>> Top-100 port scan")
    result = port_scanner.scan(target, ports=port_scanner.TOP_100_PORTS)
    _print_json(result)


def main():
    parser = argparse.ArgumentParser(description="NetSentry - all-in-one network recon toolkit", prog="netsentry")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("dns", help="DNS record lookup")
    p.add_argument("target")
    p.set_defaults(func=cmd_dns)

    p = sub.add_parser("reverse", help="Reverse DNS (PTR) lookup")
    p.add_argument("target", help="IP address")
    p.set_defaults(func=cmd_reverse)

    p = sub.add_parser("scan", help="TCP port scan")
    p.add_argument("target")
    p.add_argument("--top", type=int, default=100, help="Scan top N common ports (default 100)")
    p.add_argument("--ports", help="Comma-separated explicit port list, e.g. 22,80,443")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("whois", help="WHOIS domain lookup")
    p.add_argument("target")
    p.set_defaults(func=cmd_whois)

    p = sub.add_parser("ping", help="ICMP ping")
    p.add_argument("target")
    p.add_argument("--count", type=int, default=4)
    p.set_defaults(func=cmd_ping)

    p = sub.add_parser("traceroute", help="Traceroute to host")
    p.add_argument("target")
    p.set_defaults(func=cmd_traceroute)

    p = sub.add_parser("ssl", help="TLS/SSL certificate check")
    p.add_argument("target")
    p.add_argument("--port", type=int, default=443)
    p.set_defaults(func=cmd_ssl)

    p = sub.add_parser("http", help="HTTP header / security header analysis")
    p.add_argument("target")
    p.set_defaults(func=cmd_http)

    p = sub.add_parser("sniff", help="Live packet capture (requires root)")
    p.add_argument("--iface", default=None, help="Network interface (default: auto)")
    p.add_argument("--filter", default=None, help="BPF filter, e.g. 'tcp port 443'")
    p.set_defaults(func=cmd_sniff)

    p = sub.add_parser("all", help="Run full recon report (dns+whois+ping+ssl+http+scan)")
    p.add_argument("target")
    p.set_defaults(func=cmd_all)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
