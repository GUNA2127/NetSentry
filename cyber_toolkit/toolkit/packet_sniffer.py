"""
Real-time packet sniffer - Wireshark-style live capture & protocol breakdown.

Requires:
    - scapy (`pip install scapy`)
    - root/administrator privileges (raw sockets)
    - On Windows: Npcap installed (https://npcap.com)

Usage as a library:
    from toolkit.packet_sniffer import LiveSniffer
    sniffer = LiveSniffer(iface=None, on_packet=my_callback)
    sniffer.start()
    ...
    sniffer.stop()
"""

import threading
import time
import collections

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw, get_if_list
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False


def list_interfaces():
    if not HAVE_SCAPY:
        return []
    try:
        return get_if_list()
    except Exception:
        return []


def _describe_packet(pkt) -> dict:
    info = {
        "time": round(time.time(), 3),
        "src": None, "dst": None, "proto": "OTHER",
        "sport": None, "dport": None, "length": len(pkt), "summary": None,
    }
    try:
        if IP in pkt:
            info["src"] = pkt[IP].src
            info["dst"] = pkt[IP].dst
            if TCP in pkt:
                info["proto"] = "TCP"
                info["sport"] = pkt[TCP].sport
                info["dport"] = pkt[TCP].dport
                flags = pkt[TCP].flags
                info["flags"] = str(flags)
            elif UDP in pkt:
                info["proto"] = "UDP"
                info["sport"] = pkt[UDP].sport
                info["dport"] = pkt[UDP].dport
                if DNS in pkt:
                    info["proto"] = "DNS"
            elif ICMP in pkt:
                info["proto"] = "ICMP"
        info["summary"] = pkt.summary()
    except Exception:
        pass
    return info


class LiveSniffer:
    """
    Wraps scapy's sniff() in a background thread so it can be started/stopped
    from a web server or CLI without blocking.
    """

    def __init__(self, iface=None, bpf_filter=None, on_packet=None, max_history=500):
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.on_packet = on_packet
        self.max_history = max_history
        self.history = collections.deque(maxlen=max_history)
        self.stats = collections.Counter()
        self._thread = None
        self._stop_event = threading.Event()
        self.running = False
        self.error = None

    def _process(self, pkt):
        entry = _describe_packet(pkt)
        self.history.append(entry)
        self.stats[entry["proto"]] += 1
        self.stats["_total"] += 1
        if self.on_packet:
            try:
                self.on_packet(entry)
            except Exception:
                pass

    def _run(self):
        if not HAVE_SCAPY:
            self.error = "scapy not installed. Run: pip install scapy"
            self.running = False
            return
        try:
            sniff(
                iface=self.iface,
                filter=self.bpf_filter,
                prn=self._process,
                stop_filter=lambda p: self._stop_event.is_set(),
                store=False,
            )
        except PermissionError:
            self.error = "Permission denied - packet capture requires root/administrator privileges."
        except Exception as e:
            self.error = str(e)
        finally:
            self.running = False

    def start(self):
        if self.running:
            return
        self._stop_event.clear()
        self.error = None
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self.running = False

    def snapshot(self) -> dict:
        return {
            "running": self.running,
            "error": self.error,
            "stats": dict(self.stats),
            "recent_packets": list(self.history)[-100:],
        }


if __name__ == "__main__":
    import json
    if not HAVE_SCAPY:
        print("Install scapy first: pip install scapy")
    else:
        print("Available interfaces:", list_interfaces())
        s = LiveSniffer()
        s.start()
        print("Capturing for 5 seconds (requires root)...")
        time.sleep(5)
        s.stop()
        print(json.dumps(s.snapshot(), indent=2, default=str))
