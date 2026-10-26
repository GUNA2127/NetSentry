#!/usr/bin/env python3
"""
NetSentry Web Dashboard
Flask + Flask-SocketIO app exposing all toolkit modules through a browser UI,
with real-time packet capture streaming over WebSockets.

Run:
    python web/app.py
Then open http://localhost:5000

Packet sniffing requires root/administrator privileges:
    sudo python web/app.py
"""

import os
import sys
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

from toolkit import dns_tools, port_scanner, whois_tool, net_utils, ssl_checker, http_analyzer
from toolkit.packet_sniffer import LiveSniffer, HAVE_SCAPY, list_interfaces

app = Flask(__name__)
app.config["SECRET_KEY"] = "netsentry-dev-key"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

sniffer_instance = None
sniffer_lock = threading.Lock()


@app.route("/")
def index():
    return render_template("index.html", have_scapy=HAVE_SCAPY)


# ---------- REST API ----------

@app.route("/api/dns", methods=["POST"])
def api_dns():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(dns_tools.full_lookup(target))


@app.route("/api/reverse", methods=["POST"])
def api_reverse():
    target = request.json.get("target", "").strip()
    return jsonify(dns_tools.reverse_lookup(target))


@app.route("/api/whois", methods=["POST"])
def api_whois():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(whois_tool.lookup(target))


@app.route("/api/ping", methods=["POST"])
def api_ping():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(net_utils.ping(target, count=4))


@app.route("/api/traceroute", methods=["POST"])
def api_traceroute():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(net_utils.traceroute(target))


@app.route("/api/ssl", methods=["POST"])
def api_ssl():
    target = request.json.get("target", "").strip()
    port = int(request.json.get("port", 443))
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(ssl_checker.check(target, port=port))


@app.route("/api/http", methods=["POST"])
def api_http():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(http_analyzer.analyze(target))


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Kicks off an async port scan and streams progress over the 'scan_progress'
    socket event, then emits 'scan_complete' with the final result.
    """
    target = request.json.get("target", "").strip()
    top = int(request.json.get("top", 100))
    if not target:
        return jsonify({"error": "target required"}), 400

    ports = port_scanner.TOP_100_PORTS if top == 100 else list(port_scanner.COMMON_PORTS.keys())

    def run_scan():
        def progress(done, total, entry):
            socketio.emit("scan_progress", {"done": done, "total": total, "entry": entry})
        result = port_scanner.scan(target, ports=ports, progress_callback=progress)
        socketio.emit("scan_complete", result)

    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"status": "started", "target": target})


@app.route("/api/interfaces", methods=["GET"])
def api_interfaces():
    return jsonify({"interfaces": list_interfaces(), "have_scapy": HAVE_SCAPY})


# ---------- Live packet sniffing over WebSocket ----------

@socketio.on("sniff_start")
def handle_sniff_start(data):
    global sniffer_instance
    if not HAVE_SCAPY:
        socketio.emit("sniff_error", {"error": "scapy not installed. Run: pip install scapy"})
        return

    with sniffer_lock:
        if sniffer_instance and sniffer_instance.running:
            socketio.emit("sniff_error", {"error": "Capture already running"})
            return

        iface = data.get("iface") or None
        bpf_filter = data.get("filter") or None

        def on_packet(entry):
            socketio.emit("packet", entry)

        sniffer_instance = LiveSniffer(iface=iface, bpf_filter=bpf_filter, on_packet=on_packet)
        sniffer_instance.start()

        # Watchdog: report errors (e.g. permission denied) back to the client
        def watch():
            time.sleep(1.5)
            if sniffer_instance.error:
                socketio.emit("sniff_error", {"error": sniffer_instance.error})

        threading.Thread(target=watch, daemon=True).start()
        socketio.emit("sniff_started", {"iface": iface or "auto", "filter": bpf_filter})


@socketio.on("sniff_stop")
def handle_sniff_stop():
    global sniffer_instance
    with sniffer_lock:
        if sniffer_instance:
            sniffer_instance.stop()
            socketio.emit("sniff_stopped", sniffer_instance.snapshot())


if __name__ == "__main__":
    print("NetSentry dashboard running at http://localhost:5000")
    if not HAVE_SCAPY:
        print("NOTE: scapy not installed - live packet capture will be disabled.")
    if os.name != "nt" and os.geteuid() != 0:
        print("NOTE: not running as root - live packet capture will fail. Use: sudo python web/app.py")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)
