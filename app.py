"""
Network Packet Analyzer - Educational Prototype
Department of Computer Engineering, Sanjivani COE, Kopargaon
Presented by: Omkar Jape (114) & Tambe Pranav (112)
Guided by: Prof. P. N. Kalavadekar
"""

import csv
import io
import random
import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response

# Scapy imports
from scapy.all import IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, ARP, Raw, conf

app = Flask(__name__)

# Global state and packet storage
lock = threading.Lock()
captured_packets = []
stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "dns": 0,
    "icmp": 0,
    "other": 0,
    "total_bytes": 0,
    "start_time": None
}

capture_state = {
    "running": False,
    "mode": "demo",  # "demo" or "live"
    "interface": "Demo Network Adapter",
    "error": None
}

stop_event = threading.Event()
capture_thread = None


def format_hex_ascii(raw_bytes, max_len=128):
    """Convert raw payload bytes to formatted hex and ASCII dump"""
    if not raw_bytes:
        return "No payload data"
    sample = raw_bytes[:max_len]
    hex_str = " ".join(f"{b:02x}" for b in sample)
    ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in sample)
    suffix = f" ... ({len(raw_bytes) - max_len} more bytes)" if len(raw_bytes) > max_len else ""
    return f"HEX: {hex_str}\nASCII: {ascii_str}{suffix}"


def analyze_scapy_packet(packet):
    """Examines captured packet and extracts structured network protocol data"""
    packet_id = len(captured_packets) + 1
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    length = len(packet)
    
    src_ip = "N/A"
    dst_ip = "N/A"
    src_port = "-"
    dst_port = "-"
    protocol = "Other"
    info = ""
    layers_list = []
    tcp_flags_str = ""

    # Layer 2 / ARP
    if packet.haslayer(ARP):
        protocol = "ARP"
        arp = packet[ARP]
        src_ip = arp.psrc
        dst_ip = arp.pdst
        layers_list.append(f"ARP (Opcode: {'Request' if arp.op == 1 else 'Reply'})")
        info = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} is at {arp.hwsrc}"

    # Layer 3 - IPv4 or IPv6
    if packet.haslayer(IP):
        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        layers_list.append(f"IPv4 (TTL: {ip.ttl}, TOS: {ip.tos})")
    elif packet.haslayer(IPv6):
        ip6 = packet[IPv6]
        src_ip = ip6.src
        dst_ip = ip6.dst
        layers_list.append(f"IPv6 (Hop Limit: {ip6.hlim})")

    # Layer 4 / 7 protocols
    if packet.haslayer(DNS):
        protocol = "DNS"
        dns = packet[DNS]
        layers_list.append("DNS")
        if dns.qr == 0 and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode(errors='ignore').rstrip('.')
            info = f"Standard query A {qname}"
        elif dns.qr == 1:
            info = f"Standard query response (Answers: {dns.ancount})"
        else:
            info = "DNS Packet"
        if packet.haslayer(UDP):
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

    elif packet.haslayer(TCP):
        protocol = "TCP"
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        
        # Parse TCP flags
        flags = []
        if tcp.flags.S: flags.append("SYN")
        if tcp.flags.A: flags.append("ACK")
        if tcp.flags.F: flags.append("FIN")
        if tcp.flags.R: flags.append("RST")
        if tcp.flags.P: flags.append("PSH")
        if tcp.flags.U: flags.append("URG")
        tcp_flags_str = ",".join(flags) if flags else "NONE"
        layers_list.append(f"TCP (Flags: [{tcp_flags_str}], Seq={tcp.seq}, Ack={tcp.ack})")

        # Application layer detection for standard ports
        if dst_port == 80 or src_port == 80:
            protocol = "HTTP"
            info = f"HTTP [Port {dst_port}] Seq={tcp.seq} Ack={tcp.ack}"
        elif dst_port == 443 or src_port == 443:
            info = f"TLS/HTTPS [{tcp_flags_str}] {src_port} -> {dst_port}"
        elif dst_port == 22 or src_port == 22:
            info = f"SSH Traffic [{tcp_flags_str}]"
        else:
            info = f"[{tcp_flags_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window}"

    elif packet.haslayer(UDP):
        protocol = "UDP"
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        layers_list.append(f"UDP (Len: {udp.len})")
        if dst_port == 53 or src_port == 53:
            protocol = "DNS"
            info = "DNS Query/Response over UDP"
        elif dst_port == 123 or src_port == 123:
            info = "NTP (Network Time Protocol)"
        elif dst_port == 67 or dst_port == 68:
            info = "DHCP Packet"
        else:
            info = f"UDP Datagram {src_port} -> {dst_port} Len={udp.len}"

    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        icmp = packet[ICMP]
        icmp_type = icmp.type
        layers_list.append(f"ICMP (Type: {icmp_type}, Code: {icmp.code})")
        if icmp_type == 8:
            info = f"Echo (ping) request id={getattr(icmp, 'id', 0)} seq={getattr(icmp, 'seq', 0)}"
        elif icmp_type == 0:
            info = f"Echo (ping) reply id={getattr(icmp, 'id', 0)} seq={getattr(icmp, 'seq', 0)}"
        elif icmp_type == 3:
            info = "Destination unreachable"
        elif icmp_type == 11:
            info = "Time-to-live exceeded"
        else:
            info = f"ICMP Type {icmp_type}"

    # Raw payload preview
    payload_dump = "No payload"
    if packet.haslayer(Raw):
        raw_data = bytes(packet[Raw].load)
        payload_dump = format_hex_ascii(raw_data)

    parsed = {
        "id": packet_id,
        "timestamp": timestamp,
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": str(src_port),
        "dst_port": str(dst_port),
        "protocol": protocol,
        "length": length,
        "info": info or f"{protocol} Packet",
        "flags": tcp_flags_str,
        "layers": " > ".join(layers_list) if layers_list else "Raw Packet",
        "payload": payload_dump
    }

    # Update Statistics Module
    with lock:
        captured_packets.append(parsed)
        stats["total"] += 1
        stats["total_bytes"] += length
        p_lower = protocol.lower()
        if p_lower in stats:
            stats[p_lower] += 1
        else:
            stats["other"] += 1

    return parsed


def generate_demo_packet():
    """Generates realistic synthetic network packets using Scapy in memory"""
    client_ips = ["192.168.1.104", "192.168.1.112", "192.168.1.114", "10.0.0.45"]
    server_ips = ["142.250.190.46", "104.244.42.1", "151.101.65.140", "8.8.8.8", "1.1.1.1"]
    domain_names = ["google.com.", "sanjivani.edu.in.", "github.com.", "cloudflare.com."]

    sample_type = random.choices(["tcp", "udp", "dns", "icmp", "http"], weights=[35, 20, 20, 15, 10])[0]

    src = random.choice(client_ips)
    dst = random.choice(server_ips)
    sport = random.randint(49152, 65535)

    if sample_type == "dns":
        domain = random.choice(domain_names)
        pkt = IP(src=src, dst="8.8.8.8") / UDP(sport=sport, dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    elif sample_type == "tcp":
        flags = random.choice(["S", "SA", "A", "PA", "FA"])
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=443, flags=flags, seq=random.randint(1000, 50000), ack=random.randint(1000, 50000))
        if "P" in flags:
            pkt = pkt / Raw(load=b"\x17\x03\x03\x00\x28Encrypted Application Data Stream")
    elif sample_type == "http":
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=80, flags="PA", seq=101, ack=202) / Raw(
            load=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        )
    elif sample_type == "udp":
        pkt = IP(src=src, dst=dst) / UDP(sport=sport, dport=random.choice([123, 5004, 8080])) / Raw(
            load=b"Media / Datagram stream payload [sample data]"
        )
    else:  # ICMP
        icmp_type = random.choice([8, 0])
        pkt = IP(src=src, dst=dst) / ICMP(type=icmp_type, id=1, seq=random.randint(1, 100)) / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")

    return pkt


def demo_capture_worker():
    """Worker loop for Demo Mode simulation"""
    while not stop_event.is_set():
        pkt = generate_demo_packet()
        analyze_scapy_packet(pkt)
        # Random interval between 0.3s and 1.0s to simulate natural network activity
        sleep_time = random.uniform(0.3, 0.9)
        time.sleep(sleep_time)


def live_capture_worker(interface_name):
    """Worker loop for Live Packet Capture using Scapy sniff"""
    try:
        from scapy.all import sniff
        kwargs = {
            "prn": analyze_scapy_packet,
            "stop_filter": lambda p: stop_event.is_set(),
            "store": False,
            "timeout": 1
        }
        if interface_name and interface_name != "Default":
            kwargs["iface"] = interface_name

        while not stop_event.is_set():
            sniff(**kwargs)
    except Exception as e:
        capture_state["error"] = str(e)
        capture_state["running"] = False


# ---------------------------- API ROUTES ----------------------------

@app.route("/")
def index():
    """Serve the dashboard"""
    return render_template("index.html")


@app.route("/api/interfaces")
def get_interfaces():
    """Retrieve available network adapters"""
    interfaces = [{"name": "Demo Mode (Simulated Traffic)", "id": "demo"}]
    try:
        raw_list = conf.ifaces
        for key, iface in raw_list.items():
            name = getattr(iface, "name", str(key))
            desc = getattr(iface, "description", name)
            interfaces.append({"name": f"{desc} ({name})", "id": name})
    except Exception:
        # Fallback if Scapy ifaces list fails on Windows
        try:
            from scapy.all import get_if_list
            for iface in get_if_list():
                interfaces.append({"name": str(iface), "id": str(iface)})
        except Exception:
            pass

    return jsonify({"interfaces": interfaces})


@app.route("/api/status")
def get_status():
    """Return current status of the packet analyzer"""
    return jsonify({
        "running": capture_state["running"],
        "mode": capture_state["mode"],
        "interface": capture_state["interface"],
        "error": capture_state["error"],
        "packet_count": len(captured_packets)
    })


@app.route("/api/start", methods=["POST"])
def start_capture():
    """Start packet capture in either Demo Mode or Live Mode"""
    global capture_thread, stop_event

    data = request.get_json() or {}
    mode = data.get("mode", "demo")
    interface = data.get("interface", "demo")

    if capture_state["running"]:
        return jsonify({"success": False, "message": "Capture is already running"}), 400

    stop_event.clear()
    capture_state["running"] = True
    capture_state["mode"] = mode
    capture_state["interface"] = interface
    capture_state["error"] = None

    if stats["start_time"] is None:
        stats["start_time"] = time.time()

    if mode == "demo":
        capture_thread = threading.Thread(target=demo_capture_worker, daemon=True)
        capture_thread.start()
    else:
        # Live mode
        iface_arg = None if interface in ["demo", "Default"] else interface
        capture_thread = threading.Thread(target=live_capture_worker, args=(iface_arg,), daemon=True)
        capture_thread.start()

    return jsonify({"success": True, "mode": mode, "interface": interface})


@app.route("/api/stop", methods=["POST"])
def stop_capture():
    """Stop packet capture"""
    if not capture_state["running"]:
        return jsonify({"success": False, "message": "Capture is not running"}), 400

    stop_event.set()
    capture_state["running"] = False
    return jsonify({"success": True})


@app.route("/api/clear", methods=["POST"])
def clear_packets():
    """Clear captured packets and reset statistics"""
    global captured_packets, stats
    with lock:
        captured_packets = []
        stats = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "dns": 0,
            "icmp": 0,
            "other": 0,
            "total_bytes": 0,
            "start_time": time.time() if capture_state["running"] else None
        }
    return jsonify({"success": True})


@app.route("/api/packets")
def get_packets():
    """Fetch captured packets with optional filtering"""
    protocol_filter = request.args.get("protocol", "ALL").upper()
    src_filter = request.args.get("src_ip", "").strip()
    dst_filter = request.args.get("dst_ip", "").strip()
    since_id = int(request.args.get("since_id", 0))
    limit = int(request.args.get("limit", 200))

    with lock:
        # If since_id is provided, only fetch packets newer than since_id
        if since_id > 0:
            candidates = [p for p in captured_packets if p["id"] > since_id]
        else:
            candidates = list(captured_packets)

    # Apply filters
    filtered = []
    for pkt in candidates:
        if protocol_filter != "ALL":
            if protocol_filter == "HTTP" and pkt["protocol"] != "HTTP":
                continue
            elif protocol_filter != "HTTP" and pkt["protocol"].upper() != protocol_filter:
                continue
        if src_filter and src_filter not in pkt["src_ip"]:
            continue
        if dst_filter and dst_filter not in pkt["dst_ip"]:
            continue
        filtered.append(pkt)

    # Limit to latest packets to keep UI fast
    if len(filtered) > limit:
        filtered = filtered[-limit:]

    return jsonify({
        "packets": filtered,
        "total_captured": len(captured_packets)
    })


@app.route("/api/stats")
def get_stats():
    """Return protocol statistics and transmission counters"""
    with lock:
        res = dict(stats)
    return jsonify(res)


@app.route("/api/export")
def export_csv():
    """Export captured packets as a CSV file"""
    with lock:
        packets_copy = list(captured_packets)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["No.", "Time", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Length (Bytes)", "Info"])

    for pkt in packets_copy:
        writer.writerow([
            pkt["id"],
            pkt["timestamp"],
            pkt["src_ip"],
            pkt["src_port"],
            pkt["dst_ip"],
            pkt["dst_port"],
            pkt["protocol"],
            pkt["length"],
            pkt["info"]
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=network_packet_capture.csv"}
    )


if __name__ == "__main__":
    print("\n" + "=" * 65)
    print(" Network Packet Analyzer Prototype")
    print(" Department of Computer Engineering - Sanjivani COE, Kopargaon")
    print(" Presented by: Omkar Jape (114) & Tambe Pranav (112)")
    print(" Guided by: Prof. P. N. Kalavadekar")
    print("=" * 65)
    print(" * Running on http://127.0.0.1:5000 (Open in your browser)")
    print(" * Press CTRL+C to stop the server\n")
    app.run(debug=True, port=5000)
