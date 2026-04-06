import json
import sys

from scapy.all import IP, TCP, ICMP, Raw, wrpcap

from config import LOOPBACK_IP, PCAP_FILENAME, JSON_FILENAME, HTTP_PORT


SQLI_PAYLOADS = [
    b"GET /search?q=' OR 1=1 -- HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b"GET /login?user=admin' UNION SELECT * FROM users -- HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b"GET /page?id=1; DROP TABLE sessions; -- HTTP/1.1\r\nHost: localhost\r\n\r\n",
]


def build_packets():
    packets = []

    # 5 benign TCP SYN packets to port 80
    for _ in range(5):
        pkt = IP(src="10.0.0.5", dst=LOOPBACK_IP) / TCP(dport=80, sport=50000, flags="S")
        packets.append(pkt)

    # 22 ICMP echo requests — Ping Flood pattern from one attacker IP
    for _ in range(22):
        pkt = IP(src="192.168.1.100", dst=LOOPBACK_IP) / ICMP()
        packets.append(pkt)

    # 4 TCP SYN packets to different ports — Port Scan pattern
    for port in [22, 80, 443, 3306]:
        pkt = IP(src="10.10.10.50", dst=LOOPBACK_IP) / TCP(dport=port, sport=55000, flags="S")
        packets.append(pkt)

    # 3 TCP packets with SQL injection payloads in the HTTP layer
    for payload in SQLI_PAYLOADS:
        pkt = (
            IP(src="172.16.0.9", dst=LOOPBACK_IP)
            / TCP(dport=HTTP_PORT, sport=60000, flags="PA")
            / Raw(load=payload)
        )
        packets.append(pkt)

    return packets


def extract_record(pkt):
    if not pkt.haslayer(IP):
        return None

    record = {
        "src_ip": pkt[IP].src,
        "dst_ip": pkt[IP].dst,
        "protocol": None,
        "dst_port": None,
        "payload": None,
    }

    if pkt.haslayer(ICMP):
        record["protocol"] = "ICMP"
    elif pkt.haslayer(TCP):
        record["protocol"] = "TCP"
        record["dst_port"] = pkt[TCP].dport
        if pkt.haslayer(Raw):
            try:
                record["payload"] = bytes(pkt[Raw].load).decode("utf-8", errors="replace")
            except Exception:
                record["payload"] = None
    else:
        return None

    return record


def main():
    packets = build_packets()

    try:
        wrpcap(PCAP_FILENAME, packets)
        print(f"[INFO] Wrote {len(packets)} packets to {PCAP_FILENAME}")
    except Exception as e:
        print(f"[ERROR] Failed to write pcap file: {e}", file=sys.stderr)
        sys.exit(1)

    records = []
    for pkt in packets:
        rec = extract_record(pkt)
        if rec:
            records.append(rec)

    try:
        with open(JSON_FILENAME, "w") as f:
            json.dump(records, f, indent=2)
        print(f"[INFO] Wrote {len(records)} records to {JSON_FILENAME}")
    except Exception as e:
        print(f"[ERROR] Failed to write JSON file: {e}", file=sys.stderr)
        sys.exit(1)

    print("[INFO] Generated sample files successfully.")


if __name__ == "__main__":
    main()
