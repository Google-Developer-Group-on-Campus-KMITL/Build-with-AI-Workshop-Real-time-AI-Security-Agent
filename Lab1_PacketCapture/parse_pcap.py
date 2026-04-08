import json
import sys

from scapy.all import ICMP, IP, TCP, Raw, rdpcap

PCAP_FILE = "packets.pcap"


def extract_record(pkt):
    """Return a dict for recognised IP packets, or None to skip."""
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
                pass
    else:
        return None  # skip UDP, ARP, etc.

    return record


def main():
    print(f"[*] Reading: {PCAP_FILE}", file=sys.stderr)
    try:
        packets = rdpcap(PCAP_FILE)
    except FileNotFoundError:
        print(
            f"[!] File not found: {PCAP_FILE}\n"
            "    Capture traffic first with tcpdump or Wireshark, saving as packets.pcap",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Failed to read pcap: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loaded {len(packets)} packets.", file=sys.stderr)
    emitted = 0
    for pkt in packets:
        record = extract_record(pkt)
        if record is not None:
            print(json.dumps(record))
            emitted += 1

    print(f"[*] Emitted {emitted} NDJSON records.", file=sys.stderr)


if __name__ == "__main__":
    main()
