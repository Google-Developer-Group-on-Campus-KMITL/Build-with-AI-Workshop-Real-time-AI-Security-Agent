import json
import sys

from scapy.all import IP, TCP, ICMP, Raw, rdpcap

from config import PCAP_FILENAME


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
    print(f"[*] Reading packets from: {PCAP_FILENAME}", file=sys.stderr)

    try:
        packets = rdpcap(PCAP_FILENAME)
    except FileNotFoundError:
        print(
            f"[!] File not found: {PCAP_FILENAME}\n"
            "    Run 'python generate_samples.py' first to create the sample pcap.",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        print(f"[!] Failed to read pcap file: {e}", file=sys.stderr)
        sys.exit(1)

    total = len(packets)
    print(f"[*] Parsed {total} packets from {PCAP_FILENAME}", file=sys.stderr)

    emitted = 0
    for pkt in packets:
        record = extract_record(pkt)
        if record:
            print(json.dumps(record), flush=True)
            emitted += 1

    print(f"[*] Emitted {emitted} records to stdout.", file=sys.stderr)


if __name__ == "__main__":
    main()
