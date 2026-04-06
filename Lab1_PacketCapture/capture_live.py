import json
import sys

from scapy.all import IP, TCP, ICMP, Raw, sniff

from config import SNIFF_INTERFACE


def process_packet(pkt):
    if not pkt.haslayer(IP):
        return

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
        return

    print(json.dumps(record), flush=True)


def main():
    print(f"[*] Starting live capture on interface: {SNIFF_INTERFACE}", file=sys.stderr)
    print("[*] Filtering for ICMP and TCP — press Ctrl+C to stop.", file=sys.stderr)
    try:
        sniff(
            iface=SNIFF_INTERFACE,
            filter="icmp or tcp",
            prn=process_packet,
            store=False,
        )
    except PermissionError:
        print(
            "[!] Permission denied. Live capture requires root privileges.\n"
            "    Run: sudo python capture_live.py",
            file=sys.stderr,
        )
        sys.exit(1)
    except OSError as e:
        print(
            f"[!] Interface error on '{SNIFF_INTERFACE}': {e}\n"
            "    Check available interfaces with: ip link show",
            file=sys.stderr,
        )
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Capture stopped by user.", file=sys.stderr)


if __name__ == "__main__":
    main()
