import random
import socket
import sys
import time

import requests
from scapy.all import ICMP, IP, send

TARGET_IP = "127.0.0.1"
SCAN_PORTS = [22, 80, 443, 3306]
HTTP_URL = f"http://{TARGET_IP}/?q=' OR 1=1 --"


def ping_flood():
    print("[INFO] Generating Ping Flood...", file=sys.stderr)
    for _ in range(20):
        pkt = IP(dst=TARGET_IP) / ICMP()
        send(pkt, verbose=False)
    print("[INFO] Ping Flood complete — sent 20 ICMP packets.", file=sys.stderr)


def port_scan():
    print("[INFO] Generating Port Scan...", file=sys.stderr)
    for port in SCAN_PORTS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((TARGET_IP, port))
            sock.close()
            print(f"[INFO] Port {port}/tcp — open", file=sys.stderr)
        except (ConnectionRefusedError, OSError):
            print(f"[INFO] Port {port}/tcp — closed/filtered", file=sys.stderr)
    print("[INFO] Port Scan complete.", file=sys.stderr)


def http_sqli():
    print("[INFO] Generating HTTP GET SQLi...", file=sys.stderr)
    try:
        requests.get(HTTP_URL, timeout=2)
        print("[INFO] HTTP SQLi request sent.", file=sys.stderr)
    except requests.exceptions.ConnectionError:
        print(
            "[INFO] HTTP SQLi sent (connection refused — no server running, expected).",
            file=sys.stderr,
        )
    except requests.exceptions.Timeout:
        print("[INFO] HTTP SQLi request timed out.", file=sys.stderr)


ATTACKS = [ping_flood, port_scan, http_sqli]


def main():
    print("[INFO] Traffic simulator started. Press Ctrl+C to stop.", file=sys.stderr)
    while True:
        try:
            attack = random.choice(ATTACKS)
            attack()
            time.sleep(random.uniform(0.5, 2.0))
        except KeyboardInterrupt:
            print("\n[INFO] Simulator stopped by user.", file=sys.stderr)
            break
        except Exception as exc:
            print(f"[ERROR] Unexpected error: {exc}", file=sys.stderr)
            time.sleep(1)


if __name__ == "__main__":
    main()
