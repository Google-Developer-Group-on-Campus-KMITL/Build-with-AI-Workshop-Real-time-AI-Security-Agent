import random
import socket
import time

import requests
from scapy.all import IP, ICMP, send

from config import LOOPBACK_IP, HTTP_PORT

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' UNION SELECT username, password FROM accounts --",
]


def ping_flood():
    print(f"[INFO] Launching Ping Flood against {LOOPBACK_IP}...")
    for i in range(20):
        pkt = IP(dst=LOOPBACK_IP) / ICMP()
        send(pkt, verbose=False)
    print("[INFO] Ping Flood complete — sent 20 ICMP packets.")


def port_scan():
    print(f"[INFO] Launching Port Scan against {LOOPBACK_IP}...")
    targets = [22, 80, 443, 3306]
    for port in targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((LOOPBACK_IP, port))
            sock.close()
            print(f"[INFO] Port {port}/tcp — open")
        except (ConnectionRefusedError, OSError):
            print(f"[INFO] Port {port}/tcp — closed/filtered")
    print("[INFO] Port Scan complete.")


def http_attack():
    payload = random.choice(SQLI_PAYLOADS)
    url = f"http://{LOOPBACK_IP}:{HTTP_PORT}/search"
    print(f"[INFO] Launching HTTP SQLi attack: {payload}")
    try:
        requests.get(url, params={"q": payload}, timeout=2)
        print("[INFO] HTTP attack request sent.")
    except requests.exceptions.ConnectionError:
        print("[INFO] HTTP attack sent (connection refused — no server running, expected).")
    except requests.exceptions.Timeout:
        print("[INFO] HTTP attack timed out.")


ATTACK_POOL = [ping_flood, port_scan, http_attack]


def main():
    print("[INFO] Traffic simulator started. Press Ctrl+C to stop.")
    while True:
        try:
            attack = random.choice(ATTACK_POOL)
            attack()
            delay = random.uniform(0.5, 2.0)
            time.sleep(delay)
        except KeyboardInterrupt:
            print("\n[INFO] Simulator stopped by user.")
            break
        except Exception as e:
            print(f"[ERROR] Unexpected error during attack simulation: {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()
