"""
Lab 3: VM Publisher — Packet event generator + Pub/Sub publisher.

Default mode: generates mock attack/normal packets (no root required).
--sniff mode : live packet capture via scapy (requires root and scapy).
"""

import argparse
import json
import logging
import os
import random
import sys
import time
from datetime import datetime, timezone

from google.cloud import pubsub_v1

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "your-project-id")
TOPIC_ID = "packet-logs-topic"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("vm-publisher")


# ---------------------------------------------------------------------------
# Severity Classification
# ---------------------------------------------------------------------------
SQLI_PATTERNS = ["' or", "1=1", "union select", "drop table", "' --"]

def classify_severity(protocol: str, dst_port: int | None, payload: str | None) -> str:
    """Classify a packet's threat severity based on its fields."""
    if payload:
        lower = payload.lower()
        if any(pattern in lower for pattern in SQLI_PATTERNS):
            return "critical"
    if dst_port in (22, 3306, 3389, 5432):
        return "high"
    if protocol == "ICMP":
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Mock Packet Generator
# ---------------------------------------------------------------------------
ATTACK_TEMPLATES = [
    # SQL Injection
    {
        "src_ip": "172.16.0.9",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP",
        "dst_port": 80,
        "payload": "GET /?q=' OR 1=1 -- HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n",
    },
    # Port Scan — SSH
    {
        "src_ip": "10.10.10.50",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP",
        "dst_port": 22,
        "payload": None,
    },
    # Port Scan — MySQL
    {
        "src_ip": "10.10.10.50",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP",
        "dst_port": 3306,
        "payload": None,
    },
    # Port Scan — HTTP
    {
        "src_ip": "10.10.10.50",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP",
        "dst_port": 80,
        "payload": None,
    },
    # ICMP Flood
    {
        "src_ip": "192.168.1.100",
        "dst_ip": "10.0.0.1",
        "protocol": "ICMP",
        "dst_port": None,
        "payload": None,
    },
    # Normal HTTPS traffic
    {
        "src_ip": f"10.0.0.{random.randint(2, 254)}",
        "dst_ip": "10.0.0.1",
        "protocol": "TCP",
        "dst_port": 443,
        "payload": "GET /index.html HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n",
    },
]


def generate_mock_packets():
    """Infinite generator of mock packet events."""
    while True:
        template = random.choice(ATTACK_TEMPLATES)
        packet = dict(template)  # shallow copy
        packet["timestamp"] = datetime.now(timezone.utc).isoformat()
        packet["severity_hint"] = classify_severity(
            packet["protocol"], packet.get("dst_port"), packet.get("payload")
        )
        yield packet


# ---------------------------------------------------------------------------
# Live Sniff Mode (requires root + scapy)
# ---------------------------------------------------------------------------
def sniff_and_publish(publisher, topic_path):
    """Capture live packets with scapy and publish to Pub/Sub."""
    try:
        from scapy.all import IP, TCP, ICMP, Raw, sniff
    except ImportError:
        logger.error("scapy is not installed. Run: pip install scapy")
        sys.exit(1)

    def process_packet(pkt):
        if not pkt.haslayer(IP):
            return
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": (
                "ICMP" if pkt.haslayer(ICMP)
                else "TCP" if pkt.haslayer(TCP)
                else "OTHER"
            ),
            "dst_port": pkt[TCP].dport if pkt.haslayer(TCP) else None,
            "payload": (
                bytes(pkt[Raw].load).decode("utf-8", errors="replace")
                if pkt.haslayer(Raw) else None
            ),
        }
        record["severity_hint"] = classify_severity(
            record["protocol"], record.get("dst_port"), record.get("payload")
        )
        data = json.dumps(record).encode("utf-8")
        future = publisher.publish(topic_path, data)
        logger.info(
            f"Published (sniff): {record['protocol']} "
            f"{record['src_ip']} -> {record['dst_ip']} "
            f"[msgID={future.result()}]"
        )

    logger.info("Starting live capture (requires root)... Press Ctrl+C to stop.")
    sniff(prn=process_packet, store=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Publish packet events to Pub/Sub")
    parser.add_argument(
        "--sniff", action="store_true",
        help="Use live scapy packet capture instead of mock generator (requires root)",
    )
    parser.add_argument(
        "--interval", type=float, default=2.0,
        help="Seconds between mock packets (default: 2.0)",
    )
    args = parser.parse_args()

    if PROJECT_ID == "your-project-id":
        logger.error("GOOGLE_CLOUD_PROJECT is not set.")
        logger.error("Run: export GOOGLE_CLOUD_PROJECT='your-project-id'")
        sys.exit(1)

    publisher = pubsub_v1.PublisherClient()
    topic_path = publisher.topic_path(PROJECT_ID, TOPIC_ID)
    logger.info(f"Publishing to: {topic_path}")

    if args.sniff:
        sniff_and_publish(publisher, topic_path)
    else:
        logger.info(f"Using mock generator (interval={args.interval}s). Press Ctrl+C to stop.")
        try:
            for packet in generate_mock_packets():
                data = json.dumps(packet).encode("utf-8")
                future = publisher.publish(topic_path, data)
                logger.info(
                    f"Published: {packet['protocol']} "
                    f"{packet['src_ip']} -> {packet['dst_ip']} "
                    f"[severity={packet['severity_hint']}, msgID={future.result()}]"
                )
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("Publisher stopped by user.")


if __name__ == "__main__":
    main()
