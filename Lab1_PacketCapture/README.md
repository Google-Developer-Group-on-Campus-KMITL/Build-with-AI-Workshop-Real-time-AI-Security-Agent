# Lab 1: Packet Capture with Scapy

## Objective

Learn to generate synthetic network traffic and capture it using Python and Scapy. By the end of this lab you will understand how to craft packets, write them to a PCAP file, and stream structured JSON records from a live network interface — the foundation for Labs 2 and 3.

---

## Prerequisites

- Linux (Ubuntu 20.04+ or Debian 11+) — **macOS works for offline mode only**
- Python 3.10 or newer
- `sudo` / root access (required for live capture and packet sending)
- Scapy installed via pip

---

## Setup

```bash
cd Lab1_PacketCapture
pip install -r requirements.txt
```

---

## Files

| File | Description |
|---|---|
| `config.py` | Shared constants (IP addresses, interface name, filenames) |
| `generate_samples.py` | Craft sample packets, save to `sample_traffic.pcap` and `sample_logs.json` |
| `traffic_simulator.py` | Infinite-loop script that generates live attack traffic |
| `capture_live.py` | Sniff live traffic on the loopback interface, stream JSON to stdout |
| `capture_pcap.py` | Read an existing `.pcap` file and stream JSON to stdout |

---

## Mode 1: Offline (No Root Required)

Generate sample files and replay them. Good for development and quick testing.

```bash
# Step 1 — generate the sample pcap and JSON log file
python generate_samples.py

# Step 2 — parse the pcap and stream JSON records to stdout
python capture_pcap.py
```

Expected output on stdout (one JSON object per line):

```json
{"src_ip": "10.0.0.5", "dst_ip": "127.0.0.1", "protocol": "TCP", "dst_port": 80, "payload": null}
{"src_ip": "192.168.1.100", "dst_ip": "127.0.0.1", "protocol": "ICMP", "dst_port": null, "payload": null}
...
```

---

## Mode 2: Live Capture (Root Required)

Generate real traffic using the simulator and capture it from the loopback interface.

```bash
# Terminal 1 — generate live traffic (requires root for raw socket / ICMP)
sudo python traffic_simulator.py

# Terminal 2 — capture live traffic from loopback interface
sudo python capture_live.py
```

The capture script streams one JSON record to stdout for every ICMP or TCP packet it sees.

---

## What to Observe

- **Ping Flood**: A burst of ICMP records from the same `src_ip` (e.g. `192.168.1.100`)
- **Port Scan**: TCP records from the same `src_ip` hitting ports `22`, `80`, `443`, `3306`
- **SQL Injection**: TCP records with a `payload` field containing strings like `OR 1=1`

---

## Troubleshooting

| Error | Fix |
|---|---|
| `Operation not permitted` | Run with `sudo` |
| `Interface 'lo' not found` | Verify the interface with `ip link show`; update `SNIFF_INTERFACE` in `config.py` |
| `No such file: sample_traffic.pcap` | Run `python generate_samples.py` first |
| Scapy import error | Run `pip install -r requirements.txt` |
