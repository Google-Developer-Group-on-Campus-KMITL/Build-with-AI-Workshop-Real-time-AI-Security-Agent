# Lab 2: AI-Powered Log Analysis with Gemini

## Objective

Feed network packet logs to Google Gemini 1.5 Flash and receive a professional SOC analyst threat assessment. This lab builds on Lab 1's capture pipeline by adding an AI layer that can reason about attack patterns in structured data.

---

## Prerequisites

- Linux (Ubuntu 20.04+) — macOS works for offline mode
- Python 3.10+
- A **Google Gemini API key** — get one free at [https://aistudio.google.com](https://aistudio.google.com)
- `sudo` / root access (live mode only)

---

## Setup

```bash
cd Lab2_AI_Analysis
pip install -r requirements.txt
export GEMINI_API_KEY="your-key-here"
```

---

## Files

| File | Description |
|---|---|
| `config.py` | Shared constants |
| `generate_samples.py` | Generate `sample_traffic.pcap` and `sample_logs.json` |
| `traffic_simulator.py` | Live attack traffic generator |
| `capture_live.py` | Live packet capture → JSON stream (stdout) |
| `capture_pcap.py` | PCAP replay → JSON stream (stdout) |
| `analyze_service.py` | Read logs, call Gemini, print threat report |

---

## Mode 1: Offline File Analysis (No Root Required)

The simplest way to run the lab. Gemini analyzes the pre-generated JSON log file.

```bash
# Step 1 — generate sample data
python generate_samples.py

# Step 2 — run the AI analysis
python analyze_service.py
```

---

## Mode 2: Offline Pipe Mode (No Root Required)

Pipe the PCAP replay directly into the analyzer — no intermediate file needed.

```bash
# Step 1 — generate sample pcap
python generate_samples.py

# Step 2 — replay pcap and pipe into analyzer
python capture_pcap.py | python analyze_service.py
```

---

## Mode 3: Live Analysis (Root Required)

Capture real traffic from the loopback interface and analyze it in real-time. Because `analyze_service.py` waits for stdin to close before sending to Gemini, you need to stop the capture manually after generating enough traffic.

```bash
# Terminal 1 — generate live traffic
sudo python traffic_simulator.py

# Terminal 2 — capture and pipe to analyzer (Ctrl+C capture to trigger analysis)
sudo python capture_live.py | python analyze_service.py
```

> **Tip:** Press `Ctrl+C` in Terminal 2 after ~10 seconds to stop the capture. The analyzer will then send all collected records to Gemini.

---

## Sample Output

```
============================================================
  SOC THREAT ANALYSIS REPORT — Powered by Gemini 1.5 Flash
============================================================

## Executive Summary

Three distinct threats were identified in the packet capture data...

### Finding 1: Ping Flood (HIGH)
- Source IP: 192.168.1.100
- Evidence: 22 ICMP echo-request packets in rapid succession
- Recommended Action: Rate-limit ICMP from this source at the firewall

### Finding 2: Port Scan (HIGH)
- Source IP: 10.10.10.50
...
```

---

## Troubleshooting

| Error | Fix |
|---|---|
| `GEMINI_API_KEY not set` | `export GEMINI_API_KEY="your-key"` |
| `No log records found` | Run `python generate_samples.py` first |
| Gemini quota error | Wait 60 seconds and retry (free tier rate limit) |
| `Operation not permitted` | Run live capture with `sudo` |
