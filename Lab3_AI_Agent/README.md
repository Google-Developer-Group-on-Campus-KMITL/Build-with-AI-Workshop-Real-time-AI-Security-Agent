# Lab 3: Autonomous AI Security Agent

## Objective

Build a real-time security agent that detects attacks using a rule engine and autonomously blocks malicious IPs using Gemini 1.5 Flash Function Calling. This is the capstone lab — it combines the live capture pipeline from Lab 1 with an AI orchestrator that can take direct action.

---

## Prerequisites

- Linux (Ubuntu 20.04+)
- Python 3.10+
- A **Google Gemini API key** — get one free at [https://aistudio.google.com](https://aistudio.google.com)
- `sudo` / root access (live mode only)

---

## Setup

```bash
cd Lab3_AI_Agent
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
| `agent_service.py` | RuleEngine + Gemini agent that reads stdin and responds to threats |

---

## Architecture

```
traffic_simulator.py
        |
        v  (raw network packets on loopback)
capture_live.py  ──or──  capture_pcap.py
        |
        v  (newline-delimited JSON on stdout)
agent_service.py
   ├── RuleEngine          sliding-window threat detection
   │     ├── Ping Flood    > 10 ICMP packets from same IP in 15s
   │     ├── Port Scan     >= 4 distinct TCP ports from same IP in 15s
   │     └── SQLi / XSS    keyword match in packet payload
   │
   └── Gemini 1.5 Flash    Function Calling orchestrator
         └── block_ip()    called by model for High-severity threats
```

---

## Mode 1: Offline (No Root Required)

Run a quick end-to-end test using the sample PCAP file.

```bash
# Step 1 — generate sample data
python generate_samples.py

# Step 2 — replay pcap and pipe into the agent
python capture_pcap.py | python agent_service.py
```

The agent will detect the Ping Flood, Port Scan, and SQLi patterns embedded in the sample data, call `block_ip` for each High-severity source, and print structured JSON to stdout.

---

## Mode 2: Live Mode (Root Required)

Generate real attack traffic and respond to it in real-time.

```bash
# Terminal 1 — launch the attack simulator
sudo python traffic_simulator.py

# Terminal 2 — capture and pipe into the agent
sudo python capture_live.py | python agent_service.py
```

After roughly 15 seconds of traffic the rule engine will cross the detection thresholds and the agent will fire.

---

## Sample Output

Each time the agent fires, it prints one JSON object to stdout:

```json
{
  "analysis_summary": "High-volume ICMP flood detected from 192.168.1.100 (22 packets in 15s window). TCP port scan from 10.10.10.50 targeting ports 22, 80, 443, 3306. SQL injection attempt from 172.16.0.9 via HTTP payload.",
  "threat_level": "Critical",
  "detected_attack_type": "Ping Flood, Port Scan, SQL Injection",
  "action_taken": "Blocked 192.168.1.100, 10.10.10.50, 172.16.0.9 via firewall rules."
}
```

Status and action messages are printed to stderr (visible in the terminal but not part of the stdout JSON stream):

```
[!] Threats detected: ['Ping Flood']
[ACTION] Firewall: blocking 192.168.1.100
```

---

## How Gemini Function Calling Works

1. The `block_ip` Python function is registered as a Gemini tool.
2. When the agent sends threat data to Gemini, the model decides whether to call `block_ip`.
3. If it calls the tool, the SDK sends back a `function_call` part instead of text.
4. `agent_service.py` executes `block_ip(ip_address)` locally and returns the result to Gemini.
5. Gemini receives the result and generates its final JSON response.

This loop repeats until Gemini produces a final text response (no more function calls).

---

## Detection Thresholds (configurable in `agent_service.py`)

| Threat | Threshold |
|---|---|
| Ping Flood | > 10 ICMP packets from same IP within 15 seconds |
| Port Scan | >= 4 distinct TCP destination ports from same IP within 15 seconds |
| SQL Injection | Any payload containing: `' OR`, `SELECT`, `UNION`, `DROP`, `INSERT`, `DELETE`, `--` |
| XSS | Any payload containing: `<script>`, `onerror=`, `javascript:` |

---

## Troubleshooting

| Error | Fix |
|---|---|
| `GEMINI_API_KEY not set` | `export GEMINI_API_KEY="your-key"` |
| `Operation not permitted` | Run live capture with `sudo` |
| Agent fires repeatedly for same IP | Already handled — `blocked_ips` set suppresses repeat alerts |
| Gemini quota error | Free tier: 15 req/min. Wait 60s and retry, or reduce traffic |
| JSON parse error from agent | Model wrapped response in markdown — the code strips fences automatically |
| `No such file: sample_traffic.pcap` | Run `python generate_samples.py` first |
