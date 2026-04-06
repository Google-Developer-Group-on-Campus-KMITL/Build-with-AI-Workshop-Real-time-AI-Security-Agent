import json
import os
import sys

import google.generativeai as genai

from config import JSON_FILENAME


def read_logs():
    """Read packet records from stdin (pipe mode) or from the JSON file (file mode)."""
    if not sys.stdin.isatty():
        records = []
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[WARN] Skipping invalid JSON line: {e}", file=sys.stderr)
        return records

    try:
        with open(JSON_FILENAME) as f:
            return json.load(f)
    except FileNotFoundError:
        print(
            f"[!] Log file not found: {JSON_FILENAME}\n"
            "    Run 'python generate_samples.py' first, or pipe data from capture_pcap.py.",
            file=sys.stderr,
        )
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[!] Failed to parse {JSON_FILENAME}: {e}", file=sys.stderr)
        sys.exit(1)


def build_prompt(logs: list) -> str:
    log_text = json.dumps(logs, indent=2)
    return f"""You are a senior SOC (Security Operations Center) analyst reviewing network packet logs from an intrusion detection system.

Analyze the following JSON packet capture data and produce a structured threat assessment report.

For each threat you identify, include:
- Attack Type: (Ping Flood / Port Scan / SQL Injection / Benign)
- Source IP: the attacker's IP address
- Evidence: specific packet count, targeted ports, or payload content that confirms the threat
- Severity: Low / Medium / High
- Recommended Action: what the SOC team should do next

Packet capture data:
{log_text}

Write a clear, professional threat report. Start with an executive summary, then detail each finding."""


def main():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print(
            "[!] GEMINI_API_KEY environment variable is not set.\n"
            "    Export it before running: export GEMINI_API_KEY='your-key-here'",
            file=sys.stderr,
        )
        sys.exit(1)

    genai.configure(api_key=api_key)

    print("[*] Reading log data...", file=sys.stderr)
    logs = read_logs()

    if not logs:
        print("[!] No log records found. Nothing to analyze.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Loaded {len(logs)} packet records. Sending to Gemini...\n", file=sys.stderr)

    model = genai.GenerativeModel("gemini-1.5-flash")
    prompt = build_prompt(logs)

    try:
        response = model.generate_content(prompt)
        print("=" * 60)
        print("  SOC THREAT ANALYSIS REPORT — Powered by Gemini 1.5 Flash")
        print("=" * 60)
        print(response.text)
    except Exception as e:
        print(f"[!] Gemini API error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
