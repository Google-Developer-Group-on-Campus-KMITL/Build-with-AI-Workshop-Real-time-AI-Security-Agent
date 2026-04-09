import json
import os
import sys

import vertexai
from vertexai.generative_models import GenerativeModel

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "your-project-id")
LOCATION = "asia-southeast1"
MODEL_NAME = "gemini-2.5-flash"
SAMPLE_FILE = "sample_packets.json" # Callback when no any arg in stdin

# Zero-shot prompting
ZERO_SYSTEM_INSTRUCTION = (
    "You are a senior SOC (Security Operations Center) analyst. "
    "You review raw network packet data and produce structured, professional threat assessments in Markdown. "
    "Begin with a brief executive summary. "
    "For each threat identified, include the following sections: "
    "**Attack Type**, **Source IP**, **Evidence**, **Severity** (Low/Medium/High), "
    "and **Recommended Action**."
)

# Few-shot prompting (Recommend)
FEW_SYSTEM_INSTRUCTION = (
    "You are an elite Senior SOC (Security Operations Center) Analyst. "
    "Your goal is to analyze raw network JSON logs and provide a high-precision threat assessment.\n\n"

    "### RULES:\n"
    "1. Only analyze the provided data. Do not hallucinate external context.\n"
    "2. If no malicious activity is found, state clearly: 'NO THREATS DETECTED'.\n"
    "3. Use a professional, objective tone. No greetings like 'Hello' or 'Here is the report'.\n"
    "4. Focus on identifying SQL Injection, Port Scanning, and ICMP/Ping Floods.\n"
    "5. Always provide specific evidence by quoting values from the JSON input.\n\n"

    "### OUTPUT FORMAT (Markdown):\n"
    "Respond strictly in Markdown. Use the following structure:\n"
    "1. **Executive Summary**: A 1-sentence summary of the overall situation.\n"
    "2. For each threat, provide:\n"
    "   - **Attack Type**: [Name of attack]\n"
    "   - **Source IP**: [Attacker's IP]\n"
    "   - **Evidence**: [Specific field/value from JSON, e.g., payload contains '' OR 1=1']\n"
    "   - **Severity**: [Low/Medium/High/Critical]\n"
    "   - **Recommended Action**: [Specific technical mitigation step]\n\n"

    "### EXAMPLES (Few-Shot Prompting):\n\n"

    "Example 1: SQL Injection\n"
    "Input: [{\"src_ip\": \"192.168.1.50\", \"dst_port\": 80, \"payload\": \"' OR 1=1 --\"}]\n"
    "Output:\n"
    "**Executive Summary**: Potential SQL Injection attack detected targeting the web server.\n"
    "- **Attack Type**: SQL Injection\n"
    "- **Source IP**: 192.168.1.50\n"
    "- **Evidence**: Malicious pattern `' OR 1=1 --` found in payload field.\n"
    "- **Severity**: Critical\n"
    "- **Recommended Action**: Block source IP 192.168.1.50 at the firewall and inspect application logs.\n\n"

    "Example 2: Normal Traffic\n"
    "Input: [{\"src_ip\": \"10.0.0.1\", \"dst_port\": 443, \"payload\": \"GET /index.html\"}]\n"
    "Output:\n"
    "NO THREATS DETECTED.\n\n"

    "Example 3: Port Scanning\n"
    "Input: [{\"src_ip\": \"172.16.0.5\", \"dst_port\": 21}, {\"src_ip\": \"172.16.0.5\", \"dst_port\": 22}, {\"src_ip\": \"172.16.0.5\", \"dst_port\": 23}]\n"
    "Output:\n"
    "**Executive Summary**: Vertical Port Scanning activity detected from a single source.\n"
    "- **Attack Type**: Port Scan\n"
    "- **Source IP**: 172.16.0.5\n"
    "- **Evidence**: Rapid sequential attempts to access multiple ports (21, 22, 23).\n"
    "- **Severity**: Medium\n"
    "- **Recommended Action**: Enable temporary rate limiting or block IP 172.16.0.5."
)

def load_packets():
    """Return list of packet dicts from stdin (NDJSON) or sample_packets.json."""
    if not sys.stdin.isatty():
        print("[*] Reading NDJSON from stdin...", file=sys.stderr)
        records = []
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"[WARN] Skipping invalid JSON line: {exc}", file=sys.stderr)
        return records

    print(f"[*] Reading packets from {SAMPLE_FILE}...", file=sys.stderr)
    try:
        with open(SAMPLE_FILE) as fh:
            return json.load(fh)
    except FileNotFoundError:
        print(f"[!] {SAMPLE_FILE} not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"[!] JSON parse error in {SAMPLE_FILE}: {exc}", file=sys.stderr)
        sys.exit(1)


def main():
    if PROJECT_ID == "your-project-id":
        print("[!] ERROR: Please set GOOGLE_CLOUD_PROJECT environment variable.", file=sys.stderr)
        print("    Run: export GOOGLE_CLOUD_PROJECT='your-actual-project-id'", file=sys.stderr)
        sys.exit(1)

    vertexai.init(project=PROJECT_ID, location=LOCATION)

    packets = load_packets()
    if not packets:
        print("[!] No packet records found. Exiting.", file=sys.stderr)
        sys.exit(1)

    SELECTED_INSTRUCTION = FEW_SYSTEM_INSTRUCTION 
    MODE_NAME = "FEW-SHOT" if SELECTED_INSTRUCTION == FEW_SYSTEM_INSTRUCTION else "ZERO-SHOT"

    print(f"[*] Mode: {MODE_NAME}")
    print(f"[*] Sending {len(packets)} records to Gemini on Vertex AI ({MODEL_NAME})...", file=sys.stderr)

    model = GenerativeModel(
        model_name=MODEL_NAME,
        system_instruction=[SELECTED_INSTRUCTION],
    )

    try:
        response = model.generate_content(json.dumps(packets, indent=2))
        print("\n--- ANALYSIS REPORT ---\n")
        print(response.text)
        print("\n-----------------------\n")
    except Exception as exc:
        print(f"[!] Vertex AI API error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
