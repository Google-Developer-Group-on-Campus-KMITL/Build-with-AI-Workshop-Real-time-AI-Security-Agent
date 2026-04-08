import json
import os
import sys

import google.generativeai as genai

SAMPLE_FILE = "sample_packets.json"
MODEL_NAME = "gemini-1.5-flash"

SYSTEM_INSTRUCTION = (
    "You are a senior SOC (Security Operations Center) analyst. "
    "You review raw network packet data and produce structured, professional threat assessments in Markdown. "
    "Begin with a brief executive summary. "
    "For each threat identified, include the following sections: "
    "**Attack Type**, **Source IP**, **Evidence**, **Severity** (Low/Medium/High), "
    "and **Recommended Action**."
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
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print(
            "[!] GEMINI_API_KEY is not set.\n"
            "    Run: export GEMINI_API_KEY='your-key-here'",
            file=sys.stderr,
        )
        sys.exit(1)

    genai.configure(api_key=api_key)

    packets = load_packets()
    if not packets:
        print("[!] No packet records found. Exiting.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Sending {len(packets)} records to Gemini ({MODEL_NAME})...", file=sys.stderr)

    model = genai.GenerativeModel(
        model_name=MODEL_NAME,
        system_instruction=SYSTEM_INSTRUCTION,
    )

    try:
        response = model.generate_content(json.dumps(packets, indent=2))
        print(response.text)
    except Exception as exc:
        print(f"[!] Gemini API error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
