import json
import os
import sys
import time
from collections import deque, defaultdict

import google.generativeai as genai


# ---------------------------------------------------------------------------
# Rule Engine — sliding-window threat detection
# ---------------------------------------------------------------------------

class RuleEngine:
    WINDOW_SECONDS = 15
    PING_FLOOD_THRESHOLD = 10
    PORT_SCAN_THRESHOLD = 4
    SQLI_KEYWORDS = ["' OR", "SELECT", "UNION", "DROP", "INSERT", "DELETE", "--"]
    XSS_KEYWORDS = ["<script>", "onerror=", "javascript:"]

    def __init__(self):
        # (timestamp, packet_dict) per src_ip
        self.icmp_windows: defaultdict = defaultdict(deque)
        # (timestamp, dst_port) per src_ip
        self.port_windows: defaultdict = defaultdict(deque)
        # IPs that have already been actioned — suppress duplicate alerts
        self.blocked_ips: set = set()

    def _evict_old(self, dq: deque, now: float):
        while dq and now - dq[0][0] > self.WINDOW_SECONDS:
            dq.popleft()

    def analyze(self, pkt: dict) -> list:
        src = pkt.get("src_ip", "unknown")

        if src in self.blocked_ips:
            return []

        threats = []
        now = time.time()
        protocol = pkt.get("protocol")
        payload = pkt.get("payload") or ""

        if protocol == "ICMP":
            dq = self.icmp_windows[src]
            dq.append((now, pkt))
            self._evict_old(dq, now)

            if len(dq) > self.PING_FLOOD_THRESHOLD:
                threats.append({
                    "type": "Ping Flood",
                    "src_ip": src,
                    "packet_count": len(dq),
                    "severity": "High",
                })

        elif protocol == "TCP":
            port = pkt.get("dst_port")
            if port is not None:
                dq = self.port_windows[src]
                dq.append((now, port))
                self._evict_old(dq, now)
                distinct_ports = set(entry[1] for entry in dq)

                if len(distinct_ports) >= self.PORT_SCAN_THRESHOLD:
                    threats.append({
                        "type": "Port Scan",
                        "src_ip": src,
                        "ports_targeted": sorted(distinct_ports),
                        "severity": "High",
                    })

            payload_upper = payload.upper()
            for kw in self.SQLI_KEYWORDS:
                if kw.upper() in payload_upper:
                    threats.append({
                        "type": "SQL Injection",
                        "src_ip": src,
                        "payload_snippet": payload[:150],
                        "severity": "High",
                    })
                    break

            payload_lower = payload.lower()
            for kw in self.XSS_KEYWORDS:
                if kw.lower() in payload_lower:
                    threats.append({
                        "type": "XSS",
                        "src_ip": src,
                        "payload_snippet": payload[:150],
                        "severity": "Medium",
                    })
                    break

        return threats


# ---------------------------------------------------------------------------
# Gemini tool — called by the model when it decides to block an IP
# ---------------------------------------------------------------------------

def block_ip(ip_address: str) -> str:
    """Block a malicious IP address using a firewall rule.

    Args:
        ip_address: The IPv4 address to block.
    """
    print(f"[ACTION] Firewall: blocking {ip_address}", file=sys.stderr)
    # In production this would invoke iptables/nftables. Simulated here.
    return f"IP {ip_address} has been blocked successfully via firewall rule."


# ---------------------------------------------------------------------------
# Agent loop — multi-turn Gemini Function Calling
# ---------------------------------------------------------------------------

def run_agent(threats: list, model) -> dict:
    threat_json = json.dumps(threats, indent=2)
    prompt = f"""You are an autonomous security response agent integrated into a real-time IDS.

The rule engine has detected the following threats:

{threat_json}

Your instructions:
1. For every threat with severity "High", call the block_ip tool with that threat's src_ip.
2. You may call block_ip multiple times if there are multiple High-severity source IPs.
3. After completing all necessary actions (or if no action is needed), respond with ONLY a valid JSON object — no markdown, no code fences, no extra text.

The JSON must conform exactly to this schema:
{{
  "analysis_summary": "<brief description of what was detected>",
  "threat_level": "<Overall: Low / Medium / High / Critical>",
  "detected_attack_type": "<comma-separated list of attack types found>",
  "action_taken": "<what was done, e.g. blocked IPs or 'No action required'>"
}}"""

    chat = model.start_chat()

    try:
        response = chat.send_message(prompt)
    except Exception as e:
        raise RuntimeError(f"Gemini initial request failed: {e}") from e

    max_turns = 6
    for _ in range(max_turns):
        candidate = response.candidates[0]
        parts = candidate.content.parts

        # Check whether the model wants to call a function
        func_call_part = None
        for part in parts:
            if hasattr(part, "function_call") and part.function_call.name:
                func_call_part = part
                break

        if func_call_part is None:
            # Model returned final text — we are done
            break

        fc = func_call_part.function_call
        tool_result = "Unknown tool requested."

        if fc.name == "block_ip":
            ip_arg = fc.args.get("ip_address", "")
            if ip_arg:
                tool_result = block_ip(ip_arg)
            else:
                tool_result = "Error: ip_address argument was missing."

        # Send the function result back to the model
        try:
            response = chat.send_message(
                genai.protos.Part(
                    function_response=genai.protos.FunctionResponse(
                        name=fc.name,
                        response={"result": tool_result},
                    )
                )
            )
        except Exception as e:
            raise RuntimeError(f"Failed to send function response to Gemini: {e}") from e

    # Extract and clean the final text response
    final_text = response.candidates[0].content.parts[0].text.strip()

    # Strip markdown code fences if the model wrapped the JSON
    if final_text.startswith("```"):
        lines = final_text.splitlines()
        # Remove first line (``` or ```json) and last line (```)
        inner = lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
        final_text = "\n".join(inner).strip()

    return json.loads(final_text)


# ---------------------------------------------------------------------------
# Main — read packet stream from stdin, run rule engine + agent
# ---------------------------------------------------------------------------

def main():
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print(
            "[!] GEMINI_API_KEY is not set.\n"
            "    Export it before running: export GEMINI_API_KEY='your-key-here'",
            file=sys.stderr,
        )
        sys.exit(1)

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash", tools=[block_ip])
    engine = RuleEngine()

    print("[*] Security agent online. Reading packet stream from stdin...", file=sys.stderr)
    print("[*] Pipe output from capture_live.py or capture_pcap.py into this script.", file=sys.stderr)

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue

        try:
            pkt = json.loads(line)
        except json.JSONDecodeError:
            print(f"[WARN] Non-JSON line ignored: {line[:80]}", file=sys.stderr)
            continue

        threats = engine.analyze(pkt)
        if not threats:
            continue

        attack_types = [t["type"] for t in threats]
        print(f"\n[!] Threats detected: {attack_types}", file=sys.stderr)

        try:
            result = run_agent(threats, model)
        except json.JSONDecodeError as e:
            print(f"[ERROR] Agent response was not valid JSON: {e}", file=sys.stderr)
            continue
        except RuntimeError as e:
            print(f"[ERROR] Agent error: {e}", file=sys.stderr)
            continue
        except Exception as e:
            print(f"[ERROR] Unexpected agent error: {e}", file=sys.stderr)
            continue

        # Mark affected IPs as blocked so the engine suppresses future alerts
        for threat in threats:
            src = threat.get("src_ip")
            if src and threat.get("severity") == "High":
                engine.blocked_ips.add(src)

        print(json.dumps(result, indent=2), flush=True)


if __name__ == "__main__":
    main()
