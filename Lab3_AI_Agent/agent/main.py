"""
Lab 3: AI Security Agent — Cloud Run Service
FastAPI application with Gemini Function Calling for autonomous threat response.
"""

import base64
import datetime
import json
import logging
import os

import vertexai
from fastapi import FastAPI, Request, Response
from google.cloud import compute_v1, firestore
from vertexai.generative_models import (
    FunctionDeclaration,
    GenerativeModel,
    Part,
    Tool,
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "your-project-id")
LOCATION = os.environ.get("GOOGLE_CLOUD_REGION", "asia-southeast1")
MODEL_NAME = "gemini-2.5-flash"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("ai-sec-agent")

# ---------------------------------------------------------------------------
# Initialize Google Cloud clients (reused across requests)
# ---------------------------------------------------------------------------
vertexai.init(project=PROJECT_ID, location=LOCATION)
db = firestore.Client(project=PROJECT_ID)
firewall_client = compute_v1.FirewallsClient()

# ---------------------------------------------------------------------------
# Gemini Agent — Function Calling Setup
# ---------------------------------------------------------------------------
AGENT_SYSTEM_INSTRUCTION = (
    "You are an Autonomous SOC Agent that analyzes ONE network packet at a time "
    "and decides whether to block the source IP.\n\n"

    "### BLOCKING RULES (act on a SINGLE packet — you will NOT see patterns):\n"
    "1. **SQL Injection**: If the `payload` field contains SQL patterns "
    "(`' OR`, `1=1`, `UNION SELECT`, `DROP TABLE`, `--`), CALL block_ip IMMEDIATELY.\n"
    "2. **Sensitive Port Access**: If `dst_port` is 22 (SSH), 3306 (MySQL), "
    "3389 (RDP), or 5432 (PostgreSQL), CALL block_ip.\n"
    "3. **ICMP Flood**: If `protocol` is `ICMP` and `severity_hint` is "
    "`medium` or higher, CALL block_ip.\n"
    "4. **Critical/High Severity**: If `severity_hint` is `critical` or `high`, "
    "CALL block_ip regardless of other fields.\n"
    "5. **Normal Traffic**: If `dst_port` is 80 or 443 with no malicious payload "
    "and `severity_hint` is `low`, do NOT call block_ip. Just state it is benign.\n\n"

    "### EXAMPLES:\n\n"

    "Packet: {\"src_ip\": \"172.16.0.9\", \"dst_port\": 80, "
    "\"payload\": \"GET /?q=' OR 1=1 --\", \"severity_hint\": \"critical\"}\n"
    "Action: CALL block_ip(ip_address=\"172.16.0.9\", reason=\"SQL injection in HTTP payload\")\n\n"

    "Packet: {\"src_ip\": \"10.10.10.50\", \"dst_port\": 22, "
    "\"payload\": null, \"severity_hint\": \"high\"}\n"
    "Action: CALL block_ip(ip_address=\"10.10.10.50\", reason=\"Unauthorized SSH access attempt\")\n\n"

    "Packet: {\"src_ip\": \"192.168.1.100\", \"protocol\": \"ICMP\", "
    "\"severity_hint\": \"medium\"}\n"
    "Action: CALL block_ip(ip_address=\"192.168.1.100\", reason=\"ICMP flood activity\")\n\n"

    "Packet: {\"src_ip\": \"10.0.0.5\", \"dst_port\": 443, "
    "\"payload\": \"GET /index.html\", \"severity_hint\": \"low\"}\n"
    "Action: Benign HTTPS traffic. No action required.\n\n"

    "IMPORTANT: When in doubt, BLOCK. It is better to over-block than to miss a threat."
)

block_ip_func = FunctionDeclaration(
    name="block_ip",
    description=(
        "Block a malicious IP address by creating a VPC firewall deny rule. "
        "Use this when you detect a clear security threat that warrants "
        "blocking the source IP."
    ),
    parameters={
        "type": "object",
        "properties": {
            "ip_address": {
                "type": "string",
                "description": "The malicious IP address to block (e.g. '192.168.1.100')",
            },
            "reason": {
                "type": "string",
                "description": "A concise explanation of why this IP is being blocked",
            },
        },
        "required": ["ip_address", "reason"],
    },
)

security_tool = Tool(function_declarations=[block_ip_func])

agent_model = GenerativeModel(
    model_name=MODEL_NAME,
    system_instruction=[AGENT_SYSTEM_INSTRUCTION],
    tools=[security_tool],
)

# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(title="AI Security Agent")


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
def execute_block_ip(ip_address: str, reason: str) -> dict:
    """Create a VPC firewall deny-ingress rule for the given IP."""
    rule_name = f"ai-block-{ip_address.replace('.', '-')}"
    firewall_rule = compute_v1.Firewall(
        name=rule_name,
        network=f"projects/{PROJECT_ID}/global/networks/default",
        direction="INGRESS",
        priority=900,
        source_ranges=[f"{ip_address}/32"],
        denied=[compute_v1.Denied(I_p_protocol="all")],
        description=f"Blocked by AI Agent: {reason}"[:255],
    )
    try:
        operation = firewall_client.insert(
            project=PROJECT_ID,
            firewall_resource=firewall_rule,
        )
        operation.result()  # wait for completion
        logger.info(f"Blocked IP {ip_address} via firewall rule: {rule_name}")
        return {"status": "blocked", "ip": ip_address, "rule": rule_name}
    except Exception as exc:
        if "already exists" in str(exc).lower():
            logger.info(f"IP {ip_address} already blocked ({rule_name})")
            return {"status": "already_blocked", "ip": ip_address}
        logger.error(f"Failed to block {ip_address}: {exc}")
        return {"status": "error", "message": str(exc)}


def save_event(packet: dict, ai_reasoning: str, action: str, blocked_ip: str = None):
    """Persist a security event to the Firestore 'security_events' collection."""
    doc = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc),
        "packet": packet,
        "ai_reasoning": ai_reasoning,
        "action": action,       # "Blocked" or "Allowed"
        "blocked_ip": blocked_ip,
    }
    db.collection("security_events").add(doc)
    logger.info(f"Saved event: action={action}, blocked_ip={blocked_ip}")


def serialize_doc(doc_dict: dict) -> dict:
    """Convert Firestore datetime fields to ISO-8601 strings for JSON serialization."""
    for key, val in doc_dict.items():
        if isinstance(val, datetime.datetime):
            doc_dict[key] = val.isoformat()
    return doc_dict


# ---------------------------------------------------------------------------
# POST /pubsub — Pub/Sub Push Handler
# ---------------------------------------------------------------------------
@app.post("/pubsub")
async def handle_pubsub(request: Request):
    """Receive a Pub/Sub push message, analyze with Gemini, and act."""
    try:
        envelope = await request.json()
        message = envelope.get("message", {})
        if not message.get("data"):
            logger.warning("Received Pub/Sub message with no data")
            return {"status": "no data"}

        raw = base64.b64decode(message["data"]).decode("utf-8")
        packet = json.loads(raw)
        logger.info(
            f"Received: {packet.get('protocol')} "
            f"{packet.get('src_ip')} -> {packet.get('dst_ip')}"
        )

        # --- Gemini Function Calling Loop ---
        chat = agent_model.start_chat()
        response = chat.send_message(
            f"Analyze this network packet and decide if the source IP should be blocked:\n"
            f"{json.dumps(packet, indent=2)}"
        )

        ai_reasoning = ""
        action = "Allowed"
        blocked_ip = None

        # Check every part for a function call
        for part in response.candidates[0].content.parts:
            if part.function_call and part.function_call.name == "block_ip":
                fc = part.function_call
                ip = fc.args["ip_address"]
                reason = fc.args["reason"]

                result = execute_block_ip(ip, reason)

                # Send function result back to Gemini for final reasoning
                fn_response = chat.send_message(
                    Part.from_function_response(
                        name="block_ip",
                        response={"result": result},
                    )
                )
                ai_reasoning = fn_response.text
                action = "Blocked"
                blocked_ip = ip
                break
            elif part.text:
                ai_reasoning = part.text

        save_event(packet, ai_reasoning, action, blocked_ip)
        return {"status": "processed", "action": action}

    except Exception as exc:
        logger.error(f"Error processing message: {exc}", exc_info=True)
        # Return 200 to prevent Pub/Sub from retrying endlessly
        return {"status": "error", "message": str(exc)}


# ---------------------------------------------------------------------------
# GET /dashboard — AI-Generated CISO Report
# ---------------------------------------------------------------------------
@app.get("/dashboard")
async def dashboard():
    """Query recent security events and ask Gemini to produce a Markdown report."""
    try:
        query = (
            db.collection("security_events")
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(15)
        )
        docs = query.stream()
        events = [serialize_doc(doc.to_dict()) for doc in docs]

        if not events:
            return Response(
                content="# Security Dashboard\n\nNo security events recorded yet.\n",
                media_type="text/markdown",
            )

        dashboard_model = GenerativeModel(
            model_name=MODEL_NAME,
            system_instruction=[
                "You are a CISO (Chief Information Security Officer). "
                "Read the recent security events and generate a professional, "
                "high-vibe Executive Summary in Markdown format. "
                "Include a table of blocked IPs (with timestamps and reasons), "
                "current threat trends, and recommended next steps. "
                "Keep the tone authoritative and data-driven."
            ],
        )

        response = dashboard_model.generate_content(
            json.dumps(events, indent=2)
        )
        return Response(content=response.text, media_type="text/markdown")

    except Exception as exc:
        logger.error(f"Dashboard error: {exc}", exc_info=True)
        return Response(
            content=f"# Dashboard Error\n\n```\n{exc}\n```\n",
            media_type="text/markdown",
        )


# ---------------------------------------------------------------------------
# GET /health — Health Check
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "ai-security-agent"}
