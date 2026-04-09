"""
Lab 3: AI Security Agent — Streamlit Dashboard
Fetches Firestore security events, sends them to Gemini for analysis,
and renders the result as a live Markdown dashboard.
"""

import datetime
import json
import os

import pandas as pd
import streamlit as st
import vertexai
from google.cloud import firestore
from vertexai.generative_models import GenerativeModel

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "your-project-id")
LOCATION = os.environ.get("GOOGLE_CLOUD_REGION", "asia-southeast1")
MODEL_NAME = "gemini-2.5-flash"
COLLECTION = "security_events"

DASHBOARD_SYSTEM_INSTRUCTION = (
    "You are a CISO dashboard report generator. "
    "Analyze the security event logs and produce a clean, data-driven Markdown report.\n\n"

    "### RULES:\n"
    "1. Start with a **Status Overview** section showing: "
    "Total Events, Blocked Count, Allowed Count, and list of Unique Attacker IPs.\n"
    "2. Add a **Key Insights** section identifying patterns: "
    "repeated source IPs, common attack types, severity distribution, "
    "and any escalation trends.\n"
    "3. Include a **Latest Incidents** Markdown table with columns: "
    "| Timestamp | Source IP | Protocol | Action | Reasoning (truncated) |\n"
    "4. End with a **Recommendations** section containing 2-3 actionable next steps.\n"
    "5. Use clean, professional Markdown. No greetings or preamble. "
    "Start directly with the Status Overview heading.\n"
    "6. If no blocked events exist, note that the system is in observation-only mode."
)


# ---------------------------------------------------------------------------
# Cached Initialization (runs once per session)
# ---------------------------------------------------------------------------
@st.cache_resource
def init_firestore():
    return firestore.Client(project=PROJECT_ID)


@st.cache_resource
def init_gemini():
    vertexai.init(project=PROJECT_ID, location=LOCATION)
    return GenerativeModel(
        model_name=MODEL_NAME,
        system_instruction=[DASHBOARD_SYSTEM_INSTRUCTION],
    )


# ---------------------------------------------------------------------------
# Data Helpers
# ---------------------------------------------------------------------------
def serialize_doc(doc_dict: dict) -> dict:
    """Convert Firestore datetime fields to ISO-8601 strings."""
    for key, val in doc_dict.items():
        if isinstance(val, datetime.datetime):
            doc_dict[key] = val.isoformat()
    return doc_dict


def fetch_events(db: firestore.Client, limit: int) -> list[dict]:
    """Fetch the latest security events from Firestore."""
    docs = (
        db.collection(COLLECTION)
        .order_by("timestamp", direction=firestore.Query.DESCENDING)
        .limit(limit)
        .stream()
    )
    return [serialize_doc(doc.to_dict()) for doc in docs]


def events_to_dataframe(events: list[dict]) -> pd.DataFrame:
    """Flatten nested Firestore documents into a clean DataFrame."""
    rows = []
    for e in events:
        packet = e.get("packet", {})
        rows.append({
            "Timestamp": e.get("timestamp", ""),
            "Source IP": packet.get("src_ip", ""),
            "Dest IP": packet.get("dst_ip", ""),
            "Protocol": packet.get("protocol", ""),
            "Dst Port": packet.get("dst_port", ""),
            "Severity": packet.get("severity_hint", ""),
            "Action": e.get("action", ""),
            "Blocked IP": e.get("blocked_ip", ""),
            "AI Reasoning": (e.get("ai_reasoning", "") or "")[:120],
        })
    return pd.DataFrame(rows)


def generate_analysis(model: GenerativeModel, events: list[dict]) -> str:
    """Send events to Gemini and return the Markdown analysis."""
    response = model.generate_content(json.dumps(events, indent=2))
    return response.text


# ---------------------------------------------------------------------------
# Streamlit UI
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="AI Security Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("AI Security Agent Dashboard")

# --- Sidebar Controls ---
with st.sidebar:
    st.header("Controls")
    limit = st.slider("Events to fetch", min_value=10, max_value=100, value=50, step=10)
    analyze_btn = st.button("Refresh & Analyze", type="primary", use_container_width=True)

    st.divider()
    st.caption(f"**Project:** `{PROJECT_ID}`")
    st.caption(f"**Region:** `{LOCATION}`")
    st.caption(f"**Model:** `{MODEL_NAME}`")
    st.caption(f"**Collection:** `{COLLECTION}`")

# --- Initialize Clients ---
db = init_firestore()
model = init_gemini()

# --- Fetch & Analyze on button press or first load ---
if analyze_btn or "events" not in st.session_state:
    with st.spinner("Fetching events from Firestore..."):
        events = fetch_events(db, limit)
    st.session_state.events = events

    if events:
        with st.spinner(f"Generating AI analysis with {MODEL_NAME}..."):
            try:
                analysis = generate_analysis(model, events)
                st.session_state.analysis = analysis
                st.session_state.error = None
            except Exception as exc:
                st.session_state.analysis = None
                st.session_state.error = str(exc)
    else:
        st.session_state.analysis = None
        st.session_state.error = None

# --- Display Results ---
events = st.session_state.get("events", [])
analysis = st.session_state.get("analysis")
error = st.session_state.get("error")

if error:
    st.error(f"Gemini API error: {error}")

if not events:
    st.info(
        "No security events found in Firestore. "
        "Run `vm_publisher.py` to start generating data."
    )
    st.stop()

# Summary metrics row
total = len(events)
blocked = sum(1 for e in events if e.get("action") == "Blocked")
allowed = total - blocked
unique_ips = len({e.get("packet", {}).get("src_ip") for e in events if e.get("packet")})

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", total)
col2.metric("Blocked", blocked)
col3.metric("Allowed", allowed)
col4.metric("Unique Source IPs", unique_ips)

st.divider()

# Gemini analysis
if analysis:
    st.markdown(analysis)
else:
    st.warning("No AI analysis available. Click **Refresh & Analyze** in the sidebar.")

st.divider()

# Raw logs
with st.expander("Raw Firestore Logs", expanded=False):
    df = events_to_dataframe(events)
    st.dataframe(df, use_container_width=True, hide_index=True)

# Full JSON (for debugging)
with st.expander("Raw JSON", expanded=False):
    st.json(events)
