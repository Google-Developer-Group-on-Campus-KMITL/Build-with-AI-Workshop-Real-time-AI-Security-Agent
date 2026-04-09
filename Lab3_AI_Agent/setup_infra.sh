#!/usr/bin/env bash
set -e

# ---------------------------------------------------------------------------
# Lab 3: AI Security Agent — Infrastructure Setup
# ---------------------------------------------------------------------------

REGION="asia-southeast1"
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)

if [ -z "$PROJECT_ID" ]; then
    echo "[!] ERROR: No active GCP project. Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo "[*] Project : $PROJECT_ID"
echo "[*] Region  : $REGION"
echo ""

# ---------------------------------------------------------------------------
# 1. Enable required APIs
# ---------------------------------------------------------------------------
echo "[*] Enabling APIs..."
gcloud services enable \
    compute.googleapis.com \
    pubsub.googleapis.com \
    firestore.googleapis.com \
    aiplatform.googleapis.com \
    run.googleapis.com \
    cloudbuild.googleapis.com \
    artifactregistry.googleapis.com \
    iam.googleapis.com

# ---------------------------------------------------------------------------
# 2. Create Service Account
# ---------------------------------------------------------------------------
SA_NAME="ai-sec-agent-sa"
SA_EMAIL="${SA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com"

echo "[*] Creating Service Account: $SA_NAME"
gcloud iam service-accounts create "$SA_NAME" \
    --display-name="AI Security Agent SA" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 3. Bind IAM Roles
# ---------------------------------------------------------------------------
ROLES=(
    "roles/aiplatform.user"
    "roles/pubsub.publisher"
    "roles/pubsub.subscriber"
    "roles/datastore.user"
    "roles/compute.securityAdmin"
)

echo "[*] Binding IAM roles..."
for ROLE in "${ROLES[@]}"; do
    echo "    -> $ROLE"
    gcloud projects add-iam-policy-binding "$PROJECT_ID" \
        --member="serviceAccount:${SA_EMAIL}" \
        --role="$ROLE" \
        --quiet > /dev/null
done

# ---------------------------------------------------------------------------
# 4. Create Pub/Sub Topic
# ---------------------------------------------------------------------------
TOPIC="packet-logs-topic"
echo "[*] Creating Pub/Sub topic: $TOPIC"
gcloud pubsub topics create "$TOPIC" 2>/dev/null || true

# ---------------------------------------------------------------------------
# 5. Firewall — AI Agent will create deny rules dynamically via VPC Firewall
# ---------------------------------------------------------------------------
echo "[*] VPC Firewall: AI agent will create 'ai-block-*' deny rules at runtime."
echo "    (No pre-creation needed — firewall rules have no quota like Cloud Armor.)"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
echo "=============================================="
echo "  Infrastructure setup complete!"
echo "=============================================="
echo ""
echo "  Project          : $PROJECT_ID"
echo "  Service Account  : $SA_EMAIL"
echo "  Pub/Sub Topic    : $TOPIC"
echo "  Firewall         : AI agent creates 'ai-block-*' rules dynamically"
echo ""
echo "  IMPORTANT: You must manually initialize Firestore"
echo "  in Native mode via the Google Cloud Console before"
echo "  running the agent."
echo ""
echo "  Console -> Firestore -> Create Database -> Native Mode"
echo "  Location: ${REGION}"
echo "=============================================="
