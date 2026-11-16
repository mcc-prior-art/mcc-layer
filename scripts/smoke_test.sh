#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://localhost:8000}"
# F1b: KEY must be the per-agent credential of agent/$SESSION (main.py
# resolves tenant + principal from it and refuses a session_id naming anyone
# else; the shared MCC_API_KEY obtains no decision in strict mode). Create it
# with scripts/generate_agent_credential.py --principal-id agent/$SESSION.
SESSION="${SESSION:-s1}"
KEY="${KEY:?set KEY to the per-agent credential of agent/$SESSION}"

echo "== Health =="
curl -s "$API/health" | jq .

echo "== ALLOW payment =="
curl -s -X POST "$API/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"session_id":"'"$SESSION"'","intent":"send_payment","args":{"amount":750},"idempotency_key":"allow-1"}' | jq .

echo "== ESCALATE payment =="
curl -s -X POST "$API/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"session_id":"'"$SESSION"'","intent":"send_payment","args":{"amount":7500},"idempotency_key":"esc-1"}' | jq .

echo "== DENY database delete =="
curl -s -X POST "$API/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"session_id":"'"$SESSION"'","intent":"delete_database","args":{"database":"production-main"},"idempotency_key":"deny-1"}' | jq .

echo "== CONSTRAIN sandbox bash =="
curl -s -X POST "$API/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"session_id":"'"$SESSION"'","intent":"execute_bash","args":{"environment":"sandbox","command":"python --version"},"idempotency_key":"constrain-1"}' | jq .
