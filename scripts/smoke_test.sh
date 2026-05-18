#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://localhost:8000}"
KEY="${KEY:-demo-key}"

echo "== Health =="
curl -s "$API/health" | jq .

echo "== ALLOW payment =="
curl -s -X POST "$API/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"session_id":"s1","intent":"send_payment","args":{"amount":750},"idempotency_key":"allow-1"}' | jq .

echo "== ESCALATE payment =="
curl -s -X POST "$API/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"session_id":"s2","intent":"send_payment","args":{"amount":7500},"idempotency_key":"esc-1"}' | jq .

echo "== DENY database delete =="
curl -s -X POST "$API/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"session_id":"s3","intent":"delete_database","args":{"database":"production-main"},"idempotency_key":"deny-1"}' | jq .

echo "== CONSTRAIN sandbox bash =="
curl -s -X POST "$API/evaluate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $KEY" \
  -d '{"session_id":"s4","intent":"execute_bash","args":{"environment":"sandbox","command":"python --version"},"idempotency_key":"constrain-1"}' | jq .
