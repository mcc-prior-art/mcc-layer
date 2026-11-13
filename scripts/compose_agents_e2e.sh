#!/usr/bin/env bash
# Run a per-principal Docker Compose E2E (V05 part 2).
#
#   scripts/compose_agents_e2e.sh <compose-file> "<infra services>" "<agent services>" [log-file]
#
# Each agent principal runs in its OWN container holding only its own
# provisioned credential, so a stack has several agent services. This driver:
#   1. builds the stack (unless MCC_E2E_NO_BUILD=1, for prebuilt local images);
#   2. starts the infrastructure services (their dependencies -- including the
#      one-shot agent-credentials-init provisioner -- start automatically and a
#      failed provisioner aborts the run);
#   3. waits until every infrastructure service is healthy (or running, if it
#      has no healthcheck);
#   4. runs each agent service to completion, in order, as a one-off container
#      with the service's own configuration (its own credential volume only);
#   5. fails if ANY agent exits non-zero. Output is appended to the log file.
# Fail-closed: a timeout, an unhealthy/exited service or any agent failure
# exits non-zero. Never masks a failure.
set -uo pipefail

FILE="$1"; INFRA="$2"; AGENTS="$3"; LOG="${4:-compose.log}"
DC=(docker compose -f "$FILE")
[ -n "${MCC_E2E_PROJECT:-}" ] && DC+=(-p "$MCC_E2E_PROJECT")
[ -n "${MCC_E2E_OVERRIDE:-}" ] && DC+=(-f "$MCC_E2E_OVERRIDE")
: > "$LOG"

if [ "${MCC_E2E_NO_BUILD:-0}" != "1" ]; then
  "${DC[@]}" build 2>&1 | tail -n 40 || { echo "::error::build failed"; exit 1; }
fi

# shellcheck disable=SC2086
if ! "${DC[@]}" up -d --no-build $INFRA 2>&1 | tee -a "$LOG"; then
  echo "::error::could not start infrastructure: $INFRA"; exit 1
fi

deadline=$((SECONDS + ${MCC_E2E_READY_TIMEOUT:-600}))
for svc in $INFRA; do
  while :; do
    cid=$("${DC[@]}" ps -q "$svc" 2>/dev/null | head -n1)
    status=""
    if [ -n "$cid" ]; then
      status=$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$cid" 2>/dev/null)
    fi
    case "$status" in
      healthy) break ;;
      running) if [ -z "$(docker inspect -f '{{if .State.Health}}h{{end}}' "$cid")" ]; then break; fi ;;
      exited|dead|unhealthy) echo "::error::$svc is $status"; "${DC[@]}" logs --no-color "$svc" | tail -n 60; exit 1 ;;
    esac
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "::error::$svc did not become ready (status=${status:-absent})"; exit 1
    fi
    sleep 3
  done
  echo "ready: $svc" | tee -a "$LOG"
done

rc_all=0
for svc in $AGENTS; do
  echo "===== agent: $svc =====" | tee -a "$LOG"
  "${DC[@]}" run --no-deps --rm -T "$svc" 2>&1 | tee -a "$LOG"
  rc=${PIPESTATUS[0]}
  echo "agent $svc exit code: $rc" | tee -a "$LOG"
  if [ "$rc" -ne 0 ]; then
    echo "::error::agent $svc exited non-zero ($rc)"
    rc_all=1
  fi
done
exit "$rc_all"
