# Deployable VoltAgent + MCC-Core pilot — operator commands.
#
# Typical flow:
#   make pilot-up        # build + start the stack (detached)
#   make pilot-ready     # wait until MCC + quorum are READY
#   make pilot-allow     # compliant request  -> EXECUTED
#   make pilot-deny      # prohibited request -> blocked
#   make pilot-constrain # excessive request  -> clamped + EXECUTED
#   make pilot-escalate  # high-risk request  -> PENDING_APPROVAL
#   make pilot-approve   # operator approves  -> EXECUTED
#   make pilot-audit-verify   # verify the cryptographic audit chain
#   make pilot-restart-check  # prove audit survives a restart
#   make pilot-down      # stop (KEEPS volumes -> audit persists)
#   make pilot-clean     # stop + remove volumes (wipes audit)
#
# The VoltAgent agents never hold the operator key, the shared tenant key or
# each other's credentials, and have no network route to the external service.
# See docs/PILOT_VOLTAGENT_DEPLOYMENT.md and docs/AGENT_IDENTITY.md.

COMPOSE ?= docker compose -f docker-compose.pilot-voltagent.yml --env-file .env.pilot
# V05 (part 2): one container per agent principal, each holding ONLY its own
# provisioned credential. agent/notify-bot runs allow/deny/constrain;
# agent/unknown (a different principal, no notify.send mandate) runs ESCALATE.
AGENT         := $(COMPOSE) exec -T voltagent-agent
AGENT_UNKNOWN := $(COMPOSE) exec -T voltagent-agent-unknown
GATEWAY       := $(COMPOSE) exec -T mcc-gateway
# The provisioner's own arguments (kept in sync with docker-compose.pilot-voltagent.yml).
PILOT_PROVISION_ARGS := python -m gateway.agent_provisioning \
	--registry /config/agent_credentials.json --tenant-id pilot --owner 1000:1000 \
	--agent agent/notify-bot=/creds/notify-bot --agent agent/unknown=/creds/unknown

.PHONY: pilot-config pilot-up pilot-ready pilot-allow pilot-deny pilot-constrain \
        pilot-escalate pilot-approve pilot-rotate-agent pilot-audit-verify pilot-restart-check \
        pilot-demo pilot-down pilot-clean pilot-logs pilot-ps

pilot-config: ## Create .env.pilot from the template if missing
	@test -f .env.pilot || cp .env.pilot.example .env.pilot
	@echo ".env.pilot ready (edit it to change keys/endpoints)."

pilot-up: pilot-config ## Build + start the full pilot stack (detached)
	$(COMPOSE) up --build -d

pilot-ready: ## Wait until the gateway + quorum report READY (fail-closed)
	@echo "waiting for pilot readiness..."
	@for i in $$(seq 1 100); do \
	  if $(AGENT) node -e "fetch('http://mcc-gateway:8001/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null \
	     && $(AGENT) node -e "fetch('http://evaluator-quorum:8080/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then \
	    echo "pilot READY"; exit 0; fi; \
	  sleep 3; done; \
	echo "pilot did not become ready in time"; exit 1

pilot-allow: ## ALLOW: a compliant request -> governed execution -> EXECUTED
	$(AGENT) npx tsx src/pilot-cli.ts allow

pilot-deny: ## DENY: a prohibited request -> blocked, external service never called
	$(AGENT) npx tsx src/pilot-cli.ts deny

pilot-constrain: ## CONSTRAIN: an excessive request -> only the clamped payload executes
	$(AGENT) npx tsx src/pilot-cli.ts constrain

pilot-escalate: ## ESCALATE: agent/unknown's request -> PENDING_APPROVAL (no execution yet)
	$(AGENT_UNKNOWN) npx tsx src/pilot-cli.ts escalate

pilot-approve: ## Operator APPROVES (operator key); then agent/unknown executes with ITS OWN credential -> EXECUTED
	$(GATEWAY) python -m integrations.voltagent.mcc_side.operator_cli
	$(AGENT_UNKNOWN) npx tsx src/pilot-cli.ts execute-approved

pilot-rotate-agent: ## Rotate one agent's credential: make pilot-rotate-agent PRINCIPAL=agent/notify-bot
	@test -n "$(PRINCIPAL)" || (echo "usage: make pilot-rotate-agent PRINCIPAL=agent/..."; exit 2)
	$(COMPOSE) run --rm agent-credentials-init $(PILOT_PROVISION_ARGS) --rotate "$(PRINCIPAL)"
	$(COMPOSE) restart mcc-gateway evaluator-quorum

pilot-audit-verify: ## Verify the persisted cryptographic audit chain
	$(GATEWAY) python -c "import sys; sys.path.insert(0,'/app/src'); from mcc_core import AuditLog; ok=AuditLog.verify_chain('/data/audit.jsonl'); print('audit chain valid=%s' % ok); sys.exit(0 if ok else 1)"

pilot-restart-check: ## Prove the audit chain survives a restart
	$(MAKE) pilot-allow
	@echo "restarting the gateway (audit + keys are on persistent volumes)..."
	$(COMPOSE) restart mcc-gateway
	$(MAKE) pilot-ready
	$(MAKE) pilot-audit-verify
	@echo "audit persisted and re-verified after restart."

pilot-demo: ## Run all four scenarios + approval + audit verification end to end
	$(MAKE) pilot-allow
	$(MAKE) pilot-deny
	$(MAKE) pilot-constrain
	$(MAKE) pilot-escalate
	$(MAKE) pilot-approve
	$(MAKE) pilot-audit-verify
	@echo "\nPILOT DEMO COMPLETE: ALLOW + DENY + CONSTRAIN + ESCALATE(+approve) + audit verified."

pilot-ps: ## Show pilot container status
	$(COMPOSE) ps

pilot-logs: ## Tail pilot logs
	$(COMPOSE) logs --no-color --timestamps

pilot-down: ## Stop the stack, KEEPING volumes (audit persists)
	$(COMPOSE) down

pilot-clean: ## Stop the stack and REMOVE volumes (wipes the audit chain)
	$(COMPOSE) down -v --remove-orphans

# --- AXFlow Clinic Revenue Agent business pilot (PR #38) -------------------- #
#
# The first productized BUSINESS pilot: AXFlow is the business agent, VoltAgent
# is the framework layer, MCC-Core is the execution governance authority. Same
# deployment patterns as the notification pilot above; only the external service
# (a mock clinic) and the agent's domain (clinic actions) differ. Isolated as its
# own compose project so it does not collide with the notification pilot volumes.
#
#   make clinic-pilot-up        # build + start the clinic stack (detached)
#   make clinic-pilot-ready     # wait until MCC + quorum are READY
#   make clinic-pilot-allow     # book a normal appointment      -> EXECUTED
#   make clinic-pilot-deny      # unsafe medical advice request  -> blocked
#   make clinic-pilot-constrain # excessive 90% discount         -> clamped + EXECUTED
#   make clinic-pilot-escalate  # refund request                 -> PENDING_APPROVAL
#   make clinic-pilot-approve   # clinic operator approves       -> EXECUTED
#   make clinic-pilot-audit-verify   # verify the cryptographic audit chain
#   make clinic-pilot-restart-check  # prove audit survives a restart
#   make clinic-pilot-demo      # all four verdicts + approval + audit, end to end
#   make clinic-pilot-down      # stop (KEEPS volumes -> audit persists)
#   make clinic-pilot-clean     # stop + remove volumes (wipes audit)
#
# The clinic agent never holds the operator key and has no network route to the
# mock clinic service. See docs/PILOT_AXFLOW_CLINIC.md.

CLINIC_COMPOSE ?= docker compose -p axflow-clinic -f docker-compose.pilot-clinic-voltagent.yml --env-file .env.pilot
CLINIC_AGENT   := $(CLINIC_COMPOSE) exec -T clinic-agent
CLINIC_GATEWAY := $(CLINIC_COMPOSE) exec -T mcc-gateway

.PHONY: clinic-pilot-config clinic-pilot-up clinic-pilot-ready clinic-pilot-allow \
        clinic-pilot-deny clinic-pilot-constrain clinic-pilot-escalate \
        clinic-pilot-approve clinic-pilot-audit-verify clinic-pilot-restart-check \
        clinic-pilot-demo clinic-pilot-down clinic-pilot-clean clinic-pilot-logs \
        clinic-pilot-ps

clinic-pilot-config: ## Create .env.pilot from the template if missing
	@test -f .env.pilot || cp .env.pilot.example .env.pilot
	@echo ".env.pilot ready (edit it to change keys/endpoints)."

clinic-pilot-up: clinic-pilot-config ## Build + start the full AXFlow clinic stack (detached)
	$(CLINIC_COMPOSE) up --build -d

clinic-pilot-ready: ## Wait until the gateway + quorum report READY (fail-closed)
	@echo "waiting for AXFlow clinic pilot readiness..."
	@for i in $$(seq 1 100); do \
	  if $(CLINIC_AGENT) node -e "fetch('http://mcc-gateway:8001/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null \
	     && $(CLINIC_AGENT) node -e "fetch('http://evaluator-quorum:8080/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" 2>/dev/null; then \
	    echo "clinic pilot READY"; exit 0; fi; \
	  sleep 3; done; \
	echo "clinic pilot did not become ready in time"; exit 1

clinic-pilot-allow: ## ALLOW: book a normal appointment -> governed execution -> EXECUTED
	$(CLINIC_AGENT) npx tsx src/clinic-cli.ts allow

clinic-pilot-deny: ## DENY: an unsafe medical-advice request -> blocked, clinic never called
	$(CLINIC_AGENT) npx tsx src/clinic-cli.ts deny

clinic-pilot-constrain: ## CONSTRAIN: an excessive discount -> only the clamped payload executes
	$(CLINIC_AGENT) npx tsx src/clinic-cli.ts constrain

clinic-pilot-escalate: ## ESCALATE: a refund request -> PENDING_APPROVAL (no execution yet)
	$(CLINIC_AGENT) npx tsx src/clinic-cli.ts escalate

clinic-pilot-approve: ## Clinic operator APPROVES (operator key); then the clinic agent executes with ITS OWN credential -> EXECUTED
	$(CLINIC_GATEWAY) python -m integrations.voltagent.mcc_side.operator_cli
	$(CLINIC_AGENT) npx tsx src/clinic-cli.ts execute-approved

clinic-pilot-audit-verify: ## Verify the persisted cryptographic audit chain
	$(CLINIC_GATEWAY) python -c "import sys; sys.path.insert(0,'/app/src'); from mcc_core import AuditLog; ok=AuditLog.verify_chain('/data/audit.jsonl'); print('audit chain valid=%s' % ok); sys.exit(0 if ok else 1)"

clinic-pilot-restart-check: ## Prove the audit chain survives a restart
	$(MAKE) clinic-pilot-allow
	@echo "restarting the gateway (audit + keys are on persistent volumes)..."
	$(CLINIC_COMPOSE) restart mcc-gateway
	$(MAKE) clinic-pilot-ready
	$(MAKE) clinic-pilot-audit-verify
	@echo "audit persisted and re-verified after restart."

clinic-pilot-demo: ## Run all four verdicts + approval + audit verification end to end
	$(MAKE) clinic-pilot-allow
	$(MAKE) clinic-pilot-deny
	$(MAKE) clinic-pilot-constrain
	$(MAKE) clinic-pilot-escalate
	$(MAKE) clinic-pilot-approve
	$(MAKE) clinic-pilot-audit-verify
	@echo "\nAXFLOW CLINIC DEMO COMPLETE: ALLOW + DENY + CONSTRAIN + ESCALATE(+approve) + audit verified."

clinic-pilot-ps: ## Show clinic pilot container status
	$(CLINIC_COMPOSE) ps

clinic-pilot-logs: ## Tail clinic pilot logs
	$(CLINIC_COMPOSE) logs --no-color --timestamps

clinic-pilot-down: ## Stop the clinic stack, KEEPING volumes (audit persists)
	$(CLINIC_COMPOSE) down

clinic-pilot-clean: ## Stop the clinic stack and REMOVE volumes (wipes the audit chain)
	$(CLINIC_COMPOSE) down -v --remove-orphans

.PHONY: independent-assurance mutation-test verify-assurance
ASSURANCE_PYTHONPATH := src:.:sdk/python/src
independent-assurance: ## Run the independent adversarial assurance suite (PR #71); writes a signed evidence bundle
	PYTHONPATH=$(ASSURANCE_PYTHONPATH) python -m assurance run --output artifacts/independent-assurance

mutation-test: ## Run the mutation/defects.py corpus (PR #71 Workstream J); exit 0 iff every defect is detected
	PYTHONPATH=. python -m mutation --output artifacts/mutation-report.json

verify-assurance: ## Reproducible entry point: independent-assurance + TLC + mutation-test, in order, fail-fast, non-destructive. See docs/REPRODUCING_ASSURANCE.md. NOTE: make's own exit code is always 0/2 (GNU Make convention) -- run scripts/verify_assurance.sh directly for the exact originating exit code.
	@bash scripts/verify_assurance.sh
