# Release Notes — MCC-Core Pilot v0.1 (`v0.1.0-pilot`)

First release-grade baseline of the **real governed agent pilot**: an AI agent
whose external actions are governed end to end by MCC-Core, with reproducible
validation from a fresh clone.

## Highlights

- **Real governed execution path.** User goal → governed agent → structured
  proposal → MCC-Core (authority + decision token + gate + coordinator) →
  ALLOW / DENY / ESCALATE / CONSTRAIN → execution gate → governed HTTPS executor
  → external pilot API → audit chain. No parallel governance or execution path
  was added — the existing `src/mcc_core/` and `egress_proxy/` are reused.
- **Canonical one-command demos.** `python -m mcc_agent.demo --verdicts` (the
  four governed verdicts, staged with audit evidence) and
  `docker compose -f docker-compose.pilot.yml up --build` (full stack: agent +
  gateway/runtime + Redis + governed HTTPS executor + separate external API).
- **Audit evidence per decision.** proposal id, actor, resource, action hash,
  payload hash, policy hash, authority state, verdict, constraints, execution
  result, and audit-chain linkage; audit-before-execution and chain verification
  validated.
- **No-bypass guarantees.** The governed HTTPS executor is the only outbound
  path; a static guard fails if `requests`/`urllib`/`httpx`/`aiohttp`/`socket`/
  `subprocess`/… is imported in the agent package, plus a direct-bypass test.
- **Fail-closed reproducibility.** Selecting a Redis backend without
  `MCC_REDIS_URL` refuses startup; no secrets are committed; safe example config
  is provided.

## Components

`src/mcc_agent/` (agent), `pilot_api/` (external API), `docker-compose.pilot.yml`
+ `deploy/pilot/` (containerized stack), `evidence/governed_agent_pilot/`
(reproducible evidence), `PILOT.md` + `docs/MCC_CORE_PILOT_V0_1.md` (docs).

## Validation

```
PYTHONPATH=src python -m mcc_agent.demo --verdicts                       # 4/4 verdicts PASS
PYTHONPATH=src python -m mcc_agent.demo                                  # 10/10 checks PASS
python -m pytest tests/test_mcc_agent.py tests/test_pilot_release.py \
                 tests/test_mcc_agent_no_direct_egress.py -q             # green
MCC_REDIS_URL=redis://127.0.0.1:6399/0 python -m pytest tests/ -q        # full suite green
```

## Known limitations

Deterministic planner only (no LLM); per-action pilot authority in-process vs.
host/method/amount authority in the containerized gateway (same engine, different
config); ephemeral signing keys; config-level mandates; the Docker network
boundary is a pilot illustration. See `docs/MCC_CORE_PILOT_V0_1.md` §9–10 for the
production hardening list.

## Tagging (post-merge, manual — not performed automatically)

After this PR is reviewed and merged into `main` by the maintainer:

```bash
git tag -a v0.1.0-pilot -m "MCC-Core Pilot v0.1"
git push origin v0.1.0-pilot
```

This PR does **not** create or push the tag.
