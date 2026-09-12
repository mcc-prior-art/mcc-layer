# External Pilot Integration Pack

Makes the already-proven PR #111 (Pilot Execution API) + PR #112
(agent/framework/actuator-neutral real execution proof) governed
execution boundary consumable by an external engineering team with
minimal integration friction.

```
YOUR AGENT
   |
   | generic proposal over HTTP
   v
MCC PILOT API              (POST /v1/proposals)
   |
   v
VERIFIABLE EXECUTION AUTHORITY    (trusted authority evaluation, signed token)
   |
   v
CONTROLLED EXECUTION BOUNDARY     (POST /v1/operations/{id}/execute)
   |
   v
YOUR ACTUATOR
```

Full integration guide, including exactly how to connect your own agent
and your own actuator: [`docs/EXTERNAL_PILOT_INTEGRATION.md`](../../docs/EXTERNAL_PILOT_INTEGRATION.md).

## Fresh-clone quick start

Prerequisites: Python 3.11+, this repository cloned, dependencies
installed (`pip install -r requirements.txt -r requirements-dev.txt`).
Nothing else — the quick-start below makes zero external network calls,
requires zero credentials, and needs no Redis or other external service.

```bash
PYTHONPATH=src:.:sdk/python/src python3 examples/external_pilot/run_external_pilot_self_check.py
```

This single command: builds an in-memory governed stack (the SAME
`gateway.proposal_execution_stack.build_proposal_execution_stack` every
other governed HTTP surface in this repository uses), starts a real
`uvicorn` server on a real TCP port, and drives all eight required pilot
scenarios (happy path, policy denial, replay, tenant isolation, resource
binding, payload/action binding, UNKNOWN/reconciliation, unauthenticated
fail-closed) against it over real HTTP — printing a JSON evidence summary
and exiting non-zero if any invariant fails.

To instead run just the offline, pytest-based version of the same
scenarios:

```bash
PYTHONPATH=src:.:sdk/python/src pytest tests/test_external_pilot_scenarios.py -v
```

## What's here

```
examples/external_pilot/
├── README.md                          <- this file
├── .env.example                       <- safe placeholders; no secrets
├── server.py                          <- deployable/demo composition (reuses gateway.proposal_execution_stack)
├── scenarios.py                       <- the 8 required pilot scenarios, real-HTTP, reusable by pytest and the self-check
├── run_external_pilot_self_check.py   <- the fresh-clone self-check entry point
├── client/
│   ├── mcc_pilot_client.py            <- reference HTTP client (httpx only; zero MCC-Core imports)
│   └── example_producer.py            <- THE ONE FILE to replace with your own agent's output translation
└── actuator/
    └── demo_actuator.py               <- bring-your-own-actuator template (ResourceBoundUpstream); obviously non-production
```

## Not yet proven by this pack alone

See `docs/EXTERNAL_PILOT_INTEGRATION.md` §"What this proves / does not
prove" for the full, explicit list — in short: this pack is READY FOR
third-party integration attempts; it is not itself evidence of an actual
independent third party having integrated, a production deployment, or
any formal/regulatory certification.
