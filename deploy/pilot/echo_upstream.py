"""Tiny echo upstream for the pilot deployment.

Stands in for the external service the agent ultimately calls. It only ever sees
traffic that MCC-Core has already authorized and forwarded through the one
governed path — a blocked decision never reaches it. It echoes the body it
received so the runbook can show exactly what was executed (e.g. the clamped
amount for CONSTRAIN, never the original).

This is not part of the governance runtime; it is the thing being governed.
"""

from __future__ import annotations

from fastapi import FastAPI, Request

app = FastAPI(title="MCC pilot echo upstream")


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}


@app.api_route("/{action:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def echo(action: str, request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:
        body = {}
    return {"upstream_reached": True, "action": action, "received": body}
