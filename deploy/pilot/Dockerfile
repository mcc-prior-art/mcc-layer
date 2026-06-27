# MCC-Core pilot gateway image — the unified governance runtime as an HTTP service.
#
# Build context is the repository root:
#   docker build -f deploy/pilot/Dockerfile -t mcc-pilot-gateway .
# (docker-compose.yml in this directory sets the context to the repo root.)
FROM python:3.11-slim

# Non-root runtime user.
RUN useradd --create-home --uid 10001 mcc

WORKDIR /app

# Dependencies first for layer caching.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# The unified runtime + the gateway adapter. No keys or secrets are copied in;
# they are mounted at runtime (see docker-compose.yml / RUNBOOK.md).
COPY src /app/src
COPY gateway /app/gateway
COPY config /app/config
# The pilot echo upstream (the governed-but-external service for the demo).
COPY deploy/pilot/echo_upstream.py /app/echo_upstream.py

# Writable audit volume mountpoint.
RUN mkdir -p /data && chown -R mcc:mcc /data /app
USER mcc

EXPOSE 8001

# Liveness/readiness are HTTP endpoints (/health, /ready); see compose healthcheck.
CMD ["uvicorn", "gateway.app:app", "--host", "0.0.0.0", "--port", "8001"]
