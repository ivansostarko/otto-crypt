# syntax=docker/dockerfile:1.6
FROM python:3.12-slim

# System deps (keep minimal). Wheels should cover cryptography & pynacl,
# but include build tools in case we need to build from source.
RUN apt-get update && apt-get install -y --no-install-recommends \    build-essential \    pkg-config \    libssl-dev \    libsodium-dev \    bash ca-certificates tini \    && rm -rf /var/lib/apt/lists/*

# Use tini as PID 1
ENTRYPOINT ["/usr/bin/tini","--"]

ENV PIP_NO_CACHE_DIR=1 \    PYTHONDONTWRITEBYTECODE=1 \    PYTHONUNBUFFERED=1

# Workdir for interactive usage
WORKDIR /work

# Default command keeps container alive; use docker compose run to execute the CLI
CMD ["bash","-lc","tail -f /dev/null"]
