# syntax=docker/dockerfile:1.6
FROM node:22-bookworm-slim

# Optional: useful tools
RUN apt-get update && apt-get install -y --no-install-recommends \    bash ca-certificates tini \    && rm -rf /var/lib/apt/lists/*

# Ensure CA store & tini
ENV NODE_ENV=production
ENTRYPOINT ["/usr/bin/tini","--"]

# Workdir
WORKDIR /work

# Keep container alive by default; we will run commands with `docker compose run --rm app <cmd>`
CMD ["bash","-lc","tail -f /dev/null"]
