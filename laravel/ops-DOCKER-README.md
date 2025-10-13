# Docker usage for OTTO Crypt JS (Node.js)

This Docker setup lets you run the **otto-crypt-js** CLI and Node APIs without installing Node on your host.

## Prereqs
- Docker + Docker Compose v2

## Build
```bash
docker compose up -d --build
```

## Install package deps (inside container)
```bash
docker compose run --rm setup
```
> This runs `npm ci` (or `npm install`) in `/package`, which is your repo mounted into the container.

## Folder mounts
- `/package` → your current repo (where this Dockerfile lives).
- `/data` → host folder for test files (set `DATA_PATH=...` or defaults to `../data`).

## Run CLI (examples)

**Encrypt with password:**
```bash
docker compose run --rm app node /package/bin/otto-crypt.js encrypt /data/in.mp4 /data/in.mp4.otto --password="P@ssw0rd!"
```

**Decrypt with password:**
```bash
docker compose run --rm app node /package/bin/otto-crypt.js decrypt /data/in.mp4.otto /data/in.dec.mp4 --password="P@ssw0rd!"
```

**E2E encrypt to X25519 public key (base64 or hex):**
```bash
docker compose run --rm app node /package/bin/otto-crypt.js encrypt /data/photo.jpg /data/photo.jpg.otto --recipient="BASE64_OR_HEX_PUBLIC"
```

**E2E decrypt with X25519 secret key:**
```bash
docker compose run --rm app node /package/bin/otto-crypt.js decrypt /data/photo.jpg.otto /data/photo.jpg --sender-secret="BASE64_OR_HEX_SECRET"
```

## Use programmatic API quickly
Open a shell in the container:
```bash
docker compose exec app bash
```
Then within `/package`, run a Node REPL or a small script that imports:
```bash
node -e "const {OttoCrypt}=require('./src'); (async()=>{const o=new OttoCrypt(); const r=await o.encryptString(Buffer.from('hi'),{password:'x'}); console.log(r.header.length, r.cipher.length)})()"
```

## Notes
- We use `node:22-bookworm-slim` and `tini` for a clean PID 1.
- No native system libs required; `libsodium-wrappers` ships its own WASM.
- If you prefer global install of the CLI, you can run `npm i -g /package` inside the container and then call `otto-crypt` directly.
