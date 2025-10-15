# Docker usage for OTTO Crypt PY (Python)

Run the **otto-crypt-py** CLI and APIs in a container without installing Python and crypto libs locally.

## Quick start

1) Build the image and start the background container:
```bash
docker compose up -d --build
```

2) Install the package inside the container (editable install from the mounted repo):
```bash
docker compose run --rm setup
```

3) Use the CLI (the script `otto` is installed into PATH inside the container):

**Encrypt with password:**
```bash
docker compose run --rm app otto encrypt /data/in.mp4 /data/in.mp4.otto --password "P@ssw0rd!"
```

**Decrypt with password:**
```bash
docker compose run --rm app otto decrypt /data/in.mp4.otto /data/in.dec.mp4 --password "P@ssw0rd!"
```

**E2E encrypt to X25519 public key (base64 or hex or raw 32 bytes):**
```bash
docker compose run --rm app otto encrypt /data/photo.jpg /data/photo.jpg.otto --recipient "<BASE64_OR_HEX_PUBLIC>"
```

**E2E decrypt with X25519 secret key:**
```bash
docker compose run --rm app otto decrypt /data/photo.jpg.otto /data/photo.jpg --sender-secret "<BASE64_OR_HEX_SECRET>"
```

4) Open a shell for programmatic usage:
```bash
docker compose exec app bash
python - <<'PY'
from otto_crypt import OttoCrypt
o = OttoCrypt()
cipher, header = o.encrypt_string(b"hi", options={"password":"x"})
print(len(header), len(cipher))
PY
```

## Notes
- Base image: `python:3.12-slim`. We install minimal build deps (`build-essential`, `libsodium-dev`, `libssl-dev`) to cover environments where wheels aren’t available.
- The repo is mounted at `/package`. The `setup` service runs `pip install -e /package` so changes reflect immediately.
- `/data` is a convenience volume for test files; override via `DATA_PATH=/absolute/host/path`.
