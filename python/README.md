# OTTO Crypt PY — Demo App (Flask)

A minimal **Flask** app that demonstrates **text** and **file** (photo, documents, audio, video) encryption/decryption using the **OTTO Crypt PY** package. The output format is interoperable with the Laravel and Node implementations.

## Features
- Text encryption/decryption (shows base64 ciphertext+tag and header)
- Streaming file encryption/decryption (`.otto` format)
- Three keying modes: **Password (Argon2id)**, **X25519 E2E**, and **Raw 32‑byte key**
- X25519 keypair generator endpoint (`/keys`)

## Prerequisites
- Python 3.9+
- The **otto-crypt-py** package installed (editable or from your local path)

## Install & Run
```bash
# 1) Install dependencies
pip install -r requirements.txt

# 2) Install the OTTO package (from your local path)
pip install -e ../otto-crypt-py     # adjust path as needed

# 3) Run the demo
python app.py
# Open http://localhost:5000
```

## Usage
- **Text → Encrypt**: enter plaintext, pick mode, and submit. The page shows base64 **ciphertext+tag** and **header**.
- **Text → Decrypt**: paste the two base64 strings and submit.
- **Files**: upload any file to encrypt (`.otto` download) or upload `.otto` to decrypt (`.dec` download).
- **X25519 Keys**: click the **Generate** button to get base64 and hex keys.

## Notes
- This is a **demo**. In production, limit upload sizes, check MIME types, and move secrets off the UI.
- The app stores temp files under `uploads/` and `tmp/` (gitignored).

## Project layout
```
app.py                 # Flask server
templates/index.html   # UI template
static/style.css       # basic styling
requirements.txt
```

---

MIT © 2025 Ivan Sostarko
