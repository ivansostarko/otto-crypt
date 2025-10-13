# OTTO Crypt JS — Demo App

A small **Express + EJS** app demonstrating **text** and **file** (photo, documents, audio, video) encryption/decryption using the **OTTO Crypt JS** package (compatible with the Laravel package).

## Features
- Text encrypt/decrypt with password, X25519, or raw 32-byte keys
- Streaming file encryption/decryption (large files)
- X25519 keypair generator endpoint
- Simple UI

## Prerequisites
- Node.js >= 18
- Install the OTTO package: either from npm once published or from a local path

### Option A: Use local path (monorepo/dev)
Assuming this demo and the package live side-by-side like:
```
/path/otto-crypt-js
/path/otto-crypt-js-demo  (this folder)
```
Install dependencies and link the local package:
```bash
cd /path/otto-crypt-js-demo
npm install
npm install ../otto-crypt-js
```

### Option B: From npm (when published)
```bash
npm install
npm install otto-crypt-js
```

## Run
```bash
npm start
# open http://localhost:8080
```

## Usage
- **Text → Encrypt**: enter plaintext, pick mode, and submit. The page shows base64 **ciphertext+tag** and **header**.
- **Text → Decrypt**: paste base64 values and submit.
- **Files**: upload a file for encryption (.otto output) or upload an `.otto` file to decrypt (.dec output).  
  Works for images, PDFs, audio, video, etc.
- **X25519 Keys**: click **Generate** to get a fresh keypair (base64). Share **public**; keep **secret** safe.

## Security Notes
- This is a **demo**. In production:
  - Limit maximum upload sizes and sanitize MIME types/filenames.
  - Keep secrets out of logs and client-side code.
  - Use HTTPS.
  - Consider storing encrypted outputs in object storage and streaming directly.
- See the main package README for the full algorithm spec and security considerations.

## Troubleshooting
- "Encrypt/Decrypt error": typically wrong mode/password/key or corrupted header/cipher.
- Permission errors: ensure this app can write to `uploads/` and `tmp/` folders.

---

MIT © 2025 Ivan Sostarko
