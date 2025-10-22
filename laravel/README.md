# OTTO Crypt — Demo Laravel App Overlay

This folder contains a **demo overlay** (controllers, routes, and a Blade view) to add an interactive demo UI for **text and file (photo, document, audio, video)** encryption/decryption on top of a standard Laravel app using **OTTO Crypt**.

> Demo UI covers: text encrypt/decrypt (showing header/cipher), and streaming file encrypt/decrypt with password, X25519, or raw key modes.

## Repo links

- Package: https://github.com/ivansostarko/otto-crypt-php  
- Demo App (this overlay): https://github.com/ivansostarko/otto-crypt


## Prerequisites

- PHP 8.2+ with `ext-openssl` and `ext-sodium`.
- Laravel  12 application.
- OTTO Crypt package installed.


## UI
![Alt text](https://ivansostarko.github.io/assets/github-page/github_php-demo.png)


## Docker

This repo includes **Dockerfile** and **docker-compose.yml** that set up PHP 8.2 + Composer + required extensions.

---

## Install OTTO Crypt in your Laravel app

```bash
composer require ivansostarko/otto-crypt-php
php artisan vendor:publish --provider="IvanSostarko\OttoCrypt\OttoCryptServiceProvider"
```



## Run the demo

Serve the app:

```bash
Open http://127.0.0.1:80/
```

## Using the demo

- **Text → Encrypt**: enter plaintext and choose **Password**, **X25519 (recipient public)**, or **Raw key**.
  - Shows **Ciphertext+Tag (base64)** and **Header (base64)** that you can copy.
- **Text → Decrypt**: paste those two base64 strings and choose the appropriate mode.
- **Files (photos/docs/audio/video)**:
  - **Encrypt**: upload any file → downloads `<name>.otto` (streaming AEAD).
  - **Decrypt**: upload `.otto` → downloads `<name>.dec`.

### Key modes

- **Password**: Uses **Argon2id** to derive a per-file master key.
- **X25519 (E2E)**: Provide **recipient public key** for encryption. For decryption supply your **sender secret key**.
- **Raw key**: Provide a 32-byte key (base64/hex/raw). Only for advanced setups.

## Security notes (demo)

- This is a **demo**. Always validate and sanitize user inputs in production. Limit maximum file sizes and enforce strict MIME/extension checks.
- The demo streams files through PHP for simplicity; in production you may want to stream from/to disk or S3.
- Keep secret keys out of logs and client-side code.

## Troubleshooting

- "OpenSSL encryption failed" or "Decryption failed (auth?)": likely wrong key/password or corrupted header/cipher.
- "Raw key must be 32 bytes": supply correct base64/hex/raw.
- Permission errors: ensure `storage/` is writable by the web server user.


## Run CLI (examples)

### CLI (Artisan)

**Encrypt with a password (Argon2id):**
```bash
php artisan otto:encrypt storage/app/private/otto-demo/test.exe --out=storage/app/private/otto-demo/test.exe.otto --password="strong-pass"
```

**Decrypt with a password:**
```bash
php artisan otto:decrypt storage/app/private/otto-demo/test.exe --out=storage/app/private/otto-demo/test.exe.otto --password="strong-pass"
```

**End‑to‑end: encrypt to a recipient’s X25519 public key (base64/hex/raw):**
```bash
php artisan otto:encrypt storage/app/private/otto-demo/big.mov --out=storage/app/big.mov.otto --recipient="BASE64_OR_HEX_PUBLIC"
```

**End‑to‑end: decrypt with your X25519 secret key:**
```bash
php artisan otto:decrypt storage/app/private/otto-demo/big.mov.otto --out=storage/app/big.mov --sender-secret="BASE64_OR_HEX_SECRET"
```

### Laravel API (Facade)

```php
use IvanSostarko\OttoCrypt\Facades\OttoCrypt as Otto;

// Encrypt & decrypt small strings (single-shot)
[$cipherAndTag, $header] = Otto::encryptString("Hello OTTO!", options: ['password' => 'P@ssw0rd!']);
$plain = Otto::decryptString($cipherAndTag, $header, options: ['password' => 'P@ssw0rd!']);

// Streaming files (chunked)
Otto::encryptFile($inPath, $outPath, options: ['password' => 'P@ssw0rd!']);
Otto::decryptFile($inPath, $outPath, options: ['password' => 'P@ssw0rd!']);

// E2E using X25519 (recipient public key)
Otto::encryptFile('in.mov', 'in.mov.otto', options: ['recipient_public' => $recipientPkBase64]);

// E2E decryption using your X25519 secret (sender_secret)
Otto::decryptFile('in.mov.otto', 'in.mov', options: ['sender_secret' => $mySecretBase64]);
```



## FAQ

**Q: Is OTTO Crypt FIPS compliant?**  
A: It uses OpenSSL’s AES‑GCM and HKDF, which may be FIPS‑validated depending on your OpenSSL build, but the **overall construction is custom** and not a NIST‑standard scheme.

**Q: Can I rotate keys?**  
A: Yes. Re‑encrypt with a new recipient public key or password. The header binds parameters to ciphertext.

**Q: Why not random nonces?**  
A: Random or monotonic nonces are fine if implemented perfectly. Deterministic HKDF‑derived nonces help avoid catastrophic accidental reuse in complex streaming/parallel code.

**Q: Message vs file?**  
A: `encryptString` for small payloads; `encryptFile` for streaming large data (audio/video/files).

**Q: Does this replace libsodium secretstream?**  
A: No. If you can use libsodium’s `crypto_secretstream`, it’s excellent. OTTO focuses on AES‑GCM, Laravel integration, and simple E2E helper flows.

---

## Contributing

PRs welcome. Please include:
- Clear problem statement
- Tests (PHPUnit / Testbench)
- Security considerations for cryptographic changes

Before suggesting algorithmic changes, open an issue to discuss implications.

---

## License

MIT © 2025 Ivan Sostarko

---

## Responsible disclosure

If you discover a vulnerability, **do not open a public issue**. Email the maintainer privately (see `composer.json` author) with details and steps to reproduce. We’ll coordinate a fix and a responsible disclosure timeline.
