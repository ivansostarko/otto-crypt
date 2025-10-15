# OTTO Crypt — Demo Laravel App Overlay

This folder contains a **demo overlay** (controllers, routes, and a Blade view) to add an interactive demo UI for **text and file (photo, document, audio, video)** encryption/decryption on top of a standard Laravel app using **OTTO Crypt**.

> Demo UI covers: text encrypt/decrypt (showing header/cipher), and streaming file encrypt/decrypt with password, X25519, or raw key modes.

## Repo links

- Package: https://github.com/ivansostarko/otto-crypt-php  
- Demo App (this overlay): https://github.com/ivansostarko/otto-crypt


## Prerequisites

- PHP 8.1+ with `ext-openssl` and `ext-sodium`.
- Laravel 10 or 11 application.
- OTTO Crypt package installed.

## Docker

This repo includes **Dockerfile** and **docker-compose.yml** that set up PHP 8.3 + Composer + required extensions. See `ops-DOCKER-README.md` for step‑by‑step usage.

---

## Install OTTO Crypt in your Laravel app

```bash
composer require ivansostarko/otto-crypt-php
php artisan vendor:publish --provider="IvanSostarko\OttoCrypt\OttoCryptServiceProvider"
```

## Add the demo overlay

Copy the contents of this `demo-app` folder into the root of your Laravel app:

```
app/Http/Controllers/OttoDemoController.php
resources/views/otto-demo.blade.php
routes/otto-demo.php
```

Then include the demo routes from your `routes/web.php`:

```php
<?php
// routes/web.php
use Illuminate\Support\Facades\Route;

Route::get('/', function () { return view('welcome'); });
require base_path('routes/otto-demo.php');
```

(Optional) Ensure local storage is writeable (for uploaded files and encrypted outputs):

```bash
php artisan storage:link
chmod -R 775 storage bootstrap/cache
```

## Run the demo

Serve the app:

```bash
php artisan serve
# Open http://127.0.0.1:8000/otto-demo
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

## Uninstall

Remove the controller, view, and route include, and delete the routes line from `routes/web.php`.

---

MIT © 2025 Ivan Sostarko
