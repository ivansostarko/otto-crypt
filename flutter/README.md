# OTTO Crypt — Flutter Demo App

A minimal Flutter app that demonstrates OTTO Crypt for:
- **Text** encryption/decryption (shows base64 ciphertext+tag and header)
- **Files** (photos, documents, audio, video) — large-file streaming

The app is interoperable with the Laravel, Node, Python, .NET, Java/Android, Swift, and C++ OTTO ports.

## How to run

1. Ensure you have the OTTO Dart package available at `../otto-crypt-flutter` (the demo depends on it by **path** in `pubspec.yaml`).  
   If your layout is different, update the `otto_crypt` dependency path.
2. From this demo folder:
   ```bash
   flutter pub get
   flutter run
   ```

## Using the app

- The top tabs switch between **Text** and **Files**.
- Choose a mode:
  - **Password (Argon2id)** — enter a password.
  - **X25519** — for encrypt: recipient public key; for decrypt: sender secret key.
  - **Raw 32-byte key** — enter a base64/hex/raw 32-byte key.
- **Text tab**: enter plaintext and press **Encrypt** → copy `ciphertext+tag (base64)` and `header (base64)`; paste into **Decrypt** section with the same mode.
- **Files tab**: pick any input file, then **Suggest output** (the app proposes a file in your app documents dir), and press **Run**.
  - When **Encrypt** is selected, output ends with `.otto`.
  - When **Decrypt**, output defaults to `.dec`.

## Interop

- The demo uses the same header/wire format as Laravel:
  - AD = header; chunks = `[len(4-BE)][cipher][tag(16)]`
  - HKDF labels: `OTTO-ENC-KEY`, `OTTO-NONCE-KEY`, `OTTO-CHUNK-NONCE`, `OTTO-E2E-MASTER`
- You can encrypt in this app and decrypt with any other OTTO implementation, provided the same mode/keys.

## Notes

- The `otto_crypt` package internally uses **libsodium** for Argon2id and X25519 (via `sodium`/`sodium_libs`). Mobile/desktop are supported out of the box.
- This is a demo; add robust validation & error handling for production.

MIT © 2025 Ivan Sostarko
