# OTTO Android Demo App

A simple Android app that demonstrates **text** and **file** (photo/audio/video/any) encryption using the **OTTO** algorithm. It uses the `:ottocrypt-android` library module (AES-256-GCM + HKDF nonces, streaming).

## Features
- Generate or paste a **32-byte raw key** (Base64).
- **Text demo**: encrypts a message and shows `HEADER_B64` and `CIPHER_B64`; decrypts back.
- **File demo**: pick any file via the system picker; encrypts to `*.otto` and decrypts back (chunked streaming).

## Build & Run
Open the project in **Android Studio** (Giraffe+). Build and run the `app` module on a device/emulator (API 24+).

No storage permissions are required (uses **Storage Access Framework** + app cache).

## Interop
The demo is wire-compatible with the Laravel SDK and other OTTO SDKs:
- Header: `"OTTO1"|0xA1|0x02|flags|0x00|u16_be(16)|file_salt[16]`
- Keys via HKDF-SHA256 (`OTTO-ENC-KEY`, `OTTO-NONCE-KEY`)
- Chunk nonces via HKDF-SIV style (`OTTO-CHUNK-NONCE || counter_be64` → 12B)
- AES-256-GCM, tag 16B, AAD = header
- Streaming container: `header || [u32_be ct_len || ct || tag16]*`

## Notes
- Encrypted/decrypted files are stored in app **cache**; use `adb pull` if you need to export them.
- X25519 helpers available on API 28+ (not used in this basic UI).

MIT © 2025 Ivan Doe
