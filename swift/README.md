# OTTO Crypt — Swift Demo App (CLI)

This is a **Swift command-line demo** that exercises the `IvanSostarkoOttoCrypt` Swift package for:
- **Text** encryption/decryption
- **Files** (photos, documents, audio, video — any file) encryption/decryption via streaming
- **X25519 key generation**

It is fully **interoperable** with the Laravel/Node/Python/C#/Java/C++ ports.

> This demo depends on the library via a **local path dependency** set to `../OttoCryptSwift`. Adjust the dependency in `Package.swift` if your directory layout differs.

## Prerequisites
- Xcode 15+ or Swift 5.9+ toolchain
- The OTTO Swift library in `../OttoCryptSwift` (or change the path in this demo's `Package.swift`)

## Build
```bash
swift build -c release
# binary at .build/release/otto-swift-demo
```

## Usage

### Generate an X25519 keypair
```bash
.build/release/otto-swift-demo keygen
```

### Text

**Encrypt (password):**
```bash
.build/release/otto-swift-demo text:encrypt --password="P@ssw0rd!" --in="Hello OTTO"
# prints cipher_b64=... and header_b64=...
```

**Decrypt (password):**
```bash
.build/release/otto-swift-demo text:decrypt --password="P@ssw0rd!" --cipher-b64="..." --header-b64="..."
```

**Encrypt to recipient X25519 public key:**
```bash
.build/release/otto-swift-demo text:encrypt --recipient-public="<BASE64_OR_HEX_OR_RAW>" --in="Hello"
```

**Decrypt with sender X25519 secret key:**
```bash
.build/release/otto-swift-demo text:decrypt --sender-secret="<BASE64_OR_HEX_OR_RAW>" --cipher-b64="..." --header-b64="..."
```

### Files (photos, audio, video, docs)

**Encrypt (password):**
```bash
.build/release/otto-swift-demo file:encrypt --in=movie.mp4 --out=movie.mp4.otto --password="P@ssw0rd!"
```

**Decrypt (password):**
```bash
.build/release/otto-swift-demo file:decrypt --in=movie.mp4.otto --out=movie.dec.mp4 --password="P@ssw0rd!"
```

**Encrypt to recipient (X25519):**
```bash
.build/release/otto-swift-demo file:encrypt --in=photo.jpg --out=photo.jpg.otto --recipient-public="<BASE64_OR_HEX_OR_RAW>"
```

**Decrypt with sender secret (X25519):**
```bash
.build/release/otto-swift-demo file:decrypt --in=photo.jpg.otto --out=photo.jpg --sender-secret="<BASE64_OR_HEX_OR_RAW>"
```

**Raw key mode (32 bytes base64/hex/raw):**
```bash
.build/release/otto-swift-demo file:encrypt --in=audio.mp3 --out=audio.mp3.otto --raw-key="<base64-or-hex>"
```

## Interop
All headers, HKDF labels, nonce derivations, and chunk formats match the Laravel implementation, enabling cross-language encryption/decryption.

## Notes
- Binary format & algorithm details are documented in the library README.
- This CLI is intentionally minimal and avoids extra dependencies.
- For a GUI sample (SwiftUI), I can add a macOS app that wraps the same APIs.

MIT © 2025 Ivan Sostarko
