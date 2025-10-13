# OTTO Encryption Algorithm

**OTTO** is a pragmatic, cross-language encryption format and reference implementation designed for secure messaging and large-file protection. It combines **AES-256-GCM** with a careful **HKDF** key schedule, **Argon2id** password hardening, optional **X25519** E2E key agreement, and a robust **streaming (chunked) AEAD** layout that works for text, photos, documents, audio, and video.

- **Security:** AEAD (confidentiality + integrity), header is bound as AAD, deterministic HKDF-SIV–style nonces eliminate user-managed nonces.
- **Interoperability:** Identical wire format across SDKs; encrypt in PHP/Laravel, decrypt in Node, Python, C#, Swift, Java/Android, or Flutter—and vice versa.
- **Scales to big media:** Chunked streaming with per-chunk AEAD tags; constant memory regardless of file size.
- **Open:** MIT-licensed, human-readable spec, and production-grade reference SDKs.

> ⚠️ **Status:** OTTO is a composition of well-studied primitives, but the construction itself is new. Obtain an **independent cryptographic review** before production deployment.

---

## Table of Contents

1. [Design Goals](#design-goals)  
2. [Wire Format Overview](#wire-format-overview)  
3. [Header Layout](#header-layout)  
4. [Streaming / Chunk Format](#streaming--chunk-format)  
5. [Key Derivation](#key-derivation)  
6. [Nonce Derivation (HKDF-SIV style)](#nonce-derivation-hkdf-siv-style)  
7. [Password Mode (Argon2id)](#password-mode-argon2id)  
8. [X25519 End-to-End Mode](#x25519-end-to-end-mode)  
9. [Why OTTO vs. Alternatives](#why-otto-vs-alternatives)  
10. [Security Properties & Caveats](#security-properties--caveats)  
11. [Reference SDKs & Demos](#reference-sdks--demos)  
12. [Interoperability Checklist](#interoperability-checklist)  
13. [Parameter Guidance](#parameter-guidance)  
14. [FAQ](#faq)  
15. [License](#license)

---

## Design Goals

- **Safer defaults:** Avoid nonce-reuse footguns, bind metadata via AAD, and separate keys by purpose via HKDF labels.
- **E2E first:** Make authenticated key exchange straightforward (X25519), while preserving password support for file lockers.
- **Streaming:** Support terabyte-scale media through constant-memory encryption/decryption.
- **Portability:** One binary format, identical across languages, with small implementation surface and zero surprises.

---

## Wire Format Overview

An OTTO object is:

```
[ HEADER ] [ CHUNK_0 ] [ CHUNK_1 ] ... [ CHUNK_n ]
```

- **HEADER**: fixed + variable part (versioned) that encodes KDF, salts, and (for E2E) the sender’s **ephemeral X25519 public key**.  
  The complete header is **Additional Authenticated Data (AAD)** for all AEAD operations.
- **CHUNK_i**: authenticated records, each with its own GCM tag, enabling random access and robust streaming.

AEAD: **AES-256-GCM** (16-byte tag).  
KDF: **HKDF(SHA-256)** with explicit labels for key separation.  
Password KDF: **Argon2id** (libsodium `crypto_pwhash`).  
E2E: **X25519** (libsodium `crypto_scalarmult`) with sender-ephemeral → recipient-static.

---

## Header Layout

Fixed prefix (11 bytes):

| Field        | Size | Value / Notes                                             |
|--------------|------|-----------------------------------------------------------|
| `magic`      | 5    | ASCII `"OTTO1"`                                           |
| `algo_id`    | 1    | `0xA1` (this OTTO construction)                           |
| `kdf_id`     | 1    | `0x01`=password, `0x02`=raw key, `0x03`=X25519            |
| `flags`      | 1    | bit0=`1` if streaming/chunked payload                     |
| `reserved`   | 1    | `0x00` (for future use)                                   |
| `header_len` | 2    | big-endian length of variable part (HVAR)                 |

Variable part **HVAR** (`header_len` bytes):

- Always:
  - `file_salt` (16 bytes)
- If `kdf_id=0x01` (password):
  - `pw_salt` (16 bytes)
  - `opslimit` (uint32 BE)
  - `memlimitKiB` (uint32 BE)
- If `kdf_id=0x03` (X25519):
  - `eph_pubkey` (32 bytes) — sender’s ephemeral X25519 public key
- If `kdf_id=0x02` (raw key): no additional fields

**AAD:** The **entire header** (fixed + HVAR) is passed as AEAD associated data for every encryption operation.

---

## Streaming / Chunk Format

After the header, the payload is a sequence of AEAD chunks:

```
repeat:
  [ clen (u32 BE) ] [ ciphertext (clen bytes) ] [ tag (16 bytes) ]
until EOF
```

- Each chunk is an independent AES-GCM encryption with the **same `enc_key`** but **different nonces**, derived deterministically from a counter (see [Nonce Derivation](#nonce-derivation-hkdf-siv-style)).
- Chunking provides:
  - **O(1) memory** usage for huge files,
  - Fast **resume/retry**,
  - **Partial verification** (detect corruption early),
  - Optional **random access** by re-deriving the nonce for a given counter.

> Typical default chunk size: **1 MiB** (configurable).

---

## Key Derivation

1. **Master key** `master` is obtained from exactly one of:
   - **Password:** `Argon2id(password, pw_salt, opslimit, memlimit)` → 32 bytes  
   - **Raw key:** a 32-byte application-supplied key
   - **X25519 ECDH:** `shared = scalarmult(sender_eph_secret, recipient_static_public)`  
     `master = HKDF(shared, len=32, info="OTTO-E2E-MASTER", salt=file_salt)`

2. **Key separation** (HKDF-SHA256, salt = `file_salt`):
   - `enc_key   = HKDF(master, 32, info="OTTO-ENC-KEY",  salt=file_salt)`
   - `nonce_key = HKDF(master, 32, info="OTTO-NONCE-KEY", salt=file_salt)`

This ensures fresh keys per object, deterministic derivation, and context binding via labels.

---

## Nonce Derivation (HKDF-SIV style)

To prevent accidental **nonce reuse**—a fatal error for GCM—OTTO derives nonces **deterministically** from the `nonce_key` and the chunk counter:

```
counter64be = big_endian(counter)
nonce_i     = HKDF(nonce_key, 12, info="OTTO-CHUNK-NONCE" || counter64be, salt="")
```

- Length = **12 bytes** (standard GCM nonce size).
- This is **SIV-like** use of HKDF for nonces (not RFC-5297 SIV). No random nonces; no user state to track; the same plaintext does **not** cause reuse because the counter is unique per record.

---

## Password Mode (Argon2id)

When using passwords:

- `master = Argon2id(password, pw_salt, opslimit, memlimit)` (libsodium `crypto_pwhash`).
- The exact `opslimit` and `memlimitKiB` used are recorded in the header for verifiable and repeatable derivation.
- Choose robust parameters (see [Parameter Guidance](#parameter-guidance)); E2E mode is recommended for messengers.

---

## X25519 End-to-End Mode

- Sender generates **ephemeral** X25519 keypair `(eph_sk, eph_pk)`.
- Header includes `eph_pubkey = eph_pk`.  
- **Recipient static public key** is known to the sender.
- Both sides compute `shared = scalarmult(eph_sk, recipient_pk)` (sender) or `scalarmult(recipient_sk, eph_pk)` (recipient).
- `master = HKDF(shared, 32, "OTTO-E2E-MASTER", file_salt)`, followed by the standard OTTO key schedule.

**Properties:**
- **Forward secrecy** per object (ephemeral on sender).
- **Unauthenticated DH** by default. If you need **sender authentication**, wrap OTTO in an authenticated handshake (e.g., sign `eph_pk` & header with a long-term identity key) or bind identities at the protocol layer.

---

## Why OTTO vs. Alternatives

| Requirement / Feature            | OTTO (this spec)                          | “Just AES-GCM” (DIY) | NaCl/Libsodium Secretbox | age | Fernet |
|----------------------------------|-------------------------------------------|----------------------|--------------------------|-----|--------|
| Nonce safety                     | **Deterministic HKDF nonces**             | Risk of reuse        | Random nonce             | N/A | N/A    |
| Header bound to AEAD             | **Yes (full header as AAD)**              | Often forgotten      | Yes (implicit)           | Yes | Yes    |
| Streaming (per-chunk AEAD)       | **Yes**                                   | Usually ad-hoc       | Not standardized         | Yes | No     |
| Password hardening               | **Argon2id** (configurable)               | Varies               | Varies                    | scrypt | PBKDF2 |
| Built-in E2E (X25519)            | **Yes** (ephemeral→static)                | No                   | No                        | Yes | No     |
| Cross-language SDKs              | **Yes** (PHP, Node, Python, C#, Swift, Java/Android, Flutter) | No | Partial | Yes | Yes |
| Operational guidance             | **Spec + params + demos**                 | None                 | Library docs             | Spec | Simple |

**The bottom line:** OTTO is not “stronger crypto” than the underlying primitives; it’s **safer engineering** around them—removing nonce footguns, standardizing a header, defining an interop streaming format, and embedding modern KDFs and E2E mode.

---

## Security Properties & Caveats

**Provides**
- Confidentiality & integrity per record (AES-256-GCM).
- Header integrity via AAD binding.
- Key separation via HKDF labels.
- Forward secrecy in E2E mode (sender ephemeral).

**Does not provide**
- Built-in **sender authentication** for E2E (add a handshake or signature).
- **Replay protection / sequencing** at the protocol level (add app-level counters/timestamps).
- Guaranteed in-memory key wiping (language/VM limitations).

**Recommendations**
- Prefer **X25519 E2E** for messengers; use passwords for local file lockers or when keys can’t be exchanged.
- Bind application metadata (e.g., conversation ID, file MIME) in the **header** or include it in additional AAD fields that you validate.
- Enforce **unique ephemeral keys** per message/object in E2E mode.
- **Audit** your deployment and code. Treat OTTO as **experimental** until independently reviewed.

---

## Reference SDKs & Demos

Each SDK implements the same wire format and includes a runnable **demo** (CLI or app).  
> Replace or adjust the links to match your GitHub organization if needed.

- **PHP / Laravel** — OTTO Crypt (Package + Artisan CLI)  
  https://github.com/ivansostarko/otto-crypt-php
- **Node.js** — OTTO Crypt (Package + CLI)  
  https://github.com/ivansostarko/otto-crypt-node
- **Python** — OTTO Crypt (Package + CLI)  
  https://github.com/ivansostarko/otto-crypt-python
- **C# / .NET** — OTTO Crypt (Library + CLI)  
  https://github.com/ivansostarko/otto-crypt-csharp
- **Java & Android** — OTTO Crypt (Gradle multi-module + AAR + demo app)  
  https://github.com/ivansostarko/otto-crypt-java-android
- **Swift (iOS/macOS)** — OTTO Crypt (SwiftPM + CLI demo)  
  https://github.com/ivansostarko/otto-crypt-swift
- **Flutter / Dart** — OTTO Crypt (Package + Flutter demo app)  
  https://github.com/ivansostarko/otto-crypt-flutter

Each repository includes:
- **README** with algorithm recap and usage
- **Demo** (app or CLI) for text & files (photos, audio, video)
- **Interoperability tests** or examples

---

## Interoperability Checklist

To round-trip data between SDKs:

1. **Record both outputs** from encryption:
   - `ciphertext+tag` (base64 or binary)
   - `header` (base64 or binary)
2. **Transmit both** to the recipient/decryptor.  
3. **Use the same mode**:
   - Password → same password
   - Raw key → same 32-byte key
   - X25519 → sender ephemeral + recipient static  
     (decryptor needs sender’s **header** with `eph_pubkey` and recipient **secret**)
4. **Chunking is transparent**; the decryptor reads header then chunk records until EOF.

---

## Parameter Guidance

- **Chunk size:** default **1 MiB** (safe for RAM and fast on most platforms).  
  Larger chunks reduce per-chunk overhead; smaller chunks improve early error detection.
- **Argon2id** (password mode): start with libsodium **moderate** or **interactive** settings:
  - `opslimit`: moderate (≈3) or higher
  - `memlimit`: moderate (e.g., 256 MiB) on desktop/server; adjust for mobile
- **AES-GCM:** standard **12-byte nonce**, **16-byte tag**.  
  OTTO’s derived nonces remove nonce management from the application.
- **Labels:** do not change HKDF labels (`"OTTO-ENC-KEY"`, `"OTTO-NONCE-KEY"`, `"OTTO-CHUNK-NONCE"`, `"OTTO-E2E-MASTER"`) unless you intentionally fork the format.
- **Versioning:** `magic="OTTO1"` and `algo_id=0xA1` identify this version. Future variants will bump either.

---

## FAQ

**Q: Is OTTO the same as AES-GCM-SIV?**  
A: No. OTTO uses AES-GCM with **deterministic HKDF-derived nonces** (SIV-like idea), not the AES-GCM-SIV construction.

**Q: Does OTTO authenticate the sender in E2E mode?**  
A: Not by itself. It’s an **unauthenticated DH** by default (PFS only). Add an identity layer (e.g., Ed25519 signature over the header/`eph_pk` or a full handshake like Noise/MLS) if you need sender authentication.

**Q: Can I store extra metadata?**  
A: Yes. Extend the header (reserved byte is zero today) or include application metadata in additional AAD fields—just ensure both sides validate it consistently.

**Q: What about replay protection?**  
A: Add protocol-level counters/timestamps or store state in your app. OTTO focuses on the cryptographic container.

---

## License

MIT © 2025 Ivan Sostarko

---

### Appendix: Pseudocode

**Key Schedule**
```
if mode == PASSWORD:
    master = Argon2id(password, pw_salt, opslimit, memlimit)  // 32 bytes
elif mode == RAW:
    master = raw_key  // 32 bytes
elif mode == X25519:
    shared = scalarmult(sender_eph_sk, recipient_pk)
    master = HKDF(shared, len=32, info="OTTO-E2E-MASTER", salt=file_salt)

enc_key   = HKDF(master, len=32, info="OTTO-ENC-KEY",  salt=file_salt)
nonce_key = HKDF(master, len=32, info="OTTO-NONCE-KEY", salt=file_salt)
```

**Per-chunk Nonce & AEAD**
```
for counter = 0..:
    info     = "OTTO-CHUNK-NONCE" || uint64_be(counter)
    nonce    = HKDF(nonce_key, len=12, info=info, salt="")
    (cipher, tag) = AES256-GCM-Encrypt(enc_key, nonce, aad=HEADER, plaintext=chunk)
    write u32be(len(cipher)) || cipher || tag
```
