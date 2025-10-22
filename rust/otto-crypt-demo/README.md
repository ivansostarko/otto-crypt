# otto-crypt-demo (Rust)

Demo CLI showing **OTTO** encryption for:
- **Text**
- **Photos** (any image file)
- **Audio** (e.g., .mp3/.wav)
- **Video** (e.g., .mp4/.mov)
- **Any files** (binary/large) via chunked streaming

> OTTO = AES-256-GCM + HKDF-derived keys (enc/nonce) + HKDF-SIV-style nonces per chunk. Format is compatible with the Laravel SDK.

## Build & Run
```bash
# from workspace root
cargo build -p otto-crypt-demo

# create a 32-byte key
openssl rand -out key.bin 32
export OTTO_RAWKEY_B64=$(base64 -w0 key.bin)

# TEXT
cargo run -p otto-crypt-demo -- text --message "hello from rust"
# or explicitly provide key
cargo run -p otto-crypt-demo -- text --key-b64 "$OTTO_RAWKEY_B64" --message "hi"

# FILE (works for images/audio/video/anything)
cargo run -p otto-crypt-demo -- file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/photo.jpg
cargo run -p otto-crypt-demo -- file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/song.mp3
cargo run -p otto-crypt-demo -- file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/movie.mp4

# BATCH (process entire directory)
cargo run -p otto-crypt-demo -- batch --key-b64 "$OTTO_RAWKEY_B64" --dir ./samples --out ./out
```

### Output
- Encrypted files end with `.otto`
- Decrypted files end with `.dec`
- Format is cross-language compatible with **PHP/Laravel**, **Node**, **Python**, **C#**, **C++**, **Java/Android**, **Swift**, **Flutter** SDKs.

## Notes
- OTTO header acts as AAD and is verified by AES-GCM.
- Each file/message uses a fresh 16-byte salt to derive keys.
- Each chunk uses a deterministic HKDF nonce: `HKDF(nonceKey, info="OTTO-CHUNK-NONCE"||counter_be64, len=12)`
