# otto-demo (C++)

Demo app that showcases **OTTO** encryption for:
- **Text** messages
- **Photos** (any image file)
- **Audio** (e.g., .mp3/.wav)
- **Video** (e.g., .mp4/.mov)
- **Any other files** (documents, archives, etc.) via **chunked streaming**

OTTO format is compatible with your Laravel/PHP SDK (and other SDKs).

## Build
```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

## Generate a 32-byte key
```bash
openssl rand -out key.bin 32
export OTTO_RAWKEY_B64=$(base64 -w0 key.bin)   # Linux
# macOS: export OTTO_RAWKEY_B64=$(base64 < key.bin)
```

## Text demo
```bash
./build/otto-demo text --key-b64 "$OTTO_RAWKEY_B64" --message "hello from c++"
# prints HEADER_B64 and CIPHER_B64 and DECRYPTED=...
```

## File demo (works for images/audio/video/anything)
```bash
./build/otto-demo file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/photo.jpg
./build/otto-demo file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/song.mp3
./build/otto-demo file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/movie.mp4
```

Outputs:
- Encrypted file: `<input>.otto`
- Decrypted file: `<input>.dec`

## Batch demo (process entire directory)
```bash
mkdir -p samples
# Put photos/audio/video into ./samples
./build/otto-demo batch --key-b64 "$OTTO_RAWKEY_B64" --dir ./samples --out ./out
```

## Docker
Build everything and run the batch demo inside a container.

```bash
# from workspace root
export OTTO_RAWKEY_B64=$(base64 -w0 <(openssl rand -out /dev/stdout 32))
docker compose up --build
# The container reads /data (mapped from ./samples) and writes to /out
```

### Security notes
- Per-object salt → HKDF keys (`encKey`, `nonceKey`)
- Per-chunk nonce: `HKDF(nonceKey, info="OTTO-CHUNK-NONCE"||counter_be64) → 12 bytes`
- AAD = full OTTO header; AES-256-GCM tag = 16 bytes
