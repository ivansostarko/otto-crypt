# OTTO C Demo

This demo shows **text** and **file (photo/audio/video/any)** encryption using the OTTO C library.

## Build
```bash
cmake -S .. -B ../build -DCMAKE_BUILD_TYPE=Release
cmake --build ../build -j
```

Artifacts:
- `../build/otto-demo` — demo runner (text/file/batch)
- `../build/otto-cli`  — helper for Base64-friendly text flows

## Key
```bash
openssl rand -out key.bin 32
export OTTO_RAWKEY_B64=$(base64 -w0 key.bin)   # macOS: base64 < key.bin
```

## Text
```bash
# Encrypt + decrypt an inline message
../build/otto-demo text --key-b64 "$OTTO_RAWKEY_B64" --message "hello from C"
```

If you need Base64-encoded outputs for interop, use `otto-cli`:
```bash
# Produce Base64 header + ciphertext suitable for other SDKs
OUT=$(../build/otto-cli enc-str "$OTTO_RAWKEY_B64" "hello from C")
HEADER_B64=$(echo "$OUT" | awk -F= '/HEADER_B64/{print $2}')
CIPHER_B64=$(echo "$OUT" | awk -F= '/CIPHER_B64/{print $2}')
../build/otto-cli dec-str "$OTTO_RAWKEY_B64" "$HEADER_B64" "$CIPHER_B64"
```

## Files (photo/audio/video/any)
```bash
# Single file
../build/otto-demo file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/photo.jpg   --out-enc ./out/photo.jpg.otto --out-dec ./out/photo.jpg.dec

# Batch a directory of media
mkdir -p ./samples ./out
# put images (.jpg/.png), audio (.mp3/.wav), video (.mp4/.mov), docs, etc. into ./samples
../build/otto-demo batch --key-b64 "$OTTO_RAWKEY_B64" --dir ./samples --out ./out
```

## Format & Interop
Matches the Laravel SDK:
- Header: `"OTTO1"|0xA1|0x02|flags|0x00|u16_be(16)|file_salt[16]`
- Keys: HKDF-SHA256 → `encKey`, `nonceKey`
- Nonces: HKDF-SIV style from `nonceKey` + counter → 12 bytes
- AEAD: AES-256-GCM, tag 16B, AAD = header
- Streaming: `header || [u32_be ct_len || ct || tag16]*`
