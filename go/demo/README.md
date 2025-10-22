# OTTO Go Demo

Go CLI that demonstrates **text** and **file (photo/audio/video/any)** encryption using the OTTO algorithm.
It uses the local `otto` package and is wire-compatible with the Laravel/PHP SDK and other OTTO SDKs.

## Build
```bash
go build -o otto-demo ./demo
```

## Key (32 bytes)
```bash
# Linux
openssl rand -out key.bin 32
export OTTO_RAWKEY_B64=$(base64 -w0 key.bin)

# macOS
# export OTTO_RAWKEY_B64=$(base64 < key.bin)
```

## Text demo
```bash
./otto-demo text --key-b64 "$OTTO_RAWKEY_B64" --message "hello from go"
# prints HEADER_B64=..., CIPHER_B64=..., DECRYPTED=...
```

## File demo (photo/audio/video/any)
```bash
./otto-demo file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/photo.jpg
./otto-demo file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/song.mp3
./otto-demo file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/movie.mp4
```

Outputs:
- Encrypted: `<input>.otto`
- Decrypted: `<input>.dec`

## Batch demo (directory)
```bash
mkdir -p samples out
# put media into ./samples
./otto-demo batch --key-b64 "$OTTO_RAWKEY_B64" --dir ./samples --out ./out
```

## Interop format
- Header: `"OTTO1"|0xA1|0x02|flags|0x00|u16_be(16)|file_salt[16]`
- Keys: HKDF-SHA256 → `encKey`, `nonceKey` (salt = file_salt)
- Nonces: HKDF(nonceKey, salt="", info="OTTO-CHUNK-NONCE"||counter_be64, 12)
- AEAD: AES-256-GCM (tag 16B), AAD = header
- Streaming container: `header || [u32_be ct_len || ct || tag16]*`
