# otto-crypt-demo (Java)

Demo CLI showing **OTTO** encryption for:
- **Text**
- **Photos** (any image files)
- **Audio** (e.g., .mp3/.wav)
- **Video** (e.g., .mp4/.mov)
- **Any other files** via **chunked streaming** container

The format is wire-compatible with the Laravel SDK and other OTTO SDKs.

## Build
```bash
# from repo root (multi-module)
mvn -q -DskipTests package
```

The demo fat-jar is created at:
```
otto-crypt-demo/target/otto-demo-uber-jar-with-dependencies.jar
```

## Generate a 32-byte key
```bash
# Linux
openssl rand -out key.bin 32
export OTTO_RAWKEY_B64=$(base64 -w0 key.bin)

# macOS
# export OTTO_RAWKEY_B64=$(base64 < key.bin)
```

## Text demo
```bash
java -jar otto-crypt-demo/target/otto-demo-uber-jar-with-dependencies.jar text --key-b64 "$OTTO_RAWKEY_B64" --message "hello from java"
# prints HEADER_B64, CIPHER_B64, and DECRYPTED=...
```

## File demo (photo/audio/video/any)
```bash
java -jar otto-crypt-demo/target/otto-demo-uber-jar-with-dependencies.jar file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/photo.jpg
java -jar otto-crypt-demo/target/otto-demo-uber-jar-with-dependencies.jar file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/song.mp3
java -jar otto-crypt-demo/target/otto-demo-uber-jar-with-dependencies.jar file --key-b64 "$OTTO_RAWKEY_B64" --input ./samples/movie.mp4
```

Outputs:
- Encrypted file: `<input>.otto`
- Decrypted file: `<input>.dec`

## Batch demo (process a directory)
```bash
mkdir -p samples
# put photos/audio/video/etc into ./samples
java -jar otto-crypt-demo/target/otto-demo-uber-jar-with-dependencies.jar batch --key-b64 "$OTTO_RAWKEY_B64" --dir ./samples --out ./out
```

## Docker
```bash
# Build and run the batch demo in a container
export OTTO_RAWKEY_B64=$(base64 -w0 <(openssl rand -out /dev/stdout 32))
docker compose up --build
# The container reads /data (from ./samples) and writes to /out
```
