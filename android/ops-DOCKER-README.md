# Docker usage — OTTO Crypt (Java & Android)

This container sets up **JDK 17**, **Gradle 8.7**, and the **Android SDK** to build both modules:
- `:otto-crypt-java` (JAR)
- `:otto-crypt-android` (AAR)

It also installs `libsodium` for JVM runtime so **lazysodium-java** can load native sodium during tests/runs.

## Quick start

```bash
# Build the image & start an idle dev container
docker compose up -d --build

# Build Java JARs
docker compose run --rm java-build

# Build Android AARs (requires internet to download SDK packages on first run)
docker compose run --rm android-build

# Build both and collect artifacts
docker compose run --rm all
```

Artifacts will appear under `./artifacts/java/` (JARs) and `./artifacts/android/` (AARs).  
Override the host path via `ARTIFACTS_PATH=/some/dir`.

## Notes
- Base image: `gradle:8.7.0-jdk17`
- Android SDK installed to `/opt/android-sdk` with build-tools **34.0.0** and platform **android-34**.
- If you need a different API level/build-tools, edit the `sdkmanager` lines in `Dockerfile`.
- The `dev` service keeps the container idle so you can `docker compose exec dev bash` and run custom Gradle commands.
