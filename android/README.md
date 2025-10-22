# OTTO Crypt — Android Demo App

Android app demonstrating **text** and **file** (photos, documents, audio, video) encryption/decryption using the **OTTO Crypt** Android library.

## Integrate into your existing project

1. Place `otto-crypt-android-demo/` directory into the **same root** as your `:otto-crypt-java` and `:otto-crypt-android` modules.
2. In the root `settings.gradle`, add:
   ```gradle
   include(":otto-crypt-android-demo")
   ```
3. Sync and run the app target `:otto-crypt-android-demo`.

The demo depends on your local module:
```gradle
implementation(project(":otto-crypt-android"))
```
