# OTTO Crypt — .NET Demo App

An ASP.NET Core app demonstrating **text** and **file** (photos, docs, audio, video) encryption/decryption using the `IvanSostarko.OttoCrypt` library. The format is interoperable with the Laravel, Node, and Python implementations.

## Layout
```
OttoCryptDemo.sln
OttoCrypt.Demo/
  OttoCrypt.Demo.csproj
  Program.cs
  Controllers/OttoDemoController.cs
  Views/OttoDemo/Index.cshtml
  wwwroot/css/site.css
```

## Prerequisites
- .NET 8 SDK
- The library project `IvanSostarko.OttoCrypt` available locally (or published to a private NuGet).

By default the demo references the library as a **ProjectReference**:
```xml
<ProjectReference Include="..\otto-crypt-cs\IvanSostarko.OttoCrypt\IvanSostarko.OttoCrypt.csproj" />
```
Adjust the path to match your checkout layout. Alternatively, replace with a NuGet reference if you pack+publish the library.

## Run
```bash
# From the OttoCrypt.Demo/ folder
dotnet restore
dotnet run
# open http://localhost:5000 (or the port shown)
```

## What it demonstrates
- **Text**: Encrypt (shows base64 ciphertext+tag + header) and decrypt (paste base64 strings).
- **Files**: Upload any file to encrypt → `.otto` download; upload `.otto` → decrypted `.dec` download.
- **Modes**:
  - **Password (Argon2id)**
  - **X25519 E2E** (recipient public / sender secret)
  - **Raw 32-byte keys** (base64/hex/raw)
- **Keys**: `/OttoDemo/Keys` returns a fresh X25519 keypair (base64/hex).

## Security notes
- This is a **demo** — limit max upload size, validate MIME/extension, and avoid storing secrets in logs.
- Use HTTPS in production.
- See the library README for full algorithm & format details.

---

MIT © 2025 Ivan Sostarko
