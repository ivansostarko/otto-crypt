# Docker usage for OTTO Crypt (Laravel package)

This Docker setup gives you a ready PHP 8.3 + Composer environment with the required extensions (**openssl**, **sodium**, **zip**) to develop and run OTTO Crypt inside a Laravel app.

## Quick start

1) Build the image and start the background container:

```bash
docker compose up -d --build
```

2) Create (or use) a Laravel app on your host. By default, compose mounts `../laravel-app` into `/var/www/html` inside the container.

If you need to create it:

```bash
mkdir -p ../laravel-app
docker compose run --rm app bash -lc "composer create-project laravel/laravel ."
```

3) Wire the local package into that app (path repo + require):

```bash
docker compose run --rm install
```

This will configure Composer to use `/package` (mounted from this repo) and run:
`composer require ivansostarko/otto-crypt-php:*@dev`

4) Use the Artisan commands (streaming encryption/decryption):

```bash
# Encrypt with password
docker compose run --rm app php artisan otto:encrypt storage/app/in.mp4 --out=storage/app/in.mp4.otto --password="strong-pass"

# Decrypt
docker compose run --rm app php artisan otto:decrypt storage/app/in.mp4.otto --out=storage/app/in.dec.mp4 --password="strong-pass"

# E2E: encrypt to recipient public key (base64 or hex)
docker compose run --rm app php artisan otto:encrypt storage/app/big.mov --out=storage/app/big.mov.otto --recipient="BASE64_OR_HEX_PUBLIC"

# E2E: decrypt with your X25519 secret key
docker compose run --rm app php artisan otto:decrypt storage/app/big.mov.otto --out=storage/app/big.mov --sender-secret="BASE64_OR_HEX_SECRET"
```

5) (Optional) Serve the Laravel app for local testing:

```bash
docker compose exec app bash -lc "php artisan serve --host=0.0.0.0 --port=8000"
# Open http://localhost:8000
```

## Environment variable

- `LARAVEL_APP_PATH` — host path to your Laravel app (default: `../laravel-app`).

## Notes

- The container keeps running to make it easy to `exec` commands.
- The required PHP extensions are installed: `sodium`, `zip`, `openssl` (built-in).
- The package is mounted at `/package` and symlinked via Composer’s path repository, so changes reflect immediately in the app.
