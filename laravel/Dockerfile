# syntax=docker/dockerfile:1.6
FROM php:8.3-cli-bookworm

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \    git unzip libzip-dev libsodium-dev bash ca-certificates \    && docker-php-ext-install zip sodium \    && rm -rf /var/lib/apt/lists/*

# Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Working directory (mount your Laravel app here via docker-compose)
WORKDIR /var/www/html

ENV COMPOSER_ALLOW_SUPERUSER=1 \    PATH="/var/www/html/vendor/bin:${PATH}"

# Default command: keep container running so you can exec into it
CMD ["bash","-lc","tail -f /dev/null"]
