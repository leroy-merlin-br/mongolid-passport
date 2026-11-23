# Dependency Updates

This document describes the latest dependency bump for Mongolid Passport.

## What changed

| Dependency | Previous | New |
|---|---|---|
| `ext-mongodb` (Composer requirement) | `^1.21.13` | `^2.5.0` |
| `mongodb/mongodb` | `^1.20.0` | `^2.5.0` |
| `leroy-merlin-br/mongolid` | `v4.1.1` | `dev-chore/update-mongodb-2.3` |
| `leroy-merlin-br/mongolid-laravel` | `v4.0.1` | `dev-chore/upgrade-mongodb-extension` |
| MongoDB PECL extension (Docker) | `1.21.13` | `2.5.0` |
| Illuminate components | `^9.21 \| ^10.0 \| ^11.0 \| ^12.0` | `^12.60` |

## Impact

- Applications using this package must use Laravel 12.60 or newer within the 12.x series.
- The MongoDB PHP extension must satisfy `^2.5.0`.
- The development Docker image (`docker/php/Dockerfile`) installs MongoDB extension `2.5.0`.
- No public API of this package was changed.

## How to upgrade

1. Upgrade the MongoDB extension: `pecl install mongodb-2.5.0`.
2. Ensure the application uses Laravel 12.60 or newer.
3. Update the Mongolid and MongoDB dependencies: `composer update leroy-merlin-br/mongolid leroy-merlin-br/mongolid-laravel mongodb/mongodb`.
4. Rebuild the Docker image if you use the bundled development environment: `docker compose build`.
