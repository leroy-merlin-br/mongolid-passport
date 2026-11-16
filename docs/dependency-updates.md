# Dependency Updates

This document describes the latest dependency bump for Mongolid Passport.

## What changed

| Dependency                          | Previous  | New        |
|-------------------------------------|-----------|------------|
| `ext-mongodb` (composer constraint) | `^1.20.0` | `^1.21.13` |
| `leroy-merlin-br/mongolid`          | `v4.1.0`  | `v4.1.1`   |
| `leroy-merlin-br/mongolid-laravel`  | `v4.0.0`  | `v4.0.1`   |
| `mongodb` PECL extension (Docker)   | `1.20.1`  | `1.21.13`  |

## Impact

- Applications using this package must run the MongoDB PHP extension in version `1.21.13` or newer.
- The development Docker image (`docker/php/Dockerfile`) now installs the matching extension version.
- No public API of this package was changed.

## How to upgrade

1. Update the MongoDB extension: `pecl install mongodb-1.21.13`.
2. Run `composer update leroy-merlin-br/mongolid leroy-merlin-br/mongolid-laravel`.
3. Rebuild the Docker image if you use the bundled development environment: `docker compose build`.
