# php-captcha-country

Lightweight country-based CAPTCHA gate intended for `auto_prepend_file`. If something is misconfigured, the IP cannot be resolved, or a lookup fails, the request is **never blocked**: the code simply steps aside and your application keeps running.

## How it works

1. The script resolves the visitor IP (supports `HTTP_CF_CONNECTING_IP`, `X-Forwarded-For`, etc.).
2. Country resolution first checks a local GeoIP CSV database, then an HTTP endpoint. Results are cached in `var/state.json`.
3. Allowed countries skip the CAPTCHA entirely. Other countries must solve it. Repeated failures lead to a temporary ban.
4. Bans, attempts, and Geo cache entries are purged lazily in the background or via a CLI task.
5. Every operation is intentionally lightweight: minimal I/O, no Composer dependencies, works from PHP 5.6 to 8.4.

## Installation

1. Copy the repository to your server.
2. Ensure the `var/` directory is writable by PHP (state, cache, and logs).
3. (Optional) Enable GD for nicer CAPTCHA images; otherwise a plain-text fallback is used.
4. Add to your PHP configuration:

```ini
auto_prepend_file="/path/to/prepend.php"
```

5. Adjust the configuration (see below). If the configuration file is missing or invalid, the guard silently bypasses itself.

## Configuration (`config.php`)

The file returns an associative array. Notable options:

- `allowed_countries`: ISO 3166-1 alpha-2 codes that bypass the CAPTCHA.
- `ban_duration`: seconds before a banned IP is released.
- `failed_attempt_limit`: failed CAPTCHA attempts before banning.
- `captcha_ttl`: validity window for a generated CAPTCHA (seconds).
- `geo_cache_ttl`: cache duration for GeoIP responses (seconds).
- `storage_path`: directory for runtime files (state, cache, local DB).
- `purge_probability`: probability (0–1) to purge expired entries on each request.
- `geo_endpoint`: HTTP service used for remote GeoIP lookups (`%s` is replaced by the IP).
- `local_geo_db`: path to a local CSV database used **before** remote lookups. Format: one CIDR + country per line, e.g. `8.8.8.0/24;US`.
- `local_geo_update_url`: optional URL to refresh `local_geo_db` (same format as above).
- `log_file`: target log file.
- `log_level`: `debug`, `info`, or `error`.
- `log_max_bytes`: truncate/overwrite the log when it exceeds this size.
- `strings`: customizable UI texts.

If an IP cannot be resolved, the Geo lookup fails, or any runtime error happens, the code logs (according to the configured level) and **bypasses the CAPTCHA** to avoid accidental blocking.

## CLI maintenance tasks

You can call the prepend file directly to run maintenance without hitting the web flow:

```bash
php prepend.php purge-cache       # purge expired bans/attempts/cache
php prepend.php clear-geo-cache   # clear only Geo cache
php prepend.php update-geo-db     # download the local GeoIP DB from local_geo_update_url
```

Tasks are no-ops when the related configuration is missing. They are safe to run from cron.

## Local GeoIP database

- Provide a small CSV in the format `CIDR;COUNTRY` (semicolon, comma, or whitespace separated). Example:
  ```
  8.8.8.0/24;US
  1.1.1.0/24 AU
  ```
- Lines starting with `#` are ignored.
- The database is loaded once per request and kept in memory for speed. Cache hits are also written to `var/state.json`.

## Logging

`guard_log` writes timestamped lines with level filtering. When `log_max_bytes` is exceeded, the file is truncated before the next write. Levels:

- `debug`: verbose internal messages.
- `info`: high-level events (e.g., Geo fallback).
- `error`: serious issues (e.g., missing IP).

## Uninstall

Remove the `auto_prepend_file` directive and delete the project directory (including `var/state.json` and any downloaded GeoIP DB).
