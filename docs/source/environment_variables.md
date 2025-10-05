# Environment variables

Starting in version `5.11.0`, caches can be controlled via environment variables.

All caches have the default length of `200000` and the the default max age of `1800` seconds. These defaults can be overridden using the environment variables `CACHE_MAX_LEN` and `CACHE_MAX_AGE_SECONDS` respectively.

Values for specific caches can be set using:

- `DNS_CACHE_MAX_LEN`
- `DNS_CACHE_MAX_AGE_SECONDS`
- `DNSSEC_CACHE_MAX_LEN`
- `DNSSEC_CACHE_MAX_AGE_SECONDS`
- `SMTP_CACHE_MAX_LEN`
- `SMTP_CACHE_MAX_AGE_SECONDS`
