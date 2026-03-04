# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Project Overview

checkdmarc is a Python library and CLI tool for validating email security DNS records (SPF, DMARC, BIMI, MTA-STS, SMTP TLS Reporting, MX/STARTTLS, DNSSEC, SOA). Published on PyPI as `checkdmarc`.

## Common Commands

```bash
# Run tests with coverage
coverage run tests.py

# Lint and format
ruff check --show-fixes
ruff format .

# Build package
hatch build

# Build docs
cd docs && make html

# Full build (format + docs + package)
./build.sh
```

Tests use `unittest.TestCase` in a single `tests.py` file. Run a single test with:

```bash
python -m pytest tests.py -k "test_name"
```

Some tests require network access and are skipped when `GITHUB_ACTIONS` env var is set.

## Architecture

**Entry point:** `checkdmarc/__init__.py` — `check_domains()` orchestrates all checks, returning `DomainCheckResult` TypedDict(s).

**Modules** (each has a primary `check_*()` function):

- `spf.py` — SPF record parsing, DNS lookup counting
- `dmarc.py` — DMARC/DMARCbis record parsing with DNS tree walk algorithm
- `bimi.py` — BIMI record and certificate validation
- `mta_sts.py` — MTA-STS policy fetching and validation
- `smtp_tls_reporting.py` — TLSRPT record validation
- `smtp.py` — MX record lookup and STARTTLS testing
- `dnssec.py` — DNSSEC validation
- `soa.py` — SOA record parsing
- `utils.py` — DNS helpers, exception classes, domain normalization

**CLI:** `_cli.py` (entry point: `checkdmarc._cli:_main`)

**Constants/version:** `_constants.py`

**Output:** `results_to_json()`, `results_to_csv()`, `output_to_file()` in `__init__.py`.

## Key Dependencies

- `dnspython` for DNS queries
- `pyleri` for grammar parsing
- `publicsuffixlist` for base domain extraction
- `cryptography`/`pyopenssl`/`pem` for certificate handling
- `expiringdict` for DNS result caching

## Code Style

- Formatter/linter: **Ruff**
- Type annotations use `TypedDict` for structured results
- Python >=3.10 required
- Build backend: **hatchling**
