# checkdmarc

[![Python tests](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml/badge.svg)](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml)
[![Code Coverage](https://codecov.io/gh/domainaware/checkdmarc/branch/main/graph/badge.svg)](https://codecov.io/gh/domainaware/checkdmarc)
[![PyPI](https://img.shields.io/pypi/v/checkdmarc)](https://pypi.org/project/checkdmarc/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/checkdmarc?color=blue)](https://pypistats.org/packages/checkdmarc)

A Python module, command line utility, and [web application](https://github.com/domainaware/checkdmarc-web-frontend) for validating SPF and DMARC DNS records.

## Sponcors

This is a project is maintained by one developer.
Please consider [sponsoring my work](https://github.com/sponsors/seanthegeek) if you or your organization benefit from it.

## Features

- API, CLI, and web interfaces
- Can test multiple domains at once
- CLI output in JSON or CSV format
- DNSSEC validation
- SPF
  - Record validation
  - Counting of DNS lookups and void lookups
  - Counting of lookups per mechanism
- DMARC
  - Validation and parsing of DMARC records
  - Shows warnings when the DMARC record is made ineffective by `sp` values, or by use of the `pct`/`rf`/`ri` tags that were removed in RFC 9989
  - Checks for authorization records on reporting email addresses
- BIMI
  - Validation of the mark format and certificate against the [Minimum Security Requirements for Issuance of Mark Certificates](https://bimigroup.org/resources/VMC_Requirements_latest.pdf)
  - Parsing of the mark certificate
- MX records
  - Preference
  - IPv4 and IPv6 addresses
  - Checks for STARTTLS
  - Use of DNSSEC/TLSA/DANE to pin certificates
- MTA-STS
- SMTP TLS reporting
  - Record and policy parsing and validation
- SOA record parsing
- Nameserver listing

## Docker support

1. Build the image using docker `build . -t checkdmarc`
2. Use the image with a command like `docker run --rm checkdmarc google.nl`
