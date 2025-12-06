# checkdmarc

[![Python tests](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml/badge.svg)](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml)
[![PyPI](https://img.shields.io/pypi/v/checkdmarc)](https://pypi.org/project/checkdmarc/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/checkdmarc?color=blue)](https://pypistats.org/packages/checkdmarc)

A Python module, command line utility, and [web application](https://github.com/domainaware/checkdmarc-web-frontend) for validating SPF and DMARC DNS records.

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
  - Shows warnings when the DMARC record is made ineffective by `pct` or `sp` values
  - Checks for authorization records on reporting email addresses
- BIMI
  - Validation of the mark format and certificate
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
