# checkdmarc

[![Python tests](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml/badge.svg)](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml)
[![PyPI](https://img.shields.io/pypi/v/checkdmarc)](https://pypi.org/project/checkdmarc/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/checkdmarc?color=blue)](https://pypistats.org/packages/checkdmarc)

A Python module and command line utility for validating SPF and DMARC DNS records

## Features

- API and CLI
- Can test multiple domains at once
- CLI output in JSON or CSV format
- Parses and validates MX, SPF, and DMARC records
- Checks for DNSSEC deployment
- Lists name servers
- Checks for STARTTLS and TLS support on each mail server
