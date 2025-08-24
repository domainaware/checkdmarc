# Welcome to checkdmarc's documentation

[![Python tests](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml/badge.svg)](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml)
[![PyPI](https://img.shields.io/pypi/v/checkdmarc)](https://pypi.org/project/checkdmarc/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/checkdmarc?color=blue)](https://pypistats.org/packages/checkdmarc)

`checkdmarc` is a Python module and command line parser for SPF and DMARC DNS records

## Features

- API and CLI
- Can test multiple domains at once
- CLI output in JSON or CSV format
- Parsing and validation of many DNS records related to email
  - MX
    - Tests STARTTLS and TLS support on each mail server, including certificate validation
  - SPF
    - Counts the number of DNS lookups required in each part of the SPF record
  - DMARC
  - MTA-STS
    - Checks both the  DNS record and the policy provided over HTTPS
  - SMTP TLS reporting
  - BIMI
    - Validates the SVG format and mark certificate
  - DNSSEC

## Further reading

```{toctree}
---
maxdepth: 1
---
installation
api
cli
```

### Indices and tables

```{eval-rst}
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
```
