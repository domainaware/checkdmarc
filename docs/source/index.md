# Welcome to checkdmarc's documentation

[![Python tests](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml/badge.svg)](https://github.com/domainaware/checkdmarc/actions/workflows/python-tests.yaml)
[![PyPI](https://img.shields.io/pypi/v/checkdmarc)](https://pypi.org/project/checkdmarc/)
[![PyPI - Downloads](https://img.shields.io/pypi/dm/checkdmarc?color=blue)](https://pypistats.org/packages/checkdmarc)

`checkdmarc` is a Python module and command line parser for SPF and DMARC DNS records

## Features

- API and CLI
- Can test multiple domains at once
- CLI output in JSON or CSV format
- Parses and validates MX, SPF, and DMARC records
- Checks for DNSSEC deployment
- Lists name servers
- Checks for STARTTLS and TLS support on each mail server

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
