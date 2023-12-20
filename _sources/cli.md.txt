# CLI

```text
usage: checkdmarc [-h] [-p] [--ns NS [NS ...]] [--mx MX [MX ...]] [-d] [-f FORMAT] [-o OUTPUT [OUTPUT ...]]
                  [-n NAMESERVER [NAMESERVER ...]] [-t TIMEOUT] [-b BIMI_SELECTOR] [-v] [-w WAIT] [--skip-tls]
                  [--debug]
                  domain [domain ...]

Validates and parses email-related DNS records

positional arguments:
  domain                one or more domains, or a single path to a file containing a list of domains

options:
  -h, --help            show this help message and exit
  -p, --parked          indicate that the domains are parked
  --ns NS [NS ...]      approved nameserver substrings
  --mx MX [MX ...]      approved MX hostname substrings
  -d, --descriptions    include descriptions of tags in the JSON output
  -f FORMAT, --format FORMAT
                        specify JSON or CSV screen output format
  -o OUTPUT [OUTPUT ...], --output OUTPUT [OUTPUT ...]
                        one or more file paths to output to (must end in .json or .csv) (silences screen output)
  -n NAMESERVER [NAMESERVER ...], --nameserver NAMESERVER [NAMESERVER ...]
                        nameservers to query
  -t TIMEOUT, --timeout TIMEOUT
                        number of seconds to wait for an answer from DNS (default 2.0)
  -b BIMI_SELECTOR, --bimi-selector BIMI_SELECTOR
                        Check for a BIMI record at the provided selector
  -v, --version         show program's version number and exit
  -w WAIT, --wait WAIT  number of seconds to wait between checking domains (default 0.0)
  --skip-tls            skip TLS/SSL testing
  --debug               enable debugging output
```

## Example

```bash
checkdmarc fbi.gov
```

```json
{
    "domain": "fbi.gov",
    "base_domain": "fbi.gov",
    "dnssec": true,
    "ns": {
    "hostnames": [
        "a1.fbi.gov",
        "a2.fbi.gov",
        "a3.fbi.gov"
    ],
    "warnings": []
    },
    "mx": {
    "hosts": [
        {
        "preference": 10,
        "hostname": "mx-east.fbi.gov",
        "addresses": [
            "153.31.160.5"
        ],
        "tls": true,
        "starttls": true
        }
    ],
    "warnings": []
    },
    "spf": {
    "record": "v=spf1 +mx ip4:153.31.0.0/16 -all",
    "valid": true,
    "dns_lookups": 1,
    "warnings": [],
    "parsed": {
        "pass": [
        {
            "value": "mx-east.fbi.gov",
            "mechanism": "mx"
        },
        {
            "value": "153.31.0.0/16",
            "mechanism": "ip4"
        }
        ],
        "neutral": [],
        "softfail": [],
        "fail": [],
        "include": [],
        "redirect": null,
        "exp": null,
        "all": "fail"
    }
    },
    "dmarc": {
    "record": "v=DMARC1; p=reject; rua=mailto:dmarc-feedback@fbi.gov,mailto:reports@dmarc.cyber.dhs.gov; ruf=mailto:dmarc-feedback@fbi.gov; pct=100",
    "valid": true,
    "location": "fbi.gov",
    "warnings": [],
    "tags": {
        "v": {
        "value": "DMARC1",
        "explicit": true
        },
        "p": {
        "value": "reject",
        "explicit": true
        },
        "rua": {
        "value": [
            {
            "scheme": "mailto",
            "address": "dmarc-feedback@fbi.gov",
            "size_limit": null
            },
            {
            "scheme": "mailto",
            "address": "reports@dmarc.cyber.dhs.gov",
            "size_limit": null
            }
        ],
        "explicit": true
        },
        "ruf": {
        "value": [
            {
            "scheme": "mailto",
            "address": "dmarc-feedback@fbi.gov",
            "size_limit": null
            }
        ],
        "explicit": true
        },
        "pct": {
        "value": 100,
        "explicit": true
        },
        "adkim": {
        "value": "r",
        "explicit": false
        },
        "aspf": {
        "value": "r",
        "explicit": false
        },
        "fo": {
        "value": [
            "0"
        ],
        "explicit": false
        },
        "rf": {
        "value": [
            "afrf"
        ],
        "explicit": false
        },
        "ri": {
        "value": 86400,
        "explicit": false
        },
        "sp": {
        "value": "reject",
        "explicit": false
        }
    }
    }
}
```
