# CLI

```text
usage: checkdmarc [-h] [-p] [--ns NS [NS ...]] [--mx MX [MX ...]] [-d] [-f FORMAT]
                  [-o OUTPUT [OUTPUT ...]] [-n NAMESERVER [NAMESERVER ...]] [-t TIMEOUT]
                  [-b BIMI_SELECTOR] [-v] [-w WAIT] [--skip-tls] [--debug]
                  domain [domain ...]

Validates and parses email-related DNS records

positional arguments:
  domain                one or more domains, or a single path to a file containing a
                        list of domains

options:
  -h, --help            show this help message and exit
  -p, --parked          indicate that the domains are parked
  --ns NS [NS ...]      approved nameserver substrings
  --mx MX [MX ...]      approved MX hostname substrings
  -d, --descriptions    include descriptions of tags in the JSON output
  -f FORMAT, --format FORMAT
                        specify JSON or CSV screen output format
  -o OUTPUT [OUTPUT ...], --output OUTPUT [OUTPUT ...]
                        one or more file paths to output to (must end in .json or .csv)
                        (silences screen output)
  -n NAMESERVER [NAMESERVER ...], --nameserver NAMESERVER [NAMESERVER ...]
                        nameservers to query
  -t TIMEOUT, --timeout TIMEOUT
                        number of seconds to wait for an answer from DNS (default 2.0)
  -b BIMI_SELECTOR, --bimi-selector BIMI_SELECTOR
                        The BIMI selector to use (default default)
  -v, --version         show program's version number and exit
  -w WAIT, --wait WAIT  number of seconds to wait between checking domains (default 0.0)
  --skip-tls            skip TLS/SSL testing
  --debug               enable debugging output
```

## Example

```bash
checkdmarc --skip-tls proton.me
```

```json
{
  "domain": "proton.me",
  "base_domain": "proton.me",
  "dnssec": true,
  "ns": {
    "hostnames": [
      "ns1.proton.me",
      "ns2.proton.me",
      "ns3.proton.me"
    ],
    "warnings": []
  },
  "mx": {
    "hosts": [
      {
        "preference": 10,
        "hostname": "mail.protonmail.ch",
        "addresses": [
          "176.119.200.128",
          "185.205.70.128",
          "185.70.42.128"
        ],
        "dnssec": true,
        "tlsa": [
          "3 1 1 6111a5698d23c89e09c36ff833c1487edc1b0c841f87c49dae8f7a09e11e979e",
          "3 1 1 76bb66711da416433ca890a5b2e5a0533c6006478f7d10a4469a947acc8399e1"
        ]
      },
      {
        "preference": 20,
        "hostname": "mailsec.protonmail.ch",
        "addresses": [
          "176.119.200.129",
          "185.205.70.129",
          "185.70.42.129"
        ],
        "dnssec": true,
        "tlsa": [
          "3 1 1 6111a5698d23c89e09c36ff833c1487edc1b0c841f87c49dae8f7a09e11e979e",
          "3 1 1 76bb66711da416433ca890a5b2e5a0533c6006478f7d10a4469a947acc8399e1"
        ]
      }
    ],
    "warnings": []
  },
  "mta_sts": {
    "valid": true,
    "id": "190906205100Z",
    "policy": {
      "version": "STSv1",
      "mode": "enforce",
      "max_age": 604800,
      "mx": [
        "mail.protonmail.ch",
        "mailsec.protonmail.ch"
      ]
    },
    "warnings": [
      "MTA-STS policy lines should end with CRLF not LF"
    ]
  },
  "spf": {
    "record": "v=spf1 include:_spf.protonmail.ch ~all",
    "valid": true,
    "dns_lookups": 2,
    "dns_void_lookups": 0,
    "warnings": [],
    "parsed": {
      "pass": [],
      "neutral": [],
      "softfail": [],
      "fail": [],
      "include": [
        {
          "domain": "_spf.protonmail.ch",
          "record": "v=spf1 ip4:185.70.40.0/24 ip4:185.70.41.0/24 ip4:185.70.43.0/24 include:_spf2.protonmail.ch ~all",
          "dns_lookups": 1,
          "dns_void_lookups": 0,
          "parsed": {
            "pass": [
              {
                "value": "185.70.40.0/24",
                "mechanism": "ip4"
              },
              {
                "value": "185.70.41.0/24",
                "mechanism": "ip4"
              },
              {
                "value": "185.70.43.0/24",
                "mechanism": "ip4"
              }
            ],
            "neutral": [],
            "softfail": [],
            "fail": [],
            "include": [
              {
                "domain": "_spf2.protonmail.ch",
                "record": "v=spf1 ip4:51.89.119.103 ip4:91.134.188.129 ip4:51.77.79.158 ip4:54.38.221.122 ip4:188.165.51.139 ip4:54.36.149.183 ~all",
                "dns_lookups": 0,
                "dns_void_lookups": 0,
                "parsed": {
                  "pass": [
                    {
                      "value": "51.89.119.103",
                      "mechanism": "ip4"
                    },
                    {
                      "value": "91.134.188.129",
                      "mechanism": "ip4"
                    },
                    {
                      "value": "51.77.79.158",
                      "mechanism": "ip4"
                    },
                    {
                      "value": "54.38.221.122",
                      "mechanism": "ip4"
                    },
                    {
                      "value": "188.165.51.139",
                      "mechanism": "ip4"
                    },
                    {
                      "value": "54.36.149.183",
                      "mechanism": "ip4"
                    }
                  ],
                  "neutral": [],
                  "softfail": [],
                  "fail": [],
                  "include": [],
                  "redirect": null,
                  "exp": null,
                  "all": "softfail"
                },
                "warnings": []
              }
            ],
            "redirect": null,
            "exp": null,
            "all": "softfail"
          },
          "warnings": []
        }
      ],
      "redirect": null,
      "exp": null,
      "all": "softfail"
    }
  },
  "dmarc": {
    "record": "v=DMARC1; p=quarantine; fo=1; aspf=s; adkim=s;",
    "valid": true,
    "location": "proton.me",
    "warnings": [
      "rua tag (destination for aggregate reports) not found"
    ],
    "tags": {
      "v": {
        "value": "DMARC1",
        "explicit": true
      },
      "p": {
        "value": "quarantine",
        "explicit": true
      },
      "fo": {
        "value": "1",
        "explicit": true
      },
      "aspf": {
        "value": "s",
        "explicit": true
      },
      "adkim": {
        "value": "s",
        "explicit": true
      },
      "pct": {
        "value": 100,
        "explicit": false
      },
      "rf": {
        "value": "afrf",
        "explicit": false
      },
      "ri": {
        "value": 86400,
        "explicit": false
      },
      "sp": {
        "value": "quarantine",
        "explicit": false
      }
    }
  },
  "smtp_tls_reporting": {
    "valid": true,
    "tags": {
      "v": {
        "value": "TLSRPTv1"
      },
      "rua": {
        "value": [
          "https://reports.proton.me/reports/smtptls"
        ]
      }
    },
    "warnings": []
  }
}
```
