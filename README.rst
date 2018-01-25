checkdmarc
==========

|Build Status|

A Python module and command line utility for validating SPF and DMARC DNS records

::

    usage: checkdmarc [-h] [-d] [-f FORMAT] [-o OUTPUT]
                  [-n NAMESERVER [NAMESERVER ...]] [-t TIMEOUT] [-v]
                  [-w WAIT]
                  domain [domain ...]

    Validates and parses SPF amd DMARC DNS records

    positional arguments:
      domain                one or ore domains, or a single path to a file
                            containing a list of domains

    optional arguments:
      -h, --help            show this help message and exit
      -d, --descriptions    include descriptions of DMARC tags in the JSON output
      -f FORMAT, --format FORMAT
                            specify JSON or CSV output format
      -o OUTPUT, --output OUTPUT
                            output to a file path rather than printing to the
                            screen
      -n NAMESERVER [NAMESERVER ...], --nameserver NAMESERVER [NAMESERVER ...]
                            nameservers to query
      -t TIMEOUT, --timeout TIMEOUT
                            number of seconds to wait for an answer from DNS
                            (default 6.0)
      -v, --version         show program's version number and exit
      -w WAIT, --wait WAIT  number os seconds to wait between processing domains
                            (default 0.0)


.. code-block:: bash

    $ checkdmarc fbi.gov

.. code-block:: json

    {
      "domain": "accenture.com",
      "base_domain": "accenture.com",
      "mx": {
        "hosts": [
          {
            "preference": 10,
            "hostname": "mx0a-001dcc01.pphosted.com",
            "addresses": [
              "148.163.157.10"
            ]
          },
          {
            "preference": 10,
            "hostname": "mx0b-001dcc01.pphosted.com",
            "addresses": [
              "148.163.159.10"
            ]
          }
        ],
        "warnings": []
      },
      "spf": {
        "record": "v=spf1 mx ip4:170.252.46.0/28 ip4:170.252.248.64/27 ip4:170.252.43.192/26 ip4:170.252.38.64/26 ip4:67.231.157.136 ip4:67.231.149.140 ip4:204.90.21.128 ip4:204.90.21.132 ip4:204.90.21.133 ip4:204.90.21.134 ip4:96.65.150.125 ip4:67.192.21.185 ip4:91.209.134.59 ip4:91.209.134.60 ip4:194.224.177.201 ip4:217.130.124.201 ip4:207.254.213.9 ip4:216.130.131.68 ip4:199.255.204.5 ip4:192.104.67.6 ip4:192.104.67.3 ip4:216.244.121.94 ip4:64.21.54.41 include:spf.protection.outlook.com -all",
        "valid": true,
        "dns_lookups": 4,
        "warnings": [],
        "parsed": {
          "pass": [
            {
              "value": "mx0a-001dcc01.pphosted.com",
              "mechanism": "mx"
            },
            {
              "value": "mx0b-001dcc01.pphosted.com",
              "mechanism": "mx"
            },
            {
              "value": "170.252.46.0/28",
              "mechanism": "ip4"
            },
            {
              "value": "170.252.248.64/27",
              "mechanism": "ip4"
            },
            {
              "value": "170.252.43.192/26",
              "mechanism": "ip4"
            },
            {
              "value": "170.252.38.64/26",
              "mechanism": "ip4"
            },
            {
              "value": "67.231.157.136",
              "mechanism": "ip4"
            },
            {
              "value": "67.231.149.140",
              "mechanism": "ip4"
            },
            {
              "value": "204.90.21.128",
              "mechanism": "ip4"
            },
            {
              "value": "204.90.21.132",
              "mechanism": "ip4"
            },
            {
              "value": "204.90.21.133",
              "mechanism": "ip4"
            },
            {
              "value": "204.90.21.134",
              "mechanism": "ip4"
            },
            {
              "value": "96.65.150.125",
              "mechanism": "ip4"
            },
            {
              "value": "67.192.21.185",
              "mechanism": "ip4"
            },
            {
              "value": "91.209.134.59",
              "mechanism": "ip4"
            },
            {
              "value": "91.209.134.60",
              "mechanism": "ip4"
            },
            {
              "value": "194.224.177.201",
              "mechanism": "ip4"
            },
            {
              "value": "217.130.124.201",
              "mechanism": "ip4"
            },
            {
              "value": "207.254.213.9",
              "mechanism": "ip4"
            },
            {
              "value": "216.130.131.68",
              "mechanism": "ip4"
            },
            {
              "value": "199.255.204.5",
              "mechanism": "ip4"
            },
            {
              "value": "192.104.67.6",
              "mechanism": "ip4"
            },
            {
              "value": "192.104.67.3",
              "mechanism": "ip4"
            },
            {
              "value": "216.244.121.94",
              "mechanism": "ip4"
            },
            {
              "value": "64.21.54.41",
              "mechanism": "ip4"
            }
          ],
          "neutral": [],
          "softfail": [],
          "fail": [],
          "include": [
            {
              "domain": "spf.protection.outlook.com",
              "record": "v=spf1 ip4:207.46.100.0/24 ip4:207.46.163.0/24 ip4:65.55.169.0/24 ip4:157.56.110.0/23 ip4:157.55.234.0/24 ip4:213.199.154.0/24 ip4:213.199.180.128/26 include:spfa.protection.outlook.com -all",
              "dns_lookups": 2,
              "parsed": {
                "pass": [
                  {
                    "value": "207.46.100.0/24",
                    "mechanism": "ip4"
                  },
                  {
                    "value": "207.46.163.0/24",
                    "mechanism": "ip4"
                  },
                  {
                    "value": "65.55.169.0/24",
                    "mechanism": "ip4"
                  },
                  {
                    "value": "157.56.110.0/23",
                    "mechanism": "ip4"
                  },
                  {
                    "value": "157.55.234.0/24",
                    "mechanism": "ip4"
                  },
                  {
                    "value": "213.199.154.0/24",
                    "mechanism": "ip4"
                  },
                  {
                    "value": "213.199.180.128/26",
                    "mechanism": "ip4"
                  }
                ],
                "neutral": [],
                "softfail": [],
                "fail": [],
                "include": [
                  {
                    "domain": "spfa.protection.outlook.com",
                    "record": "v=spf1 ip4:157.56.112.0/24 ip4:207.46.51.64/26 ip4:64.4.22.64/26 ip4:40.92.0.0/14 ip4:40.107.0.0/17 ip4:40.107.128.0/17 ip4:134.170.140.0/24 include:spfb.protection.outlook.com ip6:2001:489a:2202::/48 -all",
                    "dns_lookups": 1,
                    "parsed": {
                      "pass": [
                        {
                          "value": "157.56.112.0/24",
                          "mechanism": "ip4"
                        },
                        {
                          "value": "207.46.51.64/26",
                          "mechanism": "ip4"
                        },
                        {
                          "value": "64.4.22.64/26",
                          "mechanism": "ip4"
                        },
                        {
                          "value": "40.92.0.0/14",
                          "mechanism": "ip4"
                        },
                        {
                          "value": "40.107.0.0/17",
                          "mechanism": "ip4"
                        },
                        {
                          "value": "40.107.128.0/17",
                          "mechanism": "ip4"
                        },
                        {
                          "value": "134.170.140.0/24",
                          "mechanism": "ip4"
                        },
                        {
                          "value": "2001:489a:2202::/48",
                          "mechanism": "ip6"
                        }
                      ],
                      "neutral": [],
                      "softfail": [],
                      "fail": [],
                      "include": [
                        {
                          "domain": "spfb.protection.outlook.com",
                          "record": "v=spf1 ip6:2a01:111:f400::/48 ip4:23.103.128.0/19 ip4:23.103.198.0/23 ip4:65.55.88.0/24 ip4:104.47.0.0/17 ip4:23.103.200.0/21 ip4:23.103.208.0/21 ip4:23.103.191.0/24 ip4:216.32.180.0/23 ip4:94.245.120.64/26 -all",
                          "dns_lookups": 0,
                          "parsed": {
                            "pass": [
                              {
                                "value": "2a01:111:f400::/48",
                                "mechanism": "ip6"
                              },
                              {
                                "value": "23.103.128.0/19",
                                "mechanism": "ip4"
                              },
                              {
                                "value": "23.103.198.0/23",
                                "mechanism": "ip4"
                              },
                              {
                                "value": "65.55.88.0/24",
                                "mechanism": "ip4"
                              },
                              {
                                "value": "104.47.0.0/17",
                                "mechanism": "ip4"
                              },
                              {
                                "value": "23.103.200.0/21",
                                "mechanism": "ip4"
                              },
                              {
                                "value": "23.103.208.0/21",
                                "mechanism": "ip4"
                              },
                              {
                                "value": "23.103.191.0/24",
                                "mechanism": "ip4"
                              },
                              {
                                "value": "216.32.180.0/23",
                                "mechanism": "ip4"
                              },
                              {
                                "value": "94.245.120.64/26",
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
                          },
                          "warnings": []
                        }
                      ],
                      "redirect": null,
                      "exp": null,
                      "all": "fail"
                    },
                    "warnings": []
                  }
                ],
                "redirect": null,
                "exp": null,
                "all": "fail"
              },
              "warnings": []
            }
          ],
          "redirect": null,
          "exp": null,
          "all": "fail"
        }
      },
      "dmarc": {
        "record": "v=DMARC1;p=none;fo=1;rua=mailto:dmarc_rua@emaildefense.proofpoint.com;ruf=mailto:dmarc_ruf@emaildefense.proofpoint.com",
        "valid": true,
        "location": "accenture.com",
        "tags": {
          "v": {
            "value": "DMARC1",
            "explicit": true
          },
          "p": {
            "value": "none",
            "explicit": true
          },
          "fo": {
            "value": [
              "1"
            ],
            "explicit": true
          },
          "rua": {
            "value": [
              {
                "scheme": "mailto",
                "address": "dmarc_rua@emaildefense.proofpoint.com",
                "size_limit": null
              }
            ],
            "explicit": true
          },
          "ruf": {
            "value": [
              {
                "scheme": "mailto",
                "address": "dmarc_ruf@emaildefense.proofpoint.com",
                "size_limit": null
              }
            ],
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
          "pct": {
            "value": 100,
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
            "value": "none",
            "explicit": false
          }
        },
        "warnings": []
      }
    }




Installation
------------

``checkdmarc`` requires Python 3.

On Debian or Ubuntu systems, run:

.. code-block:: bash

    $ sudo apt-get install python3-pip


Python 3 installers for Windows and macOS can be found at https://www.python.org/downloads/

To install or upgrade to the latest stable release of ``checkdmarc`` on macOS or Linux, run

.. code-block:: bash

    $ sudo -H pip3 install -U checkdmarc

Or, install the latest development release directly from GitHub:

.. code-block:: bash

    $ sudo -H pip3 install -U git+https://github.com/domainaware/checkdmarc.git

.. note::

    On Windows, ``pip3`` is ``pip``, even with Python 3. So on Windows, simply
    substitute ``pip`` as an administrator in place of ``sudo pip3``, in the above commands.


Documentation
-------------

https://domainaware.github.io/checkdmarc

Bug reports
-----------

Please report bugs on the GitHub issue tracker

https://github.com/domainaware/checkdmarc/issues

.. |Build Status| image:: https://travis-ci.org/domainaware/checkdmarc.svg?branch=master
   :target: https://travis-ci.org/domainaware/checkdmarc