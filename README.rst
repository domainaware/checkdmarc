checkdmarc
==========

|Build Status|

A Python module and command line utility for validating SPF and DMARC DNS records

::

  usage: checkdmarc  [-h] [-p] [--ns NS [NS ...]] [--mx MX [MX ...]] [-d]
                     [-f FORMAT] [-o OUTPUT [OUTPUT ...]]
                     [-n NAMESERVER [NAMESERVER ...]] [-t TIMEOUT] [-v]
                     [-w WAIT] [--skip-tls] [--debug]
                     domain [domain ...]

   Validates and parses SPF amd DMARC DNS records

   positional arguments:
     domain                one or more domains, or a single path to a file
                           containing a list of domains

   optional arguments:
     -h, --help            show this help message and exit
     -p, --parked          indicate that the domains are parked
     --ns NS [NS ...]      approved nameserver substrings
     --mx MX [MX ...]      approved MX hostname substrings
     -d, --descriptions    include descriptions of DMARC tags in the JSON output
     -f FORMAT, --format FORMAT
                           specify JSON or CSV screen output format
     -o OUTPUT [OUTPUT ...], --output OUTPUT [OUTPUT ...]
                           one or more file paths to output to (must end in .json
                           or .csv) (silences screen output)
     -n NAMESERVER [NAMESERVER ...], --nameserver NAMESERVER [NAMESERVER ...]
                           nameservers to query (Default is Cloudflare's
     -t TIMEOUT, --timeout TIMEOUT
                           number of seconds to wait for an answer from DNS
                           (default 6.0)
     -v, --version         show program's version number and exit
     -w WAIT, --wait WAIT  number of seconds to wait between checking domains
                           (default 0.0)
     --skip-tls            skip TLS/SSL testing
     --debug               enable debugging output

.. warning::

    It is **strongly recommended** to **not** use the ``--nameserver/-n`` setting.
    By default, ``checkdmarc`` uses `Cloudflare's public resolvers`_,
    which are much faster and more reliable than Google, Cisco OpenDNS, or
    even most local resolvers.

    The ``--nameservers/-n`` option should only be used if your network blocks DNS
    requests to outside resolvers.

.. code-block:: bash

    $ checkdmarc fbi.gov

.. code-block:: json

    {
      "domain": "fbi.gov",
      "base_domain": "fbi.gov",
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

Resources
=========

DMARC guides
------------

* `Demystifying DMARC`_ - A complete guide to SPF, DKIM, and DMARC


.. |Build Status| image:: https://travis-ci.org/domainaware/checkdmarc.svg?branch=master
   :target: https://travis-ci.org/domainaware/checkdmarc

.. _Cloudflare's public resolvers: https://1.1.1.1/

.. _Demystifying DMARC: https://seanthegeek.net/459/demystifying-dmarc/
