A Python module and command line parser for SPF and DMARC DNS records

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
                            (default 2.0)
      -v, --version         show program's version number and exit
      -w WAIT, --wait WAIT  number os seconds to wait between processing domains
                            (default 0.0)

::

    $ checkdmarc fbi.gov
    {
      "domain": "fbi.gov",
      "mx": {
        "hosts": [
          {
            "hostname": "mx-east.fbi.gov",
            "addresses": [
              "153.31.160.5"
            ]
          }
        ],
        "warnings": []
      },
      "spf": {
        "record": "v=spf1 +mx ip4:153.31.0.0/16 -all",
        "valid": true,
        "results": {
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
        },
        "warnings": []
      },
      "dmarc": {
        "record": "v=DMARC1; p=reject; adkim=r; aspf=r; rua=mailto:dmarc-feedback@fbi.gov; ruf=mailto:dmarc-feedback@fbi.gov; pct=100",
        "valid": true,
        "organisational_domain": "fbi.gov",
        "tags": {
          "v": {
            "value": "DMARC1",
            "explicit": true
          },
          "p": {
            "value": "reject",
            "explicit": true
          },
          "adkim": {
            "value": "r",
            "explicit": true
          },
          "aspf": {
            "value": "r",
            "explicit": true
          },
          "rua": {
            "value": "mailto:dmarc-feedback@fbi.gov",
            "explicit": true
          },
          "ruf": {
            "value": "mailto:dmarc-feedback@fbi.gov",
            "explicit": true
          },
          "pct": {
            "value": 100,
            "explicit": true
          },
          "fo": {
            "value": "0",
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
            "value": "reject",
            "explicit": false
          }
        },
        "warnings": []
      }
    }


Installation
------------

While this script should work under Python 2 and 3, using Python 3 for your OS is strongly recommended.

On Debian or Ubuntu systems, run:

::

    $ sudo apt-get install python3-pip


Python 3 installers for Windows and macOS can be found at https://www.python.org/downloads/

To install or upgrade to the latest stable release of checkdmarc on macOS or Linux, run

::

    $ sudo pip3 -U install checkdmarc

Or, install the latest development release directly from GitHub:

::

    $ sudo pip3 -U install git+https://github.com/domainaware/checkdmarc.git


Note to Windows users
^^^^^^^^^^^^^^^^^^^^^

On Windows, ``pip3`` is ``pip``, regardless if you installed Python 2 or 3. So on Windows, simply
substitute ``pip`` as an administrator in place of ``sudo pip3``, in the above commands.

Documentation
-------------

https://domainaware.github.io/checkdmarc

Bug reports
-----------

Please report bugs on the GitHub issue tracker

https://github.com/domainaware/checkdmarc/issues