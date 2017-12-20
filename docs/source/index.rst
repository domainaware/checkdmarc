.. checkdmarc documentation master file, created by
   sphinx-quickstart on Sun Dec 10 20:49:29 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to checkdmarc's documentation!
======================================

``checkdmarc`` is a Python module and command line parser for SPF and DMARC DNS records

Installation
------------

`checkdmarc`` requires Python 3.

On Debian or Ubuntu systems, run:

.. code-block:: bash

    $ sudo apt-get install python3-pip


Python 3 installers for Windows and macOS can be found at https://www.python.org/downloads/

To install or upgrade to the latest stable release checkdmarc on macOS or Linux, run

.. code-block:: bash

    $ sudo pip3 -U install checkdmarc

Or, install the latest development release directly from GitHub:

.. code-block:: bash

    $ sudo pip3 -U install git+https://github.com/domainaware/checkdmarc.git

.. note::

    On Windows, ``pip3`` is ``pip``, regardless if you installed Python 2 or 3. So on Windows, simply
    substitute ``pip`` as an administrator in place of ``sudo pip3``, in the above commands.

Command line usage
------------------
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
                            (default 4.0)
      -v, --version         show program's version number and exit
      -w WAIT, --wait WAIT  number os seconds to wait between processing domains
                            (default 0.0)


.. code-block:: bash

    $ checkdmarc fbi.gov

.. code-block:: json

    {
      "domain": "fbi.gov",
      "mx": {
        "hosts": [
          {
            "preference": 10,
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

Bug reports
-----------

Please report bugs on the GitHub issue tracker

https://github.com/domainaware/checkdmarc/issues

Module documentation
--------------------

.. toctree::
   :maxdepth: 2
   :caption: Contents:

.. include::  modules.rst

.. automodule:: checkdmarc

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
