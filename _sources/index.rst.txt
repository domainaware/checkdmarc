.. checkdmarc documentation master file, created by
   sphinx-quickstart on Sun Dec 10 20:49:29 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to checkdmarc's documentation!
======================================

checkdmarc is a Python module and command line parser for SPF and DMARC records

Installation
------------

While this script should work under Python 2 and 3, using Python 3 for your OS is strongly recommended.

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

    usage: checkdmarc [-h] [-f FORMAT] [-o OUTPUT] [-d]
                      [-n NAMESERVER [NAMESERVER ...]] [-t TIMEOUT] [-v]
                      domain [domain ...]

        Validates and parses SPF amd DMARC DNS records

        positional arguments:
          domain                one or ore domains, or a single path to a file
                                containing a list of domains

        optional arguments:
          -h, --help            show this help message and exit
          -f FORMAT, --format FORMAT
                                specify JSON or CSV output format
          -o OUTPUT, --output OUTPUT
                                output to a file path rather than printing to the
                                screen
          -d, --descriptions    include descriptions of DMARC tags in the JSON output
          -n NAMESERVER [NAMESERVER ...], --nameserver NAMESERVER [NAMESERVER ...]
                                nameservers to query
          -t TIMEOUT, --timeout TIMEOUT
                                number of seconds to wait for an answer from DNS
                                (default 2)
          -v, --version         show program's version number and exit

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
