.. checkdmarc documentation master file, created by
   sphinx-quickstart on Sun Dec 10 20:49:29 2017.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to checkdmarc's documentation!
======================================

checkdmark is a Python module and command line parser for SPF and DMARC records

Installation
------------
.. code-block:: bash

    $ sudo apt-get install python3-pip
    $ sudo pip3 install checkdmarc

Command line usage
------------------
::

    usage: checkdmarc [-h] [-f FORMAT] [-o OUTPUT] [-d]
                      [-n NAMESERVER [NAMESERVER ...]] [-v]
                      domain [domain ...]

    Validates and parses SPF amd DMARC DNS records

    positional arguments:
      domain                One or ore domains, or single a path to a file
                            containing a list of domains

    optional arguments:
      -h, --help            show this help message and exit
      -f FORMAT, --format FORMAT
                            Specify JSON or CSV output format
      -o OUTPUT, --output OUTPUT
                            Output to a file path rather than printing to the
                            screen
      -d, --descriptions    Include descriptions of DMARC tags in the JSON output
      -n NAMESERVER [NAMESERVER ...], --nameserver NAMESERVER [NAMESERVER ...]
                            Nameservers to query
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
