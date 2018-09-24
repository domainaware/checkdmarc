#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Validates and parses SPF amd DMARC DNS records"""

import logging
from collections import OrderedDict
from re import compile
import json
from csv import DictWriter
from argparse import ArgumentParser
from os import path, stat
from time import sleep
from datetime import datetime, timedelta

from io import StringIO

import publicsuffix
import dns.resolver
import dns.exception
from pyleri import (Grammar,
                    Regex,
                    Sequence,
                    List,
                    Repeat
                    )

"""Copyright 2017 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

__version__ = "2.7.1"

DMARC_VERSION_REGEX_STRING = r"v=DMARC1;"
DMARC_TAG_VALUE_REGEX_STRING = r"([a-z]{1,5})=([\w.:@/+!,_\- ]+)"
MAILTO_REGEX_STRING = r"^(mailto):" \
                      r"([\w\-!#$%&'*+-/=?^_`{|}~]" \
                      r"[\w\-.!#$%&'*+-/=?^_`{|}~]*@[\w\-.]+)(!\w+)?"
SPF_VERSION_TAG_REGEX_STRING = "v=spf1"
SPF_MECHANISM_REGEX_STRING = r"([+\-~?])?(mx|ip4|ip6|exists|include|all|a|" \
                             r"redirect|exp|ptr)[:=]?([\w+/_.:\-{%}]*)"
IPV4_REGEX_STRING = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{2})?$"

DMARC_TAG_VALUE_REGEX = compile(DMARC_TAG_VALUE_REGEX_STRING)
MAILTO_REGEX = compile(MAILTO_REGEX_STRING)
SPF_MECHANISM_REGEX = compile(SPF_MECHANISM_REGEX_STRING)
IPV4_REGEX = compile(IPV4_REGEX_STRING)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SPFError(Exception):
    """Raised when a fatal SPF error occurs"""
    def __init__(self, msg, data=None):
        """
        Args:
            msg (str): The error message
            data (dict): A dictionary of data to include in the output
        """
        self.data = data
        Exception.__init__(self, msg)


class _SPFWarning(Exception):
    """Raised when a non-fatal SPF error occurs"""


class _SPFMissingRecords(_SPFWarning):
    """Raised when a mechanism in a ``SPF`` record is missing the requested
    A/AAAA or MX records"""


class _SPFDuplicateInclude(_SPFWarning):
    """Raised when a duplicate SPF include is found"""


class _DMARCWarning(Exception):
    """Raised when a non-fatal DMARC error occurs"""


class _DMARCBestPracticeWarning(_DMARCWarning):
    """Raised when a DMARC record does not follow a best practice"""


class DNSException(Exception):
    """Raised when a general DNS error occurs"""
    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class DMARCError(Exception):
    """Raised when a fatal DMARC error occurs"""
    def __init__(self, msg, data=None):
        """
        Args:
            msg (str): The error message
            data (dict): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class SPFRecordNotFound(SPFError):
    """Raised when an SPF record could not be found"""
    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class MultipleSPFRTXTRecords(SPFError):
    """Raised when multiple TXT spf1 records are found"""


class SPFSyntaxError(SPFError):
    """Raised when an SPF syntax error is found"""


class SPFTooManyDNSLookups(SPFError):
    """Raised when an SPF record requires too many DNS lookups (10 max)"""
    def __init__(self, *args, **kwargs):
        data = dict(dns_lookups=kwargs["dns_lookups"])
        SPFError.__init__(self, args[0], data=data)


class SPFRedirectLoop(SPFError):
    """Raised when a SPF redirect loop is detected"""


class SPFIncludeLoop(SPFError):
    """Raised when a SPF include loop is detected"""


class DMARCRecordNotFound(DMARCError):
    """Raised when a DMARC record could not be found"""
    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class DMARCSyntaxError(DMARCError):
    """Raised when a DMARC syntax error is found"""


class InvalidDMARCTag(DMARCSyntaxError):
    """Raised when an invalid DMARC tag is found"""


class InvalidDMARCTagValue(DMARCSyntaxError):
    """Raised when an invalid DMARC tag value is found"""


class InvalidDMARCReportURI(InvalidDMARCTagValue):
    """Raised when an invalid DMARC reporting URI is found"""


class SPFRecordFoundWhereDMARCRecordShouldBe(DMARCError):
    """Raised when a SPF record is found where a DMARC record should be;
    most likely, the ``_dmarc`` subdomain
    record does not actually exist, and the request for ``TXT`` records was
    redirected to the base domain"""


class DMARCRecordInWrongLocation(DMARCError):
    """Raised when a DMARC record is found at the root of a domain"""


class DMARCReportEmailAddressMissingMXRecords(DMARCError):
    """Raised when a email address in a DMARC report URI is missing MX
    records"""


class UnrelatedTXTRecordFound(DMARCError):
    """Raised when a TXT record unrelated to DMARC is found"""


class UnverifiedDMARCURIDestination(DMARCError):
    """Raised when the destination of a DMARC report URI does not indicate
    that it accepts reports for the domain"""


class MultipleDMARCRecords(DMARCError):
    """Raised when multiple DMARC records are found, in violation of
    RFC 7486, section 6.6.3"""


class _SPFGrammar(Grammar):
    """Defines Pyleri grammar for SPF records"""
    version_tag = Regex(SPF_VERSION_TAG_REGEX_STRING)
    mechanism = Regex(SPF_MECHANISM_REGEX_STRING)
    START = Sequence(version_tag, Repeat(mechanism))


class _DMARCGrammar(Grammar):
    """Defines Pyleri grammar for DMARC records"""
    version_tag = Regex(DMARC_VERSION_REGEX_STRING)
    tag_value = Regex(DMARC_TAG_VALUE_REGEX_STRING)
    START = Sequence(version_tag, List(tag_value, delimiter=";", opt=True))


tag_values = OrderedDict(adkim=OrderedDict(name="DKIM Alignment Mode",
                                           default="r",
                                           description='In relaxed mode, '
                                                       'the Organizational '
                                                       'Domains of both the '
                                                       'DKIM-authenticated '
                                                       'signing domain (taken '
                                                       'from the value of the '
                                                       '"d=" tag in the '
                                                       'signature) and that '
                                                       'of the RFC 5322 '
                                                       'From domain '
                                                       'must be equal if the '
                                                       'identifiers are to be '
                                                       'considered aligned.'),
                         aspf=OrderedDict(name="SPF alignment mode",
                                          default="r",
                                          description='In relaxed mode, '
                                                      'the SPF-authenticated '
                                                      'domain and RFC5322 '
                                                      'From domain must have '
                                                      'the same '
                                                      'Organizational Domain. '
                                                      'In strict mode, only '
                                                      'an exact DNS domain '
                                                      'match is considered to '
                                                      'produce Identifier '
                                                      'Alignment.'),
                         fo=OrderedDict(name="Failure Reporting Options",
                                        default="0",
                                        description='Provides requested '
                                                    'options for generation '
                                                    'of failure reports. '
                                                    'Report generators MAY '
                                                    'choose to adhere to the '
                                                    'requested options. '
                                                    'This tag\'s content '
                                                    'MUST be ignored if '
                                                    'a "ruf" tag (below) is '
                                                    'not also specified. '
                                                    'The value of this tag is '
                                                    'a colon-separated list '
                                                    'of characters that '
                                                    'indicate failure '
                                                    'reporting options.',
                                        values={
                                            "0": 'Generate a DMARC failure '
                                                 'report if all underlying '
                                                 'authentication mechanisms '
                                                 'fail to produce an aligned '
                                                 '"pass" result.',
                                            "1": 'Generate a DMARC failure '
                                                 'report if any underlying '
                                                 'authentication mechanism '
                                                 'produced something other '
                                                 'than an aligned '
                                                 '"pass" result.',
                                            "d": 'Generate a DKIM failure '
                                                 'report if the message had '
                                                 'a signature that failed '
                                                 'evaluation, regardless of '
                                                 'its alignment. DKIM-'
                                                 'specific reporting is '
                                                 'described in AFRF-DKIM.',
                                            "s": 'Generate an SPF failure '
                                                 'report if the message '
                                                 'failed SPF evaluation, '
                                                 'regardless of its alignment.'
                                                 ' SPF-specific reporting is '
                                                 'described in AFRF-SPF'
                                            }
                                        ),
                         p=OrderedDict(name="Requested Mail Receiver Policy",
                                       description='Specifies the policy to '
                                                   'be enacted by the '
                                                   'Receiver at the '
                                                   'request of the '
                                                   'Domain Owner. The '
                                                   'policy applies to '
                                                   'the domain and to its '
                                                   'subdomains, unless '
                                                   'subdomain policy '
                                                   'is explicitly described '
                                                   'using the "sp" tag.',
                                       values={
                                           "none": 'The Domain Owner requests '
                                                   'no specific action be '
                                                   'taken regarding delivery '
                                                   'of messages.',
                                           "quarantine": 'The Domain Owner '
                                                         'wishes to have '
                                                         'email that fails '
                                                         'the DMARC mechanism '
                                                         'check be treated by '
                                                         'Mail Receivers as '
                                                         'suspicious. '
                                                         'Depending on the '
                                                         'capabilities of the '
                                                         'MailReceiver, '
                                                         'this can mean '
                                                         '"place into spam '
                                                         'folder", '
                                                         '"scrutinize '
                                                         'with additional '
                                                         'intensity", and/or '
                                                         '"flag as '
                                                         'suspicious".',
                                           "reject": 'The Domain Owner wishes '
                                                     'for Mail Receivers to '
                                                     'reject '
                                                     'email that fails the '
                                                     'DMARC mechanism check. '
                                                     'Rejection SHOULD '
                                                     'occur during the SMTP '
                                                     'transaction.'
                                           }
                                       ),
                         pct=OrderedDict(name="Percentage",
                                         default=100,
                                         description='Integer percentage of '
                                                     'messages from the '
                                                     'Domain Owner\'s '
                                                     'mail stream to which '
                                                     'the DMARC policy is to '
                                                     'be applied. '
                                                     'However, this '
                                                     'MUST NOT be applied to '
                                                     'the DMARC-generated '
                                                     'reports, all of which '
                                                     'must be sent and '
                                                     'received unhindered. '
                                                     'The purpose of the '
                                                     '"pct" tag is to allow '
                                                     'Domain Owners to enact '
                                                     'a slow rollout of '
                                                     'enforcement of the '
                                                     'DMARC mechanism.'
                                         ),
                         rf=OrderedDict(name="Report Format",
                                        default="afrf",
                                        description='A list separated by '
                                                    'colons of one or more '
                                                    'report formats as '
                                                    'requested by the '
                                                    'Domain Owner to be '
                                                    'used when a message '
                                                    'fails both SPF and DKIM '
                                                    'tests to report details '
                                                    'of the individual '
                                                    'failure. Only "afrf" '
                                                    '(the auth-failure report '
                                                    'type) is currently '
                                                    'supported in the '
                                                    'DMARC standard.',
                                        values={
                                            "afrf": ' "Authentication Failure '
                                                    'Reporting Using the '
                                                    'Abuse Reporting Format", '
                                                    'RFC 6591, April 2012,'
                                                    '<http://www.rfc-'
                                                    'editor.org/info/rfc6591>'
                                        }
                                        ),
                         ri=OrderedDict(name="Report Interval",
                                        default=86400,
                                        description='Indicates a request to '
                                                    'Receivers to generate '
                                                    'aggregate reports '
                                                    'separated by no more '
                                                    'than the requested '
                                                    'number of seconds. '
                                                    'DMARC implementations '
                                                    'MUST be able to provide '
                                                    'daily reports and '
                                                    'SHOULD be able to '
                                                    'provide hourly reports '
                                                    'when requested. '
                                                    'However, anything other '
                                                    'than a daily report is '
                                                    'understood to '
                                                    'be accommodated on a '
                                                    'best-effort basis.'
                                        ),
                         rua=OrderedDict(name="Aggregate Feedback Addresses",
                                         description=' A comma-separated list '
                                                     'of DMARC URIs to which '
                                                     'aggregate feedback '
                                                     'is to be sent.'
                                         ),
                         ruf=OrderedDict(name="Forensic Feedback Addresses",
                                         description=' A comma-separated list '
                                                     'of DMARC URIs to which '
                                                     'forensic feedback '
                                                     'is to be sent.'
                                         ),
                         sp=OrderedDict(name="Subdomain Policy",
                                        description='Indicates the policy to '
                                                    'be enacted by the '
                                                    'Receiver at the request '
                                                    'of the Domain Owner. '
                                                    'It applies only to '
                                                    'subdomains of the '
                                                    'domain queried, and not '
                                                    'to the domain itself. '
                                                    'Its syntax is identical '
                                                    'to that of the "p" tag '
                                                    'defined above. If '
                                                    'absent, the policy '
                                                    'specified by the "p" '
                                                    'tag MUST be applied '
                                                    'for subdomains.'
                                        ),
                         v=OrderedDict(name="Version",
                                       default="DMARC1",
                                       description='Identifies the record '
                                                   'retrieved as a DMARC '
                                                   'record. It MUST have the '
                                                   'value of "DMARC1". The '
                                                   'value of this tag MUST '
                                                   'match precisely; if it '
                                                   'does not or it is absent, '
                                                   'the entire retrieved '
                                                   'record MUST be ignored. '
                                                   'It MUST be the first '
                                                   'tag in the list.')
                         )

spf_qualifiers = {
    "": "pass",
    "?": "neutral",
    "+": "pass",
    "-": "fail",
    "~": "softfail"
}


def get_base_domain(domain):
    """
    Gets the base domain name for the given domain

    .. note::
        Results are based on a list of public domain suffixes at
        https://publicsuffix.org/list/public_suffix_list.dat.

        This file is saved to the current working directory,
        where it is used as a cache file for 24 hours.

    Args:
        domain (str): A domain or subdomain

    Returns:
        str: The base domain of the given domain

    """
    psl_path = ".public_suffix_list.dat"

    def download_psl():
        fresh_psl = publicsuffix.fetch().read()
        with open(psl_path, "w", encoding="utf-8") as fresh_psl_file:
            fresh_psl_file.write(fresh_psl)

    if not path.exists(psl_path):
        download_psl()
    else:
        psl_age = datetime.now() - datetime.fromtimestamp(
            stat(psl_path).st_mtime)
        if psl_age > timedelta(hours=24):
            try:
                download_psl()
            except Exception as error:
                logger.warning("Failed to download an updated PSL - \
                               {0}".format(error))
    with open(psl_path, encoding="utf-8") as psl_file:
        psl = publicsuffix.PublicSuffixList(psl_file)

    return psl.get_public_suffix(domain)


def _query_dns(domain, record_type, nameservers=None, timeout=2.0):
    resolver = dns.resolver.Resolver()
    timeout = float(timeout)
    if nameservers is None:
        nameservers = ["1.1.1.1", "1.0.0.1",
                       "2606:4700:4700::1111", "2606:4700:4700::1001",
                       ]
    resolver.nameservers = nameservers
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return list(map(
        lambda r: r.to_text().replace('"', '').rstrip("."),
        resolver.query(domain, record_type, tcp=True)))


def _get_mx_hosts(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for a list of Mail Exchange hosts

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)

    Returns:
        list: A list of ``OrderedDicts``; each containing a ``preference``
                        integer and a ``hostname``

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    hosts = []
    try:

        answers = _query_dns(domain, "MX", nameservers=nameservers,
                             timeout=timeout)
        for record in answers:
            record = record.split(" ")
            preference = int(record[0])
            hostname = record[1].rstrip(".").strip().lower()
            hosts.append(OrderedDict(
                [("preference", preference), ("hostname", hostname)]))
        hosts = sorted(hosts, key=lambda h: (h["preference"], h["hostname"]))
    except dns.resolver.NXDOMAIN:
        raise DNSException("The domain {0} does not exist".format(domain))
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException as error:
        raise DNSException(error)
    return hosts


def _get_a_records(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for A and AAAA records

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        list: A sorted list of IPv4 and IPv6 addresses

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    qtypes = ["A", "AAAA"]
    addresses = []
    for qt in qtypes:
        try:
            addresses += _query_dns(domain, qt, nameservers=nameservers,
                                    timeout=timeout)
        except dns.resolver.NXDOMAIN:
            raise DNSException("The domain {0} does not exist".format(domain))
        except dns.resolver.NoAnswer:
            # Sometimes a domain will only have A or AAAA records, but not both
            pass
        except dns.exception.DNSException as error:
            raise DNSException(error)

    addresses = sorted(addresses)
    return addresses


def _get_txt_records(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for TXT records

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        list: A list of TXT records

     Raises:
        :exc:`checkdmarc.DNSException`

    """
    try:
        records = _query_dns(domain, "TXT", nameservers=nameservers,
                             timeout=timeout)
    except dns.resolver.NXDOMAIN:
        raise DNSException("The domain {0} does not exist".format(domain))
    except dns.resolver.NoAnswer:
        raise DNSException(
            "The domain {0} does not have any TXT records".format(domain))
    except dns.exception.DNSException as error:
        raise DNSException(error)

    return records


def _query_dmarc_record(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for a DMARC record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an record from DNS

    Returns:
        str: A record string or None
    """
    target = "_dmarc.{0}".format(domain.lower())
    dmarc_record = None
    dmarc_record_count = 0
    unrelated_records = []

    try:
        records = _query_dns(target, "TXT", nameservers=nameservers,
                             timeout=timeout)
        for record in records:
            if record.startswith("v=DMARC1"):
                dmarc_record_count += 1
            else:
                unrelated_records.append(record)

        if dmarc_record_count > 1:
            raise MultipleDMARCRecords(
                "Multiple DMARC policy records are not permitted - "
                "https://tools.ietf.org/html/rfc7489#section-6.6.3")
        if len(unrelated_records) > 0:
            raise UnrelatedTXTRecordFound(
                "Unrelated TXT records were discovered. These should be "
                "removed, as some receivers may not expect to find "
                "unrelated TXT records "
                "at {0}\n\n{1}".format(target, "\n\n".join(unrelated_records)))
        dmarc_record = records[0]

    except dns.resolver.NoAnswer:
        try:
            records = _query_dns(domain.lower(), "TXT",
                                 nameservers=nameservers,
                                 timeout=timeout)
            for record in records:
                if record.startswith("v=DMARC1"):
                    raise DMARCRecordInWrongLocation(
                        "The DMARC record must be located at "
                        "{0}, not {1}".format(target, domain.lower()))
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise DMARCRecordNotFound(
                "The domain {0} does not exist".format(domain))
        except dns.exception.DNSException as error:
            DMARCRecordNotFound(error)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.exception.DNSException as error:
        raise DMARCRecordNotFound(error)

    return dmarc_record


def get_mx_hosts(domain, nameservers=None, timeout=2.0):
    """
    Gets MX hostname and their addresses

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``hosts`` - A ``list`` of ``OrderedDict`` with keys of

                       - ``hostname`` - A hostname
                       - ``addresses`` - A ``list`` of IP addresses

                     - ``warnings`` - A ``list`` of MX resolution warnings

    """
    mx_records = []
    hosts = []
    warnings = []
    try:
        mx_records = _get_mx_hosts(domain, nameservers=nameservers,
                                   timeout=timeout)
    except DNSException as warning:
        warnings.append(str(warning))
    for record in mx_records:
        hosts.append(OrderedDict([("preference", record["preference"]),
                                  ("hostname", record["hostname"]),
                                  ("addresses", [])]))
    for host in hosts:
        try:
            host["addresses"] = _get_a_records(host["hostname"],
                                               nameservers=nameservers,
                                               timeout=timeout)
        except DNSException as warning:
            warnings.append(str(warning))

    return OrderedDict([("hosts", hosts), ("warnings", warnings)])


def query_dmarc_record(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for a DMARC record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``record`` - the unparsed DMARC record string
                     - ``location`` - the domain where the record was found
                     - ``warnings`` - warning conditions found

     Raises:
        :exc:`checkdmarc.DMARCRecordNotFound`
        :exc:`checkdmarc.DMARCRecordInWrongLocation`
        :exc:`checkdmarc.MultipleDMARCRecords`
        :exc:`checkdmarc.SPFRecordFoundWhereDMARCRecordShouldBe`

    """
    warnings = []
    base_domain = get_base_domain(domain)
    location = domain.lower()
    record = _query_dmarc_record(domain, nameservers=nameservers,
                                 timeout=timeout)
    try:
        root_records = _query_dns(domain.lower(), "TXT",
                                  nameservers=nameservers,
                                  timeout=timeout)
        for root_record in root_records:
            if root_record.startswith("v=DMARC1"):
                warnings.append("DMARC record at root of {0} "
                                "has no effect".format(domain.lower()))
    except dns.exception.DNSException:
        pass

    if record is None and domain != base_domain:
        record = _query_dmarc_record(base_domain, nameservers=nameservers,
                                     timeout=timeout)
        location = base_domain
    if record is None:
        raise DMARCRecordNotFound(
            "A DMARC record does not exist for this domain or its base domain")

    return OrderedDict([("record", record), ("location", location),
                        ("warnings", warnings)])


def get_dmarc_tag_description(tag, value=None):
    """
    Get the name, default value, and description for a DMARC tag, amd/or a
    description for a tag value

    Args:
        tag (str): A DMARC tag
        value (str): An optional value

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``name`` - the tag name
                     - ``default``- the tag's default value
                     - ``description`` - A description of the tag or value
    """
    name = tag_values[tag]["name"]
    description = tag_values[tag]["description"]
    default = None
    if "default" in tag_values[tag]:
        default = tag_values[tag]["default"]
    if type(value) == str and "values" in tag_values[tag] and value in \
            tag_values[tag]["values"][value]:
        description = tag_values[tag]["values"][value]
    elif type(value) == list and "values" in tag_values[tag]:
        new_description = ""
        for value_value in value:
            if value_value in tag_values[tag]["values"]:
                new_description += "{0}: {1}\n\n".format(value_value,
                                                         tag_values[tag][
                                                             "values"][
                                                             value_value])
        new_description = new_description.strip()
        if new_description != "":
            description = new_description

    return OrderedDict(
        [("name", name), ("default", default), ("description", description)])


def parse_dmarc_report_uri(uri):
    """
    Parses a DMARC Reporting (i.e. ``rua``/``ruf``) URI

    .. note::
        ``mailto`` is the only reporting URI scheme supported in DMARC1

    Args:
        uri: A DMARC URI

    Returns:
        OrderedDict: An ``OrderedDict`` of the URI's components:
                    - ``scheme``
                    - ``address``
                    - ``size_limit``
    Raises:
        :exc:`checkdmarc.InvalidDMARCReportURI`

    """
    uri = uri.strip()
    mailto_matches = MAILTO_REGEX.findall(uri)
    if len(mailto_matches) != 1:
        raise InvalidDMARCReportURI(
            "{0} is not a valid DMARC report URI".format(uri))
    match = mailto_matches[0]
    scheme = match[0]
    email_address = match[1]
    size_limit = match[2].lstrip("!")
    if size_limit == "":
        size_limit = None

    return OrderedDict([("scheme", scheme), ("address", email_address),
                        ("size_limit", size_limit)])


def verify_dmarc_report_destination(source_domain, destination_domain,
                                    nameservers=None, timeout=2.0):
    """
      Checks if the report destination accepts reports for the source domain
      per RFC 7489, section 7.1

      Args:
          source_domain (str): The source domain
          destination_domain (str): The destination domain
          nameservers (list): A list of nameservers to query
          (Cloudflare's by default)
          timeout(float): number of seconds to wait for an answer from DNS

      Returns:
          bool: Indicates if the report domain accepts reports from the given
          domain

      Raises:
          :exc:`checkdmarc.UnverifiedDMARCURIDestination`
          :exc:`checkdmarc.UnrelatedTXTRecordFound`
      """

    source_domain = source_domain.lower()
    destination_domain = destination_domain.lower()

    if get_base_domain(source_domain) != get_base_domain(destination_domain):
        target = "{0}._report._dmarc.{1}".format(source_domain,
                                                 destination_domain)
        message = "{0} does not indicate that it accepts DMARC reports " \
                  "about {1} - " \
                  "Authorization record not found: " \
                  '{2} IN TXT "DMARC1"'.format(destination_domain,
                                               source_domain,
                                               target)
        dmarc_record_count = 0
        unrelated_records = []
        try:
            records = _query_dns(target, "TXT", nameservers=nameservers,
                                 timeout=timeout)
            for record in records:
                if record.startswith("v=DMARC1"):
                    dmarc_record_count += 1
                else:
                    unrelated_records.append(record)

            if len(unrelated_records) > 0:
                raise UnrelatedTXTRecordFound(
                    "Unrelated TXT records were discovered. "
                    "These should be removed, as some "
                    "receivers may not expect to find unrelated TXT records "
                    "at {0}\n\n{1}".format(target,
                                           "\n\n".join(unrelated_records)))

            if dmarc_record_count < 1:
                raise UnverifiedDMARCURIDestination(message)
        except dns.exception.DNSException:
            raise UnverifiedDMARCURIDestination(message)

    return True


def parse_dmarc_record(record, domain, include_tag_descriptions=False,
                       nameservers=None, timeout=2.0):
    """
    Parses a DMARC record

    Args:
        record (str): A DMARC record
        domain (str): The domain where the record is found
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``tags`` - An ``OrderedDict`` of DMARC tags

           - ``value`` - The DMARC tag value
           - ``explicit`` - ``bool``: A value is explicitly set
           - ``default`` - The tag's default value
           - ``description`` - A description of the tag/value

         - ``warnings`` - A ``list`` of warnings

         .. note::
            ``default`` and ``description`` are only included if
            ``include_tag_descriptions`` is set to ``True``

    Raises:
        :exc:`checkdmarc.DMARCSyntaxError`
        :exc:`checkdmarc.InvalidDMARCTag`
        :exc:`checkdmarc.InvaliddDMARCTagValue`
        :exc:`checkdmarc.InvalidDMARCReportURI`
        :exc:`checkdmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.UnrelatedTXTRecordFound`
        :exc:`checkdmarc.DMARCReportEmailAddressMissingMXRecords`

    """
    spf_in_dmarc_error_msg = "Found a SPF record where a DMARC record " \
                             "should be; most likely, the _dmarc " \
                             "subdomain record does not actually exist, " \
                             "and the request for TXT records was " \
                             "redirected to the base domain"
    warnings = []
    record = record.strip('"')
    if record.startswith("v=spf1"):
        raise SPFRecordFoundWhereDMARCRecordShouldBe(spf_in_dmarc_error_msg)
    dmarc_syntax_checker = _DMARCGrammar()
    parsed_record = dmarc_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        expecting = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting)))
        raise DMARCSyntaxError("Error: Expected {0} at position {1} in: "
                               "{2}".format(" or ".join(expecting),
                                            parsed_record.pos, record))

    pairs = DMARC_TAG_VALUE_REGEX.findall(record)
    tags = OrderedDict()

    # Find explicit tags
    for pair in pairs:
        tags[pair[0]] = OrderedDict(
            [("value", str(pair[1])), ("explicit", True)])

    # Include implicit tags and their defaults
    for tag in tag_values.keys():
        if tag not in tags and "default" in tag_values[tag]:
            tags[tag] = OrderedDict(
                [("value", tag_values[tag]["default"]), ("explicit", False)])
    if "p" not in tags:
        raise DMARCSyntaxError(
            'The record is missing the required policy ("p") tag')
    if "sp" not in tags:
        tags["sp"] = OrderedDict([("value", tags["p"]["value"]),
                                  ("explicit", False)])

    # Validate tag values
    for tag in tags:
        if tag not in tag_values:
            raise InvalidDMARCTag("{0} is not a valid DMARC tag".format(tag))
        if tag == "fo":
            tags[tag]["value"] = tags[tag]["value"].split(":")
            if "0" in tags[tag]["value"] and "1" in tags[tag]["value"]:
                raise InvalidDMARCTagValue(
                    "fo DMARC tag options 0 and 1 are mutually exclusive")
            for value in tags[tag]["value"]:
                if value not in tag_values[tag]["values"]:
                    raise InvalidDMARCTagValue(
                        "{0} is not a valid option for the DMARC "
                        "fo tag".format(value))
        elif tag == "rf":
            tags[tag]["value"] = tags[tag]["value"].split(":")
            for value in tags[tag]["value"]:
                if value not in tag_values[tag]["values"]:
                    raise InvalidDMARCTagValue(
                        "{0} is not a valid option for the DMARC "
                        "rf tag".format(value))

        elif "values" in tag_values[tag] and tags[tag]["value"] not in \
                tag_values[tag]["values"]:
            raise InvalidDMARCTagValue(
                "Tag {0} must have one of the following values: "
                "{1} - not {2}".format(tag,
                                       ",".join(tag_values[tag]["values"]),
                                       tags[tag]["value"]))

    try:
        tags["pct"]["value"] = int(tags["pct"]["value"])
    except ValueError:
        raise InvalidDMARCTagValue(
            "The value of the pct tag must be an integer")

    try:
        tags["ri"]["value"] = int(tags["ri"]["value"])
    except ValueError:
        raise InvalidDMARCTagValue(
            "The value of the ri tag must be an integer")

    try:
        if "rua" in tags:
            parsed_uris = []
            uris = tags["rua"]["value"].split(",")
            for uri in uris:
                uri = parse_dmarc_report_uri(uri)
                parsed_uris.append(uri)
                email_address = uri["address"]
                email_domain = email_address.split("@")[-1]
                if email_domain.lower() != domain.lower():
                    verify_dmarc_report_destination(domain, email_domain,
                                                    nameservers=nameservers,
                                                    timeout=timeout)
                try:
                    _get_mx_hosts(email_domain, nameservers=nameservers,
                                  timeout=timeout)
                except _SPFWarning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "The domain for rua email address "
                        "{0} has no MX records".format(
                            email_address)
                    )
                except DNSException as warning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "Failed to retrieve MX records for the domain of "
                        "rua email address "
                        "{0} - {1}".format(email_address, str(warning))
                    )
                tags["rua"]["value"] = parsed_uris
                if len(parsed_uris) > 2:
                    raise _DMARCBestPracticeWarning("Some DMARC reporters "
                                                    "might not send to more "
                                                    "than two rua URIs")
        else:
            raise _DMARCBestPracticeWarning(
                "rua tag (destination for aggregate reports) not found")

    except _DMARCWarning as warning:
        warnings.append(str(warning))

    try:
        if "ruf" in tags.keys():
            parsed_uris = []
            uris = tags["ruf"]["value"].split(",")
            for uri in uris:
                uri = parse_dmarc_report_uri(uri)
                parsed_uris.append(uri)
                email_address = uri["address"]
                email_domain = email_address.split("@")[-1]
                if email_domain.lower() != domain.lower():
                    verify_dmarc_report_destination(domain, email_domain,
                                                    nameservers=nameservers,
                                                    timeout=timeout)
                try:
                    _get_mx_hosts(email_domain, nameservers=nameservers,
                                  timeout=timeout)
                except _SPFWarning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "The domain for ruf email address "
                        "{0} has no MX records".format(
                            email_address)
                    )
                except DNSException as warning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "Failed to retrieve MX records for the domain of "
                        "ruf email address "
                        "{0} - {1}".format(email_address, str(warning))
                    )
                tags["ruf"]["value"] = parsed_uris
                if len(parsed_uris) > 2:
                    raise _DMARCBestPracticeWarning("Some DMARC reporters "
                                                    "might not send to more "
                                                    "than two ruf URIs")

        if tags["pct"]["value"] < 0 or tags["pct"]["value"] > 100:
            raise InvalidDMARCTagValue(
                "pct value must be an integer between 0 and 100")
        elif tags["pct"]["value"] < 100:
            warning_msg = "pct value is less than 100. This leads to " \
                          "inconsistent and unpredictable policy " \
                          "enforcement. Consider using p=none to " \
                          "monitor results instead"
            raise _DMARCBestPracticeWarning(warning_msg)

    except _DMARCWarning as warning:
        warnings.append(str(warning))

    # Add descriptions if requested
    if include_tag_descriptions:
        for tag in tags:
            details = get_dmarc_tag_description(tag, tags[tag]["value"])
            tags[tag]["name"] = details["name"]
            if details["default"]:
                tags[tag]["default"] = details["default"]
            tags[tag]["description"] = details["description"]

    return OrderedDict([("tags", tags), ("warnings", warnings)])


def get_dmarc_record(domain, include_tag_descriptions=False, nameservers=None,
                     timeout=2.0):
    """
    Retrieves a DMARC record for a domain and parses it

    Args:
        domain (str): A domain name
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``record`` - The DMARC record string
         - ``location`` -  Where the DMARC was found
         - ``parsed`` - See :meth:`checkdmarc.parse_dmarc_record`

     Raises:
        :exc:`checkdmarc.DMARCRecordNotFound`
        :exc:`checkdmarc.DMARCRecordInWrongLocation`
        :exc:`checkdmarc.MultipleDMARCRecords`
        :exc:`checkdmarc.SPFRecordFoundWhereDMARCRecordShouldBe`
        :exc:`checkdmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.DMARCSyntaxError`
        :exc:`checkdmarc.InvalidDMARCTag`
        :exc:`checkdmarc.InvalidDMARCTagValue`
        :exc:`checkdmarc.InvalidDMARCReportURI`
        :exc:`checkdmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.UnrelatedTXTRecordFound`
        :exc:`checkdmarc.DMARCReportEmailAddressMissingMXRecords`
    """
    query = query_dmarc_record(domain, nameservers=nameservers,
                               timeout=timeout)

    tag_descriptions = include_tag_descriptions

    tags = parse_dmarc_record(query["record"], query["location"],
                              include_tag_descriptions=tag_descriptions,
                              nameservers=nameservers, timeout=timeout)

    return OrderedDict([("record",
                         query["record"]),
                        ("location", query["location"]),
                        ("parsed", tags)])


def query_spf_record(domain, nameservers=None, timeout=2.0):
    """
    Queries DNS for a SPF record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``record`` - The SPF record string
         - ``warnings`` - A ``list`` of warnings

    Raises:
        :exc:`checkdmarc.SPFRecordNotFound`
    """
    warnings = []
    spf_type_records = []
    spf_txt_records = []
    try:
        spf_type_records += _query_dns(domain, "SPF", nameservers=nameservers,
                                       timeout=timeout)
    except (dns.resolver.NoAnswer, dns.exception.DNSException):
        pass

    if len(spf_type_records) > 0:
        message = "Use of DNS Type SPF has been removed in the standards " \
                   "track version of SPF, RFC 7208. These records should " \
                   "be removed and replaced with TXT records: " \
                  "{0}".format(",".join(spf_type_records))
        warnings.append(message)
    try:
        answers = _query_dns(domain, "TXT", nameservers=nameservers,
                             timeout=timeout)
        spf_record = None
        for record in answers:
            if record.startswith("v=spf1"):
                spf_txt_records.append(record)
        if len(spf_txt_records) > 1:
            raise MultipleSPFRTXTRecords(
                "{0} has multiple spf1 TXT records".format(domain)
            )
        elif len(spf_txt_records) == 1:
            spf_record = spf_txt_records[0]
        if spf_record is None:
            raise SPFRecordNotFound(
                "{0} does not have a SPF record".format(domain))
    except dns.resolver.NoAnswer:
        raise SPFRecordNotFound(
            "{0} does not have a SPF record".format(domain))
    except dns.resolver.NXDOMAIN:
        raise SPFRecordNotFound("The domain {0} does not exist".format(domain))
    except dns.exception.DNSException as error:
        raise SPFRecordNotFound(error)

    return OrderedDict([("record", spf_record), ("warnings", warnings)])


def parse_spf_record(record, domain, seen=None, nameservers=None, timeout=2.0):
    """
    Parses a SPF record, including resolving ``a``, ``mx``, and ``include``
    mechanisms

    Args:
        record (str): An SPF record
        seen (list): A list of domains seen in past loops
        domain (str): The domain that the SPF record came from
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``dns_lookups`` - Number of DNS lookups required by the record
         - ``parsed`` - An ``OrderedDict`` of a parsed SPF record values
         - ``warnings`` - A ``list`` of warnings

    Raises:
        :exc:`checkdmarc.SPFIncludeLoop`
        :exc:`checkdmarc.SPFRedirectLoop`
        :exc:`checkdmarc.SPFSyntaxError`
        :exc:`checkdmarc.SPFTooManyDNSLookups`
    """
    lookup_mechanisms = ["a", "mx", "include", "exists", "redirect"]
    if seen is None:
        seen = [domain]
    record = record.replace('" ', '').replace('"', '')
    warnings = []
    spf_syntax_checker = _SPFGrammar()
    parsed_record = spf_syntax_checker.parse(record.lower())
    if not parsed_record.is_valid:
        pos = parsed_record.pos
        expecting = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting)))
        expecting = " or ".join(expecting)
        raise SPFSyntaxError(
            "{0}: Expected {1} at position {2} in: {3}".format(domain,
                                                               expecting,
                                                               pos,
                                                               record))
    matches = SPF_MECHANISM_REGEX.findall(record.lower())
    parsed = OrderedDict([("pass", []),
                          ("neutral", []),
                          ("softfail", []),
                          ("fail", []),
                          ("include", []),
                          ("redirect", None),
                          ("exp", None),
                          ("all", "neutral")])

    lookup_mechanism_count = 0
    for match in matches:
        mechanism = match[1]
        if mechanism in lookup_mechanisms:
            lookup_mechanism_count += 1
    if lookup_mechanism_count > 10:
        raise SPFTooManyDNSLookups(
            "Parsing the SPF record requires {0}/10 maximum DNS lookups - "
            "https://tools.ietf.org/html/rfc7208#section-4.6.4".format(
                lookup_mechanism_count),
            dns_lookups=lookup_mechanism_count)

    for match in matches:
        result = spf_qualifiers[match[0]]
        mechanism = match[1]
        value = match[2]

        try:
            if mechanism == "ip4":
                if len(IPV4_REGEX.findall(value)) == 0:
                    raise SPFSyntaxError("{0} is not a valid ipv4 "
                                         "value".format(value))
                for octet in value.split("."):
                    octet = int(octet.split("/")[0])
                    if octet > 255:
                        raise SPFSyntaxError("{0} is not a valid ipv4 "
                                             "value".format(value))

            if mechanism == "a":
                if value == "":
                    value = domain
                a_records = _get_a_records(value, nameservers=nameservers,
                                           timeout=timeout)
                if len(a_records) == 0:
                    raise _SPFMissingRecords(
                        "{0} does not have any A/AAAA records".format(
                            value.lower()))
                for record in a_records:
                    parsed[result].append(OrderedDict(
                        [("value", record), ("mechanism", mechanism)]))
            elif mechanism == "mx":
                if value == "":
                    value = domain
                mx_hosts = _get_mx_hosts(value, nameservers=nameservers,
                                         timeout=timeout)
                if len(mx_hosts) == 0:
                    raise _SPFMissingRecords(
                        "{0} does not have any MX records".format(
                            value.lower()))
                if len(mx_hosts) > 10:
                    url = "https://tools.ietf.org/html/rfc7208#section-4.6.4"
                    raise SPFTooManyDNSLookups(
                        "{0} has more than 10 MX records - "
                        "{1}".format(value, url))
                for host in mx_hosts:
                    parsed[result].append(OrderedDict(
                        [("value", host["hostname"]),
                         ("mechanism", mechanism)]))
            elif mechanism == "redirect":
                if value.lower() in seen:
                    raise SPFRedirectLoop(
                        "Redirect loop: {0}".format(value.lower()))
                seen.append(value.lower())
                try:
                    redirect_record = query_spf_record(value,
                                                       nameservers=nameservers,
                                                       timeout=timeout)
                    redirect_record = redirect_record["record"]
                    redirect = parse_spf_record(redirect_record, value,
                                                seen=seen,
                                                nameservers=nameservers,
                                                timeout=timeout)
                    lookup_mechanism_count += redirect["dns_lookups"]
                    if lookup_mechanism_count > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires {0}/10 maximum "
                            "DNS lookups - "
                            "https://tools.ietf.org/html/rfc7208"
                            "#section-4.6.4".format(
                                lookup_mechanism_count),
                            dns_lookups=lookup_mechanism_count)
                    parsed["redirect"] = OrderedDict(
                        [("domain", value), ("record", redirect_record),
                         ("dns_lookups", redirect["dns_lookups"]),
                         ("parsed", redirect["parsed"]),
                         ("warnings", redirect["warnings"])])
                    warnings += redirect["warnings"]
                except DNSException as error:
                    raise _SPFWarning(str(error))
            elif mechanism == "exp":
                parsed["exp"] = _get_txt_records(value)[0]
            elif mechanism == "all":
                parsed["all"] = result
            elif mechanism == "include":
                if value.lower() == domain.lower():
                    raise SPFIncludeLoop("Include loop: {0}".format(value))
                if value.lower() in seen:
                    raise _SPFDuplicateInclude(
                        "Duplicate include: {0}".format(value.lower()))
                seen.append(value.lower())
                try:
                    include_record = query_spf_record(value,
                                                      nameservers=nameservers,
                                                      timeout=timeout)
                    include_record = include_record["record"]
                    include = parse_spf_record(include_record, value,
                                               seen=seen,
                                               nameservers=nameservers,
                                               timeout=timeout)
                    lookup_mechanism_count += include["dns_lookups"]
                    if lookup_mechanism_count > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires {0}/10 maximum "
                            "DNS lookups - "
                            "https://tools.ietf.org/html/rfc7208"
                            "#section-4.6.4".format(
                                lookup_mechanism_count),
                            dns_lookups=lookup_mechanism_count)
                    include = OrderedDict(
                        [("domain", value), ("record", include_record),
                         ("dns_lookups", include["dns_lookups"]),
                         ("parsed", include["parsed"]),
                         ("warnings", include["warnings"])])
                    parsed["include"].append(include)
                    warnings += include["warnings"]

                except DNSException as error:
                    raise _SPFWarning(str(error))
            elif mechanism == "ptr":
                parsed[result].append(
                    OrderedDict([("value", value), ("mechanism", mechanism)]))
                raise _SPFWarning("The ptr mechanism should not be used - "
                                  "https://tools.ietf.org/html/rfc7208"
                                  "#section-5.5")
            else:
                parsed[result].append(
                    OrderedDict([("value", value), ("mechanism", mechanism)]))

        except (_SPFWarning, DNSException) as warning:
            warnings.append(str(warning))
    return OrderedDict(
        [('dns_lookups', lookup_mechanism_count), ("parsed", parsed),
         ("warnings", warnings)])


def get_spf_record(domain, nameservers=None, timeout=2.0):
    """
    Retrieves and parses an SPF record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): Number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An SPF record parsed by result

    Raises:
        :exc:`checkdmarc.SPFRecordNotFound`
        :exc:`checkdmarc.SPFIncludeLoop`
        :exc:`checkdmarc.SPFRedirectLoop`
        :exc:`checkdmarc.SPFSyntaxError`
        :exc:`checkdmarc.SPFTooManyDNSLookups`

    """
    record = query_spf_record(domain, nameservers=nameservers, timeout=timeout)
    record = record["record"]
    record = parse_spf_record(record, domain, nameservers=nameservers,
                              timeout=timeout)

    return record


def check_domains(domains, output_format="json", output_path=None,
                  include_dmarc_tag_descriptions=False,
                  nameservers=None, timeout=2.0, wait=0.0):
    """
    Check the given domains for SPF and DMARC records, parse them, and return
    them

    Args:
        domains (list): A list of domains to check
        output_format (str): ``json`` or ``csv``
        output_path (str): Save output to the given file path
        include_dmarc_tag_descriptions (bool): Include descriptions of DMARC
                                               tags and/or tag values in the
                                               results
        nameservers (list): A list of nameservers to query
        (Cloudflare's by default)
        timeout(float): number of seconds to wait for an answer from DNS
        wait (float): number of seconds to wait between processing domains

    Returns:
       If ``output_format`` is ``json``, an ``OrderedDict`` is returned

       - ``domain`` - The domain name
       - ``base_domain`` The base domain
       - ``mx`` - See :func:`checkdmarc.get_mx_hosts`
       - ``spf`` -  A ``valid`` flag, plus the output of
         :func:`checkdmarc.parse_spf_record` or an ``error``
       - ``dmarc`` - A ``valid`` flag, plus the output of
         :func:`checkdmarc.parse_dmarc_record` or an ``error``

       Or, if ``output_format`` is ``csv``, the results are returned as a CSV
       string
    """
    output_format = output_format.lower()
    domains = sorted(list(set(
        map(lambda d: d.rstrip(".\r\n").strip().lower().split(",")[0],
            domains))))
    not_domains = []
    for domain in domains:
        if "." not in domain:
            not_domains.append(domain)
    for domain in not_domains:
        domains.remove(domain)
    if output_format not in ["json", "csv"]:
        raise ValueError(
            "Invalid output format {0}. Valid options are "
            "json and csv.".format(
                output_format))
    if output_format == "csv":
        fields = ["domain", "base_domain", "spf_valid", "dmarc_valid",
                  "dmarc_adkim", "dmarc_aspf",
                  "dmarc_fo", "dmarc_p", "dmarc_pct", "dmarc_rf", "dmarc_ri",
                  "dmarc_rua", "dmarc_ruf", "dmarc_sp",
                  "mx", "spf_record", "dmarc_record", "dmarc_record_location",
                  "mx_warnings", "spf_error",
                  "spf_warnings", "dmarc_error", "dmarc_warnings"]
        if output_path:
            output_file = open(output_path, "w", newline="\n")
        else:
            output_file = StringIO(newline="\n")
        writer = DictWriter(output_file, fieldnames=fields)
        writer.writeheader()
        while "" in domains:
            domains.remove("")
        for domain in domains:
            row = dict(domain=domain, base_domain=get_base_domain(domain),
                       mx="", spf_valid=True, dmarc_valid=True)
            mx = get_mx_hosts(domain, nameservers=nameservers, timeout=timeout)
            row["mx"] = ",".join(list(
                map(lambda r: "{0} {1}".format(r["preference"], r["hostname"]),
                    mx["hosts"])))
            row["mx_warnings"] = ",".join(mx["warnings"])
            try:
                spf_record = query_spf_record(domain,
                                              nameservers=nameservers,
                                              timeout=timeout)
                row["spf_record"] = spf_record["record"]
                warnings = spf_record["warnings"]
                warnings += parse_spf_record(row["spf_record"], row["domain"],
                                             nameservers=nameservers,
                                             timeout=timeout)["warnings"]

                row["spf_warnings"] = ",".join(warnings)
            except SPFError as error:
                row["spf_error"] = error
                row["spf_valid"] = False
            try:
                dmarc_query = query_dmarc_record(domain,
                                                 nameservers=nameservers,
                                                 timeout=timeout)
                row["dmarc_record"] = dmarc_query["record"]
                row["dmarc_record_location"] = dmarc_query["location"]
                dmarc = parse_dmarc_record(dmarc_query["record"],
                                           dmarc_query["location"],
                                           nameservers=nameservers,
                                           timeout=timeout)
                row["dmarc_adkim"] = dmarc["tags"]["adkim"]["value"]
                row["dmarc_aspf"] = dmarc["tags"]["aspf"]["value"]
                row["dmarc_fo"] = ":".join(dmarc["tags"]["fo"]["value"])
                row["dmarc_p"] = dmarc["tags"]["p"]["value"]
                row["dmarc_pct"] = dmarc["tags"]["pct"]["value"]
                row["dmarc_rf"] = ":".join(dmarc["tags"]["rf"]["value"])
                row["dmarc_ri"] = dmarc["tags"]["ri"]["value"]
                row["dmarc_sp"] = dmarc["tags"]["sp"]["value"]
                if "rua" in dmarc["tags"]:
                    addresses = dmarc["tags"]["rua"]["value"]
                    addresses = list(map(lambda u: u["scheme"] + ":" +
                                                   u["address"], addresses))
                    row["dmarc_rua"] = ",".join(addresses)
                if "ruf" in dmarc["tags"]:
                    addresses = dmarc["tags"]["ruf"]["value"]
                    addresses = list(map(lambda u: u["address"], addresses))
                    row["dmarc_ruf"] = ",".join(addresses)
                dmarc_warnings = dmarc_query["warnings"] + dmarc["warnings"]
                row["dmarc_warnings"] = ",".join(dmarc_warnings)
            except DMARCError as error:
                row["dmarc_error"] = error
                row["dmarc_valid"] = False
            writer.writerow(row)
            output_file.flush()
            sleep(wait)
        if output_path is None:
            return output_file.getvalue()
    elif output_format == "json":
        results = []
        for domain in domains:
            domain_results = OrderedDict(
                [("domain", domain), ("base_domain", get_base_domain(domain)),
                 ("mx", [])])
            domain_results["spf"] = OrderedDict(
                [("record", None), ("valid", True), ("dns_lookups", None)])
            domain_results["mx"] = get_mx_hosts(domain,
                                                nameservers=nameservers,
                                                timeout=timeout)
            try:
                spf_query = query_spf_record(
                    domain,
                    nameservers=nameservers,
                    timeout=timeout)
                domain_results["spf"]["record"] = spf_query["record"]
                domain_results["spf"]["warnings"] = spf_query["warnings"]
                parsed_spf = parse_spf_record(domain_results["spf"]["record"],
                                              domain_results["domain"],
                                              nameservers=nameservers,
                                              timeout=timeout)

                domain_results["spf"]["dns_lookups"] = parsed_spf[
                    "dns_lookups"]
                domain_results["spf"]["parsed"] = parsed_spf["parsed"]
                domain_results["spf"]["warnings"] += parsed_spf["warnings"]
            except SPFError as error:
                domain_results["spf"]["error"] = str(error)
                del domain_results["spf"]["dns_lookups"]
                domain_results["spf"]["valid"] = False
                if hasattr(error, "data") and error.data:
                    for key in error.data:
                        domain_results["spf"][key] = error.data[key]

            # DMARC
            domain_results["dmarc"] = OrderedDict([("record", None),
                                                   ("valid", True),
                                                   ("location", None)])
            try:
                dmarc_query = query_dmarc_record(domain,
                                                 nameservers=nameservers,
                                                 timeout=timeout)
                domain_results["dmarc"]["record"] = dmarc_query["record"]
                domain_results["dmarc"]["location"] = dmarc_query["location"]
                parsed_dmarc_record = parse_dmarc_record(
                    dmarc_query["record"],
                    dmarc_query["location"],
                    include_tag_descriptions=include_dmarc_tag_descriptions,
                    nameservers=nameservers,
                    timeout=timeout)
                domain_results["dmarc"]["warnings"] = dmarc_query["warnings"]

                domain_results["dmarc"]["tags"] = parsed_dmarc_record["tags"]
                domain_results["dmarc"]["warnings"] += parsed_dmarc_record[
                    "warnings"]
            except DMARCError as error:
                domain_results["dmarc"]["error"] = str(error)
                domain_results["dmarc"]["valid"] = False
                if hasattr(error, "data") and error.data:
                    for key in error.data:
                        domain_results["dmarc"][key] = error.data[key]
            results.append(domain_results)
            sleep(wait)
        if len(results) == 1:
            results = results[0]
        if output_path:
            with open(output_path, "w", newline="\n") as output_file:
                output_file.write(
                    json.dumps(results, ensure_ascii=False, indent=2))

        return results


def _main():
    """Called when the module in executed"""
    arg_parser = ArgumentParser(description=__doc__)
    arg_parser.add_argument("domain", nargs="+",
                            help="one or ore domains, or a single path to a "
                                 "file containing a list of domains")
    arg_parser.add_argument("-d", "--descriptions", action="store_true",
                            help="include descriptions of DMARC tags in "
                                 "the JSON output")
    arg_parser.add_argument("-f", "--format", default="json",
                            help="specify JSON or CSV output format")
    arg_parser.add_argument("-o", "--output",
                            help="output to a file path rather than "
                                 "printing to the screen")
    arg_parser.add_argument("-n", "--nameserver", nargs="+",
                            help="nameservers to query "
                                 "(Default is Cloudflare's")
    arg_parser.add_argument("-t", "--timeout",
                            help="number of seconds to wait for an answer "
                                 "from DNS (default 2.0)",
                            type=float,
                            default=2.0)
    arg_parser.add_argument("-v", "--version", action="version",
                            version=__version__)
    arg_parser.add_argument("-w", "--wait", type=float,
                            help="number of seconds to wait between "
                                 "processing domains (default 0.0)",
                            default=0.0)

    args = arg_parser.parse_args()

    domains = args.domain
    if len(domains) == 1 and path.exists(domains[0]):
        with open(domains[0]) as domains_file:
            domains = sorted(list(set(
                map(lambda d: d.rstrip(".\r\n").strip().lower().split(",")[0],
                    domains_file.readlines()))))
            not_domains = []
            for domain in domains:
                if "." not in domain:
                    not_domains.append(domain)
            for domain in not_domains:
                domains.remove(domain)

    results = check_domains(domains, output_format=args.format,
                            output_path=args.output,
                            include_dmarc_tag_descriptions=args.descriptions,
                            nameservers=args.nameserver, timeout=args.timeout)

    if args.output is None:
        if args.format.lower() == "json":
            results = json.dumps(results, ensure_ascii=False, indent=2)

        print(results)


if __name__ == "__main__":
    _main()
