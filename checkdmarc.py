#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Validates and parses SPF amd DMARC DNS records"""

from collections import OrderedDict
from re import compile
import json
from csv import DictWriter
from argparse import ArgumentParser
from os import path
from time import sleep

from io import StringIO

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


__version__ = "1.5.4"


class DNSException(Exception):
    """Raised when a general DNS error occurs"""


class DMARCException(Exception):
    """Raised when an error occurs when retrieving or parsing a DMARC record"""
    pass


class SPFException(Exception):
    """Raised when an error occurs when retrieving or parsing a SPF record"""
    pass


class SPFError(SPFException):
    """Raised when a fatal SPF error occurs"""
    pass


class SPFWarning(SPFException):
    """Raised when a non-fatal SPF error occurs"""
    pass


class DMARCError(DMARCException):
    """Raised when a fatal DMARC error occurs"""
    pass


class DMARCWarning(DMARCException):
    """Raised when a non-fatal DMARC error occurs"""
    pass


class _SPFGrammar(Grammar):
    """Defines Pyleri grammar for SPF records"""
    version_tag = Regex("v=spf[\d.]+")
    mechanism = Regex("([?+-~]?)(mx|ip4|ip6|exists|include|all|a|redirect|exp|ptr)[:=]?([\w+/_.:\-{%}]*)")
    START = Sequence(version_tag, Repeat(mechanism))


class _DMARCGrammar(Grammar):
    """Defines Pyleri grammar for DMARC records"""
    version_tag = Regex("v=DMARC[\d.]+;")
    tag_value = Regex("([a-z]{1,5})=([\w.:@\/+!,_\-]+)")
    START = Sequence(version_tag, List(tag_value, delimiter=";", opt=True))


dmarc_regex = compile(r"([a-z]{1,5})=([\w.:@/+!,_\-]+)")
spf_regex = compile(r"([?+-~]?)(mx|ip4|ip6|exists|include|all|a|redirect|exp|ptr)[:=]?([\w+/_.:\-{%}]*)")
mailto_regex = compile(r"mailto:([\w\-!#$%&'*+-/=?^_`{|}~][\w\-.!#$%&'*+-/=?^_`{|}~]+@[\w\-.]+)")


tag_values = OrderedDict(adkim=OrderedDict(name="DKIM Alignment Mode",
                                           default="r",
                                           description='In relaxed mode, the Organizational Domains of both the DKIM- '
                                                       'authenticated signing domain (taken from the value of the "d=" '
                                                       'tag in the signature) and that of the RFC5322.From domain must '
                                                       'be equal if the identifiers are to be considered aligned.'),
                         aspf=OrderedDict(name="SPF alignment mode",
                                          default="r",
                                          description='In relaxed mode, the SPF-authenticated domain and RFC5322 '
                                                      'From domain must have the same Organizational Domain. '
                                                      'In strict mode, only an exact DNS domain match is considered to '
                                                      'produce Identifier Alignment.'),
                         fo=OrderedDict(name="Failure Reporting Options",
                                        default="0",
                                        description='Provides requested options for generation of failure reports. '
                                                    'Report generators MAY choose to adhere to the requested options. '
                                                    'This tag\'s content MUST be ignored if a "ruf" tag (below) is not '
                                                    'also specified. The value of this tag is a colon-separated list '
                                                    'of characters that indicate failure reporting options.',
                                        values={"0": 'Generate a DMARC failure report if all underlying '
                                                     'authentication mechanisms fail to produce an aligned "pass" '
                                                     'result.',
                                                "1": 'Generate a DMARC failure report if any underlying '
                                                     'authentication mechanism produced something other than an '
                                                     'aligned "pass" result.',
                                                "d": 'Generate a DKIM failure report if the message had a signature '
                                                     'that failed evaluation, regardless of its alignment. DKIM-'
                                                     'specific reporting is described in AFRF-DKIM.',
                                                "s": 'Generate an SPF failure report if the message failed SPF '
                                                     'evaluation, regardless of its alignment. SPF-specific '
                                                     'reporting is described in AFRF-SPF'
                                                }
                                        ),
                         p=OrderedDict(name="Requested Mail Receiver Policy",
                                       default="none",
                                       description='Indicates the policy to be enacted by the Receiver at '
                                                   'the request of the Domain Owner. Policy applies to the domain '
                                                   'queried and to subdomains, unless subdomain policy is explicitly '
                                                   'described using the "sp" tag.',
                         values={"none": 'The Domain Owner requests no specific action be taken '
                                         'regarding delivery of messages.',
                                 "quarantine": 'The Domain Owner wishes to have email that fails the '
                                               'DMARC mechanism check be treated by Mail Receivers as '
                                               'suspicious.  Depending on the capabilities of the Mail'
                                               'Receiver, this can mean "place into spam folder", "scrutinize '
                                               'with additional intensity", and/or "flag as suspicious".',
                                 "reject": 'The Domain Owner wishes for Mail Receivers to reject '
                                         'email that fails the DMARC mechanism check. Rejection SHOULD '
                                         'occur during the SMTP transaction.'
                                 }
                         ),
                         pct=OrderedDict(name="Percentage",
                                         default=100,
                                         description='Integer percentage of messages from the Domain Owner\'s '
                                                     'mail stream to which the DMARC policy is to be applied. '
                                                     'However, this MUST NOT be applied to the DMARC-generated '
                                                     'reports, all of which must be sent and received unhindered. '
                                                     'The purpose of the "pct" tag is to allow Domain Owners to enact '
                                                     'a slow rollout of enforcement of the DMARC mechanism.'
                                         ),
                         rf=OrderedDict(name="Report Format",
                                        default="afrf",
                                        description='A list separated by colons of one or more report formats as '
                                                    'requested by the Domain Owner to be used when a message fails '
                                                    'both SPF and DKIM tests to report details of the individual '
                                                    'failure. Only "afrf" (the auth-failure report type) is '
                                                    'currently supported in the DMARC standard.',
                                        values={
                                            "afrf": ' "Authentication Failure Reporting Using the '
                                                    'Abuse Reporting Format", RFC 6591, April 2012,'
                                                    '<http://www.rfc-editor.org/info/rfc6591>'
                                        }
                                        ),
                         ri=OrderedDict(name="Report Interval",
                                        default=86400,
                                        description='Indicates a request to Receivers to generate aggregate reports '
                                                    'separated by no more than the requested number of seconds. '
                                                    'DMARC implementations MUST be able to provide daily reports '
                                                    'and SHOULD be able to provide hourly reports when requested. '
                                                    'However, anything other than a daily report is understood to '
                                                    'be accommodated on a best-effort basis.'
                                        ),
                         rua=OrderedDict(name="Aggregate Feedback Addresses",
                                         description=' A comma-separated list DMARC URIs to which aggregate feedback '
                                                     'is to be sent.'
                                         ),
                         ruf=OrderedDict(name="Forensic Feedback Addresses",
                                         description=' A comma-separated list DMARC URIs to which forensic feedback '
                                                     'is to be sent.'
                                         ),
                         sp=OrderedDict(name="Subdomain Policy",
                                        description='Indicates the policy to be enacted by the Receiver at '
                                        'the request of the Domain Owner. It applies only to subdomains of '
                                        'the domain queried and not to the domain itself. Its syntax is '
                                        'identical to that of the "p" tag defined above. If absent, the '
                                        'policy specified by the "p" tag MUST be applied for subdomains.'
                                        ),
                         v=OrderedDict(name="Version",
                                       default="DMARC1",
                                       description='Identifies the record retrieved '
                                                   'as a DMARC record. It MUST have the value of "DMARC1". The value '
                                                   'of this tag MUST match precisely; if it does not or it is absent, '
                                                   'the entire retrieved record MUST be ignored. It MUST be the first '
                                                   'tag in the list.')
                         )

spf_qualifiers = {
    "": "pass",
    "?": "neutral",
    "+": "pass",
    "-": "fail",
    "~": "softfail"
}


def _get_mx_hosts(domain, nameservers=None, timeout=6.0):
    """
    Queries DNS for a list of Mail Exchange hosts

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query

    Returns:
        list: A list of ``OrderedDicts``; each containing a ``preference integer

    """
    hosts = []
    try:
        resolver = dns.resolver.Resolver()
        timeout = float(timeout)
        if nameservers:
            resolver.nameservers = nameservers
        resolver.lifetime = timeout
        answers = resolver.query(domain, "MX")
        for record in answers:
            record = record.to_text().split(" ")
            preference = int(record[0])
            hostname = record[1].rstrip(".").strip().lower()
            hosts.append(OrderedDict([("preference", preference), ("hostname", hostname)]))
        hosts = sorted(hosts, key=lambda h: h["preference"])
    except dns.resolver.NXDOMAIN:
        raise DNSException("The domain {0} does not exist".format(domain))
    except dns.resolver.NoAnswer:
        raise DNSException("{0} does not have any MX records".format(domain))
    except (dns.exception.DNSException, ValueError) as error:
        raise DNSException(error)

    return hosts


def _get_a_records(domain, nameservers=None, timeout=6.0):
    """
    Queries DNS for A and AAAA records

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        list: A list of IPv4 and IPv6 addresses

    """
    records = []
    try:
        resolver = dns.resolver.Resolver()
        timeout = float(timeout)
        if nameservers:
            resolver.nameservers = nameservers
        resolver.lifetime = timeout
        answers = resolver.query(domain, "A")
        records = list(map(lambda r: r.to_text().rstrip("."), answers))
        answers = resolver.query(domain, "AAAA")
        records += list(map(lambda r: r.to_text().rstrip("."), answers))
    except dns.resolver.NXDOMAIN:
        raise DNSException("The domain {0} does not exist".format(domain))
    except dns.resolver.NoAnswer:
        # Sometimes a domain will only have A or AAAA records, but not both, and that's ok
        pass
    except dns.exception.DNSException as error:
        raise DNSException(error)
    finally:
        if len(records) == 0:
            raise DNSException("{0} does not have any A or AAAA records".format(domain))

    return records


def _get_txt_records(domain, nameservers=None, timeout=6.0):
    """
    Queries DNS for TXT records

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        list: A list of TXT records

    """
    try:
        resolver = dns.resolver.Resolver()
        timeout = float(timeout)
        if nameservers:
            resolver.nameservers = nameservers
        resolver.lifetime = timeout
        answers = resolver.query(domain, "TXT")
        records = list(map(lambda r: r.to_text().replace(' "', '').replace('"', ''), answers))
    except dns.resolver.NXDOMAIN:
        raise DNSException("The domain {0} does not exist".format(domain))
    except dns.resolver.NoAnswer:
        raise DNSException("The domain {0} does not have any TXT records".format(domain))
    except dns.exception.DNSException as error:
        raise DNSException(error)

    return records


def _query_dmarc_record(domain, nameservers=None, timeout=6.0):
    """
    Queries DNS for a DMARC record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an record from DNS

    Returns:
        str: A record string or None
    """
    target = "_dmarc.{0}".format(domain.lower().replace("_dmarc.", ""))
    record = None
    try:
        resolver = dns.resolver.Resolver()
        timeout = float(timeout)
        if nameservers:
            resolver.nameservers = nameservers
        resolver.lifetime = timeout
        record = resolver.query(target, "TXT")[0].to_text().replace('"', '')

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass

    except dns.exception.DNSException as error:
        raise DMARCError(error.msg)

    return record


def get_mx_hosts(domain, nameservers=None, timeout=6.0):
    """
    Returns a list of OrderedDicts with keys of ``hostname`` and ``addresses``
    
    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an record from DNS

    Returns:
        OrderedDict: with The following keys:
            - ``hosts``: A list of OrderedDicts with keys of
              - ``hostname``
              - ``addresses``,
            - ``warnings`` A list of MX resolution warnings

    """
    mx_records = []
    hosts = []
    warnings = []
    try:
        mx_records = _get_mx_hosts(domain, nameservers=nameservers, timeout=timeout)
    except DNSException as warning:
        warnings.append(str(warning))
    for record in mx_records:
        hosts.append(OrderedDict([("preference", record["preference"]), ("hostname", record["hostname"]),
                                  ("addresses", [])]))
    for host in hosts:
        try:
            host["addresses"] = _get_a_records(host["hostname"], nameservers=nameservers, timeout=timeout)
        except DNSException as warning:
            warnings.append(str(warning))

    return OrderedDict([("hosts", hosts), ("warnings", warnings)])


def query_dmarc_record(domain, nameservers=None, timeout=6.0):
    """
    Queries DNS for a DMARC record
    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an record from DNS

    Returns:
        dict: the ``organisational_domain`` and ``record``
    """
    record = _query_dmarc_record(domain, nameservers=nameservers, timeout=timeout)
    while record is None and len(domain.split(".")) > 1:
        domain = ".".join(domain.split(".")[1::])
        record = _query_dmarc_record(domain, nameservers=nameservers, timeout=timeout)
    if record is None:
        raise DMARCError("A DMARC record does not exist for this domain, or any of its upper domains")

    return OrderedDict(organisational_domain=domain, record=record)


def get_dmarc_tag_description(tag, value=None):
    """
    Get the name, default value, and description for a DMARC tag, amd/or a description for a tag value
    
    Args:
        tag (str): A DMARC tag
        value (str): An optional value

    Returns:
        OrderedDict: A OrderedDictionary containing the tag's ``name``, ``default`` value, and a ``description`` of the
        tag or value
    """
    name = tag_values[tag]["name"]
    description = tag_values[tag]["description"]
    default = None
    if "default" in tag_values[tag]:
        default = tag_values[tag]["default"]
    if type(value) == str and "values" in tag_values[tag] and value in tag_values[tag]["values"][value]:
        description = tag_values[tag]["values"][value]
    elif type(value) == list and "values" in tag_values[tag]:
        new_description = ""
        for value_value in value:
            if value_value in tag_values[tag]["values"]:
                new_description += "{0}: {1}\n\n".format(value_value, tag_values[tag]["values"][value_value])
        new_description = new_description.strip()
        if new_description != "":
            description = new_description

    return OrderedDict([("name", name), ("default", default), ("description", description)])


def parse_dmarc_report_uri(uri):
    """
    Parses a DMARC Reporting (i.e. ``rua``/``ruf)`` URI
    
    Notes:
        ``mailto:`` is the only reporting URI supported in `DMARC1` 
    
    Args:
        uri: A DMARC URI

    Returns:
        str: An email address

    """
    uri = uri.strip()
    mailto_matches = mailto_regex.findall(uri)
    if len(mailto_matches) != 1:
        raise DMARCWarning("{0} is not a valid DMARC report URI".format(uri))
    return mailto_matches[0]


def verify_external_dmarc_destination(source_domain, destination_domain, nameservers=None, timeout=6.0):
    """
      Checks if the report destination accepts reports for the source domain per RFC 7489, section 7.1
      
      Args:
          source_domain (str): The source domain
          destination_domain (str): The destination domain
          nameservers (list): A list of nameservers to query
          timeout(float): number of seconds to wait for an answer from DNS

      Returns:
          str: An unparsed DMARC string
      """
    target = "{0}._report._dmarc.{1}".format(source_domain, destination_domain)
    warning_message = "{0} does not indicate that it accepts DMARC reports about {1} - " \
                      "https://tools.ietf.org/html/rfc7489#section-7.1".format(destination_domain,
                                                                               source_domain)
    try:
        resolver = dns.resolver.Resolver()
        timeout = float(timeout)
        if nameservers:
            resolver.nameservers = nameservers
        resolver.lifetime = timeout
        answer = resolver.query(target, "TXT")[0].to_text().strip('"')
        if not answer.startswith("v=DMARC1"):
            raise DMARCWarning(warning_message)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        raise DMARCWarning(warning_message)
    except dns.exception.DNSException as error:
        raise DMARCWarning("Unable to validate that {0} DMARC accepts reports for {1} - {2}".format(destination_domain,
                                                                                                    source_domain,
                                                                                                    error.msg))
    return True


def parse_dmarc_record(record, domain, include_tag_descriptions=False, nameservers=None, timeout=6.0):
    """
    Parses a DMARC record
    
    Args:
        record (str): A DMARC record
        domain (str): The email domain
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: The DMARC record parsed by key

    """
    warnings = []
    record = record.strip('"')
    dmarc_syntax_checker = _DMARCGrammar()
    parsed_record = dmarc_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        expecting = list(map(lambda x: str(x).strip('"'), list(parsed_record.expecting)))
        raise DMARCError("Error: Expected {0} at position {1} in: {2}".format(" or ".join(expecting),
                                                                              parsed_record.pos, record))

    pairs = dmarc_regex.findall(record)
    tags = OrderedDict()

    # Find explicit tags
    for pair in pairs:
        tags[pair[0]] = OrderedDict([("value", str(pair[1])), ("explicit", True)])

    # Include implicit tags and their defaults
    for tag in tag_values.keys():
        if tag not in tags and "default" in tag_values[tag]:
            tags[tag] = OrderedDict([("value", tag_values[tag]["default"]), ("explicit", False)])
    if "sp" not in tags:
        tags["sp"] = OrderedDict([("value", tags["p"]["value"]), ("explicit", False)])

    # Validate tag values
    for tag in tags:
        if tag not in tag_values:
            raise DMARCError("{0} is not a valid DMARC tag".format(tag))
        if tag == "fo":
            tags[tag]["value"] = tags[tag]["value"].split(":")
            if "0" in tags[tag]["value"] and "1" in tags[tag]["value"]:
                raise DMARCError("fo DMARC tag options 0 and 1 are mutually exclusive")
            for value in tags[tag]["value"]:
                if value not in tag_values[tag]["values"]:
                    raise DMARCError("{0} is not a valid option for the DMARC fo tag".format(value))
        elif tag == "rf":
            tags[tag]["value"] = tags[tag]["value"].split(":")
            for value in tags[tag]["value"]:
                if value not in tag_values[tag]["values"]:
                    raise DMARCError("{0} is not a valid option for the DMARC rf tag".format(value))

        elif "values" in tag_values[tag] and tags[tag]["value"] not in tag_values[tag]["values"]:
            raise DMARCError("Tag {0} must have one of the following values: {1} - not {2}".format(
                tag,
                ",".join(tag_values[tag]["values"]),
                tags[tag]["value"]
            ))

    try:
        tags["pct"]["value"] = int(tags["pct"]["value"])
    except ValueError:
        raise DMARCError("The value of the pct tag must be an integer")

    try:
        tags["ri"]["value"] = int(tags["ri"]["value"])
    except ValueError:
        raise DMARCError("The value of the ri tag must be an integer")

    try:
        if "rua" in tags:
            tags["rua"]["value"] = tags["rua"]["value"].split(",")
            for uri in tags["rua"]["value"]:
                email_address = parse_dmarc_report_uri(uri)
                email_domain = email_address.split("@")[-1]
                if email_domain.lower() != domain.lower():
                    verify_external_dmarc_destination(domain, email_domain, nameservers=nameservers,
                                                      timeout=timeout)
                try:
                    _get_mx_hosts(email_domain)
                except SPFWarning:
                    raise DMARCWarning("The domain for rua email address {0} has no MX records".format(email_address))
                except DNSException as warning:
                    raise DMARCWarning("Failed to retrieve MX records for the domain of rua email address "
                                       "{0} - {1}".format(email_address, str(warning)))
        else:
            raise DMARCWarning("rua tag (destination for aggregate reports) not found")

    except DMARCWarning as warning:
        warnings.append(str(warning))

    try:
        if "ruf" in tags.keys():
            tags["ruf"]["value"] = tags["ruf"]["value"].split(",")
            for uri in tags["ruf"]["value"]:
                email_address = parse_dmarc_report_uri(uri)
                email_domain = email_address.split("@")[-1]
                if email_domain.lower() != domain.lower():
                    verify_external_dmarc_destination(domain, email_domain, nameservers=nameservers,
                                                      timeout=timeout)
                try:
                    _get_mx_hosts(email_domain)
                except SPFWarning:
                    raise DMARCWarning("The domain for ruf email address {0} has no MX records".format(email_address))
                except DNSException as warning:
                    raise DMARCWarning("Failed to retrieve MX records for the domain of ruf email address "
                                       "{0} - {1}".format(email_address, str(warning)))

        if tags["pct"]["value"] < 0 or tags["pct"]["value"] > 100:
            raise DMARCError("pct value must be an integer between 0 and 100")
        elif tags["pct"]["value"] < 100:
            raise DMARCWarning("pct value is less than 100")

    except DMARCWarning as warning:
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


def get_dmarc_record(domain, include_tag_descriptions=False, nameservers=None, timeout=6.0):
    """
    Retrieves a DMARC record for a domain and parses it

    Args:
        domain (str): A domain name
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: ``record`` - the DMARC record, ``tag`` - The DMARC record parsed by tag

    """
    query = query_dmarc_record(domain, nameservers=nameservers, timeout=timeout)
    organisational_domain = query["organisational_domain"]
    record = query["record"]

    tags = parse_dmarc_record(record, organisational_domain, include_tag_descriptions=include_tag_descriptions,
                              nameservers=nameservers, timeout=timeout)

    return OrderedDict([("record", record), ("organisational_domain", organisational_domain), ("tags", tags)])


def query_spf_record(domain, nameservers=None, timeout=6.0):
    """
    Queries DNS for a SPF record
    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        str: An unparsed SPF string
    """
    try:
        resolver = dns.resolver.Resolver()
        timeout = float(timeout)
        if nameservers:
            resolver.nameservers = nameservers
        resolver.lifetime = timeout
        answer = resolver.query(domain, "TXT")
        spf_record = None
        for record in answer:
            record = record.to_text()
            if record.startswith('"v=spf1'):
                spf_record = record.replace(' "', '').replace('"', '')
                break
        if spf_record is None:
            raise SPFError("{0} does not have a SPF record".format(domain))
        if not spf_record.startswith("v=spf1 "):
            raise SPFError("{0} is not a valid SPF record".format(spf_record))
    except dns.resolver.NoAnswer:
        raise SPFError("{0} does not have a SPF record".format(domain))
    except dns.resolver.NXDOMAIN:
        raise SPFError("The domain {0} does not exist".format(domain))
    except dns.exception.DNSException as error:
        raise SPFError(error)

    return spf_record


def parse_spf_record(record, domain, seen=None, query_mechanism_count=0, nameservers=None, timeout=6.0):
    """
    Parses a SPF record, including resolving ``a``, ``mx``, and ``include`` mechanisms
    
    Args:
        record (str): An SPF record
        query_mechanism_count(int): The number of mechanisms that make DNS queries used in the last recursion - limit 10
        seen (list): A list of domains seen in past loops
        domain (str): The domain that the SPF record came from
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: A OrderedDictionary containing a parsed SPF record and warnings
    """
    def _check_query_limit(count, requests):
        """
        Check if the SPF parser is within the RFC limit of 10 queries  
        Args:
            count (int): The current ``query_count`` total 
            requests (int): The number of DNS queries needed for a task

        Returns:
            int: The new ``query_count`` total 

        """
        count += requests
        if count > 10:
            raise SPFError("Parsing the SPF record requires more than the 10 maximum DNS queries "
                           "https://tools.ietf.org/html/rfc7208#section-4.6.4")
        return count

    if seen is None:
        seen = [domain]
    record = record.replace(' "', '').replace('"', '')
    warnings = []
    spf_syntax_checker = _SPFGrammar()
    parsed_record = spf_syntax_checker.parse(record.lower())
    if not parsed_record.is_valid:
        expecting = list(map(lambda x: str(x).strip('"'), list(parsed_record.expecting)))
        raise SPFError("Expected {0} at position {1} in: {2}".format(" or ".join(expecting),
                                                                     parsed_record.pos, record))
    matches = spf_regex.findall(record.lower())
    results = OrderedDict([("pass", []),
                          ("neutral", []),
                          ("softfail", []),
                          ("fail", []),
                          ("include", []),
                          ("redirect", None),
                          ("exp", None),
                          ("all", "neutral")])

    for match in matches:
        result = spf_qualifiers[match[0]]
        mechanism = match[1]
        value = match[2]

        try:
            if mechanism == "a":
                query_mechanism_count = _check_query_limit(query_mechanism_count, 1)
                if value == "":
                    value = domain
                a_records = _get_a_records(value, nameservers=nameservers, timeout=timeout)
                for record in a_records:
                    results[result].append(OrderedDict([("value", record), ("mechanism", mechanism)]))
            elif mechanism == "mx":
                query_mechanism_count = _check_query_limit(query_mechanism_count, 1)
                if value == "":
                    value = domain
                mx_hosts = _get_mx_hosts(value, nameservers=nameservers, timeout=timeout)
                if len(mx_hosts) > 10:
                    raise SPFError("{0} has more than 10 MX records - "
                                   "https://tools.ietf.org/html/rfc7208#section-4.6.4".format(value))
                for host in mx_hosts:
                    results[result].append(OrderedDict([("value", host["hostname"]), ("mechanism", mechanism)]))
            elif mechanism == "redirect":
                if value in seen:
                    raise SPFError("Redirect loop detected: {0}".format(value))
                query_mechanism_count = _check_query_limit(query_mechanism_count, 1)
                seen.append(value)
                try:
                    redirect = get_spf_record(value,
                                              query_count=query_mechanism_count,
                                              nameservers=nameservers,
                                              timeout=timeout)
                    results["redirect"] = OrderedDict([("domain", value), ("results", redirect)])
                except DNSException as error:
                    raise SPFWarning(str(error))
            elif mechanism == "exists":
                query_mechanism_count = _check_query_limit(query_mechanism_count, 1)
                results[result].append(OrderedDict([("value", value), ("mechanism", mechanism)]))
            elif mechanism == "exp":
                results["exp"] = _get_txt_records(value)[0]
            elif mechanism == "all":
                results["all"] = result
            elif mechanism == "include":
                if value in seen:
                    raise SPFError("Include loop detected: {0}".format(value))
                query_mechanism_count = _check_query_limit(query_mechanism_count, 1)
                seen.append(value)
                try:
                    include = get_spf_record(value,
                                             query_count=query_mechanism_count,
                                             nameservers=nameservers,
                                             timeout=timeout)
                    results["include"].append(OrderedDict([("domain", value), ("results", include)]))
                except DNSException as error:
                    raise SPFWarning(str(error))
            elif mechanism == "ptr":
                results[result].append(OrderedDict([("value", value), ("mechanism", mechanism)]))
                raise SPFWarning("The ptr mechanism should not be used - "
                                 "https://tools.ietf.org/html/rfc7208#section-5.5")
            else:
                results[result].append(OrderedDict([("value", value), ("mechanism", mechanism)]))

        except (SPFWarning, DNSException) as warning:
            warnings.append(str(warning))

    return OrderedDict([("results", results), ("warnings", warnings)])


def get_spf_record(domain, query_count=0, nameservers=None, timeout=6.0):
    """
    Retrieves and parses an SPF record 
    
    Args:
        domain (str): A domain name
        query_count (int): The number of queries used in the last iteration
        nameservers (list): A list of nameservers to query
        timeout(float): Number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An SPF record parsed by result

    """
    record = query_spf_record(domain, nameservers=nameservers, timeout=timeout)
    record = parse_spf_record(record, domain, query_mechanism_count=query_count, nameservers=nameservers,
                              timeout=timeout)

    return record


def check_domains(domains, output_format="json", output_path=None, include_dmarc_tag_descriptions=False,
                  nameservers=None, timeout=6.0, wait=0.0):
    """
    Check the given domains for SPF and DMARC records, parse them, and return them
    
    Args:
        domains (list): A list of domains to check 
        output_format (str): ``json`` or ``csv``
        output_path (str): Save output to the given file path 
        include_dmarc_tag_descriptions (bool): Include descriptions of DMARC tags and/or tag values in the results
        nameservers (list): A list of nameservers to query
        timeout(float): number of seconds to wait for an answer from DNS
        wait (float): number of seconds to wait between processing domains

    Returns:
        OrderedDict: Parsed SPF and DMARC records

    """
    output_format = output_format.lower()
    domains = sorted(list(set(map(lambda d: d.rstrip(".\r\n").strip().lower().split(",")[0], domains))))
    not_domains = []
    for domain in domains:
        if "." not in domain:
            not_domains.append(domain)
    for domain in not_domains:
        domains.remove(domain)
    if output_format not in ["json", "csv"]:
        raise ValueError("Invalid output format {0}. Valid options are json and csv.".format(output_format))
    if output_format == "csv":
        fields = ["domain", "spf_valid", "dmarc_valid",  "dmarc_org_domain", "dmarc_adkim", "dmarc_aspf",
                  "dmarc_fo", "dmarc_p", "dmarc_pct", "dmarc_rf", "dmarc_ri", "dmarc_rua", "dmarc_ruf", "dmarc_sp",
                  "mx", "spf_record", "dmarc_record", "mx_warnings", "spf_error", "spf_warnings", "dmarc_error",
                  "dmarc_warnings"]
        if output_path:
            output_file = open(output_path, "w", newline="\n")
        else:
            output_file = StringIO()
        writer = DictWriter(output_file, fieldnames=fields)
        writer.writeheader()
        while "" in domains:
            domains.remove("")
        for domain in domains:
            row = dict(domain=domain, mx="", spf_valid=True, dmarc_valid=True)
            mx = get_mx_hosts(domain, nameservers=nameservers, timeout=timeout)
            row["mx"] = ",".join(list(map(lambda r: "{0} {1}".format(r["preference"], r["hostname"]), mx["hosts"])))
            row["mx_warnings"] = ",".join(mx["warnings"])
            try:
                row["spf_record"] = query_spf_record(domain, nameservers=nameservers, timeout=timeout)
                row["spf_warnings"] = ",".join(parse_spf_record(row["spf_record"], row["domain"],
                                                                nameservers=nameservers,
                                                                timeout=timeout)["warnings"])
            except SPFError as error:
                row["spf_error"] = error
                row["spf_valid"] = False
            try:
                query = query_dmarc_record(domain, nameservers=nameservers, timeout=timeout)
                row["dmarc_record"] = query["record"]
                dmarc = parse_dmarc_record(query["record"], domain, nameservers=nameservers, timeout=timeout)
                row["dmarc_org_domain"] = query["organisational_domain"]
                row["dmarc_adkim"] = dmarc["tags"]["adkim"]["value"]
                row["dmarc_aspf"] = dmarc["tags"]["aspf"]["value"]
                row["dmarc_fo"] = ":".join(dmarc["tags"]["fo"]["value"])
                row["dmarc_p"] = dmarc["tags"]["p"]["value"]
                row["dmarc_pct"] = dmarc["tags"]["pct"]["value"]
                row["dmarc_rf"] = ":".join(dmarc["tags"]["rf"]["value"])
                row["dmarc_ri"] = dmarc["tags"]["ri"]["value"]
                row["dmarc_sp"] = dmarc["tags"]["sp"]["value"]
                if "rua" in dmarc:
                    row["dmarc_rua"] = ",".join(dmarc["tags"]["rua"]["value"])
                if "ruf" in dmarc:
                    row["dmarc_ruf"] = ",".join(dmarc["tags"]["ruf"]["value"])
                row["dmarc_warnings"] = ",".join(dmarc["warnings"])
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
            domain_results = OrderedDict([("domain", domain), ("mx", [])])
            domain_results["spf"] = OrderedDict([("record", None), ("valid", True)])
            domain_results["mx"] = get_mx_hosts(domain, nameservers=nameservers, timeout=timeout)
            try:
                domain_results["spf"]["record"] = query_spf_record(domain, nameservers=nameservers, timeout=timeout)
                parsed_spf = parse_spf_record(domain_results["spf"]["record"],
                                              domain_results["domain"],
                                              nameservers=nameservers,
                                              timeout=timeout)
                domain_results["spf"]["results"] = parsed_spf["results"]
                domain_results["spf"]["warnings"] = parsed_spf["warnings"]
            except SPFError as error:
                domain_results["spf"]["error"] = str(error)
                domain_results["spf"]["valid"] = False

            # DMARC
            domain_results["dmarc"] = OrderedDict([("record", None), ("valid", True), ("organisational_domain", None)])
            try:
                query = query_dmarc_record(domain, nameservers=nameservers, timeout=timeout)
                domain_results["dmarc"]["record"] = query["record"]
                parsed_dmarc_record = parse_dmarc_record(query["record"], domain,
                                                         include_tag_descriptions=include_dmarc_tag_descriptions,
                                                         nameservers=nameservers, timeout=timeout)
                domain_results["dmarc"]["organisational_domain"] = query["organisational_domain"]
                domain_results["dmarc"]["tags"] = parsed_dmarc_record["tags"]
                domain_results["dmarc"]["warnings"] = parsed_dmarc_record["warnings"]
            except DMARCError as error:
                domain_results["dmarc"]["error"] = str(error)
                domain_results["dmarc"]["valid"] = False

            results.append(domain_results)
            sleep(wait)
        if len(results) == 1:
            results = results[0]
        if output_path:
            with open(output_path, "w", newline="\n") as output_file:
                output_file.write(json.dumps(results, ensure_ascii=False, indent=2))

        return results


def _main():
    """Called when the module in executed"""
    arg_parser = ArgumentParser(description=__doc__)
    arg_parser.add_argument("domain", nargs="+",
                            help="one or ore domains, or a single path to a file containing a list of domains")
    arg_parser.add_argument("-d", "--descriptions", action="store_true",
                            help="include descriptions of DMARC tags in the JSON output")
    arg_parser.add_argument("-f", "--format", default="json", help="specify JSON or CSV output format")
    arg_parser.add_argument("-o", "--output", help="output to a file path rather than printing to the screen")
    arg_parser.add_argument("-n", "--nameserver", nargs="+", help="nameservers to query")
    arg_parser.add_argument("-t", "--timeout",
                            help="number of seconds to wait for an answer from DNS (default 6.0)", type=float,
                            default=6.0)
    arg_parser.add_argument("-v", "--version", action="version", version=__version__)
    arg_parser.add_argument("-w", "--wait", type=float,
                            help="number os seconds to wait between processing domains (default 0.0)",
                            default=0.0)

    args = arg_parser.parse_args()

    domains = args.domain
    if len(domains) == 1 and path.exists(domains[0]):
        with open(domains[0]) as domains_file:
            domains = sorted(list(set(map(lambda d: d.rstrip(".\r\n").strip().lower().split(",")[0],
                                          domains_file.readlines()))))
            not_domains = []
            for domain in domains:
                if "." not in domain:
                    not_domains.append(domain)
            for domain in not_domains:
                domains.remove(domain)

    results = check_domains(domains, output_format=args.format, output_path=args.output,
                            include_dmarc_tag_descriptions=args.descriptions,
                            nameservers=args.nameserver, timeout=args.timeout)

    if args.output is None:
        if args.format.lower() == "json":
            results = json.dumps(results, ensure_ascii=False, indent=2)

        print(results)


if __name__ == "__main__":
    _main()
