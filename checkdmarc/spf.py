# -*- coding: utf-8 -*-
"""Sender Policy framework (SPF) record validation"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict

import dns
import ipaddress
from pyleri import Grammar, Regex, Sequence, Repeat

from checkdmarc._constants import SYNTAX_ERROR_MARKER
from checkdmarc.utils import (
    normalize_domain,
    query_dns,
    get_a_records,
    get_txt_records,
    get_mx_records,
    DNSException,
    DNSExceptionNXDOMAIN,
)

"""Copyright 2019-2023 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

SPF_VERSION_TAG_REGEX_STRING = "v=spf1"
SPF_MECHANISM_REGEX_STRING = (
    r"([+\-~?])?"
    r"(mx:?|ip4:?|ip6:?|exists:?|include:?|all:?|a:?|redirect=|exp:?|ptr:?|ra=|rp=|rr=)"
    r"([\w+/_.:\-{%}]*)"
)
AFTER_ALL_REGEX_STRING = r"([\s^][+\-~?]?all)\s+.*"

SPF_MECHANISM_REGEX = re.compile(SPF_MECHANISM_REGEX_STRING, re.IGNORECASE)
AFTER_ALL_REGEX = re.compile(AFTER_ALL_REGEX_STRING, re.IGNORECASE)


class SPFError(Exception):
    """Raised when a fatal SPF error occurs"""

    def __init__(self, msg: str, data: dict = None):
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


class SPFRecordNotFound(SPFError):
    """Raised when an SPF record could not be found"""

    def __init__(self, error, domain):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)

        self.domain = domain


class MultipleSPFRTXTRecords(SPFError):
    """Raised when multiple TXT spf1 records are found"""


class UndecodableCharactersInTXTRecord(_SPFWarning):
    """Raised when a TXT record contains one or more undecodable characters"""


class SPFSyntaxError(SPFError):
    """Raised when an SPF syntax error is found"""


class SPFTooManyDNSLookups(SPFError):
    """Raised when an SPF record requires too many DNS lookups (10 max)"""

    def __init__(self, *args, **kwargs):
        data = dict(dns_lookups=kwargs["dns_lookups"])
        SPFError.__init__(self, args[0], data=data)


class SPFTooManyVoidDNSLookups(SPFError):
    """Raised when an SPF record requires too many void DNS lookups (2 max)"""

    def __init__(self, *args, **kwargs):
        data = dict(dns_void_lookups=kwargs["dns_void_lookups"])
        SPFError.__init__(self, args[0], data=data)


class SPFRedirectLoop(SPFError):
    """Raised when an SPF redirect loop is detected"""


class SPFIncludeLoop(SPFError):
    """Raised when an SPF include loop is detected"""


class _SPFGrammar(Grammar):
    """Defines Pyleri grammar for SPF records"""

    version_tag = Regex(SPF_VERSION_TAG_REGEX_STRING)
    mechanism = Regex(SPF_MECHANISM_REGEX_STRING, re.IGNORECASE)
    START = Sequence(version_tag, Repeat(mechanism))


spf_qualifiers = {"": "pass", "?": "neutral", "+": "pass", "-": "fail", "~": "softfail"}


def query_spf_record(
    domain: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> OrderedDict:
    """
    Queries DNS for an SPF record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``record`` - The SPF record string
         - ``warnings`` - A ``list`` of warnings

    Raises:
        :exc:`checkdmarc.SPFRecordNotFound`
    """
    domain = normalize_domain(domain)
    logging.debug(f"Checking for a SPF record on {domain}")
    txt_prefix = "v=spf1"
    warnings = []
    spf_type_records = []
    spf_txt_records = []
    try:
        spf_type_records += query_dns(
            domain, "SPF", nameservers=nameservers, resolver=resolver, timeout=timeout
        )
    except (dns.resolver.NoAnswer, Exception):
        pass

    if len(spf_type_records) > 0:
        message = (
            "SPF type DNS records found. Use of DNS Type SPF has been "
            "removed in the standards "
            "track version of SPF, RFC 7208. These records should "
            "be removed and replaced with TXT records: "
            f"{','.join(spf_type_records)}"
        )
        warnings.append(message)
    try:
        answers = query_dns(
            domain, "TXT", nameservers=nameservers, resolver=resolver, timeout=timeout
        )
        spf_record = None
        for record in answers:
            if record == "Undecodable characters":
                raise UndecodableCharactersInTXTRecord(
                    f"A TXT record at {domain} contains undecodable characters"
                )
            if record.startswith(txt_prefix):
                spf_txt_records.append(record)
        if len(spf_txt_records) > 1:
            raise MultipleSPFRTXTRecords(f"{domain} has multiple SPF TXT records")
        elif len(spf_txt_records) == 1:
            spf_record = spf_txt_records[0]
        if spf_record is None:
            raise SPFRecordNotFound(f"{domain} does not have a SPF TXT record", domain)
    except dns.resolver.NoAnswer:
        raise SPFRecordNotFound(f"{domain} does not have a SPF TXT record", domain)
    except dns.resolver.NXDOMAIN:
        raise SPFRecordNotFound(f"The domain {domain} does not exist", domain)
    except Exception as error:
        raise SPFRecordNotFound(error, domain)

    return OrderedDict([("record", spf_record), ("warnings", warnings)])


def parse_spf_record(
    record: str,
    domain: str,
    *,
    ignore_too_many_lookups: bool = False,
    parked: bool = False,
    seen: bool = None,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    recursion: OrderedDict = None,
    timeout: float = 2.0,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> OrderedDict:
    """
    Parses an SPF record, including resolving ``a``, ``mx``, and ``include``
    mechanisms

    Args:
        record (str): An SPF record
        domain (str): The domain that the SPF record came from
        parked (bool): indicated if a domain has been parked
        ignore_too_many_lookups (bool): Do not raise an exception for too many lookups
        seen (list): A list of domains seen in past loops
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        recursion (OrderedDict): Results from a previous call
        timeout (float): number of seconds to wait for an answer from DNS
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``dns_lookups`` - Number of DNS lookups required by the record
         - ``parsed`` - An ``OrderedDict`` of a parsed SPF record values
         - ``warnings`` - A ``list`` of warnings

    Raises:
        :exc:`checkdmarc.spf.SPFIncludeLoop`
        :exc:`checkdmarc.spf.SPFRedirectLoop`
        :exc:`checkdmarc.spf.SPFSyntaxError`
        :exc:`checkdmarc.spf.SPFTooManyDNSLookups`
    """
    logging.debug(f"Parsing the SPF record on {domain}")
    domain = normalize_domain(domain)
    lookup_mechanisms = ["a", "mx", "include", "exists", "redirect"]
    if seen is None:
        seen = [domain]
    if recursion is None:
        recursion = [domain]
    record = record.replace('" ', "").replace('"', "")
    warnings = []
    spf_syntax_checker = _SPFGrammar()
    if parked:
        correct_record = "v=spf1 -all"
        if record != correct_record:
            warnings.append(
                "The SPF record for parked domains should be: "
                f"{correct_record} not: {record}"
            )
    if len(AFTER_ALL_REGEX.findall(record)) > 0:
        warnings.append("Any text after the all mechanism is ignored")
        record = AFTER_ALL_REGEX.sub(r"\1", record)
    parsed_record = spf_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        pos = parsed_record.pos
        expecting = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting))
        )
        expecting = " or ".join(expecting)
        marked_record = record[:pos] + syntax_error_marker + record[pos:]
        raise SPFSyntaxError(
            f"{domain}: Expected {expecting} at position {pos} "
            f"(marked with {syntax_error_marker}) in: {marked_record}"
        )
    error = None
    matches = SPF_MECHANISM_REGEX.findall(record.lower())
    parsed = OrderedDict(
        [
            ("pass", []),
            ("neutral", []),
            ("softfail", []),
            ("fail", []),
            ("include", []),
            ("redirect", None),
            ("exp", None),
            ("all", "neutral"),
        ]
    )

    lookup_mechanism_count = 0
    void_lookup_mechanism_count = 0
    for match in matches:
        mechanism = match[1].lower().strip(":=")
        if mechanism in lookup_mechanisms:
            lookup_mechanism_count += 1
    if lookup_mechanism_count > 10:
        raise SPFTooManyDNSLookups(
            "Parsing the SPF record requires "
            f"{lookup_mechanism_count}/10 maximum DNS lookups - "
            "https://tools.ietf.org/html/rfc7208#section-4.6.4",
            dns_lookups=lookup_mechanism_count,
        )

    for match in matches:
        result = spf_qualifiers[match[0]]
        mechanism = match[1].strip(":=")
        value = match[2]

        try:
            if mechanism == "ip4":
                try:
                    if not isinstance(
                        ipaddress.ip_network(value, strict=False), ipaddress.IPv4Network
                    ):
                        raise SPFSyntaxError(
                            f"{value} is not a valid ipv4  value. Looks like ipv6"
                        )
                except ValueError:
                    raise SPFSyntaxError(f"{value} is not a valid ipv4 value")
            elif mechanism == "ip6":
                try:
                    if not isinstance(
                        ipaddress.ip_network(value, strict=False), ipaddress.IPv6Network
                    ):
                        raise SPFSyntaxError(
                            f"{value} is not a valid ipv6 value. Looks like ipv4"
                        )
                except ValueError:
                    raise SPFSyntaxError(f"{value} is not a valid ipv6 value")

            if mechanism == "a":
                if value == "":
                    value = domain
                cidr = None
                value = value.split("/")
                value = value[0]
                if len(value) == 2:
                    cidr = value[1]
                a_records = get_a_records(
                    value, nameservers=nameservers, resolver=resolver, timeout=timeout
                )
                if len(a_records) == 0:
                    raise _SPFMissingRecords(
                        f"{value.lower()} does not have any A/AAAA records"
                    )
                for record in a_records:
                    if cidr:
                        record = f"{record}/{cidr}"
                    parsed[result].append(
                        OrderedDict([("value", record), ("mechanism", mechanism)])
                    )
            elif mechanism == "mx":
                if value == "":
                    value = domain
                mx_hosts = get_mx_records(
                    value, nameservers=nameservers, resolver=resolver, timeout=timeout
                )
                if len(mx_hosts) == 0:
                    raise _SPFMissingRecords(
                        f"{value.lower()} does not have any MX records"
                    )
                if len(mx_hosts) > 10:
                    url = "https://tools.ietf.org/html/rfc7208#section-4.6.4"
                    raise SPFTooManyDNSLookups(
                        f"{value} has more than 10 MX records - {url}",
                        dns_lookups=len(mx_hosts),
                    )
                for host in mx_hosts:
                    hostname = host["hostname"]
                    parsed[result].append(
                        OrderedDict([("value", hostname), ("mechanism", mechanism)])
                    )
            elif mechanism == "redirect":
                if value.lower() in recursion:
                    raise SPFRedirectLoop(f"Redirect loop: {value.lower()}")
                seen.append(value.lower())
                try:
                    redirect_record = query_spf_record(
                        value,
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                    )
                    redirect_record = redirect_record["record"]
                    redirect = parse_spf_record(
                        redirect_record,
                        value,
                        seen=seen,
                        recursion=recursion + [value.lower()],
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                    )
                    lookup_mechanism_count += redirect["dns_lookups"]
                    void_lookup_mechanism_count += redirect["dns_void_lookups"]
                    if lookup_mechanism_count > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires "
                            f"{lookup_mechanism_count}/10 maximum "
                            "DNS lookups - "
                            "https://tools.ietf.org/html/rfc7208"
                            "#section-4.6.4",
                            dns_lookups=lookup_mechanism_count,
                        )
                    if void_lookup_mechanism_count > 2:
                        u = "https://tools.ietf.org/html/rfc7208#section-4.6.4"
                        raise SPFTooManyVoidDNSLookups(
                            "Parsing the SPF record has "
                            f"{void_lookup_mechanism_count}/2 maximum void "
                            "DNS lookups - "
                            f"{u}",
                            dns_void_lookups=void_lookup_mechanism_count,
                        )
                    parsed["redirect"] = OrderedDict(
                        [
                            ("domain", value),
                            ("record", redirect_record),
                            ("dns_lookups", redirect["dns_lookups"]),
                            ("dns_void_lookups", redirect["dns_void_lookups"]),
                            ("parsed", redirect["parsed"]),
                            ("warnings", redirect["warnings"]),
                        ]
                    )
                    warnings += redirect["warnings"]
                except DNSException as error:
                    if isinstance(error, DNSExceptionNXDOMAIN):
                        void_lookup_mechanism_count += 1
                    raise _SPFWarning(str(error))
            elif mechanism == "exp":
                parsed["exp"] = get_txt_records(value)[0]
            elif mechanism == "all":
                parsed["all"] = result
            elif mechanism == "include":
                if value.lower() in recursion:
                    pointer = " -> ".join(recursion + [value.lower()])
                    raise SPFIncludeLoop(f"Include loop: {pointer}")
                if value.lower() in seen:
                    raise _SPFDuplicateInclude(f"Duplicate include: {value.lower()}")
                seen.append(value.lower())
                if "%{" in value:
                    include = OrderedDict([("domain", value)])
                    parsed["include"].append(include)
                    continue
                try:
                    include_record = query_spf_record(
                        value,
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                    )
                    include_record = include_record["record"]
                    include = parse_spf_record(
                        include_record,
                        value,
                        seen=seen,
                        recursion=recursion + [value.lower()],
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                    )
                    include = OrderedDict(
                        [
                            ("domain", value),
                            ("record", include_record),
                            ("dns_lookups", include["dns_lookups"]),
                            ("dns_void_lookups", include["dns_void_lookups"]),
                            ("parsed", include["parsed"]),
                            ("warnings", include["warnings"]),
                        ]
                    )
                    parsed["include"].append(include)
                    warnings += include["warnings"]
                    lookup_mechanism_count += include["dns_lookups"]
                    void_lookup_mechanism_count += include["dns_void_lookups"]
                    if lookup_mechanism_count > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires "
                            f"{lookup_mechanism_count}/10 maximum "
                            "DNS lookups - "
                            "https://tools.ietf.org/html/rfc7208"
                            "#section-4.6.4",
                            dns_lookups=lookup_mechanism_count,
                        )
                    if void_lookup_mechanism_count > 2:
                        u = "https://tools.ietf.org/html/rfc7208#section-4.6.4"
                        raise SPFTooManyVoidDNSLookups(
                            "Parsing the SPF record has "
                            f"{void_lookup_mechanism_count}/2 maximum void "
                            "DNS lookups - "
                            f"{u}",
                            dns_void_lookups=void_lookup_mechanism_count,
                        )

                except DNSException as error:
                    if isinstance(error, DNSExceptionNXDOMAIN):
                        void_lookup_mechanism_count += 1
                    raise _SPFWarning(str(error))
                except SPFRecordNotFound as error:
                    void_lookup_mechanism_count += 1
                    raise error
            elif mechanism == "ptr":
                parsed[result].append(
                    OrderedDict([("value", value), ("mechanism", mechanism)])
                )
                raise _SPFWarning(
                    "The ptr mechanism should not be used - "
                    "https://tools.ietf.org/html/rfc7208"
                    "#section-5.5"
                )
            elif mechanism == "rr":
                tokens = value.split(":")

                for token in tokens:
                    if token not in ["all", "e", "f", "s", "n"]:
                        raise SPFSyntaxError(
                            f"{token} is not a valid token for the rr tag"
                        )

                parsed["rr"] = result
            elif mechanism == "rp":
                if not value.isdigit():
                    raise SPFSyntaxError(
                        f"{value} is not a valid ra tag value - should be a number"
                    )
                if int(value) < 0 or int(value) > 100:
                    raise SPFSyntaxError(
                        f"{value} is not a valid ra tag value - should be a number between 0 and 100"
                    )

                parsed["rp"] = result
            else:
                parsed[result].append(
                    OrderedDict([("value", value), ("mechanism", mechanism)])
                )
        except (SPFTooManyDNSLookups, SPFTooManyVoidDNSLookups) as e:
            if ignore_too_many_lookups:
                error = str(e)
            else:
                raise e
        except (_SPFWarning, DNSException) as warning:
            if isinstance(warning, (_SPFMissingRecords, DNSExceptionNXDOMAIN)):
                void_lookup_mechanism_count += 1
                if void_lookup_mechanism_count > 2:
                    raise SPFTooManyVoidDNSLookups(
                        "Parsing the SPF record has "
                        f"{void_lookup_mechanism_count}/2 maximum void DNS "
                        "lookups - "
                        "https://tools.ietf.org/html/rfc7208#section-4.6.4",
                        dns_void_lookups=void_lookup_mechanism_count,
                    )
            warnings.append(str(warning))
    if error:
        result = OrderedDict(
            [
                ("dns_lookups", lookup_mechanism_count),
                ("dns_void_lookups", void_lookup_mechanism_count),
                ("error", error),
                ("parsed", parsed),
                ("warnings", warnings),
            ]
        )
    else:
        result = OrderedDict(
            [
                ("dns_lookups", lookup_mechanism_count),
                ("dns_void_lookups", void_lookup_mechanism_count),
                ("parsed", parsed),
                ("warnings", warnings),
            ]
        )
    return result


def get_spf_record(
    domain: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> OrderedDict:
    """
    Retrieves and parses an SPF record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): Number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An SPF record parsed by result

    Raises:
        :exc:`checkdmarc.spf.SPFRecordNotFound`
        :exc:`checkdmarc.spf.SPFIncludeLoop`
        :exc:`checkdmarc.spf.SPFRedirectLoop`
        :exc:`checkdmarc.spf.SPFSyntaxError`
        :exc:`checkdmarc.spf.SPFTooManyDNSLookups`

    """
    domain = normalize_domain(domain)
    record = query_spf_record(
        domain, nameservers=nameservers, resolver=resolver, timeout=timeout
    )
    record = record["record"]
    parsed_record = parse_spf_record(
        record, domain, nameservers=nameservers, resolver=resolver, timeout=timeout
    )
    parsed_record["record"] = record

    return parsed_record


def check_spf(
    domain: str,
    *,
    parked: bool = False,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> OrderedDict:
    """
    Returns a dictionary with a parsed SPF record or an error.

    Args:
        domain (str): A domain name
        parked (bool): The domain is parked
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:

                       - ``record`` - The SPF record string
                       - ``parsed`` - The parsed SPF record
                       - ``dns_lookups`` - The number of DNS lookups
                       - ``dns_void_lookups`` - The number of void DNS lookups
                       - ``valid`` - True
                       - ``warnings`` - A ``list`` of warnings

                    If a DNS error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - Tne error message
                      - ``valid`` - False
    """
    domain = normalize_domain(domain)
    spf_results = OrderedDict(
        [
            ("record", None),
            ("valid", True),
            ("dns_lookups", None),
            ("dns_void_lookups", None),
        ]
    )
    try:
        spf_query = query_spf_record(
            domain, nameservers=nameservers, resolver=resolver, timeout=timeout
        )
        spf_results["record"] = spf_query["record"]
        spf_results["warnings"] = spf_query["warnings"]
        parsed_spf = parse_spf_record(
            spf_results["record"],
            domain,
            parked=parked,
            ignore_too_many_lookups=True,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
        )

        spf_results["dns_lookups"] = parsed_spf["dns_lookups"]
        spf_results["dns_void_lookups"] = parsed_spf["dns_void_lookups"]
        if "error" in parsed_spf:
            spf_results["valid"] = False
            spf_results["error"] = parsed_spf["error"]
        spf_results["parsed"] = parsed_spf["parsed"]
        spf_results["warnings"] += parsed_spf["warnings"]
    except SPFError as error:
        spf_results["error"] = str(error.args[0])
        del spf_results["dns_lookups"]
        spf_results["valid"] = False
        if hasattr(error, "data") and error.data:
            for key in error.data:
                spf_results[key] = error.data[key]
    return spf_results
