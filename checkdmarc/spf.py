# -*- coding: utf-8 -*-
"""Sender Policy framework (SPF) record validation"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections import OrderedDict

import dns
from pyleri import Grammar, Regex, Repeat, Sequence

from checkdmarc._constants import SYNTAX_ERROR_MARKER
from checkdmarc.utils import (
    DNSException,
    DNSExceptionNXDOMAIN,
    get_a_records,
    get_mx_records,
    get_txt_records,
    normalize_domain,
    query_dns,
)

"""Copyright 2019-2025 Sean Whalen

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
    r"(mx:?|ip4:?|ip6:?|exists:?|include:?|all|a:?|redirect=|exp=|ptr:?)"
    r"([\w+/_.:\-{}%]*)"
)
AFTER_ALL_REGEX_STRING = r"((?:^|\s)[+\-~?]?all)\s+.*"

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
    """Raised when a mechanism in a ``SPF`` record is missing the requested A/AAAA or MX records"""


class _SPFDuplicateInclude(_SPFWarning):
    """Raised when a duplicate SPF include is found"""


class SPFRecordNotFound(SPFError):
    """Raised when an SPF record could not be found"""

    def __init__(self, error, domain):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)
        self.error = error
        self.domain = domain

    def __str__(self):
        return f"{self.domain}: {str(self.error)}"


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
        data = dict(void_dns_lookups=kwargs["void_dns_lookups"])
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
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
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
            "removed in the standards track version of SPF, RFC 7208. "
            "These records should be removed and replaced with TXT records: "
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
                    "A TXT record contains undecodable characters."
                )
            # https://datatracker.ietf.org/doc/html/rfc7208#section-4.5
            #
            # Starting with the set of records that were returned by the lookup,
            # discard records that do not begin with a version section of exactly
            # "v=spf1".  Note that the version section is terminated by either an
            # SP character or the end of the record. As an example, a record with
            # a version section of "v=spf10" does not match and is discarded.
            if record.startswith(f"{txt_prefix} ") or record == txt_prefix:
                spf_txt_records.append(record)
            elif record.startswith(txt_prefix):
                raise SPFRecordNotFound(
                    "According to RFC7208 section 4.5, a SPF record should be"
                    f" equal to {txt_prefix} or begin with {txt_prefix} "
                    "followed by a space.",
                    domain,
                )
        if len(spf_txt_records) > 1:
            raise MultipleSPFRTXTRecords("The domain has multiple SPF TXT records")
        elif len(spf_txt_records) == 1:
            spf_record = spf_txt_records[0]
        if spf_record is None:
            raise SPFRecordNotFound("An SPF record does not exist.", domain)
    except dns.resolver.NoAnswer:
        raise SPFRecordNotFound("An SPF record does not exist.", domain)
    except dns.resolver.NXDOMAIN:
        raise SPFRecordNotFound("The domain does not exist.", domain)
    except SPFRecordNotFound as error:
        raise error
    except Exception as error:
        raise SPFRecordNotFound(error, domain)

    # Per RFC 7208 §3.3: any single TXT "character-string" must be ≤255 octets.
    # Per RFC 7208 §3.4: keep overall SPF record small enough for UDP (advise ~450B, warn at >512B).
    try:
        quoted_chunks = re.findall(r'"([^"]*)"', spf_record) if spf_record else []
        if quoted_chunks:
            for i, chunk in enumerate(quoted_chunks, 1):
                blen = len(chunk.encode("utf-8"))
                if blen > 255:
                    warnings.append(
                        f"SPF TXT string chunk #{i} for {domain} is {blen} bytes (>255). "
                        "Each individual TXT character-string must be ≤255 octets (RFC 7208 §3.3)."
                    )
            joined = "".join(quoted_chunks)
        else:
            joined = spf_record or ""
            blen = len(joined.encode("utf-8"))
            if blen > 255:
                warnings.append(
                    f"SPF TXT for {domain} appears to be a single {blen}-byte string; "
                    "a single TXT character-string must be ≤255 octets (RFC 7208 §3.3). "
                    "Consider splitting into multiple quoted strings."
                )

        total_bytes = len(joined.encode("utf-8"))
        if total_bytes > 512:
            warnings.append(
                f"SPF record for {domain} is {total_bytes} bytes (>512). "
                "This likely exceeds reliable UDP response size; some verifiers may ignore or fail it (RFC 7208 §3.4)."
            )
        elif total_bytes > 450:
            warnings.append(
                f"SPF record for {domain} is {total_bytes} bytes. "
                "RFC 7208 §3.4 recommends keeping answers under ~450 bytes so the whole DNS message fits in 512 bytes."
            )
    except Exception:
        # Never let the size check impact normal operation
        pass

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
    Parses an SPF record, including resolving ``a``, ``mx``, and ``include`` mechanisms

    Args:
        record (str): An SPF record
        domain (str): The domain that the SPF record came from
        parked (bool): indicated if a domain has been parked
        ignore_too_many_lookups (bool): Do not raise an exception for too many lookups
        seen (list): A list of domains seen in past loops
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
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

    if seen is None:
        seen = [domain]
    if recursion is None:
        recursion = [domain]

    # Collapse RFC-style split TXT tokens only, then remove remaining quotes.
    # (Safer than blanket replace('" ', '') which could drop valid whitespace.)
    record = re.sub(r'"\s+"', " ", record).replace('"', "")

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
        warnings.append("Any text after the all mechanism is ignored.")
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

    matches = SPF_MECHANISM_REGEX.findall(record.lower())

    parsed = OrderedDict(
        [
            ("mechanisms", []),
            ("redirect", None),
            ("exp", None),
            ("all", "neutral"),
        ]
    )

    total_dns_lookups = 0
    total_void_dns_lookups = 0
    error = None

    for match in matches:
        mechanism_dns_lookups = 0
        mechanism_void_dns_lookups = 0
        action = spf_qualifiers[match[0]]
        mechanism = match[1].strip(":=")
        value = match[2]
        try:
            if mechanism == "ip4":
                try:
                    if not isinstance(
                        ipaddress.ip_network(value, strict=False),
                        ipaddress.IPv4Network,
                    ):
                        raise SPFSyntaxError(
                            f"{value} is not a valid ipv4 value.\nLooks like ipv6."
                        )
                except ValueError:
                    raise SPFSyntaxError(f"{value} is not a valid ipv4 value.")

            elif mechanism == "ip6":
                try:
                    if not isinstance(
                        ipaddress.ip_network(value, strict=False),
                        ipaddress.IPv6Network,
                    ):
                        raise SPFSyntaxError(
                            f"{value} is not a valid ipv6 value.\nLooks like ipv4."
                        )
                except ValueError:
                    raise SPFSyntaxError(f"{value} is not a valid ipv6 value.")

            if mechanism == "a":
                mechanism_dns_lookups = 1
                total_dns_lookups += 1
                if value == "":
                    value = domain
                cidr = None
                value = value.split("/")
                value = value[0]
                if len(value) == 2:
                    cidr = value[1]
                a_records = get_a_records(
                    value,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                )
                if len(a_records) == 0:
                    mechanism_void_dns_lookups += 1
                    total_void_dns_lookups += 1
                    raise _SPFMissingRecords(
                        f"An a mechanism points to {value.lower()}, but that domain/subdomain does not have any A/AAAA records."
                    )
                for i in range(len(a_records)):
                    if cidr:
                        a_records[i] = f"{a_records[i]}/{cidr}"
                pairs = [
                    ("action", action),
                    ("mechanism", mechanism),
                    ("value", value),
                    ("dns_lookups", mechanism_dns_lookups),
                    ("void_dns_lookups", mechanism_void_dns_lookups),
                    ("addresses", a_records),
                ]
                parsed["mechanisms"].append(OrderedDict(pairs))

            elif mechanism == "mx":
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                # Use the current domain if no value was provided
                if value == "":
                    value = domain

                # Query the MX records
                mx_hosts = get_mx_records(
                    value,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                )

                if len(mx_hosts) == 0:
                    mechanism_dns_lookups += 1
                    total_void_dns_lookups += 1
                    raise _SPFMissingRecords(
                        f"An mx mechanism points to {value.lower()}, "
                        "but that domain/subdomain does not have any MX records."
                    )

                # RFC 7208 §4.6.4: no more than 10 DNS queries total per evaluation
                if len(mx_hosts) > 9:
                    raise SPFTooManyDNSLookups(
                        f"{value} has more than 9 MX records - "
                        "https://tools.ietf.org/html/rfc7208#section-4.6.4",
                        dns_lookups=len(mx_hosts),
                    )
                host_ips = {}
                for host in mx_hosts:
                    # count one DNS query per MX target
                    mechanism_dns_lookups += 1
                    total_dns_lookups += 1
                    hostname = host["hostname"]
                    # --- perform A/AAAA resolution for each MX host ---
                    try:
                        _addresses = get_a_records(
                            hostname,
                            nameservers=nameservers,
                            resolver=resolver,
                            timeout=timeout,
                        )
                        host_ips[hostname] = _addresses

                        if len(_addresses) == 0:
                            # void lookup: increment void counter
                            mechanism_void_dns_lookups += 1
                            total_void_dns_lookups += 1
                            if total_void_dns_lookups > 2:
                                raise SPFTooManyVoidDNSLookups(
                                    "Parsing the SPF record has "
                                    f"{total_void_dns_lookups}/2 maximum void DNS lookups - "
                                    "https://tools.ietf.org/html/rfc7208#section-4.6.4",
                                    void_dns_lookups=total_void_dns_lookups,
                                )

                        if total_dns_lookups > 10:
                            raise SPFTooManyDNSLookups(
                                "Parsing the SPF record requires "
                                f"{total_dns_lookups}/10 maximum DNS lookups - "
                                "https://tools.ietf.org/html/rfc7208#section-4.6.4",
                                dns_lookups=total_dns_lookups,
                            )

                    except DNSException as error:
                        if isinstance(error, DNSExceptionNXDOMAIN):
                            mechanism_void_dns_lookups += 1
                            total_void_dns_lookups += 1
                            if total_void_dns_lookups > 2:
                                raise SPFTooManyVoidDNSLookups(
                                    "Parsing the SPF record has "
                                    f"{total_void_dns_lookups}/2 maximum void DNS lookups - "
                                    "https://tools.ietf.org/html/rfc7208#section-4.6.4",
                                    void_dns_lookups=total_void_dns_lookups,
                                )
                        raise _SPFWarning(str(error))
                pairs = [
                    ("action", action),
                    ("mechanism", mechanism),
                    ("value", value),
                    ("dns_lookups", mechanism_dns_lookups),
                    ("void_dns_lookups", mechanism_void_dns_lookups),
                ]
                pairs.append(("hosts", host_ips))
                parsed["mechanisms"].append(OrderedDict(pairs))

            elif mechanism == "exists":
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                pairs = OrderedDict(
                    [
                        ("action", action),
                        ("mechanism", mechanism),
                        ("value", value),
                        ("dns_lookups", mechanism_dns_lookups),
                        ("void_dns_lookups", mechanism_void_dns_lookups),
                    ]
                )
                parsed["mechanisms"].append(OrderedDict(pairs))
                if total_dns_lookups > 10:
                    raise SPFTooManyDNSLookups(
                        "Parsing the SPF record requires "
                        f"{total_dns_lookups}/10 maximum DNS lookups - "
                        "https://tools.ietf.org/html/rfc7208#section-4.6.4",
                        dns_lookups=total_dns_lookups,
                    )
            elif mechanism == "redirect":
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
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
                    parsed["all"] = redirect["parsed"]["all"]
                    mechanism_dns_lookups += redirect["dns_lookups"]
                    mechanism_void_dns_lookups += redirect["void_dns_lookups"]
                    if total_dns_lookups > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires "
                            f"{total_dns_lookups}/10 maximum "
                            "DNS lookups - "
                            "https://tools.ietf.org/html/rfc7208"
                            "#section-4.6.4",
                            dns_lookups=total_dns_lookups,
                        )
                    if total_void_dns_lookups > 2:
                        u = "https://tools.ietf.org/html/rfc7208#section-4.6.4"
                        raise SPFTooManyVoidDNSLookups(
                            "Parsing the SPF record has "
                            f"{total_void_dns_lookups}/2 maximum void "
                            "DNS lookups - "
                            f"{u}",
                            void_dns_lookups=total_void_dns_lookups,
                        )
                    parsed["redirect"] = OrderedDict(
                        [
                            ("domain", value),
                            ("record", redirect_record),
                            ("dns_lookups", mechanism_dns_lookups),
                            ("void_dns_lookups", mechanism_void_dns_lookups),
                            ("parsed", redirect["parsed"]),
                            ("warnings", redirect["warnings"]),
                        ]
                    )
                    warnings += redirect["warnings"]
                except DNSException as error:
                    if isinstance(error, DNSExceptionNXDOMAIN):
                        total_void_dns_lookups += 1
                    raise _SPFWarning(str(error))

            elif mechanism == "exp":
                # exp is a modifier that does not count as a DNS lookup
                # Thread resolver/timeouts and handle empty TXT gracefully.
                txts = get_txt_records(
                    value,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                )
                parsed["exp"]["value"] = txts[0] if txts else None

            elif mechanism == "all":
                parsed["all"] = action

            elif mechanism == "include":
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                if value.lower() in recursion:
                    pointer = " -> ".join(recursion + [value.lower()])
                    raise SPFIncludeLoop(f"Include loop: {pointer}")
                if value.lower() in seen:
                    raise _SPFDuplicateInclude(f"Duplicate include: {value.lower()}")
                seen.append(value.lower())

                if "%{" in value:
                    include = OrderedDict(
                        [
                            ("action", action),
                            ("mechanism", mechanism),
                            ("value", value),
                            ("dns_lookups", mechanism_dns_lookups),
                            ("void_dns_lookups", mechanism_void_dns_lookups),
                        ]
                    )
                    parsed["mechanisms"].append(include)
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
                    total_dns_lookups += include["dns_lookups"]
                    total_void_dns_lookups += include["void_dns_lookups"]
                    combined_mechanism_lookups = (
                        mechanism_dns_lookups + include["dns_lookups"]
                    )
                    combined_mechanism_void_dns_lookups = (
                        mechanism_void_dns_lookups + include["void_dns_lookups"]
                    )
                    include = OrderedDict(
                        [
                            ("mechanism", mechanism),
                            ("value", value),
                            ("record", include_record),
                            ("dns_lookups", combined_mechanism_lookups),
                            ("void_dns_lookups", combined_mechanism_void_dns_lookups),
                            ("parsed", include["parsed"]),
                            ("warnings", include["warnings"]),
                        ]
                    )
                    parsed["mechanisms"].append(include)
                    warnings += include["warnings"]
                    mechanism_dns_lookups += include["dns_lookups"]
                    mechanism_void_dns_lookups += include["void_dns_lookups"]
                    if total_dns_lookups > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires "
                            f"{total_dns_lookups}/10 maximum "
                            "DNS lookups - "
                            "https://tools.ietf.org/html/rfc7208"
                            "#section-4.6.4",
                            dns_lookups=total_dns_lookups,
                        )
                    if total_void_dns_lookups > 2:
                        u = "https://tools.ietf.org/html/rfc7208#section-4.6.4"
                        raise SPFTooManyVoidDNSLookups(
                            "Parsing the SPF record has "
                            f"{total_void_dns_lookups}/2 maximum void "
                            "DNS lookups - "
                            f"{u}",
                            dns_void_lookups=total_void_dns_lookups,
                        )
                except SPFRecordNotFound as e:
                    total_void_dns_lookups += 1
                    include = OrderedDict(
                        [
                            ("mechanism", mechanism),
                            ("value", value),
                            ("record", None),
                            ("dns_lookups", 1),
                            ("void_dns_lookups", 1),
                        ]
                    )
                    parsed["mechanisms"].append(include)
                    raise _SPFWarning(str(e))

            elif mechanism == "ptr":
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                parsed["mechanisms"].append(
                    OrderedDict(
                        [
                            ("action", action),
                            ("mechanism", mechanism),
                            ("value", value),
                            ("dns_lookups", mechanism_dns_lookups),
                            ("mechanism_void_dns_lookups", mechanism_void_dns_lookups),
                        ]
                    )
                )
                raise _SPFWarning(
                    "The ptr mechanism should not be used - "
                    "https://tools.ietf.org/html/rfc7208#section-5.5"
                )
            else:
                pairs = [
                    ("mechanism", mechanism),
                    ("value", value),
                ]
                if mechanism_dns_lookups > 0:
                    pairs.append(("dns_lookups", mechanism_dns_lookups))
                    pairs.append("void_dns_lookups", mechanism_void_dns_lookups)
                pairs.append(("action", action))
                parsed["mechanisms"].append(OrderedDict(pairs))

        except (SPFTooManyDNSLookups, SPFTooManyVoidDNSLookups) as e:
            if ignore_too_many_lookups:
                error = str(e)
            else:
                raise e

        except (_SPFWarning, DNSException) as warning:
            if isinstance(warning, (_SPFMissingRecords, DNSExceptionNXDOMAIN)):
                mechanism_void_dns_lookups += 1
                total_void_dns_lookups += 1
                if total_void_dns_lookups > 2:
                    raise SPFTooManyVoidDNSLookups(
                        "Parsing the SPF record has "
                        f"{total_void_dns_lookups}/2 maximum void DNS "
                        "lookups - "
                        "https://tools.ietf.org/html/rfc7208#section-4.6.4",
                        void_dns_lookups=total_void_dns_lookups,
                    )
            warnings.append(str(warning))

    if error:
        result = OrderedDict(
            [
                ("dns_lookups", total_dns_lookups),
                ("void_dns_lookups", total_void_dns_lookups),
                ("error", error),
                ("parsed", parsed),
                ("warnings", warnings),
            ]
        )
    else:
        result = OrderedDict(
            [
                ("dns_lookups", total_dns_lookups),
                ("void_dns_lookups", total_void_dns_lookups),
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
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
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
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
            - ``record`` - The SPF record string
            - ``parsed`` - The parsed SPF record
            - ``dns_lookups`` - The number of DNS lookups
            - ``void_dns_lookups`` - The number of void DNS lookups
            - ``valid`` - True
            - ``warnings`` - A ``list`` of warnings

        If a DNS error occurs, the dictionary will have the following keys:
            - ``error`` - Tne error message
            - ``valid`` - False
    """
    domain = normalize_domain(domain)
    spf_results = OrderedDict(
        [
            ("record", None),
            ("valid", True),
            ("dns_lookups", None),
            ("void_dns_lookups", None),
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
        spf_results["void_dns_lookups"] = parsed_spf["void_dns_lookups"]

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
