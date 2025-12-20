# -*- coding: utf-8 -*-
"""Sender Policy framework (SPF) record validation"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Optional, TypedDict, Union
from collections.abc import Sequence

import dns
import dns.exception
import dns.resolver
from dns.nameserver import Nameserver
import pyleri

from checkdmarc._constants import SYNTAX_ERROR_MARKER
from checkdmarc.utils import (
    DNSException,
    DNSExceptionNXDOMAIN,
    MXHost,
    get_a_records,
    get_mx_records,
    get_reverse_dns,
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
AFTER_ALL_REGEX_STRING = r"(?:^|\s)[+\-~?]?all\s+(.+)"

SPF_MECHANISM_REGEX = re.compile(SPF_MECHANISM_REGEX_STRING, re.IGNORECASE)
AFTER_ALL_REGEX = re.compile(AFTER_ALL_REGEX_STRING, re.IGNORECASE)

# Detect an 'all' mechanism glued to the previous term without required
# whitespace, e.g., "ip4:203.0.113.7~all". This should be rejected as a
# syntax error per RFC 7208 (terms must be space-separated).
# We require that the qualifier character (one of + - ~ ?) immediately precedes
# 'all' and that 'all' ends the term (followed by whitespace or end of string),
# so we don't falsely match hostnames like 'foo-all.example'.
CONCATENATED_ALL_REGEX = re.compile(r"\S([+\-~?])all(?=\s|$)", re.IGNORECASE)

MACRO_LETTERS = set("slodiphcrtv")
MACRO_DELIMS = set(".-+,/_=")


class SPFError(Exception):
    """Raised when a fatal SPF error occurs"""

    def __init__(self, msg: str, data: Optional[dict] = None):
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

    def __init__(self, error: Union[Exception, str], domain: str):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)
        self.error = error
        self.domain = domain

    def __str__(self):
        return str(self.error)


class MultipleSPFRTXTRecords(SPFError):
    """Raised when multiple TXT spf1 records are found"""


class UndecodableCharactersInTXTRecord(_SPFWarning):
    """Raised when a TXT record contains one or more undecodable characters"""


class SPFSyntaxError(SPFError):
    """Raised when an SPF syntax error is found"""


class SPFTooManyDNSLookups(SPFError):
    """Raised when an SPF record requires too many DNS lookups (10 max)"""

    def __init__(self, *args, **kwargs):
        data = {"dns_lookups": kwargs["dns_lookups"]}
        SPFError.__init__(self, args[0], data=data)


class SPFTooManyVoidDNSLookups(SPFError):
    """Raised when an SPF record requires too many void DNS lookups (2 max)"""

    def __init__(self, *args, **kwargs):
        data = {"void_dns_lookups": kwargs["void_dns_lookups"]}
        SPFError.__init__(self, args[0], data=data)


class SPFRedirectLoop(SPFError):
    """Raised when an SPF redirect loop is detected"""


class SPFIncludeLoop(SPFError):
    """Raised when an SPF include loop is detected"""


class _SPFGrammar(pyleri.Grammar):
    """Defines Pyleri grammar for SPF records"""

    version_tag = pyleri.Regex(SPF_VERSION_TAG_REGEX_STRING)
    mechanism = pyleri.Regex(SPF_MECHANISM_REGEX_STRING, re.IGNORECASE)

    # Note: Pyleri skips whitespace by default; explicitly matching whitespace
    # would break many valid records. We keep the grammar permissive here and
    # perform whitespace separation checks in Python before invoking the grammar.
    START = pyleri.Sequence(version_tag, pyleri.Repeat(mechanism))


class SPFQueryResults(TypedDict):
    record: str
    warnings: list[str]


class SPFMechanism(TypedDict):
    action: str
    mechanism: str
    value: str


class SPFDNSLookupMechanism(SPFMechanism):
    dns_lookups: int
    void_dns_lookups: int


class SPFAMechanism(SPFDNSLookupMechanism):
    addresses: list[str]


class ParsedSPFMXMechanism(SPFDNSLookupMechanism):
    hosts: list[MXHost]


class SPFIncludeMechanism(SPFDNSLookupMechanism):
    record: Union[str, None]
    parsed: Union[ParsedSPFRecord, None]
    warnings: list[str]


class SPFRedirect(TypedDict):
    domain: str
    record: Union[str, None]
    dns_lookups: int
    void_dns_lookups: int
    parsed: Union[ParsedSPFRecord, None]
    warnings: list[str]


class ParsedSPFRecord(TypedDict):
    mechanisms: list[
        Union[
            SPFMechanism,
            SPFDNSLookupMechanism,
            SPFIncludeMechanism,
            SPFAMechanism,
            ParsedSPFMXMechanism,
        ]
    ]
    redirect: Union[SPFRedirect, None]
    exp: Union[str, None]
    all: str


class ParsedSPFRecordSuccess(TypedDict):
    record: Union[None, str]
    dns_lookups: int
    void_dns_lookups: int
    parsed: ParsedSPFRecord
    warnings: list[str]


class ParsedSPFRecordError(ParsedSPFRecordSuccess):
    error: Union[str, DNSException]


SPFRecordResults = Union[ParsedSPFRecordSuccess, ParsedSPFRecordError]

spf_qualifiers: dict[str, str] = {
    "": "pass",
    "?": "neutral",
    "+": "pass",
    "-": "fail",
    "~": "softfail",
}


def ptr_match(
    ip_address: str,
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> bool:
    """
    Preforms a ptr mechanism check.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        bool: The result of the check

    Raises:
        :exc:`checkdmarc.DNSException`
    """
    hostnames = get_reverse_dns(
        ip_address,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        timeout_retries=timeout_retries,
    )
    for name in hostnames:
        if not name.endswith(domain):
            continue
        ips = get_a_records(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
        if ip_address in ips:
            return True
    return False


def _raise_macro_syntax_error(
    value: str,
    pos: int,
    domain: str,
    syntax_error_marker: str,
) -> None:
    """Raise SPFSyntaxError with a caret-like marker inside the bad value."""
    marked_value = value[:pos] + syntax_error_marker + value[pos:]
    raise SPFSyntaxError(
        f"{domain}: Invalid SPF macro syntax at position {pos} "
        f"(marked with {syntax_error_marker}) in value: {marked_value}"
    )


def _validate_spf_macros(
    value: str,
    domain: str,
    syntax_error_marker: str,
) -> None:
    """
    Validate SPF macro syntax in a domain-spec / macro-string per RFC 7208 §7.

    This is purely syntactic; no macro expansion or DNS lookups.
    """
    i = 0
    length = len(value)

    while i < length:
        ch = value[i]
        if ch != "%":
            i += 1
            continue

        # We have a '%'; ensure there is at least one more character
        if i + 1 >= length:
            _raise_macro_syntax_error(value, i, domain, syntax_error_marker)

        next_ch = value[i + 1]

        # Escapes: %%, %_, %-
        if next_ch in ("%", "_", "-"):
            i += 2
            continue

        # Macro-expand: %{...}
        if next_ch != "{":
            _raise_macro_syntax_error(value, i, domain, syntax_error_marker)

        # Find closing brace
        close = value.find("}", i + 2)
        if close == -1:
            _raise_macro_syntax_error(value, i, domain, syntax_error_marker)

        body = value[i + 2 : close]
        if not body:
            _raise_macro_syntax_error(value, i, domain, syntax_error_marker)

        # First char: macro-letter
        letter = body[0]
        if letter not in MACRO_LETTERS:
            _raise_macro_syntax_error(value, i + 2, domain, syntax_error_marker)

        rest = body[1:]

        # transformers: *DIGIT [ "r" ]
        j = 0
        while j < len(rest) and rest[j].isdigit():
            j += 1

        if j:
            # Non-zero if digits are present
            try:
                if int(rest[:j]) == 0:
                    _raise_macro_syntax_error(
                        value, i + 2 + 1, domain, syntax_error_marker
                    )
            except ValueError:
                _raise_macro_syntax_error(value, i + 2 + 1, domain, syntax_error_marker)

        if j < len(rest) and rest[j] == "r":
            j += 1

        # Remaining chars: delimiters
        delims = rest[j:]
        for k, d in enumerate(delims):
            if d not in MACRO_DELIMS:
                _raise_macro_syntax_error(
                    value, i + 2 + 1 + j + k, domain, syntax_error_marker
                )

        # All good for this macro
        i = close + 1


def query_spf_record(
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    quoted_txt_segments: bool = False,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> SPFQueryResults:
    """
    Queries DNS for an SPF record

    Args:
        domain (str): A domain name
        quoted_txt_segments (bool): Retain quotes around TXT segments
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
        timeout (float): number of seconds to wait for an answer from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout

    Returns:
        dict: A ``dict`` with the following keys:
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
            domain,
            "SPF",
            quoted_txt_segments=quoted_txt_segments,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
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
            domain,
            "TXT",
            quoted_txt_segments=quoted_txt_segments,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
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
            if record.strip('"').startswith(txt_prefix):
                spf_txt_records.append(record)
            elif record.startswith(txt_prefix):
                raise SPFRecordNotFound(
                    "According to RFC 7208 section 4.5, an SPF record should be"
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

    # Per RFC 7208 § 3.3: any single TXT "character-string" should be ≤255 characters.
    # Per RFC 7208 § 3.4: keep overall SPF record small enough for UDP (advise ~450B, warn at >512B).
    try:
        quoted_chunks = re.findall(r'"([^"]*)"', spf_record) if spf_record else []
        if quoted_chunks:
            for i, chunk in enumerate(quoted_chunks, 1):
                blen = len(chunk.encode("utf-8"))
                if blen > 255:
                    warnings.append(
                        f"SPF TXT string chunk #{i} for {domain} is {blen} characters (>255). "
                        "Each individual TXT character-string should be ≤ 255 characters (RFC 7208 § 3.3)."
                    )
            joined = "".join(quoted_chunks).replace('"', "")
        else:
            joined = spf_record or ""
            blen = len(joined.encode("utf-8"))
            if blen > 255:
                warnings.append(
                    f" The SPF record for {domain} appears to be a single {blen}-character string; "
                    "a single TXT character-string should be ≤ 255 characters (RFC 7208 § 3.3). "
                    "Consider splitting it into multiple quoted strings."
                )

        total_bytes = len(joined.encode("utf-8"))
        if total_bytes > 512:
            warnings.append(
                f"The SPF record for {domain} is > 512 bytes ({total_bytes} bytes). "
                "This likely exceeds the reliable UDP response size; some verifiers may ignore or fail it (RFC 7208 § 3.4)."
            )
        elif total_bytes > 450:
            warnings.append(
                f"The SPF record for {domain} is {total_bytes} bytes. "
                "RFC 7208 § 3.4 recommends keeping answers under ~450 bytes so the whole DNS message fits in 512 bytes."
            )
    except Exception:
        # Never let the size check impact normal operation
        pass

    spf_record = spf_record.replace('"', "")
    results: SPFQueryResults = {"record": spf_record, "warnings": warnings}

    return results


def parse_spf_record(
    record: str,
    domain: str,
    *,
    ignore_too_many_lookups: bool = False,
    parked: bool = False,
    seen: Optional[list] = None,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    recursion: Optional[list[str]] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> SPFRecordResults:
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
        recursion (list): A list of domains used in recursion
        timeout (float): number of seconds to wait for an answer from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        dict: A ``dict`` with the following keys:
            - ``dns_lookups`` - Number of DNS lookups required by the record
            - ``void_dns_lookups`` - The number of void DNS lookups
            - ``parsed`` - A ``dict`` of a parsed SPF record values
            - ``warnings`` - A ``list`` of warnings

    Raises:
        :exc:`checkdmarc.spf.SPFIncludeLoop`
        :exc:`checkdmarc.spf.SPFRedirectLoop`
        :exc:`checkdmarc.spf.SPFSyntaxError`
        :exc:`checkdmarc.spf.SPFTooManyDNSLookups`
    """
    logging.debug(f"Parsing the SPF record on {domain}")
    domain = normalize_domain(domain)
    record.replace('"', "")

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

    # Reject records where an 'all' mechanism is concatenated to the previous
    # term without a separating space, e.g., "ip4:203.0.113.7~all".
    m = CONCATENATED_ALL_REGEX.search(record)
    if m:
        pos = m.start(1)
        marked_record = record[:pos] + syntax_error_marker + record[pos:]
        raise SPFSyntaxError(
            f"{domain}: Expected whitespace before 'all' at position {pos} "
            f"(marked with {syntax_error_marker}) in: {marked_record}"
        )

    # For grammar-level syntax checking, ignore everything after the first
    # "all" mechanism. RFC 7208 only allows modifiers (not additional
    # mechanisms) after mechanisms; we handle "exp=" explicitly below using
    # AFTER_ALL_REGEX and emit warnings for any other junk.
    #
    # This lets us:
    #   - keep strict syntax checking on everything up to "all"
    #   - accept non-standard vendor junk after "all"
    #   - still parse and preserve an exp modifier after "all"
    grammar_record = record
    after_all_match = AFTER_ALL_REGEX.search(record)
    if after_all_match:
        # AFTER_ALL_REGEX captures everything *after* the "all" token as group 1.
        # Trim from the start of that group for the grammar input, so the
        # grammar only sees "v=spf1 ... all" and not the trailing junk/exp.
        grammar_record = record[: after_all_match.start(1)].rstrip()

    parsed_record = spf_syntax_checker.parse(grammar_record)

    if not parsed_record.is_valid:
        pos = parsed_record.pos
        expecting: list[str] = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting))
        )
        expecting_str = " or ".join(expecting)
        marked_record = record[:pos] + syntax_error_marker + record[pos:]
        raise SPFSyntaxError(
            f"{domain}: Expected {expecting_str} at position {pos} "
            f"(marked with {syntax_error_marker}) in: {marked_record}"
        )

    matches: list[tuple[str, str, str]] = SPF_MECHANISM_REGEX.findall(record.lower())

    parsed: ParsedSPFRecord = {
        "mechanisms": [],
        "redirect": None,
        "exp": None,
        "all": "neutral",
    }

    exp = None
    items_after_all: list[str] = AFTER_ALL_REGEX.findall(record)
    if len(items_after_all) > 0:
        if items_after_all[0].startswith("exp="):
            # RFC 7208 § 6.2 (exp modifier): The explanation string is
            # evaluated at runtime (after result == fail) and may contain
            # macros. It MUST NOT contribute to DNS lookup counting and
            # SHOULD NOT be resolved during static parsing.
            #
            # Therefore, do not perform any DNS lookups here. Simply
            # preserve the provided value (which may include macros) so a
            # caller with SMTP context can expand it at evaluation time.
            exp = items_after_all[0].split("=")
            if len(exp) < 2 or exp[1].strip() == 0:
                raise SPFSyntaxError("The exp modifier is missing a value")
            exp = exp[1].split(" ")
            if len(exp) > 1:
                warnings.append("No text should exist after the exp modifier value.")
            exp = exp[0]
            parsed["exp"] = exp
            if "%" in exp:
                _validate_spf_macros(exp, domain, syntax_error_marker)
            else:
                try:
                    exp_txt_records = get_txt_records(
                        exp,
                        nameservers=nameservers,
                        timeout=timeout,
                        timeout_retries=timeout_retries,
                    )
                    if len(exp_txt_records) == 0:
                        warnings.append(f"No TXT records at exp value {exp}.")
                    if len(exp_txt_records) > 1:
                        warnings.append(f"Too many TXT records at exp value {exp}.")
                except Exception as e:
                    warnings.append(
                        f"Failed to get TXT records at exp value {exp}: {e}"
                    )
        else:
            warnings.append(
                "Any text after the all mechanism other than an exp modifier is ignored."
            )

    total_dns_lookups = 0
    total_void_dns_lookups = 0
    error = None
    all_seen = False
    exp_seen = False
    for match in matches:
        mechanism_dns_lookups = 0
        mechanism_void_dns_lookups = 0
        action = spf_qualifiers[match[0]]
        mechanism = match[1].strip(":=")
        value = match[2]
        # Macro syntax validation: macros are allowed only in mechanisms
        # that take a domain-spec / macro-string, not ip4/ip6.
        if "%" in value:
            if mechanism in ("ip4", "ip6"):
                raise SPFSyntaxError(
                    f"{domain}: SPF macros are not allowed in {mechanism} "
                    f"mechanisms: {value}"
                )
        _validate_spf_macros(
            value,
            domain=domain,
            syntax_error_marker=syntax_error_marker,
        )
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
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                if "%" in value:
                    a_mechanism: SPFAMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                        "addresses": [],
                    }

                    parsed["mechanisms"].append(a_mechanism)
                    continue
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
                    timeout_retries=timeout_retries,
                )
                if len(a_records) == 0:
                    # Do not pre-increment void counters here; let the outer
                    # handler for _SPFMissingRecords account for a single void lookup.
                    raise _SPFMissingRecords(
                        f"An a mechanism points to {value.lower()}, but that domain/subdomain does not have any A/AAAA records."
                    )
                for i in range(len(a_records)):
                    if cidr:
                        a_records[i] = f"{a_records[i]}/{cidr}"
                a_mechanism: SPFAMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                    "dns_lookups": mechanism_dns_lookups,
                    "void_dns_lookups": mechanism_void_dns_lookups,
                    "addresses": a_records,
                }

                parsed["mechanisms"].append(a_mechanism)

            elif mechanism == "mx":
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                if "%" in value:
                    mx_mechanism: ParsedSPFMXMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                        "hosts": [],
                    }

                    parsed["mechanisms"].append(mx_mechanism)
                    continue
                # Use the current domain if no value was provided
                if value == "":
                    value = domain

                # Query the MX records
                mx_hosts = get_mx_records(
                    value,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                    timeout_retries=timeout_retries,
                )

                if len(mx_hosts) == 0:
                    # MX query resulted in no records; count a single void lookup
                    # in the outer warning handler to avoid double counting.
                    raise _SPFMissingRecords(
                        f"An mx mechanism points to {value.lower()}, "
                        "but that domain/subdomain does not have any MX records."
                    )

                # RFC 7208 § 4.6.4: no more than 10 DNS queries total per evaluation
                if len(mx_hosts) > 10:
                    raise SPFTooManyDNSLookups(
                        f"{value} has more than 10 MX records - (RFC 7208 § 4.6.4)",
                        dns_lookups=len(mx_hosts),
                    )
                mx_host_addresses = {}
                for host in mx_hosts:
                    hostname = host["hostname"]
                    # --- perform A/AAAA resolution for each MX host ---
                    try:
                        _addresses = get_a_records(
                            hostname,
                            nameservers=nameservers,
                            resolver=resolver,
                            timeout=timeout,
                            timeout_retries=timeout_retries,
                        )
                        mx_host_addresses[hostname] = _addresses

                        if len(_addresses) == 0:
                            # void lookup: increment void counter
                            mechanism_void_dns_lookups += 1
                            total_void_dns_lookups += 1
                            if total_void_dns_lookups > 2:
                                raise SPFTooManyVoidDNSLookups(
                                    "Parsing the SPF record has "
                                    f"{total_void_dns_lookups}/2 maximum void DNS lookups - "
                                    "(RFC 7208 § 4.6.4)",
                                    void_dns_lookups=total_void_dns_lookups,
                                )

                        if total_dns_lookups > 10:
                            raise SPFTooManyDNSLookups(
                                "Parsing the SPF record requires "
                                f"{total_dns_lookups}/10 maximum DNS lookups - "
                                "(RFC 7208 § 4.6.4)",
                                dns_lookups=total_dns_lookups,
                            )

                    except DNSException as dnserror:
                        if isinstance(dnserror, DNSExceptionNXDOMAIN):
                            mechanism_void_dns_lookups += 1
                            total_void_dns_lookups += 1
                            if total_void_dns_lookups > 2:
                                raise SPFTooManyVoidDNSLookups(
                                    "Parsing the SPF record has "
                                    f"{total_void_dns_lookups}/2 maximum void DNS lookups "
                                    "(RFC 7208 § 4.6.4)",
                                    void_dns_lookups=total_void_dns_lookups,
                                )
                        raise _SPFWarning(str(dnserror))
                mx_mechanism: ParsedSPFMXMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                    "dns_lookups": mechanism_dns_lookups,
                    "void_dns_lookups": mechanism_void_dns_lookups,
                    "hosts": mx_hosts,
                }

                parsed["mechanisms"].append(mx_mechanism)

            elif mechanism == "exists":
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                exists_mechanism: SPFDNSLookupMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                    "dns_lookups": mechanism_dns_lookups,
                    "void_dns_lookups": mechanism_void_dns_lookups,
                }
                parsed["mechanisms"].append(exists_mechanism)
                if value == "":
                    raise SPFSyntaxError(f"{mechanism} must have a value")
                if total_dns_lookups > 10:
                    raise SPFTooManyDNSLookups(
                        "Parsing the SPF record requires "
                        f"{total_dns_lookups}/10 maximum DNS lookups "
                        "(RFC 7208 § 4.6.4)",
                        dns_lookups=total_dns_lookups,
                    )
            elif mechanism == "redirect":
                if parsed["redirect"]:
                    raise SPFSyntaxError("Multiple redirect modifiers")
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                if "%" in value:
                    redirect: SPFRedirect = {
                        "domain": domain,
                        "record": None,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                        "parsed": None,
                        "warnings": [],
                    }
                    parsed["redirect"] = redirect
                    continue
                if value.lower() in recursion:
                    raise SPFRedirectLoop(f"Redirect loop: {value.lower()}")
                seen.append(value.lower())
                try:
                    redirect_record = query_spf_record(
                        value,
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                        timeout_retries=timeout_retries,
                    )
                    redirect_record = redirect_record["record"]
                    redirected_spf = parse_spf_record(
                        redirect_record,
                        value,
                        seen=seen,
                        recursion=recursion + [value.lower()],
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                        timeout_retries=timeout_retries,
                    )
                    parsed["all"] = redirected_spf["parsed"]["all"]
                    mechanism_dns_lookups += redirected_spf["dns_lookups"]
                    mechanism_void_dns_lookups += redirected_spf["void_dns_lookups"]
                    total_dns_lookups += redirected_spf["dns_lookups"]
                    total_void_dns_lookups += redirected_spf["void_dns_lookups"]
                    if total_dns_lookups > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires "
                            f"{total_dns_lookups}/10 maximum "
                            "DNS lookups "
                            "(RFC 7208 § 4.6.4)",
                            dns_lookups=total_dns_lookups,
                        )
                    if total_void_dns_lookups > 2:
                        u = "(RFC 7208 § 4.6.4)"
                        raise SPFTooManyVoidDNSLookups(
                            "Parsing the SPF record has "
                            f"{total_void_dns_lookups}/2 maximum void "
                            "DNS lookups "
                            f"{u}",
                            void_dns_lookups=total_void_dns_lookups,
                        )
                    redirect: SPFRedirect = {
                        "domain": value,
                        "record": redirect_record,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                        "parsed": redirected_spf["parsed"],
                        "warnings": redirected_spf["warnings"],
                    }
                    parsed["redirect"] = redirect

                    warnings += redirected_spf["warnings"]
                except DNSException as error:
                    if isinstance(error, DNSExceptionNXDOMAIN):
                        total_void_dns_lookups += 1
                    raise _SPFWarning(str(error))

            elif mechanism == "all":
                if all_seen:
                    raise SPFSyntaxError("The all mechanism can only be used once.")
                all_seen = True
                parsed["all"] = action
            elif mechanism == "exp":
                if exp_seen:
                    raise SPFSyntaxError("Multiple exp values are not permitted")
                exp_seen = True
                parsed["exp"] = exp
                if isinstance(exp, str) and "%" in exp:
                    continue
                if isinstance(exp, str):
                    try:
                        exp_txt_records = get_txt_records(
                            exp,
                            nameservers=nameservers,
                            timeout=timeout,
                            timeout_retries=timeout_retries,
                        )
                        if len(exp_txt_records) == 0:
                            warnings.append(f"No TXT records at exp value {exp}.")
                        if len(exp_txt_records) > 1:
                            warnings.append(f"Too many TXT records at exp value {exp}.")
                    except Exception as e:
                        warnings.append(
                            f"Failed to get TXT records at exp value {exp}: {e}"
                        )

            elif mechanism == "include":
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                if "%" in value:
                    macro_include: SPFIncludeMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "record": None,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                        "parsed": None,
                        "warnings": [],
                    }
                    parsed["mechanisms"].append(macro_include)
                    continue
                if value == "":
                    raise SPFSyntaxError(f"{mechanism} must have a value")
                if value.lower() in recursion:
                    pointer = " -> ".join(recursion + [value.lower()])
                    raise SPFIncludeLoop(f"Include loop: {pointer}")
                if value.lower() in seen:
                    raise _SPFDuplicateInclude(f"Duplicate include: {value.lower()}")
                seen.append(value.lower())

                try:
                    include_record = query_spf_record(
                        value,
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                        timeout_retries=timeout_retries,
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
                        timeout_retries=timeout_retries,
                    )
                    total_dns_lookups += include["dns_lookups"]
                    total_void_dns_lookups += include["void_dns_lookups"]
                    combined_mechanism_lookups = (
                        mechanism_dns_lookups + include["dns_lookups"]
                    )
                    combined_mechanism_void_dns_lookups = (
                        mechanism_void_dns_lookups + include["void_dns_lookups"]
                    )

                    include_mechanism: SPFIncludeMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "dns_lookups": combined_mechanism_lookups,
                        "void_dns_lookups": combined_mechanism_void_dns_lookups,
                        "record": include_record,
                        "parsed": include["parsed"],
                        "warnings": include["warnings"],
                    }
                    parsed["mechanisms"].append(include_mechanism)
                    warnings += include["warnings"]
                    mechanism_dns_lookups += include["dns_lookups"]
                    mechanism_void_dns_lookups += include["void_dns_lookups"]
                    if total_dns_lookups > 10:
                        raise SPFTooManyDNSLookups(
                            "Parsing the SPF record requires "
                            f"{total_dns_lookups}/10 maximum "
                            "DNS lookups - "
                            "(RFC 7208 § 4.6.4)",
                            dns_lookups=total_dns_lookups,
                        )
                    if total_void_dns_lookups > 2:
                        u = "(RFC 7208 § 4.6.4)"
                        raise SPFTooManyVoidDNSLookups(
                            "Parsing the SPF record has "
                            f"{total_void_dns_lookups}/2 maximum void "
                            "DNS lookups - "
                            f"{u}",
                            void_dns_lookups=total_void_dns_lookups,
                        )
                except SPFRecordNotFound as e:
                    total_void_dns_lookups += 1
                    failed_include_mechanism: SPFIncludeMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "record": None,
                        "parsed": None,
                        "dns_lookups": 1,
                        "void_dns_lookups": 1,
                        "warnings": [],
                    }
                    parsed["mechanisms"].append(failed_include_mechanism)
                    raise _SPFWarning(str(e))

            elif mechanism == "ptr":
                mechanism_dns_lookups += 1
                total_dns_lookups += 1
                if "%" in value:
                    ptr_mechanism: SPFDNSLookupMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                    }
                    parsed["mechanisms"].append(ptr_mechanism)
                    raise _SPFWarning(
                        "The ptr mechanism should not be used - (RFC 7208 § 5.5)"
                    )
                if value == "":
                    value = domain
                a_records = get_a_records(
                    value,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                    timeout_retries=timeout_retries,
                )
                if len(a_records) == 0:
                    # Do not pre-increment void counters here; let the outer
                    # handler for _SPFMissingRecords account for a single void lookup.
                    raise _SPFMissingRecords(
                        f"A ptr mechanism points to {value.lower()}, but that domain/subdomain does not have any A/AAAA records."
                    )
                ptr_mechanism: SPFDNSLookupMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                    "dns_lookups": mechanism_dns_lookups,
                    "void_dns_lookups": mechanism_void_dns_lookups,
                }
                parsed["mechanisms"].append(ptr_mechanism)
                raise _SPFWarning(
                    "The ptr mechanism should not be used - (RFC 7208 § 5.5)"
                )
            else:
                if mechanism_dns_lookups > 0:
                    other_spf_dns_mechanism: SPFDNSLookupMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                    }
                    parsed["mechanisms"].append(other_spf_dns_mechanism)
                else:
                    other_mechanism: SPFMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                    }
                    parsed["mechanisms"].append(other_mechanism)

        except (SPFTooManyDNSLookups, SPFTooManyVoidDNSLookups) as e:
            if ignore_too_many_lookups:
                error = str(e)
            else:
                raise e

        except (_SPFWarning, DNSException) as warning:
            if isinstance(warning, (_SPFMissingRecords, DNSExceptionNXDOMAIN)):
                mechanism_void_dns_lookups += 1
                total_void_dns_lookups += 1

                failed_mechanism: SPFDNSLookupMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                    "dns_lookups": 1,
                    "void_dns_lookups": 1,
                }
                parsed["mechanisms"].append(failed_mechanism)
                if total_void_dns_lookups > 2:
                    raise SPFTooManyVoidDNSLookups(
                        "Parsing the SPF record has "
                        f"{total_void_dns_lookups}/2 maximum void DNS "
                        "lookups (RFC 7208 § 4.6.4)",
                        void_dns_lookups=total_void_dns_lookups,
                    )
            warnings.append(f"{value or domain}: {str(warning)}")

    if error:
        error_result: ParsedSPFRecordError = {
            "dns_lookups": total_dns_lookups,
            "void_dns_lookups": total_void_dns_lookups,
            "error": error,
            "parsed": parsed,
            "warnings": warnings,
            "record": record,
        }
        return error_result
    else:
        success_result: ParsedSPFRecordSuccess = {
            "dns_lookups": total_dns_lookups,
            "void_dns_lookups": total_void_dns_lookups,
            "parsed": parsed,
            "warnings": warnings,
            "record": record,
        }
    return success_result


def get_spf_record(
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> SPFRecordResults:
    """
    Retrieves and parses an SPF record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
        timeout (float): Number of seconds to wait for an answer from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout

    Returns:
        dict: An SPF record parsed by result

    Raises:
        :exc:`checkdmarc.spf.SPFRecordNotFound`
        :exc:`checkdmarc.spf.SPFIncludeLoop`
        :exc:`checkdmarc.spf.SPFRedirectLoop`
        :exc:`checkdmarc.spf.SPFSyntaxError`
        :exc:`checkdmarc.spf.SPFTooManyDNSLookups`
    """
    domain = normalize_domain(domain)
    record = query_spf_record(
        domain,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        timeout_retries=timeout_retries,
    )
    record = record["record"]
    parsed_record = parse_spf_record(
        record,
        domain,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        timeout_retries=timeout_retries,
    )
    parsed_record["record"] = record
    return parsed_record


def check_spf(
    domain: str,
    *,
    parked: bool = False,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> dict:
    """
    Returns a dictionary with a parsed SPF record or an error.

    Args:
        domain (str): A domain name
        parked (bool): The domain is parked
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
        timeout (float): number of seconds to wait for an answer from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout

    Returns:
        dict: A ``dict`` with the following keys:
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
    spf_results = {
        "record": None,
        "valid": True,
        "dns_lookups": None,
        "void_dns_lookups": None,
    }
    try:
        spf_query = query_spf_record(
            domain,
            quoted_txt_segments=True,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
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
            timeout_retries=timeout_retries,
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
