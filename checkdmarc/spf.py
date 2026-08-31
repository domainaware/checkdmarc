"""Sender Policy Framework (SPF) record validation"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Sequence
from typing import TypedDict

import dns
import dns.exception
import dns.resolver
import pyleri
from dns.nameserver import Nameserver

from checkdmarc._constants import (
    DEFAULT_DNS_MAX_RETRIES,
    DEFAULT_DNS_TIMEOUT,
    SYNTAX_ERROR_MARKER,
)
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

logger = logging.getLogger(__name__)

SPF_VERSION_TAG_REGEX_STRING = "v=spf1"

# One SPF term: an optional qualifier, a name, and an optional value
# introduced by ":" (a mechanism target), "/" (the a/mx CIDR shorthand), or
# "=" (a modifier). The value character class spans the full printable range
# that the RFC 7208 section 12 macro-string grammar allows; per-term
# validation in parse_spf_record narrows it further for each term kind.
SPF_MECHANISM_REGEX_STRING = (
    r"([+\-~?])?([A-Za-z][A-Za-z0-9_.\-]*)(?:([:/=])([\x21-\x7E]*))?"
)
AFTER_ALL_REGEX_STRING = r"(?:^|\s)[+\-~?]?all\s+(.+)"

SPF_MECHANISM_REGEX = re.compile(SPF_MECHANISM_REGEX_STRING, re.IGNORECASE)
AFTER_ALL_REGEX = re.compile(AFTER_ALL_REGEX_STRING, re.IGNORECASE)
# A term that is exactly an all mechanism (with optional qualifier)
ALL_TERM_REGEX = re.compile(r"[+\-~?]?all", re.IGNORECASE)
SENDER_ID_VERSION_TAG_REGEX = re.compile(
    r"^v=spf2\.0/(?:pra|mfrom)(?:,(?:pra|mfrom))?(?:\s|$)",
    re.IGNORECASE,
)

# The mechanism names defined by RFC 7208 section 12. Any other name followed
# by "=" is an unknown modifier (ignored with a warning per section 6); any
# other name without "=" is a syntax error.
SPF_MECHANISM_NAMES = frozenset(
    {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
)

# toplabel per RFC 7208 section 12: letters and digits with at least one
# letter, or a hyphenated label that starts and ends with a letter or digit.
TOPLABEL_REGEX = re.compile(r"[a-z0-9]*[a-z][a-z0-9]*|[a-z0-9]+-[a-z0-9\-]*[a-z0-9]")

# dual-cidr-length per RFC 7208 section 12: "/nn" (IPv4), "//nn" (IPv6), or
# "/nn//nn" — prefix lengths must not have leading zeros.
DUAL_CIDR_REGEX = re.compile(r"(?:/(0|[1-9][0-9]*))?(?://(0|[1-9][0-9]*))?")
# A single CIDR prefix length with no leading zeros (RFC 7208 section 12)
CIDR_PREFIX_REGEX = re.compile(r"0|[1-9][0-9]*")

# Detect an 'all' mechanism glued to the previous term without required
# whitespace, e.g., "ip4:203.0.113.7~all". This should be rejected as a
# syntax error per RFC 7208 (terms must be space-separated).
# We require that the qualifier character (one of + - ~ ?) immediately precedes
# 'all' and that 'all' ends the term (followed by whitespace or end of string),
# so we don't falsely match hostnames like 'foo-all.example'.
CONCATENATED_ALL_REGEX = re.compile(r"\S([+\-~?])all(?=\s|$)", re.IGNORECASE)

MACRO_LETTERS = set("slodiphcrtv")
# RFC 7208 section 7.2: c, r, and t may only be used in explanation text
EXP_ONLY_MACRO_LETTERS = set("crt")
MACRO_DELIMS = set(".-+,/_=")


class SPFError(Exception):
    """Raised when a fatal SPF error occurs"""

    def __init__(self, msg: str, data: dict | None = None):
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
    """Raised when a mechanism in an ``SPF`` record is missing the requested A/AAAA or MX records"""


class _SPFDuplicateInclude(_SPFWarning):
    """Raised when a duplicate SPF include is found"""


class SPFRecordNotFound(SPFError):
    """Raised when an SPF record could not be found"""

    def __init__(self, error: Exception | str, domain: str):
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
    record: str | None
    parsed: ParsedSPFRecord | None
    warnings: list[str]


class SPFRedirect(TypedDict):
    domain: str
    record: str | None
    dns_lookups: int
    void_dns_lookups: int
    parsed: ParsedSPFRecord | None
    warnings: list[str]


class ParsedSPFRecord(TypedDict):
    mechanisms: list[
        SPFMechanism
        | SPFDNSLookupMechanism
        | SPFIncludeMechanism
        | SPFAMechanism
        | ParsedSPFMXMechanism
    ]
    redirect: SPFRedirect | None
    exp: str | None
    all: str


class ParsedSPFRecordSuccess(TypedDict):
    record: None | str
    dns_lookups: int
    void_dns_lookups: int
    parsed: ParsedSPFRecord
    warnings: list[str]


class ParsedSPFRecordError(ParsedSPFRecordSuccess):
    error: str | DNSException


SPFRecordResults = ParsedSPFRecordSuccess | ParsedSPFRecordError

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
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> bool:
    """
    Performs a ptr mechanism check.

    Args:
        ip_address (str): The IP address of the sending host
        domain (str): The domain name to match against
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        bool: The result of the check

    Raises:
        :exc:`checkdmarc.utils.DNSException`
    """
    hostnames = get_reverse_dns(
        ip_address,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        retries=retries,
    )
    for name in hostnames:
        if not name.endswith(domain):
            continue
        ips = get_a_records(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
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
    *,
    allow_exp_only_letters: bool = False,
) -> None:
    """
    Validate SPF macro syntax in a domain-spec / macro-string per RFC 7208 §7.

    This is purely syntactic; no macro expansion or DNS lookups.

    Args:
        allow_exp_only_letters: Accept the c, r, and t macro letters, which
            RFC 7208 section 7.2 allows only in explanation (exp) text.
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

        # First char: macro-letter. The macro-letter grammar in RFC 7208 §7.1
        # uses ABNF quoted strings, which match case-insensitively (RFC 5234
        # §2.3), so uppercase letters (e.g. %{S}) are valid. Per RFC 7208 §7.3,
        # an uppercase macro expands exactly as its lowercase equivalent and the
        # result is then URL-encoded. Accept either case.
        letter = body[0]
        if letter.lower() not in MACRO_LETTERS:
            _raise_macro_syntax_error(value, i + 2, domain, syntax_error_marker)
        if not allow_exp_only_letters and letter.lower() in EXP_ONLY_MACRO_LETTERS:
            # RFC 7208 section 7.2: the c, r, and t macro letters are
            # allowed only in "exp" text, not in mechanism or redirect
            # domain-specs.
            raise SPFSyntaxError(
                f"{domain}: The macro letter {letter} is only allowed in "
                f"exp explanation text (RFC 7208 § 7.2): {value}"
            )

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

        # The "r" transformer is an ABNF quoted string, which matches
        # case-insensitively (RFC 5234 section 2.3), so %{iR} is valid.
        if j < len(rest) and rest[j] in ("r", "R"):
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
    nameservers: Sequence[str | Nameserver] | None = None,
    quoted_txt_segments: bool = False,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> SPFQueryResults:
    """
    Queries DNS for an SPF record

    Args:
        domain (str): A domain name
        quoted_txt_segments (bool): Retain quotes around TXT segments
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: A ``dict`` with the following keys:
            - ``record`` - The SPF record string
            - ``warnings`` - A ``list`` of warnings

    Raises:
        :exc:`checkdmarc.spf.SPFRecordNotFound`
        :exc:`checkdmarc.spf.MultipleSPFRTXTRecords`
    """
    domain = normalize_domain(domain)
    logger.debug(f"Checking for an SPF record on {domain}")
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
            retries=retries,
        )
    except (dns.exception.DNSException, OSError) as error:
        # SPF type records were removed from the standards track in RFC 7208,
        # so almost no domain publishes one and a failed lookup here is the
        # normal case rather than something worth reporting to the caller.
        logger.debug(f"SPF type record lookup failed for {domain}: {error}")

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
            retries=retries,
        )
        spf_record = None
        for record in answers:
            # https://datatracker.ietf.org/doc/html/rfc7208#section-4.5
            #
            # Starting with the set of records that were returned by the lookup,
            # discard records that do not begin with a version section of exactly
            # "v=spf1".  Note that the version section is terminated by either an
            # SP character or the end of the record. As an example, a record with
            # a version section of "v=spf10" does not match and is discarded.

            # Check for undecodable characters
            if record == "Undecodable characters":
                # We can't determine if this is an SPF record due to encoding issues
                warnings.append("A TXT record with undecodable characters was skipped.")
                continue

            # Strip only the surrounding quotes, not whitespace. Per RFC 7208
            # section 4.5, "discard records that do not begin with a version
            # section of exactly 'v=spf1'", and the ABNF (section 12) defines
            # "record = version terms *SP" — the record begins with the version
            # and only *trailing* spaces are allowed. So a record with leading
            # whitespace (e.g. " v=spf1 ...") does not begin with the version
            # section and is discarded rather than treated as valid SPF.
            cleaned_record = record.strip('"')
            cleaned_record_lower = cleaned_record.lower()

            if SENDER_ID_VERSION_TAG_REGEX.match(cleaned_record):
                warnings.append(
                    "A deprecated Sender ID record was found. Sender ID "
                    "using spf2.0/pra or spf2.0/mfrom was deprecated and "
                    "should be removed: "
                    f"{record}"
                )
                continue

            if cleaned_record_lower == txt_prefix or cleaned_record_lower.startswith(
                f"{txt_prefix} "
            ):
                spf_txt_records.append(record)
            elif cleaned_record_lower.startswith(txt_prefix):
                # RFC 7208 section 4.5: discard records that do not begin
                # with a version section of exactly "v=spf1" (for example
                # "v=spf10"), and keep looking for a valid record.
                warnings.append(
                    "A TXT record that resembles an SPF record was discarded "
                    "because its version section is not exactly "
                    f"{txt_prefix} (RFC 7208 section 4.5): {record}"
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
    except SPFRecordNotFound:
        raise
    except dns.exception.DNSException as error:
        raise SPFRecordNotFound(error, domain)

    # Per RFC 7208 § 3.3: any single TXT "character-string" should be ≤255 bytes.
    # Per RFC 7208 § 3.4: keep overall SPF record small enough for UDP (advise ~450B, warn at >512B).
    try:
        txt_strings = re.findall(r'"([^"]*)"', spf_record) if spf_record else []
        if txt_strings:
            for i, chunk in enumerate(txt_strings, 1):
                blen = len(chunk.encode("utf-8"))
                if blen > 255:
                    warnings.append(
                        f"SPF TXT string chunk #{i} for {domain} is {blen} bytes (>255). "
                        "Each individual TXT character-string should be ≤ 255 bytes (RFC 7208 § 3.3)."
                    )
            joined = "".join(txt_strings)
        else:
            joined = spf_record or ""
            blen = len(joined.encode("utf-8"))
            if blen > 255:
                warnings.append(
                    f"The SPF record for {domain} appears to be a single {blen}-byte string; "
                    "a single TXT character-string should be ≤ 255 bytes (RFC 7208 § 3.3). "
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
    except UnicodeError as size_check_error:
        # The size check is advisory only. A record with characters that
        # can't be encoded to UTF-8 (e.g. a lone surrogate) shouldn't break
        # the lookup, so skip the byte-size warnings for it. Any other error
        # here is unexpected and should surface rather than be swallowed.
        logger.debug(f"Skipped SPF size check for {domain}: {size_check_error}")

    spf_record = spf_record.replace('"', "")
    results: SPFQueryResults = {"record": spf_record, "warnings": warnings}

    return results


def parse_spf_record(
    record: str,
    domain: str,
    *,
    ignore_too_many_lookups: bool = False,
    parked: bool = False,
    seen: list | None = None,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    recursion: list[str] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
    _include_cache: dict[str, SPFRecordResults] | None = None,
) -> SPFRecordResults:
    """
    Parses an SPF record, including resolving ``a``, ``mx``, and ``include`` mechanisms

    Args:
        record (str): An SPF record
        domain (str): The domain that the SPF record came from
        parked (bool): Indicates if a domain has been parked
        ignore_too_many_lookups (bool): Do not raise an exception for too many lookups
        seen (list): A list of domains seen in past loops
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
        recursion (list): A list of domains used in recursion
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors
        syntax_error_marker (str): The marker for pointing out syntax errors

    Returns:
        dict: A ``dict`` with the following keys:
            - ``record`` - The SPF record string
            - ``dns_lookups`` - Number of DNS lookups required by the record
            - ``void_dns_lookups`` - The number of void DNS lookups
            - ``parsed`` - A ``dict`` of parsed SPF record values
            - ``warnings`` - A ``list`` of warnings

    Raises:
        :exc:`checkdmarc.spf.SPFIncludeLoop`
        :exc:`checkdmarc.spf.SPFRedirectLoop`
        :exc:`checkdmarc.spf.SPFSyntaxError`
        :exc:`checkdmarc.spf.SPFTooManyDNSLookups`
    """
    logger.debug(f"Parsing the SPF record on {domain}")
    domain = normalize_domain(domain)

    if seen is None:
        seen = [domain]
    if recursion is None:
        recursion = [domain]
    if _include_cache is None:
        # Maps an include target domain to its parse result, so that a
        # duplicate include can be counted again (RFC 7208 section 4.6.4
        # counts every evaluated term) without re-querying DNS.
        _include_cache = {}

    # Collapse RFC-style split TXT tokens only, then remove remaining quotes.
    # (Safer than blanket replace('" ', '') which could drop valid whitespace.)
    record = re.sub(r'"\s+"', " ", record).replace('"', "")

    warnings = []
    spf_syntax_checker = _SPFGrammar()

    if parked:
        correct_record = "v=spf1 -all"

        record = re.sub(r"\s+", " ", record).strip()

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

    grammar_result = spf_syntax_checker.parse(grammar_record)

    if not grammar_result.is_valid:
        pos = grammar_result.pos
        expecting: list[str] = [
            str(x).strip('"') for x in list(grammar_result.expecting)
        ]
        expecting_str = " or ".join(expecting)
        marked_record = record[:pos] + syntax_error_marker + record[pos:]
        raise SPFSyntaxError(
            f"{domain}: Expected {expecting_str} at position {pos} "
            f"(marked with {syntax_error_marker}) in: {marked_record}"
        )

    # RFC 7208 section 6.1: any redirect modifier is ignored when an all
    # mechanism is present anywhere in the record.
    all_present = any(
        ALL_TERM_REGEX.fullmatch(term) is not None for term in record.split()
    )

    parsed: ParsedSPFRecord = {
        "mechanisms": [],
        "redirect": None,
        "exp": None,
        "all": "neutral",
    }

    total_dns_lookups = 0
    total_void_dns_lookups = 0
    error = None
    exp_seen = False
    redirect_seen = False

    def _count_dns_lookups(count: int = 1) -> None:
        """Add DNS-querying terms to the total and enforce the 10-term limit.

        RFC 7208 section 4.6.4 caps the DNS-querying terms (include, a, mx,
        ptr, exists, and the redirect modifier) at 10 per evaluation. The cap
        is checked every time the total grows, no matter which term kind grew
        it, including nested include and redirect totals.
        """
        nonlocal total_dns_lookups
        total_dns_lookups += count
        if total_dns_lookups > 10:
            raise SPFTooManyDNSLookups(
                "Parsing the SPF record requires "
                f"{total_dns_lookups}/10 maximum DNS lookups "
                "(RFC 7208 § 4.6.4)",
                dns_lookups=total_dns_lookups,
            )

    def _count_void_dns_lookups(count: int = 1) -> None:
        """Add void DNS lookups to the total and enforce the limit of 2.

        RFC 7208 section 4.6.4: a term query that returns no records or
        NXDOMAIN is a void lookup, and implementations should allow at most
        two of them per evaluation.
        """
        nonlocal total_void_dns_lookups
        if count == 0:
            return
        total_void_dns_lookups += count
        if total_void_dns_lookups > 2:
            raise SPFTooManyVoidDNSLookups(
                "Parsing the SPF record has "
                f"{total_void_dns_lookups}/2 maximum void DNS lookups "
                "(RFC 7208 § 4.6.4)",
                void_dns_lookups=total_void_dns_lookups,
            )

    def _maybe_warn_domain_spec(name: str, value: str) -> None:
        """Warn when a literal domain cannot match the RFC 7208 grammar.

        A macro-free domain-spec must be a multi-label name whose last label
        is a valid toplabel (RFC 7208 section 12). Section 4.8 leaves the
        handling of an invalid domain up to the implementation, so this is a
        warning rather than an error.
        """
        labels = value.rstrip(".").split(".")
        if len(labels) < 2 or TOPLABEL_REGEX.fullmatch(labels[-1]) is None:
            warnings.append(
                f"The {name} value {value} is not a fully-qualified domain "
                "name ending in a valid top-level label (RFC 7208 § 12); "
                "receivers may treat it as a no-match (RFC 7208 § 4.8)."
            )

    def _split_domain_cidr(value: str, name: str) -> tuple[str, str | None, str | None]:
        """Split an a/mx value into (domain, IPv4 prefix, IPv6 prefix).

        dual-cidr-length per RFC 7208 section 12 is "/nn" (IPv4), "//nn"
        (IPv6), or "/nn//nn". Prefix lengths may not have leading zeros and
        must be at most 32 (IPv4) / 128 (IPv6).
        """
        domain_part, slash, cidr_rest = value.partition("/")
        if not slash:
            return domain_part, None, None
        cidr_match = DUAL_CIDR_REGEX.fullmatch(f"/{cidr_rest}")
        if cidr_match is None:
            raise SPFSyntaxError(
                f"{domain}: /{cidr_rest} is not a valid CIDR prefix length "
                f"for the {name} mechanism (RFC 7208 § 12)"
            )
        ip4_cidr = cidr_match.group(1)
        ip6_cidr = cidr_match.group(2)
        if ip4_cidr is not None and int(ip4_cidr) > 32:
            raise SPFSyntaxError(
                f"{domain}: The IPv4 prefix length /{ip4_cidr} in the {name} "
                "mechanism must be between 0 and 32 (RFC 7208 § 12)"
            )
        if ip6_cidr is not None and int(ip6_cidr) > 128:
            raise SPFSyntaxError(
                f"{domain}: The IPv6 prefix length //{ip6_cidr} in the "
                f"{name} mechanism must be between 0 and 128 (RFC 7208 § 12)"
            )
        return domain_part, ip4_cidr, ip6_cidr

    def _check_exp_value(exp_value: str) -> None:
        """Validate an exp value: macro syntax, or the TXT record behind it.

        RFC 7208 section 6.2: the explanation TXT lookup happens at
        evaluation time and never counts toward the DNS lookup limits.
        """
        if "%" in exp_value:
            # RFC 7208 section 7.2 allows the c, r, and t macro letters in
            # explanation text.
            _validate_spf_macros(
                exp_value,
                domain,
                syntax_error_marker,
                allow_exp_only_letters=True,
            )
            return
        try:
            exp_txt_records = get_txt_records(
                exp_value,
                nameservers=nameservers,
                timeout=timeout,
                retries=retries,
            )
            if len(exp_txt_records) == 0:
                warnings.append(f"No TXT records at exp value {exp_value}.")
            if len(exp_txt_records) > 1:
                warnings.append(f"Too many TXT records at exp value {exp_value}.")
        except DNSException as e:
            warnings.append(f"Failed to get TXT records at exp value {exp_value}: {e}")

    # Handle the text after the first all mechanism. Evaluation stops at the
    # first matching mechanism (RFC 7208 section 4.6.2), so terms after all
    # are never used and are not processed, counted, or listed; only an exp
    # modifier placed there is still honored.
    items_after_all: list[str] = AFTER_ALL_REGEX.findall(record)
    if len(items_after_all) > 0:
        # Modifier names are case-insensitive (RFC 7208 section 4.6.1), so
        # EXP= and Exp= must be recognized here too.
        if items_after_all[0][:4].lower() == "exp=":
            # RFC 7208 § 6.2 (exp modifier): The explanation string is
            # evaluated at runtime (after result == fail) and may contain
            # macros. It MUST NOT contribute to DNS lookup counting and
            # SHOULD NOT be resolved during static parsing.
            exp_value = items_after_all[0].split("=", 1)[1]
            if exp_value.strip() == "":
                raise SPFSyntaxError("The exp modifier is missing a value")
            exp_tokens = exp_value.split(" ")
            if len(exp_tokens) > 1:
                warnings.append("No text should exist after the exp modifier value.")
            exp_value = exp_tokens[0]
            parsed["exp"] = exp_value
            exp_seen = True
            _check_exp_value(exp_value)
        else:
            after_tokens = items_after_all[0].split()
            extra_all_tokens = [
                token
                for token in after_tokens
                if ALL_TERM_REGEX.fullmatch(token) is not None
            ]
            if extra_all_tokens:
                # RFC 7208 places no uniqueness constraint on all; the first
                # match simply wins (section 4.6.2).
                warnings.append(
                    "The record contains multiple all mechanisms; only the "
                    "first one is used (RFC 7208 § 4.6.2)."
                )
            if len(extra_all_tokens) < len(after_tokens):
                warnings.append(
                    "Any text after the all mechanism other than an exp modifier is ignored."
                )

    # Split the record into terms. Everything after the first all mechanism
    # was trimmed from grammar_record above.
    terms = grammar_record.split()
    if terms and terms[0].lower() == "v=spf1":
        terms = terms[1:]

    # First pass: per-term syntax validation against the RFC 7208 section 12
    # ABNF. Running every syntax check before any DNS work means a record
    # with a syntax error is rejected without network traffic.
    prepared_terms: list[tuple[str, str, str | None, str, str]] = []
    for term in terms:
        term_match = SPF_MECHANISM_REGEX.fullmatch(term)
        if term_match is None:
            raise SPFSyntaxError(f"{domain}: {term} is not a valid SPF term")
        qualifier, raw_name, sep, raw_value = term_match.groups()
        qualifier = qualifier or ""
        raw_value = raw_value or ""
        name = raw_name.lower()
        value = raw_value.lower()
        if sep == "=":
            # Modifiers. The RFC 7208 section 12 ABNF does not allow a
            # qualifier on a modifier.
            if qualifier != "":
                raise SPFSyntaxError(
                    f"{domain}: Qualifiers are not allowed on modifiers "
                    f"(RFC 7208 § 12): {term}"
                )
            if name == "redirect":
                if value == "":
                    raise SPFSyntaxError("The redirect modifier is missing a value")
                _validate_spf_macros(value, domain, syntax_error_marker)
                if "%" not in value:
                    _maybe_warn_domain_spec(name, value)
            elif name == "exp":
                if value == "":
                    raise SPFSyntaxError("The exp modifier is missing a value")
            else:
                # RFC 7208 section 6: "Unrecognized modifiers MUST be
                # ignored no matter where, or how often, they appear in a
                # record."
                warnings.append(
                    f"The unknown modifier {name} was ignored (RFC 7208 § 6)."
                )
                continue
        else:
            if name not in SPF_MECHANISM_NAMES:
                raise SPFSyntaxError(
                    f"{domain}: {raw_name} is not a valid SPF mechanism or modifier"
                )
            if name == "all":
                # all takes no value (RFC 7208 section 12)
                if sep is not None:
                    raise SPFSyntaxError(
                        f"{domain}: The all mechanism does not accept a "
                        f"value (RFC 7208 § 12): {term}"
                    )
            elif name in ("ip4", "ip6"):
                if sep != ":" or value == "":
                    raise SPFSyntaxError(f"{name} must have a value")
                if "%" in value:
                    raise SPFSyntaxError(
                        f"{domain}: SPF macros are not allowed in {name} "
                        f"mechanisms: {value}"
                    )
                if "/" in value:
                    prefix_length = value.split("/", 1)[1]
                    if CIDR_PREFIX_REGEX.fullmatch(prefix_length) is None:
                        # The ipaddress module tolerates leading zeros that
                        # the RFC 7208 section 12 ABNF forbids.
                        raise SPFSyntaxError(
                            f"{value} is not a valid {name} value. CIDR "
                            "prefix lengths must not have leading zeros "
                            "(RFC 7208 § 12)."
                        )
                if name == "ip4":
                    try:
                        if not isinstance(
                            ipaddress.ip_network(value, strict=False),
                            ipaddress.IPv4Network,
                        ):
                            raise SPFSyntaxError(
                                f"{value} is not a valid IPv4 value.\nLooks like IPv6."
                            )
                    except ValueError:
                        raise SPFSyntaxError(f"{value} is not a valid IPv4 value.")
                else:
                    try:
                        if not isinstance(
                            ipaddress.ip_network(value, strict=False),
                            ipaddress.IPv6Network,
                        ):
                            raise SPFSyntaxError(
                                f"{value} is not a valid IPv6 value.\nLooks like IPv4."
                            )
                    except ValueError:
                        raise SPFSyntaxError(f"{value} is not a valid IPv6 value.")
            elif name in ("include", "exists"):
                if sep != ":" or value == "":
                    raise SPFSyntaxError(f"{name} must have a value")
                _validate_spf_macros(value, domain, syntax_error_marker)
                if "%" not in value:
                    _maybe_warn_domain_spec(name, value)
            elif name in ("a", "mx"):
                if sep == ":" and value == "":
                    raise SPFSyntaxError(f"{name} must have a value after the :")
                if sep == "/":
                    # a/24 shorthand: the value is only a CIDR length
                    value = f"/{value}"
                _validate_spf_macros(value, domain, syntax_error_marker)
                if "%" not in value:
                    domain_part, _, _ = _split_domain_cidr(value, name)
                    if sep == ":" and domain_part == "":
                        raise SPFSyntaxError(f"{name} must have a value after the :")
                    if domain_part != "":
                        _maybe_warn_domain_spec(name, domain_part)
            elif name == "ptr":
                if sep == "/":
                    raise SPFSyntaxError(
                        f"{domain}: The ptr mechanism does not accept a "
                        f"CIDR prefix length (RFC 7208 § 12): {term}"
                    )
                if sep == ":" and value == "":
                    raise SPFSyntaxError(f"{name} must have a value after the :")
                _validate_spf_macros(value, domain, syntax_error_marker)
                if "%" not in value and value != "":
                    _maybe_warn_domain_spec(name, value)
        prepared_terms.append((qualifier, name, sep, value, raw_value))

    # Second pass: process the validated terms, resolving DNS where needed
    # and enforcing the RFC 7208 section 4.6.4 lookup limits after every
    # counted term.
    for qualifier, name, _sep, value, raw_value in prepared_terms:
        mechanism_dns_lookups = 0
        mechanism_void_dns_lookups = 0
        action = spf_qualifiers[qualifier]
        mechanism = name
        try:
            if mechanism == "all":
                # Only one all term can reach this loop: everything after
                # the first all mechanism was trimmed from grammar_record,
                # and extra all mechanisms are warned about there.
                parsed["all"] = action

            elif mechanism in ("ip4", "ip6"):
                ip_mechanism: SPFMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                }
                parsed["mechanisms"].append(ip_mechanism)

            elif mechanism == "a":
                _count_dns_lookups()
                mechanism_dns_lookups += 1
                if "%" in value:
                    macro_a_mechanism: SPFAMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                        "addresses": [],
                    }
                    parsed["mechanisms"].append(macro_a_mechanism)
                    continue
                domain_part, ip4_cidr, ip6_cidr = _split_domain_cidr(value, mechanism)
                # An a mechanism with no domain (a or a/24) means the
                # current domain (RFC 7208 section 5.3)
                value = domain_part or domain
                a_records = get_a_records(
                    value,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                    retries=retries,
                )
                if len(a_records) == 0:
                    # Do not pre-increment void counters here; let the outer
                    # handler for _SPFMissingRecords account for a single void lookup.
                    raise _SPFMissingRecords(
                        f"An a mechanism points to {value.lower()}, but that domain/subdomain does not have any A/AAAA records."
                    )
                addresses = []
                for address in a_records:
                    # The IPv4 prefix applies to A records and the IPv6
                    # prefix to AAAA records (RFC 7208 section 5.3)
                    ip_version = ipaddress.ip_address(address).version
                    if ip_version == 4 and ip4_cidr is not None:
                        addresses.append(f"{address}/{ip4_cidr}")
                    elif ip_version == 6 and ip6_cidr is not None:
                        addresses.append(f"{address}/{ip6_cidr}")
                    else:
                        addresses.append(address)
                a_mechanism: SPFAMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                    "dns_lookups": mechanism_dns_lookups,
                    "void_dns_lookups": mechanism_void_dns_lookups,
                    "addresses": addresses,
                }
                parsed["mechanisms"].append(a_mechanism)

            elif mechanism == "mx":
                _count_dns_lookups()
                mechanism_dns_lookups += 1
                if "%" in value:
                    macro_mx_mechanism: ParsedSPFMXMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                        "hosts": [],
                    }
                    parsed["mechanisms"].append(macro_mx_mechanism)
                    continue
                # RFC 7208 sections 5.4 and 12: the dual-cidr-length applies
                # to the addresses of the MX hosts, not to the MX query
                # name, so strip it before querying DNS.
                domain_part, _ip4_cidr, _ip6_cidr = _split_domain_cidr(value, mechanism)
                # Use the current domain if no value was provided
                value = domain_part or domain

                # Query the MX records
                mx_hosts = get_mx_records(
                    value,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                    retries=retries,
                )

                if len(mx_hosts) == 0:
                    # MX query resulted in no records; count a single void lookup
                    # in the outer warning handler to avoid double counting.
                    raise _SPFMissingRecords(
                        f"An mx mechanism points to {value.lower()}, "
                        "but that domain/subdomain does not have any MX records."
                    )

                # RFC 7208 § 4.6.4: evaluating an mx term must not require
                # more than 10 address lookups
                if len(mx_hosts) > 10:
                    raise SPFTooManyDNSLookups(
                        f"{value} has more than 10 MX records (RFC 7208 § 4.6.4)",
                        dns_lookups=len(mx_hosts),
                    )
                for host in mx_hosts:
                    hostname = host["hostname"]
                    try:
                        host_addresses = get_a_records(
                            hostname,
                            nameservers=nameservers,
                            resolver=resolver,
                            timeout=timeout,
                            retries=retries,
                        )
                    except DNSException as dnserror:
                        raise _SPFWarning(str(dnserror))
                    if len(host_addresses) == 0:
                        # RFC 7208 section 4.6.4 defines void lookups per
                        # term query; an MX host without address records is
                        # not a void lookup, so warn without counting one.
                        warnings.append(
                            f"The MX host {hostname} does not have any A/AAAA records."
                        )
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
                _count_dns_lookups()
                mechanism_dns_lookups += 1
                exists_mechanism: SPFDNSLookupMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                    "dns_lookups": mechanism_dns_lookups,
                    "void_dns_lookups": mechanism_void_dns_lookups,
                }
                parsed["mechanisms"].append(exists_mechanism)

            elif mechanism == "redirect":
                # RFC 7208 section 6: more than one redirect modifier is a
                # permanent error
                if redirect_seen:
                    raise SPFSyntaxError("Multiple redirect modifiers")
                redirect_seen = True
                if all_present:
                    # RFC 7208 section 6.1: "Any 'redirect' modifier MUST be
                    # ignored if there is an 'all' mechanism anywhere in the
                    # record." No DNS queries, no lookup counting.
                    warnings.append(
                        "The redirect modifier was ignored because the "
                        "record contains an all mechanism (RFC 7208 § 6.1)."
                    )
                    continue
                _count_dns_lookups()
                mechanism_dns_lookups += 1
                if "%" in value:
                    macro_redirect: SPFRedirect = {
                        "domain": domain,
                        "record": None,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                        "parsed": None,
                        "warnings": [],
                    }
                    parsed["redirect"] = macro_redirect
                    continue
                if value in recursion:
                    raise SPFRedirectLoop(f"Redirect loop: {value}")
                seen.append(value)
                try:
                    redirect_query = query_spf_record(
                        value,
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                        retries=retries,
                    )
                    redirect_record = redirect_query["record"]
                    redirected_spf = parse_spf_record(
                        redirect_record,
                        value,
                        seen=seen,
                        recursion=recursion + [value],
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                        retries=retries,
                        _include_cache=_include_cache,
                    )
                    parsed["all"] = redirected_spf["parsed"]["all"]
                    mechanism_dns_lookups += redirected_spf["dns_lookups"]
                    mechanism_void_dns_lookups += redirected_spf["void_dns_lookups"]
                    _count_dns_lookups(redirected_spf["dns_lookups"])
                    _count_void_dns_lookups(redirected_spf["void_dns_lookups"])
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
                except DNSException as redirect_err:
                    # Local name distinct from the outer ``error`` accumulator;
                    # ``except ... as <name>`` deletes the name when the block
                    # exits, which would shadow and unset the function-level
                    # ``error`` set at the top of parse_spf_record.
                    if isinstance(redirect_err, DNSExceptionNXDOMAIN):
                        # An NXDOMAIN answer for the redirect target is a
                        # void lookup (RFC 7208 § 4.6.4)
                        _count_void_dns_lookups()
                    raise _SPFWarning(str(redirect_err))

            elif mechanism == "exp":
                # RFC 7208 section 6: modifiers may appear anywhere in the
                # record, so honor exp even before the all mechanism. The
                # exp value keeps its original case because uppercase macro
                # letters change how macros expand (RFC 7208 section 7.3).
                if exp_seen:
                    raise SPFSyntaxError("Multiple exp values are not permitted")
                exp_seen = True
                parsed["exp"] = raw_value
                _check_exp_value(raw_value)

            elif mechanism == "include":
                if "%" in value:
                    _count_dns_lookups()
                    mechanism_dns_lookups += 1
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
                if value in recursion:
                    pointer = " -> ".join(recursion + [value])
                    raise SPFIncludeLoop(f"Include loop: {pointer}")
                if value in seen:
                    warnings.append(f"Duplicate include: {value}")
                    cached_include = _include_cache.get(value)
                    if cached_include is not None:
                        # RFC 7208 section 4.6.4: real evaluation counts
                        # every evaluated term, repeats included, so count
                        # the duplicate again using the earlier parse result
                        # instead of re-querying DNS.
                        _count_dns_lookups(1 + cached_include["dns_lookups"])
                        _count_void_dns_lookups(cached_include["void_dns_lookups"])
                        duplicate_include_mechanism: SPFIncludeMechanism = {
                            "action": action,
                            "mechanism": mechanism,
                            "value": value,
                            "dns_lookups": 1 + cached_include["dns_lookups"],
                            "void_dns_lookups": cached_include["void_dns_lookups"],
                            "record": cached_include["record"],
                            "parsed": cached_include["parsed"],
                            "warnings": cached_include["warnings"],
                        }
                        parsed["mechanisms"].append(duplicate_include_mechanism)
                        continue
                else:
                    seen.append(value)
                _count_dns_lookups()
                mechanism_dns_lookups += 1
                try:
                    include_query = query_spf_record(
                        value,
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                        retries=retries,
                    )
                except SPFRecordNotFound as missing_include:
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
                    _count_void_dns_lookups()
                    # RFC 7208 section 5.2: when the recursive evaluation of
                    # an include target returns "none" (no SPF record, or
                    # the domain does not exist), the whole record is a
                    # permanent error (permerror), not just a warning.
                    raise SPFRecordNotFound(
                        f"The include target {value} has no SPF record, "
                        "which RFC 7208 § 5.2 defines as a permanent error "
                        f"(permerror): {missing_include}",
                        value,
                    )
                include_record = include_query["record"]
                include = parse_spf_record(
                    include_record,
                    value,
                    seen=seen,
                    recursion=recursion + [value],
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                    retries=retries,
                    _include_cache=_include_cache,
                )
                _include_cache[value] = include
                _count_dns_lookups(include["dns_lookups"])
                _count_void_dns_lookups(include["void_dns_lookups"])
                mechanism_dns_lookups += include["dns_lookups"]
                mechanism_void_dns_lookups += include["void_dns_lookups"]
                include_mechanism: SPFIncludeMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                    "dns_lookups": mechanism_dns_lookups,
                    "void_dns_lookups": mechanism_void_dns_lookups,
                    "record": include_record,
                    "parsed": include["parsed"],
                    "warnings": include["warnings"],
                }
                parsed["mechanisms"].append(include_mechanism)
                warnings += include["warnings"]

            elif mechanism == "ptr":
                _count_dns_lookups()
                mechanism_dns_lookups += 1
                if "%" in value:
                    macro_ptr_mechanism: SPFDNSLookupMechanism = {
                        "action": action,
                        "mechanism": mechanism,
                        "value": value,
                        "dns_lookups": mechanism_dns_lookups,
                        "void_dns_lookups": mechanism_void_dns_lookups,
                    }
                    parsed["mechanisms"].append(macro_ptr_mechanism)
                    raise _SPFWarning(
                        "The ptr mechanism should not be used (RFC 7208 § 5.5)"
                    )
                if value == "":
                    value = domain
                a_records = get_a_records(
                    value,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                    retries=retries,
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
                    "The ptr mechanism should not be used (RFC 7208 § 5.5)"
                )

        except (SPFTooManyDNSLookups, SPFTooManyVoidDNSLookups) as e:
            if ignore_too_many_lookups:
                error = str(e)
            else:
                raise

        except (_SPFWarning, DNSException) as warning:
            if isinstance(warning, (_SPFMissingRecords, DNSExceptionNXDOMAIN)):
                mechanism_void_dns_lookups += 1

                failed_mechanism: SPFDNSLookupMechanism = {
                    "action": action,
                    "mechanism": mechanism,
                    "value": value,
                    "dns_lookups": 1,
                    "void_dns_lookups": 1,
                }
                parsed["mechanisms"].append(failed_mechanism)
                _count_void_dns_lookups()
            warnings.append(f"Error when processing {value or domain}: {warning!s}")

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
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> SPFRecordResults:
    """
    Retrieves and parses an SPF record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
        timeout (float): Number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: The parsed SPF record results

    Raises:
        :exc:`checkdmarc.spf.SPFRecordNotFound`
        :exc:`checkdmarc.spf.SPFIncludeLoop`
        :exc:`checkdmarc.spf.SPFRedirectLoop`
        :exc:`checkdmarc.spf.SPFSyntaxError`
        :exc:`checkdmarc.spf.SPFTooManyDNSLookups`
    """
    domain = normalize_domain(domain)
    query_result = query_spf_record(
        domain,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        retries=retries,
    )
    record = query_result["record"]
    query_warnings = query_result.get("warnings", [])

    parsed_record = parse_spf_record(
        record,
        domain,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        retries=retries,
    )
    parsed_record["record"] = record

    # Merge warnings from query_spf_record with warnings from parse_spf_record
    if query_warnings:
        parsed_record["warnings"] = query_warnings + parsed_record.get("warnings", [])

    return parsed_record


def check_spf(
    domain: str,
    *,
    parked: bool = False,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> dict:
    """
    Returns a dictionary with a parsed SPF record or an error.

    Args:
        domain (str): A domain name
        parked (bool): The domain is parked
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: A ``dict`` with the following keys:
            - ``record`` - The SPF record string
            - ``parsed`` - The parsed SPF record
            - ``dns_lookups`` - The number of DNS lookups
            - ``void_dns_lookups`` - The number of void DNS lookups
            - ``valid`` - True
            - ``warnings`` - A ``list`` of warnings

        If a DNS error occurs, the dictionary will have the following keys:
            - ``error`` - The error message
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
            retries=retries,
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
            retries=retries,
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
