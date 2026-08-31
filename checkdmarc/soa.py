from __future__ import annotations

import re
from collections.abc import Sequence
from typing import TypedDict

import dns.resolver
from dns.nameserver import Nameserver

from checkdmarc._constants import DEFAULT_DNS_MAX_RETRIES, DEFAULT_DNS_TIMEOUT
from checkdmarc.utils import DNSException, get_soa_record

"""Functions for parsing DNS Start of Authority records"""

U32_MAX = 2**32 - 1

# RFC 5322 section 3.2.3 atext, one atom (no dots), and dot-atom-text
# (runs of atext separated by single dots). A local part that matches the
# dot-atom form needs no quoting; each decoded domain label must be a
# single atom.
_ATEXT_CLASS = r"[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]"
_ATOM_TEXT_REGEX = re.compile(rf"{_ATEXT_CLASS}+")
_DOT_ATOM_TEXT_REGEX = re.compile(rf"{_ATEXT_CLASS}+(?:\.{_ATEXT_CLASS}+)*")


class ParsedSOARecord(TypedDict):
    primary_nameserver: str
    rname_email_address: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


class SOARecordSuccessful(TypedDict):
    record: str
    values: ParsedSOARecord


class SOARecordError(TypedDict):
    record: str | None
    error: str


SOARecordResults = SOARecordSuccessful | SOARecordError


def soa_rname_to_email(rname: str) -> str:
    """
    Converts a SOA RNAME domain-style name into an RFC 822 email address.

    The first label of the RNAME is the local part of the address and the
    rest is the domain. The label boundary is the first *unescaped* dot,
    found by walking the string and consuming RFC 1035 section 5.1 escapes
    as we go: ``\\X`` stands for the literal character ``X`` (so ``\\.`` is
    a dot inside the local part and ``\\\\`` is a literal backslash), and
    ``\\DDD`` (exactly three decimal digits) stands for the byte with that
    value. A simple regex lookbehind gets ``a\\\\.b.example.com.`` wrong:
    the dot there follows an *escaped* backslash, so it is a real label
    boundary (local part ``a\\``, domain ``b.example.com``).

    A decoded local part that is not a plain dot-atom (for example one
    holding a space or ``@``) is returned as an RFC 5322 quoted-string, so
    the result is always a syntactically valid address; a local part
    holding a character no valid address can carry (a control character or
    a byte outside ASCII) raises ``ValueError``. Escapes in the domain
    labels are decoded the same way, and each label is validated on its
    own before the labels are joined with dots: a domain has no quoted
    form to fall back to, so a label that decodes to something an email
    domain label cannot carry — including a literal dot, which would
    silently move the label boundary — raises ``ValueError``.
    """
    s = rname.rstrip(".")
    # Decode the whole name into labels, not just the first one: the
    # domain labels can carry RFC 1035 escapes too (e.g. ex\097mple), and
    # copying them verbatim would leave DNS presentation syntax in the
    # returned address.
    labels: list[str] = []
    current_chars: list[str] = []
    i = 0
    while i < len(s):
        char = s[i]
        if char == "\\":
            digits = s[i + 1 : i + 4]
            if len(digits) == 3 and digits.isdigit():
                value = int(digits)
                if value > 255:
                    raise ValueError(
                        f"Invalid SOA RNAME (escape value over 255): {rname!r}"
                    )
                current_chars.append(chr(value))
                i += 4
            elif i + 1 < len(s):
                current_chars.append(s[i + 1])
                i += 2
            else:
                raise ValueError(f"Invalid SOA RNAME (trailing backslash): {rname!r}")
        elif char == ".":
            labels.append("".join(current_chars))
            current_chars = []
            i += 1
        else:
            current_chars.append(char)
            i += 1
    labels.append("".join(current_chars))
    if len(labels) < 2:
        raise ValueError(f"Invalid SOA RNAME (no unescaped dot): {rname!r}")
    local = labels[0]
    if not local:
        raise ValueError(f"Invalid SOA RNAME split: {rname!r}")
    # Validate each decoded domain label before joining them with dots:
    # an escape like ex\.ample decodes to ONE DNS label that contains a
    # literal dot, and joining it would silently move the label boundary
    # (host@ex.ample.com names a different mailbox domain). Each label
    # must be a single atom (RFC 5322 section 3.2.3) — nonempty, no dots,
    # and no characters an email domain cannot carry; unlike the local
    # part, a domain has no quoted form to fall back to.
    for label in labels[1:]:
        if _ATOM_TEXT_REGEX.fullmatch(label) is None:
            raise ValueError(
                f"Invalid SOA RNAME (a domain label does not decode to a "
                f"valid email domain label): {rname!r}"
            )
    domain = ".".join(labels[1:])
    if _DOT_ATOM_TEXT_REGEX.fullmatch(local) is None:
        # Decoded escapes can produce characters an unquoted local part
        # cannot carry (e.g. "\@" -> "@", "\032" -> a space). RFC 5322
        # section 3.2.4 allows them inside a quoted-string, with '"' and
        # "\" escaped as quoted-pairs; characters outside VCHAR and WSP
        # cannot appear in a valid address at all.
        for char in local:
            if char not in (" ", "\t") and not ("\x21" <= char <= "\x7e"):
                raise ValueError(
                    f"Invalid SOA RNAME (local part contains a character "
                    f"that cannot appear in an email address): {rname!r}"
                )
        escaped = local.replace("\\", "\\\\").replace('"', '\\"')
        local = f'"{escaped}"'
    return f"{local}@{domain}"


def parse_soa_string(rr: str) -> ParsedSOARecord:
    """
    Parses a raw SOA record string and returns a dict with validated fields.
    """
    if not isinstance(rr, str) or not rr.strip():
        raise ValueError("SOA rrdata must be a non-empty string.")

    tokens = rr.strip().split()
    if len(tokens) != 7:
        raise ValueError(
            f"SOA rrdata must have 7 fields, got {len(tokens)}: {tokens!r}"
        )

    mname, rname, serial, refresh, retry, expire, minimum = tokens

    def check_u32(name, val):
        try:
            n = int(val)
        except ValueError:
            raise ValueError(f"{name} must be an integer, got {val!r}")
        if not (0 <= n <= U32_MAX):
            raise ValueError(f"{name} out of range: {n}")
        return n

    soa_record: ParsedSOARecord = {
        "primary_nameserver": mname.rstrip("."),
        "rname_email_address": soa_rname_to_email(rname),
        "serial": check_u32("serial", serial),
        "refresh": check_u32("refresh", refresh),
        "retry": check_u32("retry", retry),
        "expire": check_u32("expire", expire),
        "minimum": check_u32("minimum", minimum),
    }

    return soa_record


def check_soa(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> SOARecordResults:
    """
    Returns a dictionary with a domain's SOA record and its parsed values, or a
    dictionary with the record (``None`` on a DNS error) and an error.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors
    Returns:
        dict: A dictionary with the following keys:

              - ``record`` - The SOA record as a string
              - ``values``  - A parsed version of the SOA record

             If a parsing error occurs, the dictionary will have the following
             keys:

              - ``record`` - the SOA record
              - ``error``  - An error message
    """
    try:
        record = get_soa_record(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )

    except DNSException as e:
        failure_results: SOARecordError = {"record": None, "error": str(e)}
        return failure_results
    try:
        results: SOARecordSuccessful = {
            "record": record,
            "values": parse_soa_string(record),
        }
        return results
    except ValueError as e:
        failure_results: SOARecordError = {"record": record, "error": str(e)}
        return failure_results
