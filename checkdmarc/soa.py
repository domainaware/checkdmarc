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

# RFC 5322 section 3.2.3 dot-atom-text: runs of atext separated by single
# dots. A local part that matches this needs no quoting.
_DOT_ATOM_TEXT_REGEX = re.compile(
    r"[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*"
)


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
    a byte outside ASCII) raises ``ValueError``.
    """
    s = rname.rstrip(".")
    local_chars: list[str] = []
    domain: str | None = None
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
                local_chars.append(chr(value))
                i += 4
            elif i + 1 < len(s):
                local_chars.append(s[i + 1])
                i += 2
            else:
                raise ValueError(f"Invalid SOA RNAME (trailing backslash): {rname!r}")
        elif char == ".":
            domain = s[i + 1 :]
            break
        else:
            local_chars.append(char)
            i += 1
    if domain is None:
        raise ValueError(f"Invalid SOA RNAME (no unescaped dot): {rname!r}")
    local = "".join(local_chars)
    if not local or not domain:
        raise ValueError(f"Invalid SOA RNAME split: {rname!r}")
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
