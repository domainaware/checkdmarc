from __future__ import annotations

import re
from typing import Optional, TypedDict, Union
from collections.abc import Sequence

import dns.resolver
from dns.nameserver import Nameserver

from checkdmarc.utils import get_soa_record

"""Functions for parsing DNS Start of Authority records"""

U32_MAX = 2**32 - 1


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
    record: Union[str, None]
    error: str


SOARecordResults = Union[SOARecordSuccessful, SOARecordError]


def soa_rname_to_email(rname: str) -> str:
    """
    Converts a SOA RNAME domain-style name into an RFC 822 email address.
    """
    s = rname.rstrip(".")
    m = re.search(r"(?<!\\)\.", s)
    if not m:
        raise ValueError(f"Invalid SOA RNAME (no unescaped dot): {rname!r}")
    local = s[: m.start()].replace(r"\.", ".")
    domain = s[m.start() + 1 :]
    if not local or not domain:
        raise ValueError(f"Invalid SOA RNAME split: {rname!r}")
    return f"{local}@{domain}"


def parse_soa_string(rr: str) -> ParsedSOARecord:
    """
    Parses a raw SOA record string and returns an dict with validated fields.
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
        "retry": check_u32("refresh", retry),
        "expire": check_u32("refresh", expire),
        "minimum": check_u32("refresh", minimum),
    }

    return soa_record


def check_soa(
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> SOARecordResults:
    """
    Returns a dictionary of a domain's SOA record and a parsed version of the record or a dictionary with an
    the record and an error.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout
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
            timeout_retries=timeout_retries,
        )

    except Exception as e:
        failure_results: SOARecordError = {"record": None, "error": str(e)}
        return failure_results
    try:
        results: SOARecordSuccessful = {
            "record": record,
            "values": parse_soa_string(record),
        }
        return results
    except Exception as e:
        failure_results: SOARecordError = {"record": record, "error": str(e)}
        return failure_results
