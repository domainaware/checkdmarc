from __future__ import annotations

from typing import List

import re
from collections import OrderedDict

import dns
from checkdmarc.utils import get_soa_record

"""Functions for parsing DNS Start of Authority records"""

U32_MAX = 2**32 - 1


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


def parse_soa_string(rr: str) -> OrderedDict:
    """
    Parses a raw SOA record string and returns an OrderedDict with validated fields.
    """
    if not isinstance(rr, str) or not rr.strip():
        raise ValueError("SOA rrdata must be a non-empty string")

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

    return OrderedDict(
        [
            ("primary_nameserver", mname.rstrip(".")),
            ("rname_email_address", soa_rname_to_email(rname)),
            ("serial", check_u32("serial", serial)),
            ("refresh", check_u32("refresh", refresh)),
            ("retry", check_u32("retry", retry)),
            ("expire", check_u32("expire", expire)),
            ("minimum", check_u32("minimum", minimum)),
        ]
    )


def check_soa(
    domain: str,
    *,
    nameservers: List[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> OrderedDict:
    """
    Returns a dictionary of a domain's SOA record and a parsed version of the record or a dictionary with an
    the record and an error.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
    Returns:
        OrderedDict: A dictionary with the following keys:

              - ``record`` - The SOA record as a string
              - ``values``  - A parsed version of the SOA record

             If a parsing error occurs, the dictionary will have the following
             keys:

              - ``record`` - the SOA record
              - ``error``  - An error message
    """
    try:
        record = get_soa_record(
            domain, nameservers=nameservers, resolver=resolver, timeout=timeout
        )
        results = OrderedDict([("record", record)])
    except Exception as e:
        results = OrderedDict([("error", str(e))])
    try:
        results["values"] = parse_soa_string(record)
    except Exception as e:
        results["error"] = str(e)
    return results
