# -*- coding: utf-8 -*-
"""DNSSEC tests"""

from __future__ import annotations

import logging
from collections.abc import Sequence

import dns.dnssec
import dns.exception
import dns.message
import dns.query
import dns.resolver
import dns.rdatatype
import dns.name
import dns.rrset
from dns.nameserver import Nameserver
from dns.rdatatype import RdataType
from expiringdict import ExpiringDict

from checkdmarc._constants import (
    DEFAULT_DNS_TIMEOUT,
    DNSSEC_CACHE_MAX_AGE_SECONDS,
    DNSSEC_CACHE_MAX_LEN,
)
from checkdmarc.utils import get_base_domain, normalize_domain

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

DNSSEC_CACHE = ExpiringDict(
    max_len=DNSSEC_CACHE_MAX_LEN, max_age_seconds=DNSSEC_CACHE_MAX_AGE_SECONDS
)
DNSKEY_CACHE = ExpiringDict(
    max_len=DNSSEC_CACHE_MAX_LEN, max_age_seconds=DNSSEC_CACHE_MAX_AGE_SECONDS
)
TLSA_CACHE = ExpiringDict(
    max_len=DNSSEC_CACHE_MAX_LEN, max_age_seconds=DNSSEC_CACHE_MAX_AGE_SECONDS
)


def _find_record_and_signature(
    answer: Sequence[dns.rrset.RRset],
    name: dns.name.Name,
    rdatatype: RdataType,
) -> tuple[dns.rrset.RRset | None, dns.rrset.RRset | None]:
    """
    Pick the record set of the requested type out of a DNS answer, along with
    the signature that covers it

    An answer can hold more than one record set. A name that points at another
    name, for example, returns every link in that chain, and each link may sit
    in a different zone with a different signature (or no signature at all).
    Picking records out by name and type keeps a record from being paired with
    a signature that belongs to something else, or with no signature at all.

    Args:
        answer (Sequence): The answer section of a DNS response
        name (dns.name.Name): The name that was queried
        rdatatype (RdataType): The record type that was queried

    Returns:
        tuple: The matching record set and its signature, either of which is
        ``None`` when the answer does not contain it
    """
    rrset = None
    rrsig = None
    for rset in answer:
        if rset.name != name:
            continue
        if rset.rdtype == RdataType.RRSIG:
            if rset.covers == rdatatype:
                rrsig = rset
        elif rset.rdtype == rdatatype:
            rrset = rset

    return rrset, rrsig


def get_dnskey(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    cache: ExpiringDict | None = None,
) -> dict | None:
    """
    Get a DNSKEY RRSet on the given domain

    Args:
        domain (str): The domain to check
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds
        cache (ExpiringDict): A cache

    Returns:
        A DNSKEY dictionary if a DNSKEY is found
    """
    if nameservers is None:
        nameservers = dns.resolver.Resolver().nameservers
    if cache is None:
        cache = DNSKEY_CACHE

    domain = normalize_domain(domain)

    if domain in cache:
        cached_result = cache[domain]
        if isinstance(cached_result, dict):
            return cached_result

    logging.debug(f"Checking for DNSKEY records at {domain}")
    request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
    for nameserver in nameservers:
        try:
            response = dns.query.tcp(request, str(nameserver), timeout=timeout)
            if response is not None:
                name = dns.name.from_text(domain)
                rrset, _ = _find_record_and_signature(
                    response.answer, name, RdataType.DNSKEY
                )
                # An answer that holds no DNSKEY for this name means the same
                # thing as an empty answer: the name is not the apex of a
                # signed zone. A name that points at another name answers with
                # that chain rather than with a key, so check the base domain.
                if rrset is None:
                    logging.debug(f"No DNSKEY records found at {domain}")
                    base_domain = get_base_domain(domain)
                    if domain != base_domain:
                        return get_dnskey(
                            base_domain,
                            nameservers=nameservers,
                            timeout=timeout,
                            cache=cache,
                        )
                    cache[domain] = None
                    return None
                key = {name: rrset}
                cache[domain] = key
                return key
        except (dns.exception.DNSException, OSError, EOFError) as e:
            cache[domain] = None
            logging.debug(f"DNSKEY query error: {e}")


def test_dnssec(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    cache: ExpiringDict | None = None,
) -> bool:
    """
    Check for DNSSEC on the given domain

    Args:
        domain (str): The domain to check
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds
        cache (ExpiringDict): Cache

    Returns:
        bool: DNSSEC status
    """
    if nameservers is None:
        nameservers = dns.resolver.Resolver().nameservers
    if cache is None:
        cache = DNSSEC_CACHE

    if domain in cache:
        cached_result = cache[domain]
        if isinstance(cached_result, bool):
            return cached_result

    key = get_dnskey(domain, nameservers=nameservers, timeout=timeout)
    if key is None:
        return False
    rdatatypes = [
        dns.rdatatype.DNSKEY,
        dns.rdatatype.MX,
        dns.rdatatype.A,
        dns.rdatatype.NS,
        dns.rdatatype.CNAME,
    ]
    name = dns.name.from_text(domain)
    for rdatatype in rdatatypes:
        request = dns.message.make_query(domain, rdatatype, want_dnssec=True)
        for nameserver in nameservers:
            try:
                response = dns.query.tcp(request, str(nameserver), timeout=timeout)
                if response is not None:
                    rrset, rrsig = _find_record_and_signature(
                        response.answer, name, rdatatype
                    )
                    if rrset is None or rrsig is None:
                        continue
                    dns.dnssec.validate(rrset, rrsig, key)
                    logging.debug(f"Found a signed {rdatatype.name} record")
                    cache[domain] = True
                    return True
            except (dns.exception.DNSException, OSError, EOFError) as e:
                logging.debug(f"DNSSEC query error: {e}")

    cache[domain] = False
    return False


def get_tlsa_records(
    hostname: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    port: int = 25,
    protocol: str = "tcp",
    cache: ExpiringDict | None = None,
) -> list[str]:
    """
    Checks for TLSA records on the given hostname

    Args:
        hostname (str): The domain to check
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds
        port (int): The port
        protocol (str): The protocol
        cache (ExpiringDict): A cache

    Returns:
        list: A list of TLSA records
    """
    if nameservers is None:
        nameservers = dns.resolver.Resolver().nameservers
    protocol = protocol.lower()
    if cache is None:
        cache = TLSA_CACHE

    query_hostname = f"_{port}._{protocol}.{hostname}"
    if query_hostname in cache:
        cached_results = cache[query_hostname]
        if isinstance(cached_results, list):
            return cached_results
    tlsa_records: list[str] = []
    logging.debug(f"Checking for TLSA records at {query_hostname}")
    request = dns.message.make_query(
        query_hostname, dns.rdatatype.TLSA, want_dnssec=True
    )
    if len(nameservers) == 0:
        raise ValueError("At lease one nameserver is required")
    for nameserver in nameservers:
        try:
            response = dns.query.tcp(request, str(nameserver), timeout=timeout)
            if response is not None:
                rrset, rrsig = _find_record_and_signature(
                    response.answer,
                    dns.name.from_text(query_hostname),
                    RdataType.TLSA,
                )
                if rrset is None or rrsig is None:
                    return tlsa_records
                dnskey = get_dnskey(
                    domain=hostname, nameservers=nameservers, timeout=timeout
                )
                if dnskey is None:
                    logging.debug(
                        f"Found TLSA records at {hostname} but not "
                        f"a DNSKEY record to verify them"
                    )
                    return tlsa_records
                dns.dnssec.validate(rrset, rrsig, dnskey)
                tlsa_records = list(map(lambda x: str(x), list(rrset.items.keys())))
                cache[query_hostname] = tlsa_records
                return tlsa_records
        except (dns.exception.DNSException, OSError, EOFError) as e:
            logging.debug(f"TLSA query error: {e}")
            return tlsa_records
    return tlsa_records
