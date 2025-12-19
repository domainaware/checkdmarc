# -*- coding: utf-8 -*-
"""DNSSEC tests"""

from __future__ import annotations

import logging
from typing import Optional
from collections.abc import Sequence

import dns.dnssec
import dns.message
import dns.query
import dns.resolver
import dns.rdatatype
import dns.name
from dns.nameserver import Nameserver
from dns.rdatatype import RdataType
from expiringdict import ExpiringDict

from checkdmarc._constants import DNSSEC_CACHE_MAX_AGE_SECONDS, DNSSEC_CACHE_MAX_LEN
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


def get_dnskey(
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    timeout: float = 2.0,
    cache: Optional[ExpiringDict] = None,
) -> Optional[dict]:
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
                answer = response.answer
                if len(answer) == 0:
                    logging.debug(f"No DNSKEY records found at {domain}")
                    base_domain = get_base_domain(domain)
                    if domain != base_domain:
                        return get_dnskey(
                            base_domain, nameservers=nameservers, timeout=timeout
                        )
                    cache[domain] = None
                    return None
                rrset = None
                for rset in answer:
                    if rset.rdtype != RdataType.RRSIG:
                        rrset = rset
                        break
                name = dns.name.from_text(f"{domain}.")
                key = {name: rrset}
                cache[domain] = key
                return key
        except Exception as e:
            cache[domain] = None
            logging.debug(f"DNSKEY query error: {e}")


def test_dnssec(
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    timeout: float = 2.0,
    cache: Optional[ExpiringDict] = None,
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
    for rdatatype in rdatatypes:
        request = dns.message.make_query(domain, rdatatype, want_dnssec=True)
        for nameserver in nameservers:
            try:
                response = dns.query.tcp(request, str(nameserver), timeout=timeout)
                if response is not None:
                    answer = response.answer
                    if len(answer) != 2:
                        continue
                    rrset = None
                    rrsig = None
                    for rset in answer:
                        if rset.rdtype == RdataType.RRSIG:
                            rrsig = rset
                        else:
                            rrset = rset
                    dns.dnssec.validate(rrset, rrsig, key)
                    logging.debug(f"Found a signed {rdatatype.name} record")
                    cache[domain] = True
                    return True
            except Exception as e:
                logging.debug(f"DNSSEC query error: {e}")

    cache[domain] = False
    return False


def get_tlsa_records(
    hostname: str,
    *,
    nameservers: Sequence[str | Nameserver],
    timeout: float = 2.0,
    port: int = 25,
    protocol: str = "tcp",
    cache: Optional[ExpiringDict] = None,
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
    if isinstance(cache, ExpiringDict):
        if query_hostname in TLSA_CACHE:
            cached_results = TLSA_CACHE[query_hostname]
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
                answer = response.answer
                if len(answer) != 2:
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
                rrset = None
                rrsig = None
                for rset in answer:
                    if rset.rdtype == RdataType.RRSIG:
                        rrsig = rset
                    else:
                        rrset = rset
                if rrset is not None:
                    dns.dnssec.validate(rrset, rrsig, dnskey)
                    tlsa_records = list(map(lambda x: str(x), list(rrset.items.keys())))
                    cache[query_hostname] = tlsa_records
                return tlsa_records
        except Exception as e:
            logging.debug(f"TLSA query error: {e}")
            return tlsa_records
    return tlsa_records
