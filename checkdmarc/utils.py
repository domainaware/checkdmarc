# -*- coding: utf-8 -*-
"""DNS utility functions"""

from __future__ import annotations

import logging
import dns
import dns.resolver
import re
import unicodedata
from collections import OrderedDict

import publicsuffixlist
from expiringdict import ExpiringDict

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

DNS_CACHE = ExpiringDict(max_len=200000, max_age_seconds=1800)

WSP_REGEX = r"[ \t]"
HTTPS_REGEX = r"(https:\/\/)([\w\-]+\.)+[\w-]+([\w\- ,.\/?%&=]*)"
MAILTO_REGEX_STRING = (
    r"^(mailto):([\w\-!#$%&'*+-/=?^_`{|}~]"
    r"[\w\-.!#$%&'*+-/=?^_`{|}~]*@[\w\-.]+)(!\w+)?"
)
ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF]")  # includes ZWSP, ZWNJ, ZWJ, BOM
MAILTO_REGEX = re.compile(MAILTO_REGEX_STRING, re.IGNORECASE)
PSL = publicsuffixlist.PublicSuffixList()


class DNSException(Exception):
    """Raised when a general DNS error occurs"""

    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class DNSExceptionNXDOMAIN(DNSException):
    """Raised when a NXDOMAIN DNS error (RCODE:3) occurs"""


def get_base_domain(domain: str) -> str:
    """
    Gets the base domain name for the given domain

    .. note::
        Results are based on a list of public domain suffixes at
        https://publicsuffix.org/list/public_suffix_list.dat.

    Args:
        domain (str): A domain or subdomain

    Returns:
        str: The base domain of the given domain

    """
    domain = normalize_domain(domain)
    return PSL.privatesuffix(domain) or domain


def normalize_domain(domain: str) -> str:
    """
    Normalize an input domain by removing zero-width characters and lowering it

    Args:
        domain (str): A domain or subdomain

    Returns:
        str: A normalized domain
    """
    # 1. Normalize Unicode (NFC form for consistency)
    domain = unicodedata.normalize("NFC", domain)
    # 2. Remove zero-width and similar hidden chars
    domain = ZERO_WIDTH_RE.sub("", domain)
    # 3. Lowercase for case-insensitivity (domains are case-insensitive)
    return domain.lower()


def query_dns(
    domain: str,
    record_type: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
    cache: ExpiringDict = None,
) -> list[str]:
    """
    Queries DNS

    Args:
        domain (str): The domain or subdomain to query about
        record_type (str): The record type to query for
        nameservers (list): A list of one or more nameservers to use
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): Sets the DNS timeout in seconds
        cache (ExpiringDict): Cache storage

    Returns:
        list: A list of answers
    """
    domain = normalize_domain(domain)
    record_type = record_type.upper()
    cache_key = f"{domain}_{record_type}"
    if cache is None:
        cache = DNS_CACHE
    if type(cache) is ExpiringDict:
        records = cache.get(cache_key)
        if records:
            return records
    if not resolver:
        resolver = dns.resolver.Resolver()
        timeout = float(timeout)
        if nameservers is not None:
            resolver.nameservers = nameservers
        resolver.timeout = timeout
        resolver.lifetime = timeout
    if record_type == "TXT":
        resource_records = list(
            map(
                lambda r: r.strings,
                resolver.resolve(domain, record_type, lifetime=timeout),
            )
        )
        _resource_record = [
            resource_record[0][:0].join(resource_record)
            for resource_record in resource_records
            if resource_record
        ]
        records = []
        for r in _resource_record:
            try:
                r = r.decode()
            except UnicodeDecodeError:
                r = "Undecodable characters"
            records.append(r)
    else:
        records = list(
            map(
                lambda r: r.to_text().replace('"', "").rstrip("."),
                resolver.resolve(domain, record_type, lifetime=timeout),
            )
        )
    if type(cache) is ExpiringDict:
        cache[cache_key] = records

    return records


def get_a_records(
    domain: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> list[str]:
    """
    Queries DNS for A and AAAA records

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        list: A sorted list of IPv4 and IPv6 addresses

    Raises:
        :exc:`checkdmarc.DNSException`
    """
    qtypes = ["A", "AAAA"]
    addresses = []
    for qt in qtypes:
        try:
            logging.debug(f"Getting {qt} records for {domain}")
            addresses += query_dns(
                domain, qt, nameservers=nameservers, resolver=resolver, timeout=timeout
            )
        except dns.resolver.NXDOMAIN:
            raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            # Sometimes a domain will only have A or AAAA records, but not both
            pass
        except Exception as error:
            raise DNSException(error)

    addresses = sorted(addresses)
    return addresses


def get_reverse_dns(
    ip_address: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> list[str]:
    """
    Queries for an IP addresses reverse DNS hostname(s)

    Args:
        ip_address (str): An IPv4 or IPv6 address
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        list: A list of reverse DNS hostnames

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    try:
        name = str(dns.reversename.from_address(ip_address))
        logging.debug(f"Getting PTR records for {ip_address}")
        hostnames = query_dns(
            name, "PTR", nameservers=nameservers, resolver=resolver, timeout=timeout
        )
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as error:
        raise DNSException(error)

    return hostnames


def get_txt_records(
    domain: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> list[str]:
    """
    Queries DNS for TXT records

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        list: A list of TXT records

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    try:
        records = query_dns(
            domain, "TXT", nameservers=nameservers, resolver=resolver, timeout=timeout
        )
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        raise DNSException(f"The domain {domain} does not have any TXT records")
    except Exception as error:
        raise DNSException(error)

    return records


def get_soa_record(
    domain: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> list[str]:
    """
    Queries DNS for an SOA record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        str: An SOA record

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    try:
        record = query_dns(
            domain, "SOA", nameservers=nameservers, resolver=resolver, timeout=timeout
        )[0]
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        raise DNSException(f"The domain {domain} does not have an SOA record")
    except Exception as error:
        raise DNSException(error)

    return record


def get_nameservers(
    domain: str,
    *,
    approved_nameservers: list[str] = None,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> dict:
    """
    Gets a list of nameservers for a given domain

    Args:
        domain (str): A domain name
        approved_nameservers (list): A list of approved nameserver substrings
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS

    Returns:
        OrderedDict: A dictionary with the following keys:
                     - ``hostnames`` - A list of nameserver hostnames
                     - ``warnings``  - A list of warnings
    """
    logging.debug(f"Getting NS records on {domain}")
    warnings = []

    ns_records = []
    try:
        ns_records = query_dns(
            domain, "NS", nameservers=nameservers, resolver=resolver, timeout=timeout
        )
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        pass
    except Exception as error:
        raise DNSException(error)

    if approved_nameservers:
        approved_nameservers = list(map(lambda h: h.lower(), approved_nameservers))
    for nameserver in ns_records:
        if approved_nameservers:
            approved = False
            for approved_nameserver in approved_nameservers:
                if approved_nameserver in nameserver.lower():
                    approved = True
                    break
            if not approved:
                warnings.append(f"Unapproved nameserver: {nameserver}")

    return OrderedDict([("hostnames", ns_records), ("warnings", warnings)])


def get_mx_records(
    domain: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> list[OrderedDict]:
    """
    Queries DNS for a list of Mail Exchange hosts

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        list: A list of ``OrderedDicts``; each containing a ``preference``
                        integer and a ``hostname``

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    hosts = []
    try:
        logging.debug(f"Checking for MX records on {domain}")
        answers = query_dns(
            domain, "MX", nameservers=nameservers, resolver=resolver, timeout=timeout
        )
        if answers == ["0 "]:
            logging.debug('"No Service" MX record found')
            return []
        for record in answers:
            record = record.split(" ")
            preference = int(record[0])
            hostname = record[1].rstrip(".").strip().lower()
            hosts.append(
                OrderedDict([("preference", preference), ("hostname", hostname)])
            )
        hosts = sorted(hosts, key=lambda h: (h["preference"], h["hostname"]))
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        pass
    except Exception as error:
        raise DNSException(error)
    return hosts
