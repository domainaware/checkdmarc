"""DNS utility functions"""

from __future__ import annotations

import logging
import platform
import dns
import re
from collections import OrderedDict

import publicsuffixlist
from expiringdict import ExpiringDict

from checkdmarc.smtp import test_tls, test_starttls, SMTPError

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
HTTPS_REGEX = (
    r"https://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F]"
    r"[0-9a-fA-F]))+"
)
MAILTO_REGEX_STRING = (
    r"^(mailto):([\w\-!#$%&'*+-/=?^_`{|}~]"
    r"[\w\-.!#$%&'*+-/=?^_`{|}~]*@[\w\-.]+)(!\w+)?"
)

MAILTO_REGEX = re.compile(MAILTO_REGEX_STRING, re.IGNORECASE)


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

    psl = publicsuffixlist.PublicSuffixList()
    domain = domain.lower()
    return psl.privatesuffix(domain) or domain


def _query_dns(domain: str, record_type: str, nameservers: list[str] = None,
               resolver: dns.resolver.Resolver = None,
               timeout: float = 2.0, cache: ExpiringDict = None) -> list[str]:
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
    domain = domain.lower()
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
        resource_records = list(map(
            lambda r: r.strings,
            resolver.resolve(domain, record_type, lifetime=timeout)))
        _resource_record = [
            resource_record[0][:0].join(resource_record)
            for resource_record in resource_records if resource_record]
        records = [r.decode() for r in _resource_record]
    else:
        records = list(map(
            lambda r: r.to_text().replace('"', '').rstrip("."),
            resolver.resolve(domain, record_type, lifetime=timeout)))
    if type(cache) is ExpiringDict:
        cache[cache_key] = records

    return records


def _get_nameservers(domain: str, nameservers: list[str] = None,
                     resolver: dns.resolver.Resolver = None,
                     timeout: float = 2.0) -> list[str]:
    """
    Queries DNS for a list of nameservers

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        list: A list of hostnames

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    answers = []
    try:

        answers = _query_dns(domain, "NS", nameservers=nameservers,
                             resolver=resolver, timeout=timeout)
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(
            f"The domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        pass
    except Exception as error:
        raise DNSException(error)
    return answers


def _get_mx_hosts(domain: str, nameservers: list[str] = None,
                  resolver: dns.resolver.Resolver = None,
                  timeout: float = 2.0) -> list[OrderedDict]:
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
        answers = _query_dns(domain, "MX", nameservers=nameservers,
                             resolver=resolver, timeout=timeout)
        if answers == ['0 ']:
            logging.debug("\"No Service\" MX record found")
            return []
        for record in answers:
            record = record.split(" ")
            preference = int(record[0])
            hostname = record[1].rstrip(".").strip().lower()
            hosts.append(OrderedDict(
                [("preference", preference), ("hostname", hostname)]))
        hosts = sorted(hosts, key=lambda h: (h["preference"], h["hostname"]))
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(
            f"The domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        pass
    except Exception as error:
        raise DNSException(error)
    return hosts


def _get_a_records(domain: str, nameservers: list[str] = None,
                   resolver: dns.resolver.Resolver = None,
                   timeout: float = 2.0) -> list[str]:
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
            addresses += _query_dns(domain, qt, nameservers=nameservers,
                                    resolver=resolver, timeout=timeout)
        except dns.resolver.NXDOMAIN:
            raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist")
        except dns.resolver.NoAnswer:
            # Sometimes a domain will only have A or AAAA records, but not both
            pass
        except Exception as error:
            raise DNSException(error)

    addresses = sorted(addresses)
    return addresses


def _get_reverse_dns(ip_address: str, nameservers: list[str] = None,
                     resolver: dns.resolver.Resolver = None,
                     timeout: float = 2.0) -> list[str]:
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
        hostnames = _query_dns(name, "PTR", nameservers=nameservers,
                               resolver=resolver, timeout=timeout)
    except dns.resolver.NXDOMAIN:
        return []
    except Exception as error:
        raise DNSException(error)

    return hostnames


def _get_txt_records(domain: str, nameservers: list[str] = None,
                     resolver: dns.resolver.Resolver = None,
                     timeout: float = 2.0) -> list[str]:
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
        records = _query_dns(domain, "TXT", nameservers=nameservers,
                             resolver=resolver, timeout=timeout)
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist")
    except dns.resolver.NoAnswer:
        raise DNSException(
            f"The domain {domain} does not have any TXT records")
    except Exception as error:
        raise DNSException(error)

    return records


def get_mx_hosts(domain: str, skip_tls: bool = False,
                 approved_hostnames: list[str] = None,
                 parked: bool = False,
                 nameservers: list[str] = None,
                 resolver: dns.resolver.Resolver = None,
                 timeout: float = 2.0):
    """
    Gets MX hostname and their addresses

    Args:
        domain (str): A domain name
        skip_tls (bool): Skip STARTTLS testing
        approved_hostnames (list): A list of approved MX hostname substrings
        parked (bool): Indicates that the domains are parked
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``hosts`` - A ``list`` of ``OrderedDict`` with keys of

                       - ``hostname`` - A hostname
                       - ``addresses`` - A ``list`` of IP addresses

                     - ``warnings`` - A ``list`` of MX resolution warnings

    """
    hosts = []
    warnings = []
    hostnames = set()
    dupe_hostnames = set()
    mx_records = _get_mx_hosts(domain, nameservers=nameservers,
                               resolver=resolver, timeout=timeout)
    for record in mx_records:
        hosts.append(OrderedDict([("preference", record["preference"]),
                                  ("hostname", record["hostname"].lower()),
                                  ("addresses", [])]))
    if parked and len(hosts) > 0:
        warnings.append("MX records found on parked domains")
    elif not parked and len(hosts) == 0:
        warnings.append("No MX records found. Is the domain parked?")

    if approved_hostnames:
        approved_hostnames = list(map(lambda h: h.lower(),
                                      approved_hostnames))
    for host in hosts:
        hostname = host["hostname"]
        if hostname in hostnames:
            if hostname not in dupe_hostnames:
                warnings.append(
                    f"Hostname {hostname} is listed in multiple MX records")
                dupe_hostnames.add(hostname)
            continue
        hostnames.add(hostname)
        if approved_hostnames:
            approved = False
            for approved_hostname in approved_hostnames:
                if approved_hostname in hostname:
                    approved = True
                    break
            if not approved:
                warnings.append(f"Unapproved MX hostname: {hostname}")

        try:
            host["addresses"] = []
            host["addresses"] = _get_a_records(hostname,
                                               nameservers=nameservers,
                                               resolver=resolver,
                                               timeout=timeout)
            if len(host["addresses"]) == 0:
                warnings.append(
                    f"{hostname} does not have any A or AAAA DNS records")
        except Exception as e:
            if hostname.lower().endswith(".msv1.invalid"):
                warnings.append(f"{e}. Consider using a TXT record to "
                                " validate domain ownership in Office 365 "
                                "instead.")
            else:
                warnings.append(e.__str__())

        for address in host["addresses"]:
            try:
                reverse_hostnames = _get_reverse_dns(address,
                                                     nameservers=nameservers,
                                                     resolver=resolver,
                                                     timeout=timeout)
            except DNSException:
                reverse_hostnames = []
            if len(reverse_hostnames) == 0:
                warnings.append(
                    f"{address} does not have any reverse DNS (PTR) "
                    "records")
            for hostname in reverse_hostnames:
                try:
                    _addresses = _get_a_records(hostname, resolver=resolver)
                except DNSException as warning:
                    warnings.append(str(warning))
                    _addresses = []
                if address not in _addresses:
                    warnings.append(f"The reverse DNS of "
                                    f"{address} is {hostname}, but "
                                    "the A/AAAA DNS records for "
                                    f"{hostname} do not resolve to "
                                    f"{address}")
        if not skip_tls and platform.system() == "Windows":
            logging.warning("Testing TLS is not supported on Windows")
            skip_tls = True
        if skip_tls:
            logging.debug(f"Skipping TLS/SSL tests on {hostname}")
        else:
            try:
                starttls = test_starttls(hostname)
                if not starttls:
                    warnings.append(f"STARTTLS is not supported on {hostname}")
                tls = test_tls(hostname)

                if not tls:
                    warnings.append(f"SSL/TLS is not supported on {hostname}")
                host["tls"] = tls
                host["starttls"] = starttls
            except DNSException as warning:
                warnings.append(str(warning))
                tls = False
                starttls = False
                host["tls"] = tls
                host["starttls"] = starttls
            except SMTPError as error:
                tls = False
                starttls = False
                warnings.append(f"{hostname}: {error}")

                host["tls"] = tls
                host["starttls"] = starttls

    return OrderedDict([("hosts", hosts), ("warnings", warnings)])


def get_nameservers(domain: str, approved_nameservers: list[str] = None,
                    nameservers: list[str] = None,
                    resolver: dns.resolver.Resolver = None,
                    timeout: float = 2.0) -> dict:
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

    ns_records = _get_nameservers(domain, nameservers=nameservers,
                                  resolver=resolver, timeout=timeout)

    if approved_nameservers:
        approved_nameservers = list(map(lambda h: h.lower(),
                                        approved_nameservers))
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
