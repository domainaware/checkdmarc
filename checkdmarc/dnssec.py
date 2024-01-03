# -*- coding: utf-8 -*-
"""DNSSEC tests"""

from __future__ import annotations

import logging

import dns
import dns.dnssec


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


def test_dnssec(domain: str, nameservers: list[str] = None,
                timeout: float = 2.0) -> bool:
    """
    Check for DNSSEC on the given domain

    Args:
        domain (str): The domain to check
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds

    Returns:
        bool: DNSSEC status
    """
    if nameservers is None:
        nameservers = dns.resolver.Resolver().nameservers

    request = dns.message.make_query(domain,
                                     dns.rdatatype.DNSKEY,
                                     want_dnssec=True)
    for nameserver in nameservers:
        try:
            response = dns.query.udp(request, nameserver, timeout=timeout)
            if response is not None:
                answer = response.answer
                if len(answer) != 2:
                    return False
                rrset = answer[0]
                rrsig = answer[1]
                name = dns.name.from_text(f'{domain}.')
                dns.dnssec.validate(rrset, rrsig, {name: rrset})
                return True
        except Exception as e:
            logging.debug(f"DNSSEC query error: {e}")

    return False


def get_tlsa_records(hostname: str, nameservers: list[str] = None,
              timeout: float = 2.0) -> bool:
    """
    Check for TLSA records for SMTP on the given hostname

    Args:
        hostname (str): The domain to check
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds

    Returns:
        bool: DNSSEC status
    """
    if nameservers is None:
        nameservers = dns.resolver.Resolver().nameservers

    request = dns.message.make_query(f"_25._tcp.{hostname}",
                                     dns.rdatatype.TLSA,
                                     want_dnssec=True)
    for nameserver in nameservers:
        try:
            response = dns.query.udp(request, nameserver, timeout=timeout)
            if response is not None:
                answer = response.answer
                if len(answer) != 2:
                    return False
                rrset = answer[0]
                rrsig = answer[1]
                name = dns.name.from_text(f'{hostname}.')
                dns.dnssec.validate(rrset, rrsig, {name: rrset})
                tlsa_records = rrset.items.keys()
                return tlsa_records
        except Exception as e:
            logging.debug(f"TLSA query error: {e}")
