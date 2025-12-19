# -*- coding: utf-8 -*-

"""Validates and parses email-related DNS records"""

from __future__ import annotations

import json
import logging
from csv import DictWriter
from io import StringIO
from time import sleep
from typing import Optional, Union
from collections.abc import Sequence

import dns.resolver
from dns.nameserver import Nameserver

import checkdmarc._constants
from checkdmarc.bimi import check_bimi
from checkdmarc.dmarc import check_dmarc
from checkdmarc.dnssec import test_dnssec
from checkdmarc.mta_sts import check_mta_sts
from checkdmarc.smtp import check_mx
from checkdmarc.smtp_tls_reporting import check_smtp_tls_reporting
from checkdmarc.soa import check_soa
from checkdmarc.spf import check_spf
from checkdmarc.utils import (
    DNSException,
    MXHost,
    NameserverResult,
    get_base_domain,
    get_nameservers,
    normalize_domain,
)

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


__version__ = checkdmarc._constants.__version__


def check_domains(
    domains: list[str],
    *,
    parked: bool = False,
    approved_nameservers: Optional[Sequence[str | Nameserver]] = None,
    approved_mx_hostnames: Optional[bool] = None,
    skip_tls: bool = False,
    bimi_selector: str = "default",
    include_tag_descriptions: bool = False,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
    wait: float = 0.0,
) -> MXHost:
    """
    Check the given domains for SPF and DMARC records, parse them, and return
    them

    Args:
        domains (list): A list of domains to check
        parked (bool): Indicates that the domains are parked
        approved_nameservers (list): A list of approved nameservers
        approved_mx_hostnames (list): A list of approved MX hostname
        skip_tls (bool): Skip STARTTLS testing
        bimi_selector (str): The BIMI selector to test
        include_tag_descriptions (bool): Include descriptions of
                                               tags and/or tag values in the
                                               results
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout
        wait (float): number of seconds to wait between processing domains

    Returns:
       A ``dict`` or ``list`` of  `dict` with the following keys

       - ``domain`` - The domain name
       - ``base_domain`` The base domain
       - ``mx`` - See :func:`checkdmarc.smtp.get_mx_hosts`
       - ``spf`` -  A ``valid`` flag, plus the output of
         :func:`checkdmarc.spf.parse_spf_record` or a ``error``
       - ``dmarc`` - A ``valid`` flag, plus the output of
         :func:`checkdmarc.dmarc.parse_dmarc_record` or a ``error``
    """
    domains = sorted(
        list(
            set(
                map(
                    lambda d: normalize_domain(d.rstrip(".\r\n").strip().split(",")[0]),
                    domains,
                )
            )
        )
    )
    not_domains = []
    for domain in domains:
        if "." not in domain:
            not_domains.append(domain)
    for domain in not_domains:
        domains.remove(domain)
    while "" in domains:
        domains.remove("")
    results = []
    for domain in domains:
        domain = normalize_domain(domain)
        logging.debug(f"Checking: {domain}")

        domain_results = {
            "domain": domain,
            "base_domain": get_base_domain(domain),
            "dnssec": None,
            "soa": {},
            "ns": [],
            "mx": [],
        }

        domain_results["dnssec"] = test_dnssec(
            domain, nameservers=nameservers, timeout=timeout
        )
        domain_results["soa"] = check_soa(
            domain, nameservers=nameservers, resolver=resolver, timeout=timeout
        )

        domain_results["ns"] = check_ns(
            domain,
            approved_nameservers=approved_nameservers,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )

        mta_sts_mx_patterns = None
        domain_results["mta_sts"] = check_mta_sts(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
        if domain_results["mta_sts"]["valid"]:
            mta_sts_mx_patterns = domain_results["mta_sts"]["policy"]["mx"]
        domain_results["mx"] = check_mx(
            domain,
            approved_mx_hostnames=approved_mx_hostnames,
            mta_sts_mx_patterns=mta_sts_mx_patterns,
            skip_tls=skip_tls,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )

        domain_results["spf"] = check_spf(
            domain,
            parked=parked,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )

        domain_results["dmarc"] = check_dmarc(
            domain,
            parked=parked,
            include_dmarc_tag_descriptions=include_tag_descriptions,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )

        domain_results["smtp_tls_reporting"] = check_smtp_tls_reporting(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
        if bimi_selector is not None:
            domain_results["bimi"] = check_bimi(
                domain,
                selector=bimi_selector,
                parsed_dmarc_record=domain_results["dmarc"],
                include_tag_descriptions=include_tag_descriptions,
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                timeout_retries=timeout_retries,
            )

        results.append(domain_results)
        if wait > 0.0:
            logging.debug(f"Sleeping for {wait} seconds")
            sleep(wait)
    if len(results) == 1:
        results = results[0]

    return results


def check_ns(
    domain: str,
    *,
    approved_nameservers: Optional[Sequence[str | Nameserver]] = None,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> NameserverResult:
    """
    Returns a dictionary of nameservers and warnings or a dictionary with an
    empty list and an error.

    Args:
        domain (str): A domain name
        approved_nameservers (list): A list of approved nameserver substrings
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
    Returns:
        dict: A dictionary with the following keys:

              - ``hostnames`` - A list of nameserver hostnames
              - ``warnings``  - A list of warnings

             If a DNS error occurs, the dictionary will have the following
             keys:

              - ``hostnames`` - An empty list
              - ``error``  - An error message
    """
    try:
        ns_results = get_nameservers(
            domain,
            approved_nameservers=approved_nameservers,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
    except DNSException as error:
        ns_results = {"hostnames": [], "error": error.__str__()}
    return ns_results


def results_to_json(
    results: Union[dict[str, object], list[dict[str, str]]],
) -> str:
    """
    Converts a dictionary of results or list of results to a JSON string

    Args:
        results (dict): A dictionary of results

    Returns:
        str: Results in JSON format
    """
    return json.dumps(results, ensure_ascii=False, indent=2)


def results_to_csv_rows(
    results: Union[dict, list[dict]],
) -> list[dict]:
    """
    Converts a results dictionary or list of dictionaries and returns a
    list of CSV row dictionaries

    Args:
        results (dict): A dictionary of results

    Returns:
        list: A list of CSV row dictionaries
    """
    rows = []

    if type(results) is dict:
        results = [results]

    for result in results:
        row = {}
        ns = result["ns"]
        mx = result["mx"]
        _mta_sts = result["mta_sts"]
        _spf = result["spf"]
        _dmarc = result["dmarc"]
        row["domain"] = result["domain"]
        row["base_domain"] = result["base_domain"]
        row["dnssec"] = result["dnssec"]
        row["ns"] = "|".join(ns["hostnames"])
        _smtp_tls_reporting = result["smtp_tls_reporting"]
        if "error" in ns:
            row["ns_error"] = ns["error"]
        else:
            row["ns_warnings"] = "|".join(ns["warnings"])
        if "error" in _mta_sts:
            row["mta_sts_error"] = _mta_sts["error"]
        else:
            row["mta_sts_id"] = _mta_sts["id"]
            row["mta_sts_mode"] = _mta_sts["policy"]["mode"]
            row["mta_sts_max_age"] = _mta_sts["policy"]["max_age"]
            row["mta_sts_mx"] = "|".join(_mta_sts["policy"]["mx"])
            row["mta_sts_warnings"] = "|".join(_mta_sts["warnings"])
        if "bimi" in result:
            _bimi = result["bimi"]
            row["bimi_selector"] = _bimi["selector"]
            bimi_error = None
            if "error" in _bimi:
                bimi_error = _bimi["error"]
            row["bimi_error"] = bimi_error

            if "warnings" in _bimi:
                row["bimi_warnings"] = "|".join(_bimi["warnings"])
            if "error" in _bimi:
                row["bimi_error"] = _bimi["error"]
                if "tags" in _bimi:
                    if "l" in _bimi["tags"]:
                        row["bimi_l"] = _bimi["tags"]["l"]["value"]
                    if "a" in _bimi["tags"]:
                        row["bimi_a"] = _bimi["tags"]["a"]["value"]
        row["mx"] = "|".join(
            list(map(lambda r: f"{r['preference']}, {r['hostname']}", mx["hosts"]))
        )
        tls = None
        try:
            tls_results = list(map(lambda r: f"{r['starttls']}", mx["hosts"]))
            for tls_result in tls_results:
                tls = tls_result
                if tls_result is False:
                    tls = False
                    break
        except KeyError:
            # The user might opt to skip the STARTTLS test
            pass
        finally:
            row["tls"] = tls

        starttls = None
        try:
            starttls_results = list(map(lambda r: f"{r['starttls']}", mx["hosts"]))
            for starttls_result in starttls_results:
                starttls = starttls_result
                if starttls_result is False:
                    starttls = False
        except KeyError:
            # The user might opt to skip the STARTTLS test
            pass
        finally:
            row["starttls"] = starttls

        if "error" in mx:
            row["mx_error"] = mx["error"]
        else:
            row["mx_warnings"] = "|".join(mx["warnings"])
        row["spf_record"] = _spf["record"]
        row["spf_valid"] = _spf["valid"]
        if "error" in _spf:
            row["spf_error"] = _spf["error"]
        else:
            row["spf_warnings"] = "|".join(_spf["warnings"])

        row["dmarc_record"] = _dmarc["record"]
        row["dmarc_record_location"] = _dmarc["location"]
        row["dmarc_valid"] = _dmarc["valid"]
        if "error" in _dmarc:
            row["dmarc_error"] = _dmarc["error"]
        else:
            row["dmarc_adkim"] = _dmarc["tags"]["adkim"]["value"]
            row["dmarc_aspf"] = _dmarc["tags"]["aspf"]["value"]
            row["dmarc_fo"] = ":".join(_dmarc["tags"]["fo"]["value"])
            row["dmarc_p"] = _dmarc["tags"]["p"]["value"]
            row["dmarc_pct"] = _dmarc["tags"]["pct"]["value"]
            row["dmarc_rf"] = ":".join(_dmarc["tags"]["rf"]["value"])
            row["dmarc_ri"] = _dmarc["tags"]["ri"]["value"]
            row["dmarc_sp"] = _dmarc["tags"]["sp"]["value"]
            if "rua" in _dmarc["tags"]:
                addresses = _dmarc["tags"]["rua"]["value"]
                addresses = list(
                    map(lambda u: "{}:{}".format(u["scheme"], u["address"]), addresses)
                )
                row["dmarc_rua"] = "|".join(addresses)
            if "ruf" in _dmarc["tags"]:
                addresses = _dmarc["tags"]["ruf"]["value"]
                addresses = list(
                    map(lambda u: "{}:{}".format(u["scheme"], u["address"]), addresses)
                )
                row["dmarc_ruf"] = "|".join(addresses)
            row["dmarc_warnings"] = "|".join(_dmarc["warnings"])
        if "error" in _smtp_tls_reporting:
            row["smtp_tls_reporting_valid"] = False
            row["smtp_tls_reporting_error"] = _smtp_tls_reporting["error"]
        else:
            row["smtp_tls_reporting_valid"] = True
            row["smtp_tls_reporting_rua"] = "|".join(
                _smtp_tls_reporting["tags"]["rua"]["value"]
            )
            row["smtp_tls_reporting_warnings"] = _smtp_tls_reporting["warnings"]
        rows.append(row)
    return rows


def results_to_csv(results: dict[str, object]) -> str:
    """
    Converts a dictionary of results to CSV

    Args:
        results (dict): A dictionary of results

    Returns:
        str: A CSV of results
    """
    fields = [
        "domain",
        "base_domain",
        "dnssec",
        "spf_valid",
        "dmarc_valid",
        "dmarc_adkim",
        "dmarc_aspf",
        "dmarc_fo",
        "dmarc_p",
        "dmarc_pct",
        "dmarc_rf",
        "dmarc_ri",
        "dmarc_rua",
        "dmarc_ruf",
        "dmarc_sp",
        "tls",
        "starttls",
        "spf_record",
        "dmarc_record",
        "dmarc_record_location",
        "mx",
        "mx_error",
        "mx_warnings",
        "mta_sts_id",
        "mta_sts_mode",
        "mta_sts_max_age",
        "smtp_tls_reporting_valid",
        "smtp_tls_reporting_rua",
        "mta_sts_mx",
        "mta_sts_error",
        "mta_sts_warnings",
        "spf_error",
        "spf_warnings",
        "dmarc_error",
        "dmarc_warnings",
        "ns",
        "ns_error",
        "ns_warnings",
        "bimi_selector",
        "bimi_error",
        "bimi_warnings",
        "smtp_tls_reporting_error",
        "smtp_tls_reporting_warnings",
    ]
    output = StringIO(newline="\n")
    writer = DictWriter(output, fieldnames=fields)
    writer.writeheader()
    rows = results_to_csv_rows(results)
    writer.writerows(rows)
    output.flush()

    return output.getvalue()


def output_to_file(path: str, content: str):
    """
    Write given content to the given path

    Args:
        path (str): A file path
        content (str): JSON or CSV text
    """
    with open(
        path, "w", newline="\n", encoding="utf-8", errors="ignore"
    ) as output_file:
        output_file.write(content)
