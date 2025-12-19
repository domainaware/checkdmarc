# -*- coding: utf-8 -*-
"""SMTP tests"""

from __future__ import annotations

import logging
import platform
import smtplib
import socket
import ssl
from typing import TypedDict, Optional, Union
from collections.abc import Sequence

import dns.resolver
from dns.nameserver import Nameserver
import timeout_decorator
from expiringdict import ExpiringDict

from checkdmarc._constants import SMTP_CACHE_MAX_AGE_SECONDS, SMTP_CACHE_MAX_LEN
from checkdmarc.dnssec import get_tlsa_records, test_dnssec
from checkdmarc.mta_sts import mx_in_mta_sts_patterns
from checkdmarc.utils import (
    DNSException,
    MXHost,
    get_a_records,
    get_mx_records,
    get_reverse_dns,
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


TLS_CACHE = ExpiringDict(
    max_len=SMTP_CACHE_MAX_LEN, max_age_seconds=SMTP_CACHE_MAX_AGE_SECONDS
)
STARTTLS_CACHE = ExpiringDict(
    max_len=SMTP_CACHE_MAX_LEN, max_age_seconds=SMTP_CACHE_MAX_AGE_SECONDS
)


class MXResultsSuccess(TypedDict):
    hosts: list[MXHost]
    warnings: list[str]


class MXResultsFailure(TypedDict):
    hosts: list[MXHost]
    error: str


MXResults = Union[MXResultsSuccess, MXResultsFailure]


def _get_timeout_method():
    """
    Determine the best timeout method based on platform and environment.

    Returns:
        bool: True to use signals, False to use multiprocessing
    """
    # On macOS, use signals to avoid multiprocessing spawn issues
    if platform.system() == "Darwin":
        return True

    # On Windows, signals are not available, so use multiprocessing
    if platform.system() == "Windows":
        return False

    # On Linux and other Unix-like systems, prefer signals for better performance
    # unless we detect we're in a multithreaded environment
    try:
        # Check if we're in a multithreaded environment by looking for threading
        import threading

        if threading.active_count() > 1:
            # Multiple threads detected, use multiprocessing to avoid signal conflicts
            return False
    except ImportError:
        pass

    # Default to signals for better performance on Unix-like systems
    return True


class SMTPError(Exception):
    """Raised when SMTP error occurs"""


@timeout_decorator.timeout(
    5,
    timeout_exception=SMTPError,  # type: ignore
    exception_message="Connection timed out",
    use_signals=_get_timeout_method(),
)
def test_tls(
    hostname: str,
    *,
    ssl_context: Optional[ssl.SSLContext] = None,
    cache: Optional[ExpiringDict] = None,
) -> bool:
    """
    Attempt to connect to an SMTP server port 465 and validate TLS/SSL support

    Args:
        hostname (str): The hostname
        cache (ExpiringDict): Cache storage
        ssl_context (SSLContext): A SSL context

    Returns:
        bool: True if TLS supported
    Raises:
        checkdmarc.smtp.SMTPError: SMTP connection failed
    """
    tls = False
    hostname = normalize_domain(hostname)
    if isinstance(cache, ExpiringDict):
        cached_result = cache.get(hostname)
        if isinstance(cached_result, dict):
            if cached_result["error"] is not None:
                raise SMTPError(cached_result["error"])
            return cached_result["tls"]
    if ssl_context is None:
        ssl_context = ssl.create_default_context()
    logging.debug(f"Testing TLS/SSL on {hostname}")
    try:
        server = smtplib.SMTP_SSL(hostname, context=ssl_context)
        server.ehlo_or_helo_if_needed()
        tls = True
        if cache is not None:
            cache[hostname] = {"tls": tls, "error": None}
        try:
            server.quit()
            server.close()
        except Exception as e:
            logging.debug(e)
        return tls

    except socket.gaierror:
        error = "DNS resolution failed"
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except ConnectionRefusedError:
        error = "Connection refused"
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except ConnectionResetError:
        error = "Connection reset"
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except ConnectionAbortedError:
        error = "Connection aborted"
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except TimeoutError:
        error = "Connection timed out"
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except BlockingIOError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except ssl.SSLError as e:
        error = f"SSL error: {e}"
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPConnectError as e:
        message = e.__str__()
        error_code = int(message.lstrip("(").split(",")[0])
        if error_code == 554:
            message = " SMTP error code 554 - Not allowed"
        else:
            message = f" SMTP error code {error_code}"
        error = f"Could not connect: {message}"
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPHeloError as e:
        error = f"HELO error: {e}"
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPException as e:
        error = e.__str__()
        try:
            error_code = error.lstrip("(").split(",")[0]
            error = f"SMTP error code {error_code}"
        except ValueError:
            pass
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except OSError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except Exception as e:
        error = e.__str__()
        if cache:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)


@timeout_decorator.timeout(
    5,
    timeout_exception=SMTPError,  # pyright: ignore[reportArgumentType]
    exception_message="Connection timed out",
    use_signals=_get_timeout_method(),
)
def test_starttls(
    hostname: str,
    *,
    ssl_context: Optional[ssl.SSLContext] = None,
    cache: Optional[ExpiringDict] = None,
) -> bool:
    """
    Attempt to connect to an SMTP server and validate STARTTLS support

    Args:
        hostname (str): The hostname
        cache (ExpiringDict): Cache storage
        ssl_context: A SSL context

    Returns:
        bool: True if STARTTLS supported
    Raises:
        checkdmarc.smtp.SMTPError: SMTP connection failed
    """
    hostname = normalize_domain(hostname)
    starttls = False
    if isinstance(cache, ExpiringDict):
        cached_result = cache.get(hostname)
        if isinstance(cached_result, dict):
            if cached_result["error"] is not None:
                raise SMTPError(cached_result["error"])
            return cached_result["starttls"]
    if ssl_context is None:
        ssl_context = ssl.create_default_context()
    logging.debug(f"Testing STARTTLS on {hostname}")
    try:
        server = smtplib.SMTP(hostname)
        server.ehlo_or_helo_if_needed()
        if server.has_extn("starttls"):
            server.starttls(context=ssl_context)
            server.ehlo()
            starttls = True
            if cache:
                cache[hostname] = {"starttls": starttls, "error": None}
        try:
            server.quit()
            server.close()

        except Exception as e:
            logging.debug(e)
        return starttls

    except socket.gaierror:
        error = "DNS resolution failed"
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except ConnectionRefusedError:
        error = "Connection refused"
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except ConnectionResetError:
        error = "Connection reset"
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except ConnectionAbortedError:
        error = "Connection aborted"
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except TimeoutError:
        error = "Connection timed out"
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except BlockingIOError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except ssl.SSLError as e:
        error = f"SSL error: {e}"
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPConnectError as e:
        message = e.__str__()
        error_code = int(message.lstrip("(").split(",")[0])
        if error_code == 554:
            message = " SMTP error code 554 - Not allowed"
        else:
            message = f" SMTP error code {error_code}"
        error = f"Could not connect: {message}"
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPHeloError as e:
        error = f"HELO error: {e}"
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPException as e:
        error = e.__str__()
        try:
            error_code = error.lstrip("(").split(",")[0]
            error = f"SMTP error code {error_code}"
        except ValueError:
            pass
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except OSError as e:
        error = e.__str__()
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except Exception as e:
        error = e.__str__()
        if cache:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)


def get_mx_hosts(
    domain: str,
    *,
    skip_tls: bool = False,
    approved_hostnames: Optional[list[str]] = None,
    mta_sts_mx_patterns: Optional[list[str]] = None,
    parked: bool = False,
    nameservers: Sequence[str | Nameserver],
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> MXResultsSuccess:
    """
    Gets MX hostname and their addresses

    Args:
        domain (str): A domain name
        skip_tls (bool): Skip STARTTLS testing
        approved_hostnames (list): A list of approved MX hostname substrings
        mta_sts_mx_patterns (list): A list of MX patterns from MTA-STS
        parked (bool): Indicates that the domains are parked
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS

    Returns:
        dict: a ``dict`` with the following keys:
                     - ``hosts`` - A ``list`` of ``dict`` with keys of

                       - ``hostname`` - A hostname
                       - ``dnssec`` - DNSSEC status
                       - ``addresses`` - A ``list`` of IP addresses
                       - ``tlsa`` - A list of TLSA records, if they exist

                     - ``warnings`` - A ``list`` of MX resolution warnings

    """
    hosts = []
    warnings = []
    hostnames = set()
    dupe_hostnames = set()
    logging.debug(f"Getting MX records for {domain}")
    mx_records = get_mx_records(
        domain,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        timeout_retries=timeout_retries,
    )
    for record in mx_records:
        hosts.append(
            {
                "preference": record["preference"],
                "hostname": record["hostname"].lower(),
                "addresses": [],
            }
        )
    if parked and len(hosts) > 0:
        warnings.append("MX records found on parked domains")

    if approved_hostnames:
        approved_hostnames = list(map(lambda h: h.lower(), approved_hostnames))
    for host in hosts:
        hostname = host["hostname"]
        if hostname in hostnames:
            if hostname not in dupe_hostnames:
                warnings.append(f"Hostname {hostname} is listed in multiple MX records")
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
        if mta_sts_mx_patterns:
            if not mx_in_mta_sts_patterns(hostname, mta_sts_mx_patterns):
                warnings.append(f"{hostname} is not included in the MTA-STS policy")

        try:
            dnssec = False
            try:
                dnssec = test_dnssec(
                    hostname,
                    nameservers=nameservers,
                    timeout=timeout,
                )
            except Exception as e:
                logging.debug(e)
            host["dnssec"] = dnssec
            host["addresses"] = []
            host["addresses"] = get_a_records(
                hostname,
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                timeout_retries=timeout_retries,
            )
            tlsa_records = get_tlsa_records(
                hostname,
                nameservers=nameservers,
                timeout=timeout,
            )

            if len(tlsa_records) > 0:
                host["tlsa"] = tlsa_records
            if len(host["addresses"]) == 0:
                warnings.append(f"{hostname} does not have any A or AAAA DNS records.")
        except Exception as e:
            if hostname.lower().endswith(".msv1.invalid"):
                warnings.append(
                    f"{e}. Consider using a TXT record to "
                    " validate domain ownership in Office 365 "
                    "instead."
                )
            else:
                warnings.append(e.__str__())

        for address in host["addresses"]:
            try:
                reverse_hostnames = get_reverse_dns(
                    address,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                    timeout_retries=timeout_retries,
                )
            except DNSException:
                reverse_hostnames = []
            if len(reverse_hostnames) == 0:
                warnings.append(
                    f"{address} does not have any reverse DNS (PTR) records"
                )
            for reverse_hostname in reverse_hostnames:
                try:
                    _addresses = get_a_records(
                        reverse_hostname,
                        resolver=resolver,
                        timeout=timeout,
                        timeout_retries=timeout_retries,
                    )
                except DNSException as warning:
                    warnings.append(str(warning))
                    _addresses = []
                if address not in _addresses:
                    warnings.append(
                        f"The reverse DNS of "
                        f"{address} is {reverse_hostname}, but "
                        "the A/AAAA DNS records for "
                        f"{reverse_hostname} do not resolve to "
                        f"{address}"
                    )
        if not skip_tls and platform.system() == "Windows":
            logging.warning("Testing TLS is not supported on Windows")
            skip_tls = True
        if skip_tls:
            logging.debug(f"Skipping TLS/SSL tests on {hostname}")
        else:
            try:
                starttls = test_starttls(hostname, cache=STARTTLS_CACHE)
                tls = starttls
                if not starttls:
                    warnings.append(f"STARTTLS is not supported on {hostname}.")
                    tls = test_tls(hostname, cache=TLS_CACHE)

                    if not tls:
                        warnings.append(f"SSL/TLS is not supported on {hostname}.")
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
    results: MXResultsSuccess = {"hosts": hosts, "warnings": warnings}
    return results


def check_mx(
    domain: str,
    *,
    approved_mx_hostnames: Optional[list[str]] = None,
    mta_sts_mx_patterns: Optional[list[str]] = None,
    skip_tls: bool = False,
    nameservers: Sequence[str | Nameserver],
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> MXResults:
    """
    Gets MX hostname and their addresses, or an empty list of hosts and an
    error if a DNS error occurs

    Args:
        domain (str): A domain name
        skip_tls (bool): Skip STARTTLS testing
        approved_mx_hostnames (list): A list of approved MX hostname substrings
        mta_sts_mx_patterns (list): A list of MX patterns from MTA-STS
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout

    Returns:
        dict: a ``dict`` with the following keys:

                     - ``hosts`` - A ``list`` of ``dict`` with keys of

                       - ``hostname`` - A hostname
                       - ``addresses`` - A ``list`` of IP addresses

                     - ``warnings`` - A ``list`` of MX resolution warnings

                    If a DNS error occurs, the dictionary will have the
                    following keys:

                      - ``hosts`` - An empty list
                      - ``error``  - An error message
    """
    try:
        mx_results = get_mx_hosts(
            domain,
            skip_tls=skip_tls,
            approved_hostnames=approved_mx_hostnames,
            mta_sts_mx_patterns=mta_sts_mx_patterns,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
        return mx_results
    except DNSException as error:
        failure: MXResultsFailure = {"hosts": [], "error": str(error)}
    return failure
