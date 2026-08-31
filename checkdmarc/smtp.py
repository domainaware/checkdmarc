"""SMTP tests"""

from __future__ import annotations

import logging
import platform
import smtplib
import socket
import ssl
import warnings as _warnings
from collections.abc import Sequence
from typing import TypedDict

import dns.exception
import dns.resolver
from dns.nameserver import Nameserver
from expiringdict import ExpiringDict

from checkdmarc._constants import (
    DEFAULT_DNS_MAX_RETRIES,
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_SMTP_TIMEOUT,
    SMTP_CACHE_MAX_AGE_SECONDS,
    SMTP_CACHE_MAX_LEN,
)
from checkdmarc.dnssec import check_dnssec, get_tlsa_records
from checkdmarc.mta_sts import mx_in_mta_sts_patterns
from checkdmarc.utils import (
    DNSException,
    MXHost,
    get_a_records,
    get_mx_record_set,
    get_reverse_dns,
    normalize_domain,
    query_dns,
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

logger = logging.getLogger(__name__)


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


MXResults = MXResultsSuccess | MXResultsFailure


class SMTPError(Exception):
    """Raised when an SMTP error occurs"""


def test_tls(
    hostname: str,
    *,
    ssl_context: ssl.SSLContext | None = None,
    cache: ExpiringDict | None = None,
    timeout: float = DEFAULT_SMTP_TIMEOUT,
) -> bool:
    """
    Attempt to connect to an SMTP server on port 465 and validate TLS/SSL support

    Args:
        hostname (str): The hostname
        cache (ExpiringDict): Cache storage
        ssl_context (SSLContext): An SSL context
        timeout (float): Number of seconds to wait for the SMTP server (default 5.0)

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
    logger.debug(f"Testing TLS/SSL on {hostname}")
    try:
        with smtplib.SMTP_SSL(hostname, context=ssl_context, timeout=timeout) as server:
            server.ehlo_or_helo_if_needed()
            tls = True
            if cache is not None:
                cache[hostname] = {"tls": tls, "error": None}
            return tls

    except socket.gaierror:
        error = "DNS resolution failed"
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except ConnectionRefusedError:
        error = "Connection refused"
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except ConnectionResetError:
        error = "Connection reset"
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except ConnectionAbortedError:
        error = "Connection aborted"
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except TimeoutError:
        error = "Connection timed out"
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except BlockingIOError as e:
        error = e.__str__()
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except ssl.SSLError as e:
        error = f"SSL error: {e}"
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPConnectError as e:
        message = e.__str__()
        error_code = int(message.lstrip("(").split(",")[0])
        if error_code == 554:
            message = "SMTP error code 554 - Not allowed"
        else:
            message = f"SMTP error code {error_code}"
        error = f"Could not connect: {message}"
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPHeloError as e:
        error = f"HELO error: {e}"
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPException as e:
        error = e.__str__()
        try:
            error_code = error.lstrip("(").split(",")[0]
            error = f"SMTP error code {error_code}"
        except ValueError:
            pass
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)
    except OSError as e:
        error = e.__str__()
        if cache is not None:
            cache[hostname] = {"tls": False, "error": error}
        raise SMTPError(error)


def test_starttls(
    hostname: str,
    *,
    ssl_context: ssl.SSLContext | None = None,
    cache: ExpiringDict | None = None,
    timeout: float = DEFAULT_SMTP_TIMEOUT,
) -> bool:
    """
    Attempt to connect to an SMTP server and validate STARTTLS support

    Args:
        hostname (str): The hostname
        cache (ExpiringDict): Cache storage
        ssl_context (SSLContext): An SSL context
        timeout (float): Number of seconds to wait for the SMTP server (default 5.0)

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
    logger.debug(f"Testing STARTTLS on {hostname}")
    try:
        with smtplib.SMTP(hostname, timeout=timeout) as server:
            server.ehlo_or_helo_if_needed()
            if server.has_extn("starttls"):
                server.starttls(context=ssl_context)
                server.ehlo()
                starttls = True
            # Cache the answer either way: a server that does not offer
            # STARTTLS is just as conclusive as one that does, and caching
            # only successes meant re-probing such servers on every call.
            if cache is not None:
                cache[hostname] = {"starttls": starttls, "error": None}
            return starttls

    except socket.gaierror:
        error = "DNS resolution failed"
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except ConnectionRefusedError:
        error = "Connection refused"
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except ConnectionResetError:
        error = "Connection reset"
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except ConnectionAbortedError:
        error = "Connection aborted"
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except TimeoutError:
        error = "Connection timed out"
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except BlockingIOError as e:
        error = e.__str__()
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except ssl.SSLError as e:
        error = f"SSL error: {e}"
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPConnectError as e:
        message = e.__str__()
        error_code = int(message.lstrip("(").split(",")[0])
        if error_code == 554:
            message = "SMTP error code 554 - Not allowed"
        else:
            message = f"SMTP error code {error_code}"
        error = f"Could not connect: {message}"
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPHeloError as e:
        error = f"HELO error: {e}"
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except smtplib.SMTPException as e:
        error = e.__str__()
        try:
            error_code = error.lstrip("(").split(",")[0]
            error = f"SMTP error code {error_code}"
        except ValueError:
            pass
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)
    except OSError as e:
        error = e.__str__()
        if cache is not None:
            cache[hostname] = {"starttls": False, "error": error}
        raise SMTPError(error)


def get_mx_hosts(
    domain: str,
    *,
    check_mx_tls: bool = False,
    skip_tls: bool | None = None,
    approved_mx_hostnames: list[str] | None = None,
    approved_hostnames: list[str] | None = None,
    mta_sts_mx_patterns: list[str] | None = None,
    parked: bool = False,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> MXResultsSuccess:
    """
    Gets MX hostnames and their addresses

    Args:
        domain (str): A domain name
        check_mx_tls (bool): Test each MX host for STARTTLS and TLS support
                             (off by default)
        skip_tls (bool): Deprecated, no effect — TLS testing is opt-in via
                         ``check_mx_tls``
        approved_mx_hostnames (list): A list of approved MX hostname substrings
        approved_hostnames (list): Deprecated alias for ``approved_mx_hostnames``
        mta_sts_mx_patterns (list): A list of MX patterns from MTA-STS
        parked (bool): Indicates that the domain is parked
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: a ``dict`` with the following keys:
                     - ``hosts`` - A ``list`` of ``dict`` with keys of

                       - ``preference`` - The MX preference integer
                       - ``hostname`` - A hostname
                       - ``dnssec`` - DNSSEC status
                       - ``addresses`` - A ``list`` of IP addresses
                       - ``tlsa`` - A list of TLSA records, if they exist
                       - ``tls`` - TLS support status (absent if TLS testing is skipped)
                       - ``starttls`` - STARTTLS support status (absent if TLS testing is skipped)

                     - ``warnings`` - A ``list`` of MX resolution warnings

    """
    if approved_hostnames is not None:
        _warnings.warn(
            "The approved_hostnames parameter is deprecated; use approved_mx_hostnames",
            DeprecationWarning,
            stacklevel=2,
        )
        if approved_mx_hostnames is None:
            approved_mx_hostnames = approved_hostnames
    if skip_tls is not None:
        _warnings.warn(
            "The skip_tls parameter is deprecated and has no effect; "
            "TLS testing is opt-in via check_mx_tls",
            DeprecationWarning,
            stacklevel=2,
        )
    hosts = []
    warnings = []
    hostnames = set()
    dupe_hostnames = set()
    logger.debug(f"Getting MX records for {domain}")
    mx_record_set = get_mx_record_set(
        domain,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        retries=retries,
    )
    warnings.extend(mx_record_set["warnings"])
    if mx_record_set["null_mx"]:
        # A null MX record (RFC 7505) is a deliberate statement, unlike
        # having no MX records at all — surface the difference.
        warnings.append(
            f"{domain} has a null MX record (RFC 7505): the domain "
            "explicitly does not accept mail"
        )
    elif len(mx_record_set["hosts"]) == 0:
        warnings.append(
            f"{domain} has no MX records; mail could still be delivered to "
            "the address of an A or AAAA record for the domain, if one "
            "exists (the implicit MX rule in RFC 5321 section 5.1)"
        )
    for record in mx_record_set["hosts"]:
        hosts.append(
            {
                "preference": record["preference"],
                "hostname": record["hostname"].lower(),
                "addresses": [],
            }
        )
    if parked and len(hosts) > 0:
        warnings.append("MX records found on a parked domain")

    if approved_mx_hostnames:
        approved_mx_hostnames = [h.lower() for h in approved_mx_hostnames]
    for host in hosts:
        hostname = host["hostname"]
        if hostname in hostnames:
            if hostname not in dupe_hostnames:
                warnings.append(f"Hostname {hostname} is listed in multiple MX records")
                dupe_hostnames.add(hostname)
            continue
        hostnames.add(hostname)
        if approved_mx_hostnames:
            approved = False
            for approved_hostname in approved_mx_hostnames:
                if approved_hostname in hostname:
                    approved = True
                    break
            if not approved:
                warnings.append(f"Unapproved MX hostname: {hostname}")
        if mta_sts_mx_patterns and not mx_in_mta_sts_patterns(
            hostname, mta_sts_mx_patterns
        ):
            warnings.append(f"{hostname} is not included in the MTA-STS policy")

        # RFC 2181 section 10.3: an MX record must not point at a CNAME
        # alias. Address lookups follow CNAME chains silently, so ask for
        # the CNAME record itself — an answer means the target is an alias.
        # A failed lookup only skips this check (the address lookup below
        # reports actual resolution problems).
        try:
            cname_answers = query_dns(
                hostname,
                "CNAME",
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                retries=retries,
            )
            if len(cname_answers) > 0:
                warnings.append(
                    f"The MX record for {domain} points at {hostname}, "
                    f"which is a CNAME alias for {cname_answers[0]}; "
                    "MX records must not point at aliases "
                    "(RFC 2181 section 10.3)"
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            pass  # Not an alias
        except dns.exception.DNSException as error:
            logger.debug(f"CNAME check for MX host {hostname} failed: {error}")

        try:
            dnssec = False
            try:
                dnssec = check_dnssec(
                    hostname,
                    nameservers=nameservers,
                    timeout=timeout,
                )
            except (dns.exception.DNSException, OSError, EOFError) as e:
                logger.debug(e)
            host["dnssec"] = dnssec
            host["addresses"] = []
            host["addresses"] = get_a_records(
                hostname,
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                retries=retries,
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
        except (DNSException, ValueError) as e:
            if hostname.lower().endswith(".msv1.invalid"):
                warnings.append(
                    f"{e}. Consider using a TXT record to "
                    "validate domain ownership in Office 365 "
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
                    retries=retries,
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
                        retries=retries,
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
        if check_mx_tls and platform.system() == "Windows":
            logger.warning("Testing TLS is not supported on Windows")
            check_mx_tls = False
        if not check_mx_tls:
            logger.debug(f"Skipping TLS/SSL tests on {hostname}")
        else:
            try:
                starttls = test_starttls(hostname, cache=STARTTLS_CACHE)
                tls = starttls
                if not starttls:
                    warnings.append(f"STARTTLS is not supported on {hostname}.")
                    try:
                        tls = test_tls(hostname, cache=TLS_CACHE)
                    except SMTPError as error:
                        # Name the probe that failed: this fallback tests
                        # implicit TLS on port 465, not the port 25
                        # STARTTLS session that was already reported.
                        raise SMTPError(
                            f"implicit TLS on port 465 failed: {error}"
                        ) from error

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
    approved_mx_hostnames: list[str] | None = None,
    mta_sts_mx_patterns: list[str] | None = None,
    check_mx_tls: bool = False,
    skip_tls: bool | None = None,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> MXResults:
    """
    Gets MX hostnames and their addresses, or an empty list of hosts and an
    error if a DNS error occurs

    Args:
        domain (str): A domain name
        check_mx_tls (bool): Test each MX host for STARTTLS and TLS support
                             (off by default)
        skip_tls (bool): Deprecated, no effect — TLS testing is opt-in via
                         ``check_mx_tls``
        approved_mx_hostnames (list): A list of approved MX hostname substrings
        mta_sts_mx_patterns (list): A list of MX patterns from MTA-STS
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: a ``dict`` with the following keys:

                     - ``hosts`` - A ``list`` of ``dict`` with keys of

                       - ``preference`` - The MX preference integer
                       - ``hostname`` - A hostname
                       - ``dnssec`` - DNSSEC status
                       - ``addresses`` - A ``list`` of IP addresses
                       - ``tlsa`` - A list of TLSA records, if they exist
                       - ``tls`` - TLS support status (absent if TLS testing is skipped)
                       - ``starttls`` - STARTTLS support status (absent if TLS testing is skipped)

                     - ``warnings`` - A ``list`` of MX resolution warnings

                    If a DNS error occurs, the dictionary will have the
                    following keys:

                      - ``hosts`` - An empty list
                      - ``error``  - An error message
    """
    try:
        mx_results = get_mx_hosts(
            domain,
            check_mx_tls=check_mx_tls,
            skip_tls=skip_tls,
            approved_mx_hostnames=approved_mx_hostnames,
            mta_sts_mx_patterns=mta_sts_mx_patterns,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        return mx_results
    except DNSException as error:
        failure: MXResultsFailure = {"hosts": [], "error": str(error)}
    return failure
