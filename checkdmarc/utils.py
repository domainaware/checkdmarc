"""DNS utility functions"""

from __future__ import annotations

import logging
import os
import re
import unicodedata
from collections.abc import Callable, Sequence
from typing import TypedDict
from urllib.parse import urlsplit

import dns.exception
import dns.inet
import dns.message
import dns.nameserver
import dns.query
import dns.resolver
import dns.reversename
import httpx
import publicsuffixlist
from dns.nameserver import Nameserver
from expiringdict import ExpiringDict

from checkdmarc._constants import (
    DEFAULT_DNS_MAX_RETRIES,
    DEFAULT_DNS_TIMEOUT,
    DNS_CACHE_MAX_AGE_SECONDS,
    DNS_CACHE_MAX_LEN,
    DNS_NAMESERVER_FAILURE_COOLDOWN_SECONDS,
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

DNS_CACHE = ExpiringDict(
    max_len=DNS_CACHE_MAX_LEN, max_age_seconds=DNS_CACHE_MAX_AGE_SECONDS
)

# The process-wide httpx client used for DNS over HTTPS queries, and the PID
# it was created under. See _get_doh_session().
_DOH_SESSION: httpx.Client | None = None
_DOH_SESSION_PID: int | None = None

# Errors considered transient and retryable by query_dns. LifetimeTimeout is
# dnspython's deadline expiry; NoNameservers typically wraps a SERVFAIL from
# upstream; OSError covers socket-level failures during TCP fallback.
_RETRYABLE_DNS_ERRORS = (
    dns.resolver.LifetimeTimeout,
    dns.resolver.NoNameservers,
    OSError,
)

# Errors that mean one nameserver could not answer and the next one should be
# tried. ssl.SSLError is an OSError subclass, so DNS over TLS handshake
# failures are covered; httpx.HTTPError covers DNS over HTTPS transport
# failures (connection, proxy, and timeout errors). Anything else raised by
# a nameserver's query() — a TypeError from a caller-built Nameserver, say —
# is a programming error, not a sign the server is down.
_TRANSPORT_ERRORS = (dns.exception.DNSException, OSError, EOFError, httpx.HTTPError)

# Nameservers that recently failed to answer, keyed by _nameserver_key().
# Entries expire after DNS_NAMESERVER_FAILURE_COOLDOWN_SECONDS. See
# _order_nameservers() and _note_nameserver_failure().
_NAMESERVER_FAILURES: ExpiringDict = ExpiringDict(
    max_len=256, max_age_seconds=DNS_NAMESERVER_FAILURE_COOLDOWN_SECONDS
)

WSP_REGEX = r"[ \t]"
HTTPS_REGEX = r"(https:\/\/)([\w\-]+\.)+[\w-]+([\w\- ,.\/?%&=]*)"
MAILTO_REGEX_STRING = (
    r"^(mailto):([\w\-!#$%&'*+-/=?^_`{|}~]"
    r"[\w\-.!#$%&'*+-/=?^_`{|}~]*@[\w\-.]+)(!\w+)?"
)
ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF]")  # includes ZWSP, ZWNJ, ZWJ, BOM
MAILTO_REGEX = re.compile(MAILTO_REGEX_STRING, re.IGNORECASE)
PSL = publicsuffixlist.PublicSuffixList()


class NameserverResultOk(TypedDict):
    hostnames: list[str]
    warnings: list[str]


class NameserverResultError(TypedDict):
    hostnames: list[str]
    error: str


NameserverResult = NameserverResultOk | NameserverResultError


class MXRecord(TypedDict):
    """One MX record: a hostname and its preference"""

    hostname: str
    preference: int


class MXHost(MXRecord, total=False):
    """A Mail Exchange host

    ``hostname`` and ``preference`` come from the MX record itself
    (``get_mx_records()``); the remaining fields are added by
    ``checkdmarc.smtp.get_mx_hosts()`` — ``tls`` and ``starttls`` only when
    TLS testing is not skipped.
    """

    addresses: list[str]
    dnssec: bool
    tlsa: list[str]
    tls: bool
    starttls: bool


class DNSException(Exception):
    """Raised when a general DNS error occurs"""

    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class DNSExceptionNXDOMAIN(DNSException):
    """Raised when an NXDOMAIN DNS error (RCODE:3) occurs"""


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
    Normalize an input domain by removing zero-width characters and lowercasing it

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


def _get_doh_session() -> httpx.Client:
    """
    Returns the shared ``httpx.Client`` used for DNS over HTTPS queries.

    The client is created on first use and reused afterwards, so DoH queries
    share TLS connections instead of renegotiating one per lookup. It is
    deliberately never closed: like the module's other shared state, it lives
    for the life of the process.

    The client is rebuilt when the current PID differs from the one it was
    created under, because an application embedding this library in a
    ``fork()``-based worker pool would otherwise inherit — and concurrently
    use — the parent's sockets.

    ``httpx.Client`` defaults are what make this work behind a corporate
    proxy: ``trust_env=True`` honors ``HTTP_PROXY``/``HTTPS_PROXY``/
    ``NO_PROXY`` and ``SSL_CERT_FILE``/``SSL_CERT_DIR``, and ``verify=True``
    keeps certificate verification on. Neither is overridden here.

    Returns:
        httpx.Client: The shared DoH client for this process
    """
    global _DOH_SESSION, _DOH_SESSION_PID
    pid = os.getpid()
    if _DOH_SESSION is None or _DOH_SESSION_PID != pid:
        _DOH_SESSION = httpx.Client(http1=True, http2=True)
        _DOH_SESSION_PID = pid
    return _DOH_SESSION


class _SessionDoHNameserver(dns.nameserver.DoHNameserver):
    """
    A DNS over HTTPS nameserver that queries through a shared ``httpx``
    client.

    dnspython's stock ``DoHNameserver`` calls ``dns.query.https()`` without a
    ``session``, which makes that function build an ``httpx.Client`` with its
    own custom transport — and httpx only reads proxy environment variables
    when no transport is supplied (``allow_env_proxies = trust_env and
    transport is None``). Stock DoH therefore ignores ``HTTPS_PROXY``
    entirely — and a proxy is the only way out of the networks encrypted DNS
    support exists for.

    Passing our own session instead gets environment proxies, environment CA
    configuration (``SSL_CERT_FILE``), and connection reuse across queries.
    ``bootstrap_address`` is deliberately not passed: with a session, the DoH
    server's hostname is resolved by httpx — locally through the OS resolver,
    or by the proxy itself via ``CONNECT`` when one is configured — so no
    UDP/53 access is required.
    """

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool = False,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        return dns.query.https(
            request,
            self.url,
            timeout=timeout,
            source=source,
            source_port=source_port,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            verify=self.verify,
            post=(not self.want_get),
            http_version=self.http_version,
            session=_get_doh_session(),
        )


def _parse_dot_nameserver(entry: str) -> dns.nameserver.DoTNameserver:
    """
    Parses a ``tls://ip[:port][#hostname]`` nameserver entry.

    The optional ``#hostname`` suffix names the TLS certificate identity to
    use for SNI and verification, matching systemd-resolved's syntax.

    Args:
        entry (str): A ``tls://`` nameserver entry

    Returns:
        dns.nameserver.DoTNameserver: The parsed nameserver

    Raises:
        ValueError: The entry has no host, an unusable port, a host that
            is not a literal IP address, or extra URL components
    """
    parts = urlsplit(entry)
    try:
        port = parts.port
    except ValueError as e:
        # urlsplit only validates the port when it is accessed
        raise ValueError(f"Invalid DNS over TLS nameserver {entry}: {e}") from e
    if parts.username or parts.path or parts.query:
        # Catch tls://9.9.9.9/dns.quad9.net — a plausible slash-for-#
        # typo that would otherwise "work" with no certificate identity
        # and fail only at query time with an opaque TLS error
        raise ValueError(
            f"Invalid DNS over TLS nameserver {entry}: only "
            "tls://ip[:port][#hostname] is supported — the TLS certificate "
            "identity is given after #, not /"
        )
    address = parts.hostname
    if not address:
        raise ValueError(f"Invalid DNS over TLS nameserver {entry}: missing IP address")
    if not dns.inet.is_address(address):
        raise ValueError(
            f"Invalid DNS over TLS nameserver {entry}: {address} is not an IP "
            "address. Use tls://ip[:port][#hostname], where the optional "
            "#hostname is the TLS certificate identity of the server"
        )
    hostname = parts.fragment or None
    if port is None:
        return dns.nameserver.DoTNameserver(address, hostname=hostname)
    return dns.nameserver.DoTNameserver(address, port, hostname=hostname)


def _nameservers_to_resolver_input(
    nameservers: Sequence[str | Nameserver],
) -> list[str | Nameserver]:
    """
    Converts configured nameserver entries into values that
    ``dns.resolver.Resolver.nameservers`` accepts.

    ``https://`` entries become DNS over HTTPS nameservers that share this
    process's ``httpx`` client (so proxy and CA environment variables apply),
    and ``tls://ip[:port][#hostname]`` entries become DNS over TLS
    nameservers. Plain IPv4/IPv6 addresses become plain-DNS (port 53)
    nameservers — the same objects dnspython would build from them itself —
    so that every valid entry has one stable text form for failure tracking
    (see ``_nameserver_key()``). ``dns.nameserver.Nameserver`` objects a
    caller built itself, and strings that are none of the above, are passed
    through untouched, leaving dnspython to validate the latter exactly as
    before.

    Args:
        nameservers (list): The configured nameservers

    Returns:
        list: A list of strings and/or ``dns.nameserver.Nameserver`` objects,
        in the configured order

    Raises:
        ValueError: A ``tls://`` entry is malformed
    """
    resolver_input: list[str | Nameserver] = []
    for entry in nameservers:
        if not isinstance(entry, str):
            resolver_input.append(entry)
            continue
        try:
            # urlsplit lowercases the scheme, so HTTPS:// and TLS:// work too
            scheme = urlsplit(entry).scheme
        except ValueError:
            # e.g. an unbalanced IPv6 bracket; let dnspython reject it with
            # its own message about what a nameserver may be
            scheme = ""
        if scheme == "https":
            resolver_input.append(_SessionDoHNameserver(entry))
        elif scheme == "tls":
            resolver_input.append(_parse_dot_nameserver(entry))
        elif dns.inet.is_address(entry):
            resolver_input.append(dns.nameserver.Do53Nameserver(entry))
        else:
            resolver_input.append(entry)
    return resolver_input


def _nameserver_key(nameserver: str | Nameserver) -> str:
    """
    Returns the identity a nameserver entry is tracked under in
    ``_NAMESERVER_FAILURES``.

    ``_nameservers_to_resolver_input()`` turns every valid entry into a
    ``dns.nameserver.Nameserver`` object whose text form names its transport
    and address (for example ``Do53:1.1.1.1@53``), so the same configured
    entry gets the same key whether it is queried through
    ``dns.resolver.Resolver`` in ``query_dns()`` or directly in
    ``checkdmarc.dnssec``.

    Args:
        nameserver: A nameserver entry

    Returns:
        str: The tracking key
    """
    return str(nameserver)


def _note_nameserver_failure(nameserver: str | Nameserver) -> None:
    """
    Records that a nameserver failed to answer a query, so that
    ``_order_nameservers()`` puts the other configured nameservers ahead of
    it until ``DNS_NAMESERVER_FAILURE_COOLDOWN_SECONDS`` have passed.

    A nameserver that fails is not dropped: it stays in the list and is still
    tried when the others fail, and it gets another turn in front once the
    cool-down expires. That keeps one dropped packet from sidelining a
    healthy server for long, while an unreachable server costs one timeout
    per cool-down period instead of one per query.

    Args:
        nameserver: The nameserver entry that failed
    """
    key = _nameserver_key(nameserver)
    if key not in _NAMESERVER_FAILURES:
        logger.warning(
            f"Nameserver {key} failed to answer a query; the other configured "
            "nameservers will be tried before it for the next "
            f"{DNS_NAMESERVER_FAILURE_COOLDOWN_SECONDS:g} seconds"
        )
    _NAMESERVER_FAILURES[key] = True


def _order_nameservers(
    nameservers: Sequence[str | Nameserver],
) -> list[str | Nameserver]:
    """
    Returns the nameservers in the configured order, except that any that
    recently failed to answer (see ``_note_nameserver_failure()``) are moved
    behind the rest.

    Both query paths — ``query_dns()`` and the direct queries in
    ``checkdmarc.dnssec`` — try nameservers in order and only move on when
    one fails, so without this a nameserver that is down would cost a full
    timeout on every query.

    Args:
        nameservers (list): The configured nameservers

    Returns:
        list: The same entries, with recently failed ones last
    """
    recently_failed = [
        _nameserver_key(nameserver) in _NAMESERVER_FAILURES
        for nameserver in nameservers
    ]
    healthy = [ns for ns, skip in zip(nameservers, recently_failed) if not skip]
    failed = [ns for ns, skip in zip(nameservers, recently_failed) if skip]
    return healthy + failed


class _FailureTrackingNameserver(Nameserver):
    """
    Wraps a nameserver so that a ``dns.resolver.Resolver.resolve()`` call
    reveals which servers raised a transport error along the way.

    dnspython tries nameservers in order and moves on when one fails, but a
    successful answer does not say which servers it skipped past, or why. A
    server that answered SERVFAIL for one name is not broken, so guessing
    from position would demote it unfairly. Observing ``query()`` directly
    records only actual transport failures — timeouts, refused connections,
    malformed replies — for exactly the servers that raised them.

    A truncated UDP reply is not a failure: dnspython retries it over TCP on
    the same server, so ``dns.message.Truncated`` is passed through without
    being recorded. So is anything outside ``_TRANSPORT_ERRORS``, such as a
    programming error in a caller-built ``Nameserver``.
    """

    def __init__(self, nameserver: Nameserver, failed: list[Nameserver]):
        super().__init__()
        self.nameserver = nameserver
        self._failed = failed

    def __str__(self) -> str:
        return str(self.nameserver)

    def kind(self) -> str:
        return self.nameserver.kind()

    def is_always_max_size(self) -> bool:
        return self.nameserver.is_always_max_size()

    def answer_nameserver(self) -> str:
        return self.nameserver.answer_nameserver()

    def answer_port(self) -> int:
        return self.nameserver.answer_port()

    def query(
        self,
        request: dns.message.QueryMessage,
        timeout: float,
        source: str | None,
        source_port: int,
        max_size: bool,
        one_rr_per_rrset: bool = False,
        ignore_trailing: bool = False,
    ) -> dns.message.Message:
        try:
            return self.nameserver.query(
                request,
                timeout,
                source,
                source_port,
                max_size,
                one_rr_per_rrset=one_rr_per_rrset,
                ignore_trailing=ignore_trailing,
            )
        except dns.message.Truncated:
            raise
        except _TRANSPORT_ERRORS:
            # Not handled here — only observed. dnspython's resolve() loop
            # catches every exception from query() and decides what to do
            # with it; this just notes which server it came from.
            self._failed.append(self.nameserver)
            raise


def _resolve_with_failover(
    domain: str,
    record_type: str,
    *,
    nameservers: Sequence[str | Nameserver] | None,
    resolver: dns.resolver.Resolver | None,
    timeout: float,
    retries: int,
) -> dns.resolver.Answer:
    """
    Resolves one name and record type, with the resolver setup, nameserver
    ordering, failure bookkeeping, and retry behavior that every resolver
    based lookup in this package shares.

    When no resolver is supplied, one is built with the configured (or
    system) nameservers ordered by ``_order_nameservers()`` and wrapped in
    ``_FailureTrackingNameserver`` so that every server that raises a
    transport error during the call is recorded with
    ``_note_nameserver_failure()`` — whether the call then succeeds, fails
    with a retryable error, or ends in NXDOMAIN. A retry rebuilds the
    resolver so its nameserver order reflects the failures just recorded.
    A caller-supplied resolver is used as-is and is not reordered.

    Args:
        domain (str): The name to query
        record_type (str): The record type to query for
        nameservers (list): The configured nameservers, or ``None`` for the
                            system resolvers
        resolver (dns.resolver.Resolver): A caller-supplied resolver, or
                                          ``None`` to build one
        timeout (float): Lifetime budget in seconds per configured nameserver
        retries (int): Number of times to retry after a retryable error

    Returns:
        dns.resolver.Answer: The answer
    """
    timeout = float(timeout)
    attempt = 0
    while True:
        failed: list[Nameserver] = []
        active = resolver
        if active is None:
            active = dns.resolver.Resolver()
            configured = active.nameservers if nameservers is None else nameservers
            # Try nameservers that recently failed to answer last; see
            # _order_nameservers()
            ordered = _order_nameservers(_nameservers_to_resolver_input(configured))
            active.nameservers = [
                _FailureTrackingNameserver(ns, failed)
                if isinstance(ns, Nameserver)
                else ns
                for ns in ordered
            ]
            # Cap per-query UDP timeout at 1s so dnspython retries within the
            # lifetime window on transient packet loss — otherwise with a
            # single nameserver and timeout == lifetime, one dropped UDP
            # datagram consumes the whole budget and raises LifetimeTimeout
            # without a retry (dig's default +tries=3 masks this case). With
            # multiple nameservers the same cap lets a slow/broken one fall
            # through.
            active.timeout = min(1.0, timeout)
            if len(active.nameservers) > 1:
                active.lifetime = timeout * len(active.nameservers)
            else:
                active.lifetime = timeout
        try:
            return active.resolve(domain, record_type, lifetime=active.lifetime)
        except _RETRYABLE_DNS_ERRORS:
            attempt += 1
            if attempt > retries:
                raise
        finally:
            for nameserver in failed:
                _note_nameserver_failure(nameserver)


def _txt_cname_conflict_warning(
    name: str,
    record: str,
    *,
    record_kind: str,
    is_record: Callable[[str], bool],
    multiple_records_outcome: str | None,
    lookup: Callable[..., list[str]],
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> str | None:
    """
    Builds a warning when ``name`` holds both the TXT record that was found
    and a CNAME record.

    RFC 1034 section 3.6.2: "If a CNAME RR is present at a node, no other
    data should be present ... This rule also insures that a cached CNAME
    can be used without checking with an authoritative server for other RR
    types." A DNS provider that serves a TXT record for TXT queries and a
    CNAME record for CNAME queries at the same name (seen in the wild at
    ``_dmarc`` names) breaks that rule. A resolver that asks for TXT
    directly gets the local record; one holding the CNAME in its cache
    follows it to the target's record instead; and one returning both
    leaves the receiver with two records for one name, where each
    protocol's multiple-record rule decides the outcome (permerror for
    SPF, no record or no policy for the others). Which record applies
    therefore depends on the receiver. The same holds for every
    TXT-based record this package checks (DMARC, SPF, MTA-STS, SMTP TLS
    Reporting, BIMI); MTA-STS and BIMI even recommend CNAME delegation
    (RFC 8461 section 8.2, BIMI draft section 6.3), so they are the most
    exposed.

    A CNAME on its own is fine: the resolver follows it and the target's
    TXT record is the record. That case is told apart by comparing the
    record that was found with the matching records at the CNAME target;
    when the record came through the CNAME, the target holds exactly that
    one record. A local record identical to the target's single record is
    not reported either, since whichever one a resolver picks, the outcome
    is the same. A target holding the matching record plus another matching
    record is still a conflict: following the CNAME yields several records,
    and each protocol's rule for that case applies instead of one of them
    (``multiple_records_outcome``). More than one CNAME record is a conflict
    outright,
    whatever the targets hold: an alias may have only one canonical name
    (RFC 2181 section 10.1), so no resolver behavior is predictable there.

    Args:
        name (str): The name the record was found at
        record (str): The record that was found there
        record_kind (str): How to call the record in the warning, e.g. "DMARC"
        is_record (callable): Tells whether a TXT record is one of this kind
        multiple_records_outcome (str): What a receiver does when several
            records of this kind remain at one name, as a verb phrase with
            its citation, e.g. ``"returns permerror (RFC 7208 section
            4.5)"``; ``None`` when the spec does not say
        lookup (callable): The caller's ``query_dns``; passing it keeps the
            probe on the same lookup path (and the same test double) as
            the caller's own record lookup
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        str: The warning text, or ``None`` when there is no conflict or the
        lookups needed to tell could not be completed
    """
    try:
        cnames = lookup(
            name,
            "CNAME",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None  # Not an alias
    except (dns.exception.DNSException, OSError) as error:
        # query_dns() re-raises socket-level OSErrors once its retries are
        # used up; this probe is a diagnostic and must not fail the check
        logger.debug(f"CNAME check for {name} failed: {error}")
        return None
    if len(cnames) == 0:
        return None
    if len(cnames) > 1:
        return (
            f"{name} has both a TXT record and {len(cnames)} CNAME records "
            f"({', '.join(cnames)}). A name with a CNAME record must have no "
            "other records (RFC 1034 section 3.6.2), and an alias may have "
            "only one CNAME record (RFC 2181 section 10.1), so which "
            f"{record_kind} record a receiver uses is unpredictable. Remove "
            "the CNAME records or the TXT record."
        )
    cname_target = cnames[0]
    try:
        target_records = lookup(
            cname_target,
            "TXT",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        target_records = []
    except (dns.exception.DNSException, OSError) as error:
        logger.debug(
            f"TXT lookup at {cname_target}, the CNAME target of {name}, failed: {error}"
        )
        return None
    matching = [r for r in target_records if is_record(r)]
    if matching == [record]:
        # Following the CNAME yields exactly the record that was found: an
        # ordinary alias, or a duplicate that changes nothing
        return None
    if len(matching) > 1 and multiple_records_outcome is not None:
        # A receiver that follows the CNAME sees several records at one
        # name, and this spec says what it does then (never "use one of
        # them"), while the local record gives it exactly one
        via_cname = (
            f"whatever follows when {cname_target} publishes {len(matching)} "
            f"{record_kind} records: a receiver {multiple_records_outcome}"
        )
    elif len(matching) > 1:
        # The spec does not say what a receiver does with several records,
        # so do not claim an outcome
        via_cname = (
            f"an unpredictable result, because {cname_target} publishes "
            f"{len(matching)} {record_kind} records"
        )
    elif len(matching) == 1:
        via_cname = f"the {record_kind} record at {cname_target}"
    else:
        via_cname = f"no {record_kind} record at all, because {cname_target} has none"
    if multiple_records_outcome is None:
        both_returned = "or an unpredictable result if both records are returned"
    else:
        both_returned = (
            "or, if both records are returned, the same as for several "
            f"{record_kind} records at one name, where a receiver "
            f"{multiple_records_outcome}"
        )
    return (
        f"{name} has both a TXT record and a CNAME record pointing to "
        f"{cname_target}. A name with a CNAME record must have no other "
        f"records (RFC 1034 section 3.6.2), so which {record_kind} record a "
        f"receiver uses depends on its resolver: the TXT record at {name}, "
        f"{via_cname}, {both_returned}. Remove one of the two records."
    )


def query_dns(
    domain: str,
    record_type: str,
    *,
    quoted_txt_segments: bool = False,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    _attempt: int = 0,
    cache: ExpiringDict | None = None,
) -> list[str]:
    """
    Queries DNS

    Args:
        domain (str): The domain or subdomain to query about
        record_type (str): The record type to query for
        quoted_txt_segments (bool): Preserve quotes in TXT records
        nameservers (list): A list of one or more nameservers to use.
                            Defaults to the system-configured resolvers
                            (``/etc/resolv.conf`` on Linux/macOS, the OS
                            resolver on Windows). For reliability, pass
                            ``RECOMMENDED_DNS_NAMESERVERS`` or your own mix
                            of public resolvers so failover happens when one
                            provider's path is slow or broken. Each entry is
                            an IP address (DNS over UDP/TCP port 53), an
                            ``https://`` URL (DNS over HTTPS, honoring the
                            ``HTTP_PROXY``/``HTTPS_PROXY``/``NO_PROXY`` and
                            ``SSL_CERT_FILE`` environment variables), or
                            ``tls://ip[:port][#hostname]`` (DNS over TLS,
                            port 853 by default, with the optional
                            ``#hostname`` naming the server's TLS
                            certificate identity).
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): Overall DNS lifetime budget in seconds per
                         configured nameserver. Per-query UDP attempts are
                         capped at ``min(1.0, timeout)`` so dnspython retries
                         within the lifetime on transient UDP packet loss
                         (mirroring ``dig``'s default ``+tries=3`` behavior);
                         with multiple nameservers configured this same cap
                         also makes a slow or broken nameserver fall through
                         to the next quickly
        retries (int): Number of times to retry the whole query after a
                       timeout or other transient error (``LifetimeTimeout``,
                       ``NoNameservers``, ``OSError``). Failover between
                       configured nameservers happens within each attempt.
        cache (ExpiringDict): Cache storage

    Returns:
        list: A list of answers
    """
    domain = normalize_domain(domain)
    record_type = record_type.upper()
    cache_key = f"{domain}_{record_type}_{quoted_txt_segments}"
    if cache is None:
        cache = DNS_CACHE
    if isinstance(cache, ExpiringDict):
        records = cache.get(cache_key)
        if isinstance(records, list):
            return records
    answers = _resolve_with_failover(
        domain,
        record_type,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        # _attempt counts attempts already made by an older caller that
        # drove the retries itself
        retries=max(retries - _attempt, 0),
    )
    if record_type == "TXT":
        resource_records = [r.strings for r in answers]
        if quoted_txt_segments:
            # Join each sequence of byte chunks, adding quotes around each
            joined_records = [
                b"".join(b'"' + part + b'"' for part in record)
                for record in resource_records
                if record  # skip empty or None
            ]
        else:
            # Join each sequence of byte chunks into a single bytes object
            joined_records = [
                b"".join(record)
                for record in resource_records
                if record  # skip empty or None
            ]
        records = []
        for r in joined_records:
            try:
                r = r.decode()
            except UnicodeDecodeError:
                r = "Undecodable characters"
            records.append(r)
    else:
        records = [r.to_text().rstrip(".") for r in answers]
    if type(cache) is ExpiringDict:
        cache[cache_key] = records

    return records


def get_a_records(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> list[str]:
    """
    Queries DNS for A and AAAA records

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        list: A sorted list of IPv4 and IPv6 addresses

    Raises:
        :exc:`checkdmarc.DNSException`
    """
    qtypes = ["A", "AAAA"]
    addresses = []
    for qt in qtypes:
        try:
            logger.debug(f"Getting {qt} records for {domain}")
            addresses += query_dns(
                domain,
                qt,
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                retries=retries,
            )
        except dns.resolver.NXDOMAIN:
            raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist.")
        except dns.resolver.NoAnswer:
            # Sometimes a domain will only have A or AAAA records, but not both
            pass
        except dns.exception.DNSException as error:
            raise DNSException(error)

    addresses = sorted(addresses)
    return addresses


def get_reverse_dns(
    ip_address: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> list[str]:
    """
    Queries for an IP address's reverse DNS hostname(s)

    Args:
        ip_address (str): An IPv4 or IPv6 address
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        list: A list of reverse DNS hostnames

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    try:
        name = str(dns.reversename.from_address(ip_address))
        logger.debug(f"Getting PTR records for {ip_address}")
        hostnames = query_dns(
            name,
            "PTR",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
    except dns.resolver.NXDOMAIN:
        return []
    except dns.exception.DNSException as error:
        raise DNSException(error)

    return hostnames


def get_txt_records(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    quoted_txt_segments: bool = False,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> list[str]:
    """
    Queries DNS for TXT records

    Args:
        domain (str): A domain name
        quoted_txt_segments (bool): Preserve quotes in TXT records
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        list: A list of TXT records

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    try:
        records = query_dns(
            domain,
            "TXT",
            quoted_txt_segments=quoted_txt_segments,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist.")
    except dns.resolver.NoAnswer:
        raise DNSException(f"The domain {domain} does not have any TXT records.")
    except dns.exception.DNSException as error:
        raise DNSException(error)

    return records


def get_soa_record(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> str:
    """
    Queries DNS for an SOA record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        str: An SOA record

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    # Every zone has its own SOA record at its top (RFC 2181 section 7), and
    # a delegated child zone (e.g. cl.cam.ac.uk inside cam.ac.uk) is its own
    # zone. Walk from the domain itself up through each ancestor to the
    # registered/base domain, returning the first SOA found, so a delegated
    # zone between the queried name and the base domain (cl.cam.ac.uk
    # between www.cl.cam.ac.uk and cam.ac.uk) is not skipped.
    domain = normalize_domain(domain)
    base_domain = get_base_domain(domain)
    labels = domain.split(".")
    base_label_count = len(base_domain.split("."))
    candidates = [
        ".".join(labels[i:]) for i in range(max(1, len(labels) - base_label_count + 1))
    ]
    last_error_was_nxdomain = False
    for candidate in candidates:
        try:
            return query_dns(
                candidate,
                "SOA",
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                retries=retries,
            )[0]
        except dns.resolver.NXDOMAIN:
            last_error_was_nxdomain = True
        except dns.resolver.NoAnswer:
            last_error_was_nxdomain = False
        except dns.exception.DNSException as error:
            raise DNSException(error)
    if last_error_was_nxdomain:
        raise DNSExceptionNXDOMAIN(f"The domain {base_domain} does not exist.")
    raise DNSException(f"The domain {base_domain} does not have an SOA record.")


def get_nameservers(
    domain: str,
    *,
    approved_nameservers: Sequence[str | Nameserver] | None = None,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> NameserverResultOk:
    """
    Gets a list of nameservers for a given domain

    Args:
        domain (str): A domain name
        approved_nameservers (list): A list of approved nameserver substrings
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: A dictionary with the following keys:
                     - ``hostnames`` - A list of nameserver hostnames
                     - ``warnings``  - A list of warnings
    """
    logger.debug(f"Getting NS records on {domain}")
    warnings = []

    ns_records = []
    try:
        ns_records = query_dns(
            domain,
            "NS",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist.")
    except dns.resolver.NoAnswer:
        pass
    except dns.exception.DNSException as error:
        raise DNSException(error)

    approved_substrings = None
    if approved_nameservers:
        approved_substrings = [str(h).lower() for h in approved_nameservers]
    for ns_hostname in ns_records:
        if approved_substrings:
            approved = False
            for approved_substring in approved_substrings:
                if approved_substring in ns_hostname.lower():
                    approved = True
                    break
            if not approved:
                warnings.append(f"Unapproved nameserver: {ns_hostname}")

    result: NameserverResultOk = {"hostnames": ns_records, "warnings": warnings}
    return result


# One label (dot-separated part) of a hostname: it starts and ends with a
# letter or digit and may contain hyphens in between, up to 63 characters
# total (RFC 5321 sections 2.3.5 and 4.1.2; the length cap is from RFC 1035
# section 2.3.4). Underscores and leading/trailing hyphens are not allowed.
_HOSTNAME_LABEL_REGEX = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class MXRecordSet(TypedDict):
    """Everything learned from a domain's MX lookup: the usable hosts,
    warnings about problems in the records themselves, and whether the
    domain published a null MX record (RFC 7505) declaring that it does
    not accept mail."""

    hosts: list[MXHost]
    warnings: list[str]
    null_mx: bool
    record_count: int


def _is_valid_mx_hostname(hostname: str) -> bool:
    """Returns True if every label of the hostname follows RFC 5321
    section 2.3.5 hostname syntax."""
    return all(
        _HOSTNAME_LABEL_REGEX.match(label) is not None for label in hostname.split(".")
    )


def _resolve_mx_rdatas(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> list[tuple[int, str]]:
    """
    Queries DNS for a domain's MX records and returns
    ``(preference, exchange)`` pairs read from dnspython's parsed answer
    objects. Each exchange keeps its absolute form (trailing dot), so a
    null MX target is exactly ``"."``.

    MX answers get their own query path instead of ``query_dns()`` because
    that function flattens answers to text and strips trailing dots, which
    turns the null MX ``"0 ."`` into the ambiguous ``"0 "``. Resolver
    setup, nameserver failover, and retries are shared with ``query_dns()``
    through ``_resolve_with_failover()``; caching mirrors it.
    """
    domain = normalize_domain(domain)
    cache_key = f"{domain}_MX_parsed"
    cached = DNS_CACHE.get(cache_key)
    if isinstance(cached, list):
        return cached
    answers = _resolve_with_failover(
        domain,
        "MX",
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        retries=retries,
    )
    records = [(int(rdata.preference), rdata.exchange.to_text()) for rdata in answers]
    DNS_CACHE[cache_key] = records
    return records


def get_mx_record_set(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> MXRecordSet:
    """
    Queries DNS for a domain's Mail Exchange records, validates them, and
    reports what the records mean

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: A dictionary with the following keys:

              - ``hosts`` - A list of ``dicts``; each containing a
                ``preference`` integer and a ``hostname``
              - ``warnings`` - Warnings about the MX records themselves
              - ``null_mx`` - True when the domain publishes only a null MX
                record (``0 .``), meaning it explicitly does not accept
                mail (RFC 7505)
              - ``record_count`` - The number of MX records in the DNS
                answer, including null and malformed records that do not
                become ``hosts`` entries

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    hosts: list[MXHost] = []
    warnings: list[str] = []
    null_mx = False
    logger.debug(f"Checking for MX records on {domain}")
    try:
        answers = _resolve_mx_rdatas(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
    except dns.resolver.NXDOMAIN:
        raise DNSExceptionNXDOMAIN(f"The domain {domain} does not exist.")
    except dns.resolver.NoAnswer:
        answers = []
    except dns.exception.DNSException as error:
        raise DNSException(error)
    # Records whose target is the DNS root (".") are not real mail hosts:
    # with preference 0 that is the RFC 7505 null MX ("this domain does not
    # accept mail"); with any other preference it is simply malformed.
    # Either way the record must not become a host entry.
    root_target_records = [(p, x) for (p, x) in answers if x == "."]
    named_records = [(p, x) for (p, x) in answers if x != "."]
    for preference, _exchange in root_target_records:
        if preference != 0:
            warnings.append(
                f"The MX record '{preference} .' on {domain} is malformed: "
                "a root (.) target is only valid in a null MX record, "
                "which must use preference 0 (RFC 7505 section 3)"
            )
    if any(preference == 0 for (preference, _) in root_target_records):
        if len(answers) > 1:
            # RFC 7505 section 3: "A domain that advertises a null MX
            # MUST NOT advertise any other MX RR." Any additional record —
            # named or another root target — invalidates the null MX.
            warnings.append(
                f"{domain} advertises a null MX record (0 .) alongside "
                "other MX records; RFC 7505 section 3 requires the null MX "
                "to be the only MX record"
            )
        else:
            logger.debug('"No Service" (null MX) record found')
            null_mx = True
    for preference, exchange in named_records:
        hostname = exchange.rstrip(".").lower()
        # RFC 5321 section 5.1: the MX data field must be a domain name,
        # never an IP address literal.
        if dns.inet.is_address(hostname.strip("[]")):
            warnings.append(
                f"The MX record for {domain} points at the IP address "
                f"{hostname}; RFC 5321 section 5.1 requires MX records "
                "to point at a domain name"
            )
        elif not _is_valid_mx_hostname(hostname):
            warnings.append(
                f"The MX hostname {hostname} for {domain} is not valid "
                "hostname syntax: each dot-separated part must contain "
                "only letters, digits, and interior hyphens "
                "(RFC 5321 section 2.3.5)"
            )
        hosts.append({"preference": preference, "hostname": hostname})
    hosts = sorted(hosts, key=lambda h: (h["preference"], h["hostname"]))
    results: MXRecordSet = {
        "hosts": hosts,
        "warnings": warnings,
        "null_mx": null_mx,
        "record_count": len(answers),
    }
    return results


def get_mx_records(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> list[MXHost]:
    """
    Queries DNS for a list of Mail Exchange hosts

    Use :func:`get_mx_record_set` instead when the warnings about the
    records or the null MX status are needed; this function returns only
    the hosts (an empty list for a domain with a null MX record).

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        list: A list of ``dicts``; each containing a ``preference``
                        integer and a ``hostname``

    Raises:
        :exc:`checkdmarc.DNSException`

    """
    return get_mx_record_set(
        domain,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        retries=retries,
    )["hosts"]
