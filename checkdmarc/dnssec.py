"""DNSSEC tests"""

from __future__ import annotations

import logging
import warnings
from collections.abc import Sequence

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import httpx
from dns.dnssectypes import DSDigest
from dns.nameserver import Nameserver
from dns.rdatatype import RdataType
from expiringdict import ExpiringDict

from checkdmarc._constants import (
    DEFAULT_DNS_TIMEOUT,
    DNSSEC_CACHE_MAX_AGE_SECONDS,
    DNSSEC_CACHE_MAX_LEN,
)
from checkdmarc.utils import (
    _nameservers_to_resolver_input,
    get_base_domain,
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

logger = logging.getLogger(__name__)

DNSSEC_CACHE = ExpiringDict(
    max_len=DNSSEC_CACHE_MAX_LEN, max_age_seconds=DNSSEC_CACHE_MAX_AGE_SECONDS
)
DNSKEY_CACHE = ExpiringDict(
    max_len=DNSSEC_CACHE_MAX_LEN, max_age_seconds=DNSSEC_CACHE_MAX_AGE_SECONDS
)
TLSA_CACHE = ExpiringDict(
    max_len=DNSSEC_CACHE_MAX_LEN, max_age_seconds=DNSSEC_CACHE_MAX_AGE_SECONDS
)


# Errors that mean one nameserver could not answer and the next one should be
# tried. ssl.SSLError is an OSError subclass, so DNS over TLS handshake
# failures are covered; httpx.HTTPError covers DNS over HTTPS transport
# failures (connection, proxy, and timeout errors).
_TRANSPORT_ERRORS = (dns.exception.DNSException, OSError, EOFError, httpx.HTTPError)


def _query_nameserver(
    request: dns.message.QueryMessage,
    nameserver: str | Nameserver,
    timeout: float,
) -> dns.message.Message:
    """
    Sends one DNS query to one nameserver, honoring its transport.

    A ``dns.nameserver.Nameserver`` object — such as the DNS over HTTPS and
    DNS over TLS nameservers that ``https://`` and ``tls://`` entries map to —
    is queried through its own ``query()`` method, with ``max_size=True`` so
    a plain-DNS ``Do53Nameserver`` uses TCP, matching the direct
    ``dns.query.tcp()`` call used for plain string entries. DNSSEC answers
    carry signatures that routinely overflow a UDP datagram.

    Args:
        request (dns.message.QueryMessage): The query to send
        nameserver: An IP address string or a ``dns.nameserver.Nameserver``
        timeout (float): Timeout in seconds

    Returns:
        dns.message.Message: The response
    """
    if isinstance(nameserver, Nameserver):
        return nameserver.query(
            request, timeout, source=None, source_port=0, max_size=True
        )
    return dns.query.tcp(request, str(nameserver), timeout=timeout)


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


def _query_rrset(
    domain: str,
    rdatatype: RdataType,
    nameservers: Sequence[str | Nameserver],
    timeout: float,
) -> tuple[dns.rrset.RRset | None, dns.rrset.RRset | None, dns.message.Message | None]:
    """
    Query one record type at one name, asking for DNSSEC signatures

    Nameservers are tried in order until one answers; a transport failure
    moves on to the next entry. The raw response is returned alongside the
    record set and its signature so the caller can inspect the response code
    and flags — a SERVFAIL from a validating resolver carries meaning that an
    empty answer does not.

    Args:
        domain (str): The name to query
        rdatatype (RdataType): The record type to query
        nameservers (list): A list of nameservers to query
        timeout (float): Timeout in seconds

    Returns:
        tuple: The record set, the RRSIG covering it, and the raw response.
        All three are ``None`` when no nameserver answered; the first two are
        ``None`` when the response does not contain them.
    """
    request = dns.message.make_query(domain, rdatatype, want_dnssec=True)
    name = dns.name.from_text(domain)
    for nameserver in nameservers:
        try:
            response = _query_nameserver(request, nameserver, timeout)
        except _TRANSPORT_ERRORS as e:
            logger.debug(f"{rdatatype.name} query error at {domain}: {e}")
            continue
        if response is None:
            continue
        rrset, rrsig = _find_record_and_signature(response.answer, name, rdatatype)
        return rrset, rrsig, response
    return None, None, None


def _ds_matched_keys(
    zone_name: dns.name.Name,
    ds_rrset: dns.rrset.RRset,
    dnskey_rrset: dns.rrset.RRset,
) -> dns.rrset.RRset:
    """
    Find the DNSKEYs that the parent zone's DS records vouch for

    Per RFC 4035 section 5.2, a DS record authenticates a DNSKEY when a
    digest of that key, computed with the DS record's digest algorithm,
    matches the digest the DS record carries. Each key is digested with
    ``dns.dnssec.make_ds`` and compared against each DS record; keys with
    a digest algorithm this host cannot compute are skipped rather than
    treated as matches.

    Args:
        zone_name (dns.name.Name): The zone apex the records belong to
        ds_rrset (dns.rrset.RRset): The DS records from the parent zone
        dnskey_rrset (dns.rrset.RRset): The zone's DNSKEY records

    Returns:
        dns.rrset.RRset: The keys a DS record matches (empty when none do)
    """
    matched = dns.rrset.RRset(zone_name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    for ds in ds_rrset:
        for key in dnskey_rrset:
            try:
                computed = dns.dnssec.make_ds(
                    zone_name, key, DSDigest(ds.digest_type), validating=True
                )
            except (
                # An undefined digest type number
                ValueError,
                # A digest type dnspython cannot compute (e.g. GOST)
                dns.exception.UnsupportedAlgorithm,
                # A digest type policy forbids validating with (NULL)
                dns.exception.DeniedByPolicy,
            ) as e:
                logger.debug(f"Skipping DS digest comparison for {zone_name}: {e}")
                continue
            if computed == ds:
                matched.add(key)
    return matched


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
    nameservers = _nameservers_to_resolver_input(nameservers)
    if cache is None:
        cache = DNSKEY_CACHE

    domain = normalize_domain(domain)

    if domain in cache:
        cached_result = cache[domain]
        if isinstance(cached_result, dict):
            return cached_result

    logger.debug(f"Checking for DNSKEY records at {domain}")
    request = dns.message.make_query(domain, dns.rdatatype.DNSKEY, want_dnssec=True)
    for nameserver in nameservers:
        try:
            response = _query_nameserver(request, nameserver, timeout)
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
                    logger.debug(f"No DNSKEY records found at {domain}")
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
        except _TRANSPORT_ERRORS as e:
            cache[domain] = None
            logger.debug(f"DNSKEY query error: {e}")


def check_dnssec(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    cache: ExpiringDict | None = None,
) -> bool:
    """
    Check that DNSSEC protects the given domain's records

    ``True`` means the chain from the parent zone held together when this
    function checked it directly:

    - The parent zone publishes a DS record for the domain's zone (the
      domain itself, or its base domain when the domain is not a zone apex)
    - The zone's DNSKEY record set contains a key whose digest matches that
      DS record (RFC 4034 section 5)
    - The signature over the DNSKEY record set verifies against a DS-matched
      key (RFC 4035 section 5)
    - For a domain below the zone apex, a record set at the domain itself
      carries a signature that verifies against those keys

    ``False`` covers every other outcome, and the log tells them apart: an
    unsigned zone (no DS record at the parent — including a zone that
    publishes a DNSKEY anyway, which validating resolvers treat as unsigned
    per RFC 4033 section 4.3), a broken zone whose parent publishes a DS
    record that its keys or signatures do not live up to (logged as a
    warning, because mail from such a domain is rejected by receivers that
    validate), and a lookup that could not complete (not cached).

    Trust assumptions: the DS record itself arrives over an unauthenticated
    channel unless the configured resolver validates (the AD flag on its
    answers, logged at debug level, says whether it claims to). This is a
    one-level chain check anchored at the DS record the resolver reports,
    not a full validator walking signatures down from the root, so a
    resolver — or an attacker able to spoof its answers — that forges the DS
    record along with everything below it would not be caught.

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
    nameservers = _nameservers_to_resolver_input(nameservers)
    # get_dnskey keeps its own module-level cache; only hand it a cache the
    # caller supplied, so caller-isolated caches stay isolated.
    dnskey_cache = cache
    if cache is None:
        cache = DNSSEC_CACHE

    domain = normalize_domain(domain)
    if domain in cache:
        cached_result = cache[domain]
        if isinstance(cached_result, bool):
            return cached_result

    # Find the zone the parent vouches for by walking from the domain
    # itself up through each ancestor to the base domain and using the
    # first (deepest) name with a DS record. A delegated signed zone
    # between the queried name and the base domain (for example
    # signed-child.example.com under www.signed-child.example.com) holds
    # the keys that actually sign the name's records, so jumping straight
    # to the base domain would validate against the wrong keys.
    base_domain = get_base_domain(domain)
    labels = domain.split(".")
    base_label_count = len(base_domain.split("."))
    candidates = [
        ".".join(labels[i:]) for i in range(max(1, len(labels) - base_label_count + 1))
    ]
    zone = candidates[-1]
    ds_rrset = None
    ds_response = None
    for candidate in candidates:
        logger.debug(f"Checking for DS records at {candidate}")
        ds_rrset, _, ds_response = _query_rrset(
            candidate, RdataType.DS, nameservers, timeout
        )
        if (
            ds_response is None
            or ds_response.rcode() == dns.rcode.SERVFAIL
            or ds_rrset is not None
        ):
            zone = candidate
            break
    if ds_response is None:
        logger.warning(
            f"Could not check DNSSEC for {domain}: no nameserver answered the DS query"
        )
        return False
    if ds_rrset is None:
        if ds_response.rcode() == dns.rcode.SERVFAIL:
            logger.warning(
                f"Could not check DNSSEC for {domain}: "
                f"the DS query for {zone} failed with SERVFAIL"
            )
            return False
        # A clean empty answer: the parent does not vouch for this zone, so
        # it is unsigned/insecure no matter what keys it publishes
        # (RFC 4033 section 4.3).
        key = get_dnskey(
            domain, nameservers=nameservers, timeout=timeout, cache=dnskey_cache
        )
        if key is not None:
            logger.warning(
                f"{zone} publishes a DNSKEY record, but its parent zone "
                f"publishes no DS record for it, so validating resolvers "
                f"treat the zone as unsigned (RFC 4033 section 4.3)"
            )
        else:
            logger.debug(
                f"{zone} is not signed: no DS record at its parent and no DNSKEY record"
            )
        cache[domain] = False
        return False

    zone_name = dns.name.from_text(zone)
    logger.debug(f"Found DS records for {zone}; checking its DNSKEY against them")
    dnskey_rrset, dnskey_rrsig, key_response = _query_rrset(
        zone, RdataType.DNSKEY, nameservers, timeout
    )
    if key_response is None:
        logger.warning(
            f"Could not check DNSSEC for {domain}: "
            f"no nameserver answered the DNSKEY query"
        )
        return False
    if key_response.rcode() == dns.rcode.SERVFAIL:
        logger.warning(
            f"DNSSEC for {zone} is broken: its parent zone publishes a DS "
            f"record, but the DNSKEY query failed with SERVFAIL — a "
            f"validating resolver rejected the zone as bogus"
        )
        cache[domain] = False
        return False
    if dnskey_rrset is None or dnskey_rrsig is None:
        logger.warning(
            f"DNSSEC for {zone} is broken: its parent zone publishes a DS "
            f"record, but {zone} did not answer with a signed DNSKEY "
            f"record set"
        )
        cache[domain] = False
        return False
    if key_response.flags & dns.flags.AD:
        logger.debug(
            f"The resolver set the AD flag on the {zone} DNSKEY answer: "
            f"it validated the answer itself"
        )

    matched_keys = _ds_matched_keys(zone_name, ds_rrset, dnskey_rrset)
    if len(matched_keys) == 0:
        logger.warning(
            f"DNSSEC for {zone} is broken: no key in its DNSKEY record set "
            f"matches a DS record at its parent"
        )
        cache[domain] = False
        return False
    try:
        dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {zone_name: matched_keys})
    except dns.exception.ValidationFailure as e:
        logger.warning(
            f"DNSSEC for {zone} is broken: the signature over its DNSKEY "
            f"record set does not verify against the DS-matched key: {e}"
        )
        cache[domain] = False
        return False
    logger.debug(
        f"The {zone} DNSKEY record set matches a DS record at its parent "
        f"and its signature verifies"
    )

    if zone == domain:
        # The domain is the zone apex, and its DNSKEY record set — one of
        # the zone's own record sets — just validated against the parent's
        # DS record.
        cache[domain] = True
        return True

    # The domain sits below the zone apex, so DNSSEC only covers it if its
    # own records carry signatures that verify against the zone's keys.
    keyring = {zone_name: dnskey_rrset}
    rdatatypes = [
        dns.rdatatype.MX,
        dns.rdatatype.A,
        dns.rdatatype.NS,
        dns.rdatatype.CNAME,
    ]
    for rdatatype in rdatatypes:
        rrset, rrsig, response = _query_rrset(domain, rdatatype, nameservers, timeout)
        if response is not None and response.rcode() == dns.rcode.SERVFAIL:
            logger.warning(
                f"DNSSEC for {domain} is broken: the {rdatatype.name} query "
                f"failed with SERVFAIL below the signed zone {zone} — a "
                f"validating resolver rejected the answer as bogus"
            )
            cache[domain] = False
            return False
        if rrset is None or rrsig is None:
            continue
        try:
            dns.dnssec.validate(rrset, rrsig, keyring)
        except dns.exception.ValidationFailure as e:
            logger.warning(
                f"The signature over the {rdatatype.name} record set at "
                f"{domain} does not verify against the {zone} keys: {e}"
            )
            continue
        logger.debug(f"Found a signed {rdatatype.name} record")
        cache[domain] = True
        return True

    logger.debug(f"{zone} is signed, but no signed records were found at {domain}")
    cache[domain] = False
    return False


def test_dnssec(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    cache: ExpiringDict | None = None,
) -> bool:
    """Deprecated alias for :func:`check_dnssec`"""
    warnings.warn(
        "test_dnssec() is deprecated; use check_dnssec()",
        DeprecationWarning,
        stacklevel=2,
    )
    return check_dnssec(domain, nameservers=nameservers, timeout=timeout, cache=cache)


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
        hostname (str): The hostname to check
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
    nameservers = _nameservers_to_resolver_input(nameservers)
    protocol = protocol.lower()
    # get_dnskey keeps its own module-level cache; only hand it a cache the
    # caller supplied, so caller-isolated caches stay isolated.
    dnskey_cache = cache
    if cache is None:
        cache = TLSA_CACHE

    query_hostname = f"_{port}._{protocol}.{hostname}"
    if query_hostname in cache:
        cached_results = cache[query_hostname]
        if isinstance(cached_results, list):
            return cached_results
    tlsa_records: list[str] = []
    logger.debug(f"Checking for TLSA records at {query_hostname}")
    request = dns.message.make_query(
        query_hostname, dns.rdatatype.TLSA, want_dnssec=True
    )
    if len(nameservers) == 0:
        raise ValueError("At least one nameserver is required")
    for nameserver in nameservers:
        try:
            response = _query_nameserver(request, nameserver, timeout)
            if response is not None:
                rrset, rrsig = _find_record_and_signature(
                    response.answer,
                    dns.name.from_text(query_hostname),
                    RdataType.TLSA,
                )
                if rrset is None or rrsig is None:
                    return tlsa_records
                dnskey = get_dnskey(
                    domain=hostname,
                    nameservers=nameservers,
                    timeout=timeout,
                    cache=dnskey_cache,
                )
                if dnskey is None:
                    logger.debug(
                        f"Found TLSA records at {hostname} but not "
                        f"a DNSKEY record to verify them"
                    )
                    return tlsa_records
                dns.dnssec.validate(rrset, rrsig, dnskey)
                tlsa_records = [str(x) for x in list(rrset.items.keys())]
                cache[query_hostname] = tlsa_records
                return tlsa_records
        except _TRANSPORT_ERRORS as e:
            logger.debug(f"TLSA query error: {e}")
            return tlsa_records
    return tlsa_records
