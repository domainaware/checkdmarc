"""Tests for checkdmarc.dnssec"""

import os
import unittest
from typing import ClassVar, cast
from unittest.mock import MagicMock, patch

import dns.dnssec
import dns.exception
import dns.flags
import dns.name
import dns.rcode
import dns.rdatatype
import dns.rrset
import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from dns.dnssectypes import Algorithm
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from expiringdict import ExpiringDict

import checkdmarc.dnssec
import checkdmarc.utils

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"

network_test = unittest.skipIf(
    OFFLINE_MODE, "Real-network test skipped on GitHub Actions"
)
mocked_only = unittest.skipUnless(
    OFFLINE_MODE, "Mocked counterpart skipped locally; network test covers this"
)

# A syntactically valid DNSKEY and RRSIG. Nothing here has to verify
# cryptographically; these exist so the code under test sorts real record sets
# by name and type instead of by their position in the answer.
DNSKEY_RDATA = "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
TLSA_RDATA = "3 1 1 " + "ab" * 32


def _rrsig(
    name: str, covered_type: str, signer: str = "example.com."
) -> dns.rrset.RRset:
    """Build an RRSIG record set covering the given record type"""
    return dns.rrset.from_text(
        name,
        300,
        "IN",
        "RRSIG",
        f"{covered_type} 13 2 300 20990101000000 20200101000000 1234 {signer} ab==",
    )


def _response(*rrsets: dns.rrset.RRset, rcode: int = dns.rcode.NOERROR) -> MagicMock:
    """A stand-in DNS response; its answer section, response code, and
    flags are read"""
    response = MagicMock()
    response.answer = list(rrsets)
    response.rcode.return_value = rcode
    response.flags = 0
    return response


def _matching_ds(zone: str) -> dns.rrset.RRset:
    """A DS record set whose digest really matches DNSKEY_RDATA at the zone

    Computed with the same dns.dnssec.make_ds call the code under test uses,
    so the DS-to-DNSKEY comparison in check_dnssec exercises real hashing.
    """
    key_rrset = dns.rrset.from_text(zone, 300, "IN", "DNSKEY", DNSKEY_RDATA)
    ds = dns.dnssec.make_ds(dns.name.from_text(zone), next(iter(key_rrset)), "SHA256")
    return dns.rrset.from_text(zone, 300, "IN", "DS", ds.to_text())


# A DS record with a well-formed but wrong digest: no DNSKEY hashes to it
MISMATCHED_DS_RDATA = "12345 13 2 " + "ab" * 32


def _signed_zone(zone: str) -> tuple[dns.rrset.RRset, dns.rrset.RRset, dns.rrset.RRset]:
    """A freshly generated zone key with a real signature and matching DS

    Returns the DS, DNSKEY, and RRSIG(DNSKEY) record sets. Everything
    verifies cryptographically, so tests built on this need no patch on
    dns.dnssec.validate.
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    name = dns.name.from_text(zone)
    dnskey = dns.dnssec.make_dnskey(
        private_key.public_key(), Algorithm.ECDSAP256SHA256, flags=257
    )
    key_rrset = dns.rrset.from_rdata(name, 300, dnskey)
    rrsig = dns.dnssec.sign(key_rrset, private_key, name, dnskey, lifetime=3600)
    sig_rrset = dns.rrset.from_rdata(name, 300, rrsig)
    ds = dns.dnssec.make_ds(name, dnskey, "SHA256")
    ds_rrset = dns.rrset.from_text(zone, 300, "IN", "DS", ds.to_text())
    return ds_rrset, key_rrset, sig_rrset


def _cname_chain() -> tuple[dns.rrset.RRset, dns.rrset.RRset]:
    """The answer shape from issue #265: a name pointing at another name

    Two record sets, neither of them a signature. Code that assumes a
    two-record answer is always "one record plus its signature" pairs the
    second link of the chain with a missing signature.
    """
    return (
        dns.rrset.from_text(
            "aws.amazon.com.", 60, "IN", "CNAME", "tp.frontier.amazon.com."
        ),
        dns.rrset.from_text(
            "tp.frontier.amazon.com.", 60, "IN", "CNAME", "d123.cloudfront.net."
        ),
    )


def _fresh_cache() -> ExpiringDict:
    return ExpiringDict(max_len=10, max_age_seconds=60)


class TestFindRecordAndSignature(unittest.TestCase):
    def testPairsRecordWithItsSignature(self):
        """A record and the signature covering it are returned together"""
        a = dns.rrset.from_text("example.com.", 300, "IN", "A", "192.0.2.1")
        sig = _rrsig("example.com.", "A")
        rrset, rrsig = checkdmarc.dnssec._find_record_and_signature(
            [a, sig], dns.name.from_text("example.com"), dns.rdatatype.A
        )
        self.assertIs(rrset, a)
        self.assertIs(rrsig, sig)

    def testIgnoresRecordsForOtherNames(self):
        """Records further along a chain belong to another name and are skipped"""
        first, second = _cname_chain()
        rrset, rrsig = checkdmarc.dnssec._find_record_and_signature(
            [first, second], dns.name.from_text("aws.amazon.com"), dns.rdatatype.CNAME
        )
        self.assertIs(rrset, first)
        self.assertIsNone(rrsig)

    def testIgnoresSignatureCoveringAnotherType(self):
        """An RRSIG over a different record type is not treated as a match"""
        mx = dns.rrset.from_text(
            "example.com.", 300, "IN", "MX", "10 mail.example.com."
        )
        rrset, rrsig = checkdmarc.dnssec._find_record_and_signature(
            [mx, _rrsig("example.com.", "A")],
            dns.name.from_text("example.com"),
            dns.rdatatype.MX,
        )
        self.assertIs(rrset, mx)
        self.assertIsNone(rrsig)

    def testNameMatchIsCaseInsensitive(self):
        """DNS names are case-insensitive, so casing must not defeat the match"""
        a = dns.rrset.from_text("Example.COM.", 300, "IN", "A", "192.0.2.1")
        rrset, _ = checkdmarc.dnssec._find_record_and_signature(
            [a, _rrsig("example.com.", "A")],
            dns.name.from_text("example.com"),
            dns.rdatatype.A,
        )
        self.assertIs(rrset, a)


class Test(unittest.TestCase):
    @network_test
    def testDNSSEC(self):
        """Test known good DNSSEC"""
        self.assertEqual(checkdmarc.dnssec.check_dnssec("fbi.gov"), True)

    @network_test
    def testDNSSECKnownGood(self):
        """A zone with a valid DS-to-DNSKEY chain reports True"""
        self.assertEqual(checkdmarc.dnssec.check_dnssec("ietf.org"), True)

    @network_test
    def testDNSSECUnsignedDomain(self):
        """A well-known unsigned zone reports False"""
        self.assertEqual(checkdmarc.dnssec.check_dnssec("amazon.com"), False)

    @network_test
    def testDNSSECDeliberatelyBrokenDomain(self):
        """dnssec-failed.org is deliberately broken and must report False

        This is the chain-of-trust check: the zone's own answers are
        internally consistent, so only comparing its DNSKEY against the DS
        record its parent publishes exposes the break. It must fail through
        any resolver, validating or not, and say why in a warning.
        """
        with self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs:
            result = checkdmarc.dnssec.check_dnssec("dnssec-failed.org")
        self.assertFalse(result)
        self.assertTrue(any("dnssec-failed.org" in line for line in logs.output))

    @network_test
    def testDNSSECNameChainDoesNotRaise(self):
        """A name that points at an unsigned name reports no DNSSEC

        Regression test for issue #265: aws.amazon.com answers with a chain of
        names rather than with records of its own.
        """
        self.assertEqual(
            checkdmarc.dnssec.check_dnssec("aws.amazon.com", nameservers=["1.1.1.1"]),
            False,
        )

    @mocked_only
    def testDNSSECMocked(self):
        """check_dnssec returns True when the DS, DNSKEY, and signature all
        line up (mocked network, real cryptography)"""
        ds, key, sig = _signed_zone("example.com.")
        with patch(
            "dns.query.tcp",
            side_effect=[_response(ds), _response(key, sig)],
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", cache=_fresh_cache(), nameservers=["192.0.2.1"]
            )
        self.assertTrue(result)

    def testDnssecFalseWhenNoKey(self):
        """check_dnssec returns False when the zone has no DS and no DNSKEY"""
        with patch("dns.query.tcp", return_value=_response()):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", cache=_fresh_cache(), nameservers=["192.0.2.1"]
            )
        self.assertFalse(result)

    def testGetDnskeyCache(self):
        """get_dnskey uses cache"""
        cache = _fresh_cache()
        mock_key = {"test": "data"}
        cache["example.com"] = mock_key
        result = checkdmarc.dnssec.get_dnskey("example.com", cache=cache)
        self.assertEqual(result, mock_key)


class TestGetDnskey(unittest.TestCase):
    def testFound(self):
        """A DNSKEY answer at the apex is returned as a dict keyed by dns.name"""
        rrset = dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", DNSKEY_RDATA)
        response = _response(rrset, _rrsig("example.com.", "DNSKEY"))

        with patch("dns.query.tcp", return_value=response):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        assert result is not None  # narrow Optional for pyright
        self.assertEqual(result, {dns.name.from_text("example.com."): rrset})

    def testEmptyAnswerAtApexReturnsNone(self):
        """If the apex has no DNSKEY answer, get_dnskey returns None"""
        with patch("dns.query.tcp", return_value=_response()):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertIsNone(result)

    def testNameChainAnswerIsNotMistakenForAKey(self):
        """A chain of names in a DNSKEY answer must not be returned as a key

        The apex here is the queried name, so there is nowhere left to fall
        back to and the answer holds no key.
        """
        with patch("dns.query.tcp", return_value=_response(*_cname_chain())):
            result = checkdmarc.dnssec.get_dnskey(
                "amazon.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertIsNone(result)

    def testNameChainAtSubdomainRecursesToBase(self):
        """A subdomain answering with a chain of names falls back to the base domain"""
        key = dns.rrset.from_text("amazon.com.", 300, "IN", "DNSKEY", DNSKEY_RDATA)
        with patch(
            "dns.query.tcp",
            side_effect=[_response(*_cname_chain()), _response(key)],
        ):
            result = checkdmarc.dnssec.get_dnskey(
                "aws.amazon.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertEqual(result, {dns.name.from_text("amazon.com."): key})

    def testEmptyAnswerAtSubdomainRecursesToBase(self):
        """A subdomain with no DNSKEY records recurses up to the base domain"""
        key = dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", DNSKEY_RDATA)
        with patch("dns.query.tcp", side_effect=[_response(), _response(key)]):
            result = checkdmarc.dnssec.get_dnskey(
                "sub.example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertEqual(result, {dns.name.from_text("example.com."): key})

    def testRecursionUsesTheCallersCache(self):
        """The base domain result is stored in the cache the caller passed in

        Without this the recursive lookup falls back to the module-level cache,
        so the caller's cache stays empty and results leak between callers.
        """
        cache = _fresh_cache()
        key = dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", DNSKEY_RDATA)
        with patch("dns.query.tcp", side_effect=[_response(), _response(key)]):
            checkdmarc.dnssec.get_dnskey(
                "sub.example.com", nameservers=["1.1.1.1"], cache=cache
            )
        self.assertEqual(
            cache["example.com"], {dns.name.from_text("example.com."): key}
        )
        self.assertNotIn("example.com", checkdmarc.dnssec.DNSKEY_CACHE)

    def testQueryExceptionIsNotCached(self):
        """A lookup that never completed says nothing about whether the
        zone is signed, so it returns None without caching a negative
        result that would stick for the life of the cache entry"""
        cache = _fresh_cache()
        with patch("dns.query.tcp", side_effect=OSError("boom")):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com", nameservers=["1.1.1.1"], cache=cache
            )
        self.assertIsNone(result)
        self.assertNotIn("example.com", cache)

    def testUnusableRcodeTriesTheNextNameserver(self):
        """A nameserver answering REFUSED could not answer; it does not
        mean the zone publishes no key, so the next nameserver is tried
        and its answer is the one that counts"""
        key_response = _response(
            dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", DNSKEY_RDATA)
        )
        answers = [_response(rcode=dns.rcode.REFUSED), key_response]
        cache = _fresh_cache()
        with patch("checkdmarc.dnssec._query_nameserver", side_effect=answers):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com", nameservers=["192.0.2.1", "192.0.2.2"], cache=cache
            )
        self.assertIsNotNone(result)
        self.assertIn("example.com", cache)

    def testAllNameserversRefusedIsNotCached(self):
        """When every nameserver refuses, the result is a failed lookup
        rather than an unsigned zone, and nothing is cached"""
        cache = _fresh_cache()
        answers = [
            _response(rcode=dns.rcode.REFUSED),
            _response(rcode=dns.rcode.FORMERR),
        ]
        with patch("checkdmarc.dnssec._query_nameserver", side_effect=answers):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com", nameservers=["192.0.2.1", "192.0.2.2"], cache=cache
            )
        self.assertIsNone(result)
        self.assertNotIn("example.com", cache)

    def testServfailIsNotCached(self):
        """SERVFAIL means a validating resolver rejected the zone; the key
        lookup could not complete, so it is not cached as unsigned"""
        cache = _fresh_cache()
        with patch("dns.query.tcp", return_value=_response(rcode=dns.rcode.SERVFAIL)):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertIsNone(result)
        self.assertNotIn("example.com", cache)


class TestCheckDnssec(unittest.TestCase):
    """check_dnssec unit tests with the network mocked out

    The query order under test: DS at the domain (falling back to the base
    domain), then DNSKEY at the zone the DS anchors, then — for names below
    the zone apex — MX, A, NS, and CNAME at the domain itself.
    """

    def testCacheHitTrue(self):
        cache = _fresh_cache()
        cache["example.com"] = True
        with patch("dns.query.tcp") as query:
            result = checkdmarc.dnssec.check_dnssec("example.com", cache=cache)
        self.assertTrue(result)
        self.assertFalse(query.called)

    def testCacheHitFalse(self):
        cache = _fresh_cache()
        cache["example.com"] = False
        result = checkdmarc.dnssec.check_dnssec("example.com", cache=cache)
        self.assertFalse(result)

    def testValidChainReturnsTrue(self):
        """DS present, a DNSKEY matching it, and a verifying signature: True

        Real cryptography end to end; nothing but the network is mocked.
        """
        cache = _fresh_cache()
        ds, key, sig = _signed_zone("example.com.")
        with patch("dns.query.tcp", side_effect=[_response(ds), _response(key, sig)]):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertTrue(result)
        self.assertIs(cache["example.com"], True)

    def testIslandOfSecurityReturnsFalse(self):
        """A self-consistent signed DNSKEY with no DS at the parent: False

        The zone signs itself, but nothing vouches for it, so it is insecure
        per RFC 4033 section 4.3 — this is the self-signed false positive the
        old implementation reported as True.
        """
        cache = _fresh_cache()
        _, key, sig = _signed_zone("example.com.")
        with (
            patch("dns.query.tcp", side_effect=[_response(), _response(key, sig)]),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertFalse(result)
        self.assertIs(cache["example.com"], False)
        self.assertTrue(any("no DS record" in line for line in logs.output))

    def testNoDsNoDnskeyReturnsFalse(self):
        """No DS and no DNSKEY: an ordinary unsigned zone"""
        with (
            patch("dns.query.tcp", return_value=_response()),
            self.assertLogs("checkdmarc.dnssec", level="DEBUG") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)
        self.assertTrue(any("is not signed" in line for line in logs.output))

    def testDsMismatchReturnsFalse(self):
        """A DS that matches no key in the DNSKEY record set: broken, False"""
        ds = dns.rrset.from_text("example.com.", 300, "IN", "DS", MISMATCHED_DS_RDATA)
        _, key, sig = _signed_zone("example.com.")
        with (
            patch("dns.query.tcp", side_effect=[_response(ds), _response(key, sig)]),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)
        self.assertTrue(any("matches a DS record" in line for line in logs.output))

    def testBadDnskeySignatureReturnsFalse(self):
        """A DNSKEY that matches the DS but whose signature does not verify:
        broken, False"""
        ds = _matching_ds("example.com.")
        key = dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", DNSKEY_RDATA)
        with (
            patch(
                "dns.query.tcp",
                side_effect=[
                    _response(ds),
                    _response(key, _rrsig("example.com.", "DNSKEY")),
                ],
            ),
            patch(
                "dns.dnssec.validate",
                side_effect=dns.exception.ValidationFailure("bad signature"),
            ),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)
        self.assertTrue(any("does not verify" in line for line in logs.output))

    def testUnsignedDnskeyWithDsReturnsFalse(self):
        """A DS at the parent but a DNSKEY answer with no signature: broken"""
        ds = _matching_ds("example.com.")
        key = dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", DNSKEY_RDATA)
        with (
            patch("dns.query.tcp", side_effect=[_response(ds), _response(key)]),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)
        self.assertTrue(any("signed DNSKEY record set" in line for line in logs.output))

    def testDnskeyServfailWithDsIsReportedAsBogus(self):
        """DS at the parent but SERVFAIL on the DNSKEY query: a validating
        resolver rejected the zone, which is a broken zone, not an unsigned
        one — the warning must say so"""
        ds = _matching_ds("example.com.")
        with (
            patch(
                "dns.query.tcp",
                side_effect=[
                    _response(ds),
                    _response(rcode=dns.rcode.SERVFAIL),
                ],
            ),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)
        self.assertTrue(any("bogus" in line for line in logs.output))

    def testDsServfailIsNotCached(self):
        """SERVFAIL on the DS query itself: the check could not run, so the
        result is False but nothing is cached"""
        cache = _fresh_cache()
        with (
            patch(
                "dns.query.tcp",
                return_value=_response(rcode=dns.rcode.SERVFAIL),
            ),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertFalse(result)
        self.assertNotIn("example.com", cache)
        self.assertTrue(any("SERVFAIL" in line for line in logs.output))

    def testTransportFailureIsNotCached(self):
        """No nameserver reachable: False, not cached, and logged"""
        cache = _fresh_cache()
        with (
            patch("dns.query.tcp", side_effect=OSError("boom")),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertFalse(result)
        self.assertNotIn("example.com", cache)
        self.assertTrue(any("no nameserver answered" in line for line in logs.output))

    def testNameChainReturnsFalseInsteadOfRaising(self):
        """A chain of names is reported as unsigned rather than crashing

        Regression test for issue #265: every query answers with the CNAME
        chain, so no DS and no DNSKEY is ever found.
        """
        with patch("dns.query.tcp", return_value=_response(*_cname_chain())):
            result = checkdmarc.dnssec.check_dnssec(
                "aws.amazon.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)

    def testSubdomainWithSignedRecordReturnsTrue(self):
        """A name below a signed zone apex whose own records verify: True"""
        ds, key, sig = _signed_zone("example.com.")
        mx_response = _response(
            dns.rrset.from_text(
                "sub.example.com.", 300, "IN", "MX", "10 mail.example.com."
            ),
            _rrsig("sub.example.com.", "MX"),
        )
        with (
            patch(
                "dns.query.tcp",
                side_effect=[
                    _response(),  # DS sub.example.com: none
                    _response(ds),  # DS example.com
                    _response(key, sig),  # DNSKEY example.com
                    mx_response,  # MX sub.example.com
                ],
            ),
            # The MX signature is synthetic, so signature verification is
            # patched out; the DS-to-DNSKEY digest comparison still runs for
            # real. testValidChainReturnsTrue covers real verification.
            patch("dns.dnssec.validate", return_value=None),
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "sub.example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertTrue(result)

    def testSubdomainWithOnlySignedAaaaReturnsTrue(self):
        """A name below a signed zone apex whose only record set is a
        signed AAAA must count as covered, not fall off the end of the
        record-type list"""
        ds, key, sig = _signed_zone("example.com.")
        aaaa_response = _response(
            dns.rrset.from_text("sub.example.com.", 300, "IN", "AAAA", "2001:db8::1"),
            _rrsig("sub.example.com.", "AAAA"),
        )
        with (
            patch(
                "dns.query.tcp",
                side_effect=[
                    _response(),  # DS sub.example.com: none
                    _response(ds),  # DS example.com
                    _response(key, sig),  # DNSKEY example.com
                    _response(),  # MX
                    _response(),  # A
                    aaaa_response,  # AAAA with a signature
                ],
            ),
            # The AAAA signature is synthetic, so signature verification is
            # patched out; the DS-to-DNSKEY digest comparison still runs
            # for real.
            patch("dns.dnssec.validate", return_value=None),
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "sub.example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertTrue(result)

    def testSubdomainWithUnsignedRecordsReturnsFalse(self):
        """A name below a signed zone apex with no signed records: False"""
        ds, key, sig = _signed_zone("example.com.")
        a_response = _response(
            dns.rrset.from_text("sub.example.com.", 300, "IN", "A", "192.0.2.1")
        )
        with (
            patch(
                "dns.query.tcp",
                side_effect=[
                    _response(),  # DS sub.example.com: none
                    _response(ds),  # DS example.com
                    _response(key, sig),  # DNSKEY example.com
                    _response(),  # MX
                    a_response,  # A record without a signature
                    _response(),  # AAAA
                    _response(),  # NS
                    _response(),  # TXT
                    _response(),  # CNAME
                ],
            ),
            self.assertLogs("checkdmarc.dnssec", level="DEBUG") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "sub.example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)
        self.assertTrue(
            any("no signed records were found" in line for line in logs.output)
        )

    def testSubdomainBadRecordSignatureIsWarnedAndSkipped(self):
        """A record signature below the apex that fails to verify is warned
        about and does not count as signed"""
        ds, key, sig = _signed_zone("example.com.")
        mx_response = _response(
            dns.rrset.from_text(
                "sub.example.com.", 300, "IN", "MX", "10 mail.example.com."
            ),
            _rrsig("sub.example.com.", "MX"),
        )
        with (
            patch(
                "dns.query.tcp",
                side_effect=[
                    _response(),  # DS sub.example.com: none
                    _response(ds),  # DS example.com
                    _response(key, sig),  # DNSKEY example.com
                    mx_response,  # MX with a signature that will not verify
                    _response(),  # A
                    _response(),  # AAAA
                    _response(),  # NS
                    _response(),  # TXT
                    _response(),  # CNAME
                ],
            ),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "sub.example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)
        self.assertTrue(any("does not verify" in line for line in logs.output))

    def testSubdomainServfailBelowSignedZoneReturnsFalse(self):
        """SERVFAIL on a record query below a signed zone is warned about as
        a broken zone rather than treated as an unsigned record"""
        ds, key, sig = _signed_zone("example.com.")
        with (
            patch(
                "dns.query.tcp",
                side_effect=[
                    _response(),  # DS sub.example.com: none
                    _response(ds),  # DS example.com
                    _response(key, sig),  # DNSKEY example.com
                    _response(rcode=dns.rcode.SERVFAIL),  # MX
                ],
            ),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "sub.example.com", nameservers=["192.0.2.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)
        self.assertTrue(any("bogus" in line for line in logs.output))

    def testDnskeyQueryUnanswered(self):
        """DS present but no nameserver answers the DNSKEY query: False"""
        cache = _fresh_cache()
        ds, _, _ = _signed_zone("example.com.")
        with (
            patch(
                "checkdmarc.dnssec._query_nameserver",
                side_effect=[_response(ds), None],
            ),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertFalse(result)
        self.assertTrue(
            any("DNSKEY query" in line for line in logs.output),
            logs.output,
        )

    def testUnsupportedDsDigestTypeMatchesNoKey(self):
        """A DS record whose digest type cannot be computed is skipped, so
        no key anchors and the result is False"""
        cache = _fresh_cache()
        _, key, sig = _signed_zone("example.com.")
        keytag = dns.dnssec.key_id(cast(DNSKEY, key[0]))
        bad_ds = dns.rrset.from_text(
            "example.com.", 300, "IN", "DS", f"{keytag} 13 99 aabbccdd"
        )
        with patch(
            "dns.query.tcp", side_effect=[_response(bad_ds), _response(key, sig)]
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertFalse(result)

    def testAdFlagLogged(self):
        """A resolver-validated (AD-flagged) DNSKEY answer is noted in the
        debug log and the chain still validates"""
        cache = _fresh_cache()
        ds, key, sig = _signed_zone("example.com.")
        key_response = _response(key, sig)
        key_response.flags = dns.flags.AD
        with (
            patch("dns.query.tcp", side_effect=[_response(ds), key_response]),
            self.assertLogs("checkdmarc.dnssec", level="DEBUG") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertTrue(result)
        self.assertTrue(any("AD flag" in line for line in logs.output), logs.output)

    def testIntermediateSignedZoneWalk(self):
        """A delegated signed zone between the queried name and the base
        domain anchors validation, instead of being skipped for the base
        domain's keys

        www.signed-child.example.com has no DS of its own; the walk must
        stop at signed-child.example.com (which has one) rather than
        jumping to example.com. Real cryptography end to end.
        """
        cache = _fresh_cache()
        private_key = ec.generate_private_key(ec.SECP256R1())
        zone = dns.name.from_text("signed-child.example.com.")
        dnskey = dns.dnssec.make_dnskey(
            private_key.public_key(), Algorithm.ECDSAP256SHA256, flags=257
        )
        key_rrset = dns.rrset.from_rdata(zone, 300, dnskey)
        key_sig = dns.rrset.from_rdata(
            zone,
            300,
            dns.dnssec.sign(key_rrset, private_key, zone, dnskey, lifetime=3600),
        )
        ds = dns.dnssec.make_ds(zone, dnskey, "SHA256")
        ds_rrset = dns.rrset.from_text(
            "signed-child.example.com.", 300, "IN", "DS", ds.to_text()
        )
        www = dns.name.from_text("www.signed-child.example.com.")
        a_rrset = dns.rrset.from_text(
            "www.signed-child.example.com.", 300, "IN", "A", "192.0.2.1"
        )
        a_sig = dns.rrset.from_rdata(
            www,
            300,
            dns.dnssec.sign(a_rrset, private_key, zone, dnskey, lifetime=3600),
        )
        with patch(
            "dns.query.tcp",
            side_effect=[
                _response(),  # DS at www.signed-child.example.com: empty
                _response(ds_rrset),  # DS at signed-child.example.com
                _response(key_rrset, key_sig),  # DNSKEY for the child zone
                _response(),  # MX at www: empty
                _response(a_rrset, a_sig),  # A at www, signed by the child
            ],
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "www.signed-child.example.com",
                nameservers=["192.0.2.1"],
                cache=cache,
            )
        self.assertTrue(result)


class TestGetTlsaRecords(unittest.TestCase):
    def testNoNameserversRaises(self):
        """An empty nameservers list raises ValueError"""
        self.assertRaises(
            ValueError,
            checkdmarc.dnssec.get_tlsa_records,
            "mail.example.com",
            nameservers=[],
            cache=_fresh_cache(),
        )

    def testTransportFailureTriesTheNextNameserver(self):
        """One unreachable nameserver must not end the lookup: the next
        one is tried, and its TLSA records are returned"""
        tlsa = dns.rrset.from_text(
            "_25._tcp.mail.example.com.", 300, "IN", "TLSA", TLSA_RDATA
        )
        sig = _rrsig("_25._tcp.mail.example.com.", "TLSA")
        cache = _fresh_cache()
        with (
            patch(
                "checkdmarc.dnssec._query_nameserver",
                side_effect=[OSError("unreachable"), _response(tlsa, sig)],
            ),
            patch(
                "checkdmarc.dnssec.get_dnskey",
                return_value={dns.name.from_text("mail.example.com."): "key"},
            ),
            patch("dns.dnssec.validate", return_value=None),
        ):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["192.0.2.1", "192.0.2.2"], cache=cache
            )
        self.assertEqual(result, [TLSA_RDATA])

    def testUnusableRcodeTriesTheNextNameserver(self):
        """A REFUSED answer is a nameserver that could not answer, not a
        host without TLSA records"""
        tlsa = dns.rrset.from_text(
            "_25._tcp.mail.example.com.", 300, "IN", "TLSA", TLSA_RDATA
        )
        sig = _rrsig("_25._tcp.mail.example.com.", "TLSA")
        with (
            patch(
                "checkdmarc.dnssec._query_nameserver",
                side_effect=[
                    _response(rcode=dns.rcode.REFUSED),
                    _response(tlsa, sig),
                ],
            ),
            patch(
                "checkdmarc.dnssec.get_dnskey",
                return_value={dns.name.from_text("mail.example.com."): "key"},
            ),
            patch("dns.dnssec.validate", return_value=None),
        ):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com",
                nameservers=["192.0.2.1", "192.0.2.2"],
                cache=_fresh_cache(),
            )
        self.assertEqual(result, [TLSA_RDATA])

    def testServfailReturnsNoRecords(self):
        """A validating resolver answers SERVFAIL for a bogus answer; that
        is a lookup that could not produce trustworthy records, so none are
        returned and nothing is cached"""
        cache = _fresh_cache()
        with (
            patch("dns.query.tcp", return_value=_response(rcode=dns.rcode.SERVFAIL)),
            self.assertLogs("checkdmarc.dnssec", level="DEBUG") as logs,
        ):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertEqual(result, [])
        self.assertNotIn("_25._tcp.mail.example.com", cache)
        self.assertTrue(any("SERVFAIL" in line for line in logs.output))

    def testRecordsThatDoNotVerifyAreNotReturned(self):
        """TLSA records whose signature fails validation are not returned
        and are not cached"""
        tlsa = dns.rrset.from_text(
            "_25._tcp.mail.example.com.", 300, "IN", "TLSA", TLSA_RDATA
        )
        sig = _rrsig("_25._tcp.mail.example.com.", "TLSA")
        cache = _fresh_cache()
        with (
            patch("dns.query.tcp", return_value=_response(tlsa, sig)),
            patch(
                "checkdmarc.dnssec.get_dnskey",
                return_value={dns.name.from_text("mail.example.com."): "key"},
            ),
            patch(
                "dns.dnssec.validate",
                side_effect=dns.exception.ValidationFailure("bad signature"),
            ),
        ):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertEqual(result, [])
        self.assertNotIn("_25._tcp.mail.example.com", cache)

    def testCacheHit(self):
        """A cached result is returned from the cache the caller passed in

        The lookup must read the caller's cache, not the module-level one, and
        must not reach the network to do it.
        """
        cache = _fresh_cache()
        cache["_25._tcp.mail.example.com"] = ["cached"]
        with patch("dns.query.tcp") as query:
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["1.1.1.1"], cache=cache
            )
        self.assertEqual(result, ["cached"])
        self.assertFalse(query.called)

    def testModuleCacheNotConsultedWhenCallerPassesOne(self):
        """A stale module-level entry must not leak into a caller's own cache"""
        checkdmarc.dnssec.TLSA_CACHE["_25._tcp.mail.example.com"] = ["stale"]
        try:
            with patch("dns.query.tcp", return_value=_response()):
                result = checkdmarc.dnssec.get_tlsa_records(
                    "mail.example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
                )
            self.assertEqual(result, [])
        finally:
            checkdmarc.dnssec.TLSA_CACHE.pop("_25._tcp.mail.example.com", None)

    def testNoRecordsReturnsEmpty(self):
        """An answer with no TLSA records returns an empty list"""
        with patch("dns.query.tcp", return_value=_response()):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertEqual(result, [])

    def testNameChainReturnsEmptyInsteadOfRaising(self):
        """A chain of names returns no TLSA records rather than crashing

        The same missing-signature bug as issue #265, on the TLSA path. The
        signature check is left unpatched so the bug would surface here.
        """
        with patch("dns.query.tcp", return_value=_response(*_cname_chain())):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertEqual(result, [])

    def testUnsignedTlsaRecordsReturnsEmpty(self):
        """TLSA records with no signature are not reported"""
        rrset = dns.rrset.from_text(
            "_25._tcp.mail.example.com.", 300, "IN", "TLSA", TLSA_RDATA
        )
        with patch("dns.query.tcp", return_value=_response(rrset)):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertEqual(result, [])

    def testNoDnskeyReturnsEmpty(self):
        """TLSA records present but no DNSKEY to verify them returns an empty list"""
        response = _response(
            dns.rrset.from_text(
                "_25._tcp.mail.example.com.", 300, "IN", "TLSA", TLSA_RDATA
            ),
            _rrsig("_25._tcp.mail.example.com.", "TLSA"),
        )
        with (
            patch("dns.query.tcp", return_value=response),
            patch("checkdmarc.dnssec.get_dnskey", return_value=None),
        ):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertEqual(result, [])

    def testTlsaRecordsExtracted(self):
        """A signed TLSA RRset is decoded and cached"""
        cache = _fresh_cache()
        response = _response(
            dns.rrset.from_text(
                "_25._tcp.mail.example.com.", 300, "IN", "TLSA", TLSA_RDATA
            ),
            _rrsig("_25._tcp.mail.example.com.", "TLSA"),
        )
        with (
            patch("dns.query.tcp", return_value=response),
            patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()),
            patch("dns.dnssec.validate", return_value=None),
        ):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["1.1.1.1"], cache=cache
            )
        self.assertEqual(result, [TLSA_RDATA])
        self.assertEqual(cache["_25._tcp.mail.example.com"], [TLSA_RDATA])

    def testQueryExceptionReturnsEmpty(self):
        with patch("dns.query.tcp", side_effect=OSError("boom")):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertEqual(result, [])


class TestEncryptedDnsTransports(unittest.TestCase):
    """The DNSSEC checks query each nameserver directly rather than through
    a resolver, so ``tls://`` and ``https://`` entries are mapped to
    dnspython nameserver objects and dispatched through their own
    ``query()`` method. These tests mock at the dnspython SDK boundary
    (``dns.query.tls`` / ``dns.query.https`` / ``dns.query.tcp``) and assert
    on the key get_dnskey parses out of the answer."""

    @staticmethod
    def _dnskey_response() -> MagicMock:
        return _response(
            dns.rrset.from_text("example.com.", 300, "IN", "DNSKEY", DNSKEY_RDATA)
        )

    def _fresh_cache(self) -> ExpiringDict:
        return ExpiringDict(max_len=10, max_age_seconds=60)

    def test_dot_nameserver_entry_is_queried_over_tls(self):
        """A tls:// entry reaches dns.query.tls with the address, the
        default port, and the #hostname suffix as server_hostname — the
        name the server's certificate is checked against."""
        captured = []

        def responder(request, address, **kwargs):
            captured.append((address, kwargs))
            return self._dnskey_response()

        with patch("dns.query.tls", side_effect=responder):
            key = checkdmarc.dnssec.get_dnskey(
                "example.com",
                nameservers=["tls://9.9.9.9#dns.quad9.net"],
                cache=self._fresh_cache(),
            )
        assert key is not None  # narrow Optional for pyright
        self.assertIn(dns.name.from_text("example.com"), key)
        address, kwargs = captured[0]
        self.assertEqual(address, "9.9.9.9")
        self.assertEqual(kwargs["server_hostname"], "dns.quad9.net")
        self.assertEqual(kwargs["port"], 853)

    def test_doh_nameserver_entry_is_queried_over_https_with_shared_session(self):
        """An https:// entry reaches dns.query.https with the URL and the
        module's shared httpx client, so proxy and CA environment
        variables apply to DNSSEC queries too."""
        captured = []

        def responder(request, url, **kwargs):
            captured.append((url, kwargs))
            return self._dnskey_response()

        with patch("dns.query.https", side_effect=responder):
            key = checkdmarc.dnssec.get_dnskey(
                "example.com",
                nameservers=["https://dns.example/dns-query"],
                cache=self._fresh_cache(),
            )
        self.assertIsNotNone(key)
        url, kwargs = captured[0]
        self.assertEqual(url, "https://dns.example/dns-query")
        self.assertIs(kwargs["session"], checkdmarc.utils._DOH_SESSION)

    def test_plain_string_entry_still_uses_tcp(self):
        """An IP address entry keeps the direct dns.query.tcp call — the
        behavior of every earlier release."""
        with patch("dns.query.tcp", return_value=self._dnskey_response()) as tcp:
            key = checkdmarc.dnssec.get_dnskey(
                "example.com",
                nameservers=["9.9.9.9"],
                cache=self._fresh_cache(),
            )
        self.assertIsNotNone(key)
        self.assertEqual(tcp.call_args.args[1], "9.9.9.9")

    def test_doh_transport_error_falls_through_to_next_nameserver(self):
        """An httpx transport failure from a DoH nameserver is treated like
        any other unreachable nameserver: it is logged and the next entry
        is tried."""
        with (
            patch("dns.query.https", side_effect=httpx.ConnectError("boom")),
            patch("dns.query.tcp", return_value=self._dnskey_response()),
        ):
            key = checkdmarc.dnssec.get_dnskey(
                "example.com",
                nameservers=["https://dns.example/dns-query", "9.9.9.9"],
                cache=self._fresh_cache(),
            )
        self.assertIsNotNone(key)

    def test_malformed_tls_entry_raises_before_any_query(self):
        """A malformed tls:// entry is a configuration error, not a DNS
        failure, so it raises rather than being swallowed by the
        per-nameserver error handling."""
        with self.assertRaises(ValueError) as ctx:
            checkdmarc.dnssec.get_dnskey(
                "example.com",
                nameservers=["tls://not-an-ip"],
                cache=self._fresh_cache(),
            )
        self.assertIn("tls://not-an-ip", str(ctx.exception))


class TestQueryRrsetRcodeHandling(unittest.TestCase):
    NAMESERVERS: ClassVar[list[str]] = ["192.0.2.1", "192.0.2.2"]

    def _ds_answer(self):
        ds = dns.rrset.from_text("example.com.", 300, "IN", "DS", MISMATCHED_DS_RDATA)
        return _response(ds, _rrsig("example.com.", "DS"))

    def testRefusedFallsThroughToNextNameserver(self):
        """REFUSED means the nameserver would not answer, not that the
        record set is absent; the next nameserver's answer must be used"""
        answers = [_response(rcode=dns.rcode.REFUSED), self._ds_answer()]
        with patch("checkdmarc.dnssec._query_nameserver", side_effect=answers):
            rrset, rrsig, response = checkdmarc.dnssec._query_rrset(
                "example.com", dns.rdatatype.DS, self.NAMESERVERS, 2.0
            )
        self.assertIsNotNone(rrset)
        self.assertIsNotNone(rrsig)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response.rcode(), dns.rcode.NOERROR)

    def testAllRefusedMeansNoAnswer(self):
        """When every nameserver refuses, the caller must see a lookup
        failure, not a clean empty answer that reads as an unsigned zone"""
        answers = [
            _response(rcode=dns.rcode.REFUSED),
            _response(rcode=dns.rcode.FORMERR),
        ]
        with patch("checkdmarc.dnssec._query_nameserver", side_effect=answers):
            rrset, rrsig, response = checkdmarc.dnssec._query_rrset(
                "example.com", dns.rdatatype.DS, self.NAMESERVERS, 2.0
            )
        self.assertIsNone(rrset)
        self.assertIsNone(rrsig)
        self.assertIsNone(response)

    def testServfailPreservedWhenNoBetterAnswer(self):
        """A SERVFAIL from a validating resolver carries DNSSEC meaning, so
        it is returned when no nameserver gives a real answer"""
        answers = [
            _response(rcode=dns.rcode.SERVFAIL),
            _response(rcode=dns.rcode.REFUSED),
        ]
        with patch("checkdmarc.dnssec._query_nameserver", side_effect=answers):
            rrset, _, response = checkdmarc.dnssec._query_rrset(
                "example.com", dns.rdatatype.DS, self.NAMESERVERS, 2.0
            )
        self.assertIsNone(rrset)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response.rcode(), dns.rcode.SERVFAIL)

    def testServfailThenRealAnswerPrefersTheAnswer(self):
        """A later nameserver's real answer wins over an earlier SERVFAIL"""
        answers = [_response(rcode=dns.rcode.SERVFAIL), self._ds_answer()]
        with patch("checkdmarc.dnssec._query_nameserver", side_effect=answers):
            rrset, _, response = checkdmarc.dnssec._query_rrset(
                "example.com", dns.rdatatype.DS, self.NAMESERVERS, 2.0
            )
        self.assertIsNotNone(rrset)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response.rcode(), dns.rcode.NOERROR)

    def testDsRefusedIsNotCached(self):
        """REFUSED on the DS query from the only nameserver: the check
        could not run, so the result is False but nothing is cached"""
        cache = _fresh_cache()
        with (
            patch("dns.query.tcp", return_value=_response(rcode=dns.rcode.REFUSED)),
            self.assertLogs("checkdmarc.dnssec", level="WARNING") as logs,
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["192.0.2.1"], cache=cache
            )
        self.assertFalse(result)
        self.assertNotIn("example.com", cache)
        self.assertTrue(any("no nameserver answered" in line for line in logs.output))


class TestDeprecatedTestDnssecAlias(unittest.TestCase):
    def testAliasWarnsAndDelegates(self):
        """test_dnssec() warns that it is deprecated and returns
        check_dnssec()'s result"""
        with (
            patch("dns.query.tcp", return_value=_response()),
            self.assertWarns(DeprecationWarning),
        ):
            result = checkdmarc.dnssec.test_dnssec(
                "example.com",
                nameservers=["9.9.9.9"],
                cache=ExpiringDict(max_len=10, max_age_seconds=60),
            )
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
