"""Tests for checkdmarc.dnssec"""

import os
import unittest
from unittest.mock import MagicMock, patch

import dns.exception
import dns.name
import dns.rdatatype
import dns.rrset
import httpx
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


def _response(*rrsets: dns.rrset.RRset) -> MagicMock:
    """A stand-in DNS response; only its answer section is read"""
    response = MagicMock()
    response.answer = list(rrsets)
    return response


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
        """test_dnssec returns True when a record/RRSIG pair validates (mocked)

        The signature check itself is stubbed out; what is under test is that
        test_dnssec finds the record and its signature and reports success.
        """
        response = _response(
            dns.rrset.from_text("example.com.", 300, "IN", "A", "192.0.2.1"),
            _rrsig("example.com.", "A"),
        )
        with (
            patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()),
            patch("dns.query.tcp", return_value=response),
            patch("dns.dnssec.validate", return_value=None),
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", cache=_fresh_cache(), nameservers=["192.0.2.1"]
            )
        self.assertTrue(result)

    def testDnssecFalseWhenNoKey(self):
        """test_dnssec returns False when no DNSKEY found"""
        with patch("checkdmarc.dnssec.get_dnskey") as mock_key:
            mock_key.return_value = None
            result = checkdmarc.dnssec.check_dnssec("example.com")
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

    def testQueryExceptionCachedAsNone(self):
        """Network exceptions cache None and let the function return None"""
        cache = _fresh_cache()
        with patch("dns.query.tcp", side_effect=OSError("boom")):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com", nameservers=["1.1.1.1"], cache=cache
            )
        self.assertIsNone(result)
        self.assertIsNone(cache["example.com"])


class TestTestDnssec(unittest.TestCase):
    def testCacheHitTrue(self):
        cache = _fresh_cache()
        cache["example.com"] = True
        with patch("checkdmarc.dnssec.get_dnskey") as mock_key:
            result = checkdmarc.dnssec.check_dnssec("example.com", cache=cache)
        self.assertTrue(result)
        mock_key.assert_not_called()

    def testCacheHitFalse(self):
        cache = _fresh_cache()
        cache["example.com"] = False
        result = checkdmarc.dnssec.check_dnssec("example.com", cache=cache)
        self.assertFalse(result)

    def testNoSignedRecordsReturnsFalse(self):
        """If no signed records validate across all rdatatypes, return False"""
        with (
            patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()),
            patch("dns.query.tcp", return_value=_response()),
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)

    def testNameChainReturnsFalseInsteadOfRaising(self):
        """A chain of names is reported as unsigned rather than crashing

        Regression test for issue #265. The signature check is deliberately
        left unpatched: passing it a missing signature is exactly the bug, and
        would surface here as an AttributeError.
        """
        with (
            patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()),
            patch("dns.query.tcp", return_value=_response(*_cname_chain())),
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "aws.amazon.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)

    def testUnsignedRecordReturnsFalse(self):
        """A record with no signature alongside it is reported as unsigned"""
        response = _response(
            dns.rrset.from_text("example.com.", 300, "IN", "A", "192.0.2.1")
        )
        with (
            patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()),
            patch("dns.query.tcp", return_value=response),
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)

    def testInvalidSignatureReturnsFalse(self):
        """A bad signature (ValidationFailure) at every rdatatype reports
        DNSSEC as not validated, rather than propagating the exception."""
        response = _response(
            dns.rrset.from_text("example.com.", 300, "IN", "A", "192.0.2.1"),
            _rrsig("example.com.", "A"),
        )
        with (
            patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()),
            patch("dns.query.tcp", return_value=response),
            patch(
                "dns.dnssec.validate",
                side_effect=dns.exception.ValidationFailure("bad signature"),
            ),
        ):
            result = checkdmarc.dnssec.check_dnssec(
                "example.com", nameservers=["1.1.1.1"], cache=_fresh_cache()
            )
        self.assertFalse(result)


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
