"""Tests for checkdmarc.dnssec"""

import os
import unittest
from unittest.mock import MagicMock, patch

import checkdmarc.dnssec

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"

network_test = unittest.skipIf(
    OFFLINE_MODE, "Real-network test skipped on GitHub Actions"
)
mocked_only = unittest.skipUnless(
    OFFLINE_MODE, "Mocked counterpart skipped locally; network test covers this"
)


class Test(unittest.TestCase):
    @network_test
    def testDNSSEC(self):
        """Test known good DNSSEC"""
        self.assertEqual(checkdmarc.dnssec.test_dnssec("fbi.gov"), True)

    @mocked_only
    def testDNSSECMocked(self):
        """test_dnssec returns True when a record/RRSIG pair validates (mocked)

        The full DNSSEC chain (DNSKEY -> RRSIG -> validated RRset) is
        synthesised here; we are exercising the success branch of
        test_dnssec, not the cryptographic validator itself.
        """
        import dns.rdatatype

        fake_response = MagicMock()
        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.A
        rrsig = MagicMock()
        rrsig.rdtype = dns.rdatatype.RRSIG
        fake_response.answer = [rrset, rrsig]

        from expiringdict import ExpiringDict

        fresh_cache = ExpiringDict(max_len=10, max_age_seconds=60)
        with patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()):
            with patch("dns.query.tcp", return_value=fake_response):
                with patch("dns.dnssec.validate", return_value=None):
                    result = checkdmarc.dnssec.test_dnssec(
                        "example.com", cache=fresh_cache, nameservers=["192.0.2.1"]
                    )
        self.assertTrue(result)

    def testDnssecFalseWhenNoKey(self):
        """test_dnssec returns False when no DNSKEY found"""
        with patch("checkdmarc.dnssec.get_dnskey") as mock_key:
            mock_key.return_value = None
            result = checkdmarc.dnssec.test_dnssec("example.com")
            self.assertFalse(result)

    def testGetDnskeyCache(self):
        """get_dnskey uses cache"""
        from expiringdict import ExpiringDict

        cache = ExpiringDict(max_len=100, max_age_seconds=60)
        mock_key = {"test": "data"}
        cache["example.com"] = mock_key
        result = checkdmarc.dnssec.get_dnskey("example.com", cache=cache)
        self.assertEqual(result, mock_key)


class TestGetDnskey(unittest.TestCase):
    @staticmethod
    def _fresh_cache():
        from expiringdict import ExpiringDict

        return ExpiringDict(max_len=10, max_age_seconds=60)

    def testFound(self):
        """A DNSKEY answer at the apex is returned as a dict keyed by dns.name"""
        import dns.rdatatype

        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.DNSKEY
        response = MagicMock()
        response.answer = [rrset]

        with patch("dns.query.tcp", return_value=response):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com",
                nameservers=["1.1.1.1"],
                cache=self._fresh_cache(),
            )
        assert result is not None  # narrow Optional for pyright
        # The single entry should map to the rrset we returned
        self.assertIn(rrset, result.values())

    def testEmptyAnswerAtApexReturnsNone(self):
        """If the apex has no DNSKEY answer, get_dnskey returns None"""
        response = MagicMock()
        response.answer = []

        with patch("dns.query.tcp", return_value=response):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com",
                nameservers=["1.1.1.1"],
                cache=self._fresh_cache(),
            )
        self.assertIsNone(result)

    def testEmptyAnswerAtSubdomainRecursesToBase(self):
        """A subdomain with no DNSKEY records recurses up to the base domain"""
        import dns.rdatatype

        empty_response = MagicMock()
        empty_response.answer = []
        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.DNSKEY
        valid_response = MagicMock()
        valid_response.answer = [rrset]

        with patch("dns.query.tcp", side_effect=[empty_response, valid_response]):
            result = checkdmarc.dnssec.get_dnskey(
                "sub.example.com",
                nameservers=["1.1.1.1"],
                cache=self._fresh_cache(),
            )
        self.assertIsNotNone(result)

    def testQueryExceptionCachedAsNone(self):
        """Network exceptions cache None and let the function return None"""
        cache = self._fresh_cache()
        with patch("dns.query.tcp", side_effect=OSError("boom")):
            result = checkdmarc.dnssec.get_dnskey(
                "example.com", nameservers=["1.1.1.1"], cache=cache
            )
        self.assertIsNone(result)
        self.assertIsNone(cache["example.com"])


class TestTestDnssec(unittest.TestCase):
    @staticmethod
    def _fresh_cache():
        from expiringdict import ExpiringDict

        return ExpiringDict(max_len=10, max_age_seconds=60)

    def testCacheHitTrue(self):
        cache = self._fresh_cache()
        cache["example.com"] = True
        with patch("checkdmarc.dnssec.get_dnskey") as mock_key:
            result = checkdmarc.dnssec.test_dnssec("example.com", cache=cache)
        self.assertTrue(result)
        mock_key.assert_not_called()

    def testCacheHitFalse(self):
        cache = self._fresh_cache()
        cache["example.com"] = False
        result = checkdmarc.dnssec.test_dnssec("example.com", cache=cache)
        self.assertFalse(result)

    def testNoSignedRecordsReturnsFalse(self):
        """If no signed records validate across all rdatatypes, return False"""
        # Each per-rdatatype query returns an answer of length != 2,
        # which fails the rrset/rrsig pairing check and continues.
        response = MagicMock()
        response.answer = []
        with patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()):
            with patch("dns.query.tcp", return_value=response):
                result = checkdmarc.dnssec.test_dnssec(
                    "example.com",
                    nameservers=["1.1.1.1"],
                    cache=self._fresh_cache(),
                )
        self.assertFalse(result)

    def testValidationExceptionContinues(self):
        """A failure on dns.dnssec.validate is swallowed and we fall through to False"""
        import dns.rdatatype

        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.A
        rrsig = MagicMock()
        rrsig.rdtype = dns.rdatatype.RRSIG
        response = MagicMock()
        response.answer = [rrset, rrsig]

        with patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()):
            with patch("dns.query.tcp", return_value=response):
                with patch(
                    "dns.dnssec.validate",
                    side_effect=Exception("invalid signature"),
                ):
                    result = checkdmarc.dnssec.test_dnssec(
                        "example.com",
                        nameservers=["1.1.1.1"],
                        cache=self._fresh_cache(),
                    )
        self.assertFalse(result)


class TestGetTlsaRecords(unittest.TestCase):
    @staticmethod
    def _fresh_cache():
        from expiringdict import ExpiringDict

        return ExpiringDict(max_len=10, max_age_seconds=60)

    def testNoNameserversRaises(self):
        """An empty nameservers list raises ValueError"""
        self.assertRaises(
            ValueError,
            checkdmarc.dnssec.get_tlsa_records,
            "mail.example.com",
            nameservers=[],
            cache=self._fresh_cache(),
        )

    def testCacheHit(self):
        cache = self._fresh_cache()
        checkdmarc.dnssec.TLSA_CACHE["_25._tcp.mail.example.com"] = ["cached"]
        try:
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com",
                nameservers=["1.1.1.1"],
                cache=cache,
            )
            self.assertEqual(result, ["cached"])
        finally:
            checkdmarc.dnssec.TLSA_CACHE.pop("_25._tcp.mail.example.com", None)

    def testFewerThanTwoAnswersReturnsEmpty(self):
        """An answer of length != 2 returns an empty list"""
        response = MagicMock()
        response.answer = []
        with patch("dns.query.tcp", return_value=response):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com",
                nameservers=["1.1.1.1"],
                cache=self._fresh_cache(),
            )
        self.assertEqual(result, [])

    def testNoDnskeyReturnsEmpty(self):
        """TLSA records present but no DNSKEY to verify them returns an empty list"""
        import dns.rdatatype

        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.TLSA
        rrsig = MagicMock()
        rrsig.rdtype = dns.rdatatype.RRSIG
        response = MagicMock()
        response.answer = [rrset, rrsig]
        with patch("dns.query.tcp", return_value=response):
            with patch("checkdmarc.dnssec.get_dnskey", return_value=None):
                result = checkdmarc.dnssec.get_tlsa_records(
                    "mail.example.com",
                    nameservers=["1.1.1.1"],
                    cache=self._fresh_cache(),
                )
        self.assertEqual(result, [])

    def testTlsaRecordsExtracted(self):
        """A signed TLSA RRset is decoded and cached"""
        import dns.rdatatype

        rrset = MagicMock()
        rrset.rdtype = dns.rdatatype.TLSA

        # Simple stand-in for a TLSA RR whose str() is the parsed record text.
        class _StubRr:
            def __str__(self) -> str:
                return "3 1 1 abc123"

        rr_item = _StubRr()
        rrset.items = {rr_item: None}
        rrsig = MagicMock()
        rrsig.rdtype = dns.rdatatype.RRSIG
        response = MagicMock()
        response.answer = [rrset, rrsig]
        with patch("dns.query.tcp", return_value=response):
            with patch("checkdmarc.dnssec.get_dnskey", return_value=MagicMock()):
                with patch("dns.dnssec.validate", return_value=None):
                    result = checkdmarc.dnssec.get_tlsa_records(
                        "mail.example.com",
                        nameservers=["1.1.1.1"],
                        cache=self._fresh_cache(),
                    )
        self.assertEqual(result, ["3 1 1 abc123"])

    def testQueryExceptionReturnsEmpty(self):
        with patch("dns.query.tcp", side_effect=OSError("boom")):
            result = checkdmarc.dnssec.get_tlsa_records(
                "mail.example.com",
                nameservers=["1.1.1.1"],
                cache=self._fresh_cache(),
            )
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
