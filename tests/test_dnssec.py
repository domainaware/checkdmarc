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


if __name__ == "__main__":
    unittest.main(verbosity=2)
