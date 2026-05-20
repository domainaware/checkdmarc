"""Tests for checkdmarc.dnssec"""

import os
import unittest
from unittest.mock import patch

import checkdmarc.dnssec

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"


class Test(unittest.TestCase):
    @unittest.skipIf(OFFLINE_MODE, "No network access in GitHub Actions")
    def testDNSSEC(self):
        """Test known good DNSSEC"""
        self.assertEqual(checkdmarc.dnssec.test_dnssec("fbi.gov"), True)

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
