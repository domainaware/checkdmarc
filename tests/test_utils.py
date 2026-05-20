"""Tests for checkdmarc.utils"""

import unittest

import checkdmarc.utils


class Test(unittest.TestCase):
    def testGetBaseDomain(self):
        subdomain = "foo.example.com"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "example.com"

        # Test reserved domains
        subdomain = "_dmarc.nonauth-rua.invalid.example"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "invalid.example"

        subdomain = "_dmarc.nonauth-rua.invalid.test"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "invalid.test"

        subdomain = "_dmarc.nonauth-rua.invalid.invalid"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "invalid.invalid"

        subdomain = "_dmarc.nonauth-rua.invalid.localhost"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "invalid.localhost"

        # Test newer PSL entries
        subdomain = "e3191.c.akamaiedge.net"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "c.akamaiedge.net"

    def testNormalizeDomain(self):
        """normalize_domain handles various inputs correctly"""
        # Basic lowering
        self.assertEqual(
            checkdmarc.utils.normalize_domain("Example.COM"), "example.com"
        )
        # Zero-width character removal
        self.assertEqual(
            checkdmarc.utils.normalize_domain("exam​ple.com"),
            "example.com",
        )
        # Unicode normalization
        self.assertEqual(
            checkdmarc.utils.normalize_domain("example.com"), "example.com"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
