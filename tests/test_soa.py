"""Tests for checkdmarc.soa"""

import unittest
from unittest.mock import patch
from typing import cast

import checkdmarc.soa
from checkdmarc.soa import SOARecordSuccessful


class Test(unittest.TestCase):
    def testSoaRnameToEmail(self):
        """soa_rname_to_email converts RNAME to email"""
        email = checkdmarc.soa.soa_rname_to_email("admin.example.com.")
        self.assertEqual(email, "admin@example.com")

    def testSoaRnameToEmailEscapedDot(self):
        """soa_rname_to_email handles escaped dots in local part"""
        email = checkdmarc.soa.soa_rname_to_email(r"first\.last.example.com.")
        self.assertEqual(email, "first.last@example.com")

    def testSoaRnameToEmailInvalid(self):
        """soa_rname_to_email raises ValueError for invalid RNAME"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.soa_rname_to_email,
            "nodotatall",
        )

    def testParseSoaString(self):
        """parse_soa_string parses a valid SOA record"""
        soa_record = (
            "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"
        )
        result = checkdmarc.soa.parse_soa_string(soa_record)
        self.assertEqual(result["primary_nameserver"], "ns1.example.com")
        self.assertEqual(result["serial"], 2024010101)
        self.assertEqual(result["refresh"], 3600)

    def testParseSoaStringEmpty(self):
        """parse_soa_string raises ValueError for empty string"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.parse_soa_string,
            "",
        )

    def testParseSoaStringWrongFields(self):
        """parse_soa_string raises ValueError for wrong number of fields"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.parse_soa_string,
            "ns1.example.com. admin.example.com. 12345",
        )

    def testCheckSoaSuccess(self):
        """check_soa returns parsed record on success"""
        with patch("checkdmarc.soa.get_soa_record") as mock_soa:
            mock_soa.return_value = (
                "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"
            )
            result = checkdmarc.soa.check_soa("example.com")
            self.assertIn("values", result)
            self.assertEqual(
                cast(SOARecordSuccessful, result)["values"]["serial"], 2024010101
            )

    def testCheckSoaError(self):
        """check_soa returns error on a DNS lookup failure"""
        with patch("checkdmarc.soa.get_soa_record") as mock_soa:
            mock_soa.side_effect = checkdmarc.soa.DNSException("DNS error")
            result = checkdmarc.soa.check_soa("example.com")
            self.assertIn("error", result)

    def testRnameEmptyLocalPart(self):
        """A leading dot in the RNAME (empty local part) raises ValueError"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.soa_rname_to_email,
            ".example.com.",
        )

    def testParseSoaStringNonIntegerField(self):
        """A non-integer in a numeric field raises ValueError"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.parse_soa_string,
            "ns1.example.com. admin.example.com. notanumber 3600 900 604800 86400",
        )

    def testParseSoaStringNegativeField(self):
        """A negative integer (outside the u32 range) raises ValueError"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.parse_soa_string,
            "ns1.example.com. admin.example.com. -1 3600 900 604800 86400",
        )

    def testCheckSoaParseError(self):
        """get_soa_record succeeds but parse_soa_string fails — error result with the record"""
        # 7 fields but one is unparseable, so parse_soa_string raises
        bad_record = (
            "ns1.example.com. admin.example.com. notanumber 3600 900 604800 86400"
        )
        with patch("checkdmarc.soa.get_soa_record", return_value=bad_record):
            result = checkdmarc.soa.check_soa("example.com")
        self.assertIn("error", result)
        # The original record is preserved on the failure result
        self.assertEqual(result["record"], bad_record)


if __name__ == "__main__":
    unittest.main(verbosity=2)
