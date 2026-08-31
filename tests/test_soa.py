"""Tests for checkdmarc.soa"""

import os
import unittest
from typing import cast
from unittest.mock import patch

import checkdmarc.soa
from checkdmarc.soa import SOARecordSuccessful

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"


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

    def testSoaRnameToEmailEscapedBackslashBeforeDot(self):
        """An escaped backslash before a real dot keeps the dot as the
        label boundary (RFC 1035 section 5.1): in a\\\\.b.example.com. the
        local part is 'a\\', which is not a valid dot-atom, so it comes
        back as a quoted-string with the backslash escaped"""
        email = checkdmarc.soa.soa_rname_to_email("a\\\\.b.example.com.")
        self.assertEqual(email, '"a\\\\"@b.example.com')

    def testSoaRnameToEmailEscapedAtSign(self):
        """A \\@ escape expands to a literal @ in the local part, which
        RFC 5322 only allows inside a quoted-string"""
        email = checkdmarc.soa.soa_rname_to_email(r"a\@b.example.com.")
        self.assertEqual(email, '"a@b"@example.com')

    def testSoaRnameToEmailDecimalEscape(self):
        """A \\DDD escape (RFC 1035 section 5.1) expands to the byte with
        that decimal value; a space forces the quoted-string form"""
        email = checkdmarc.soa.soa_rname_to_email(r"john\032doe.example.com.")
        self.assertEqual(email, '"john doe"@example.com')

    def testSoaRnameToEmailQuoteCharacterIsEscaped(self):
        """A decoded '"' must be escaped as a quoted-pair inside the
        quoted-string (RFC 5322 section 3.2.4)"""
        email = checkdmarc.soa.soa_rname_to_email(r"a\"b.example.com.")
        self.assertEqual(email, '"a\\"b"@example.com')

    def testSoaRnameToEmailDomainEscapesDecoded(self):
        """RFC 1035 escapes in the domain labels are decoded too, instead
        of leaving DNS presentation syntax in the returned address"""
        email = checkdmarc.soa.soa_rname_to_email(r"host.ex\097mple.com.")
        self.assertEqual(email, "host@example.com")

    def testSoaRnameToEmailInvalidDomainEscape(self):
        """A domain label that decodes to something no email domain can
        carry (here a space) is invalid; unlike the local part, a domain
        has no quoted form to fall back to"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.soa_rname_to_email,
            r"host.bad\032domain.com.",
        )

    def testSoaRnameToEmailUnrepresentableCharacter(self):
        """A decoded control character cannot appear in any valid email
        address, quoted or not"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.soa_rname_to_email,
            r"a\000b.example.com.",
        )

    def testSoaRnameToEmailDecimalEscapeOutOfRange(self):
        """A \\DDD escape over 255 is invalid"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.soa_rname_to_email,
            r"a\999.example.com.",
        )

    def testSoaRnameToEmailTrailingBackslash(self):
        """A dangling escape at the end of the RNAME is invalid"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.soa_rname_to_email,
            "ab\\",
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

    @unittest.skipIf(OFFLINE_MODE, "Network tests skipped in offline mode")
    def testCheckSoaDelegatedChildZoneLive(self):
        """A delegated child zone's own SOA is returned, not the parent's

        cl.cam.ac.uk is a zone of its own inside cam.ac.uk; RFC 2181
        section 7 puts its SOA at its own apex."""
        result = checkdmarc.soa.check_soa("cl.cam.ac.uk")
        self.assertIn("values", result)
        values = cast(SOARecordSuccessful, result)["values"]
        self.assertEqual(values["primary_nameserver"], "dns0.cl.cam.ac.uk")

    @unittest.skipIf(OFFLINE_MODE, "Network tests skipped in offline mode")
    def testCheckSoaFallsBackToBaseDomainLive(self):
        """A name with no SOA of its own falls back to the base domain"""
        result = checkdmarc.soa.check_soa("www.ietf.org")
        self.assertIn("values", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
