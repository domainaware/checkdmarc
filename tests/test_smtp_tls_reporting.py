"""Tests for checkdmarc.smtp_tls_reporting"""

import unittest
from typing import Any, cast
from unittest.mock import patch

import dns.resolver

import checkdmarc.smtp_tls_reporting


class Test(unittest.TestCase):
    def testParseSmtpTlsReportingRecord(self):
        """parse_smtp_tls_reporting_record parses a valid record"""
        record = "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(record)
        self.assertIn("rua", result["tags"])
        self.assertIn("mailto:tlsrpt@example.com", result["tags"]["rua"]["value"])

    def testParseSmtpTlsReportingRecordWithDescriptions(self):
        """parse_smtp_tls_reporting_record includes descriptions when requested"""
        record = "v=TLSRPTv1; rua=mailto:tlsrpt@example.com"
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(
            record, include_tag_descriptions=True
        )
        self.assertIn("description", result["tags"]["rua"])

    def testParseSmtpTlsReportingExtensionTag(self):
        """Unknown extension fields are ignored with a warning (RFC 8460 s3)"""
        record = "v=TLSRPTv1; rua=mailto:a@example.com; extension-field.1=foo"
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(record)
        self.assertEqual(result["tags"]["rua"]["value"], ["mailto:a@example.com"])
        self.assertNotIn("extension-field.1", result["tags"])
        self.assertTrue(
            any("extension-field.1" in warning for warning in result["warnings"])
        )

    def testParseSmtpTlsReportingDigitInitialExtensionTag(self):
        """Digit-initial extension names are legal per the RFC 8460 s3 ABNF"""
        record = "v=TLSRPTv1; rua=mailto:a@example.com; 1ext=foo"
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(record)
        self.assertEqual(result["tags"]["rua"]["value"], ["mailto:a@example.com"])
        self.assertNotIn("1ext", result["tags"])
        self.assertTrue(any("1ext" in warning for warning in result["warnings"]))

    def testParseSmtpTlsReportingDuplicateTag(self):
        """Duplicate rua tags warn but stay valid; the first value is used"""
        record = "v=TLSRPTv1; rua=mailto:a@example.com; rua=mailto:b@example.com"
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(record)
        self.assertEqual(result["tags"]["rua"]["value"], ["mailto:a@example.com"])
        self.assertTrue(
            any("more than one rua" in warning for warning in result["warnings"])
        )

    def testParseSmtpTlsReportingWhitespaceAroundURICommas(self):
        """Whitespace around rua URI commas is allowed (RFC 8460 s3 ABNF)"""
        record = "v=TLSRPTv1; rua=mailto:a@x.com, mailto:b@x.com"
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(record)
        self.assertEqual(
            result["tags"]["rua"]["value"], ["mailto:a@x.com", "mailto:b@x.com"]
        )
        self.assertEqual(result["warnings"], [])

    def testParseSmtpTlsReportingWSPAroundEquals(self):
        """Whitespace around = is a syntax error per the RFC 8460 s3 ABNF"""
        record = "v = TLSRPTv1; rua=mailto:a@example.com"
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            record,
        )
        record = "v=TLSRPTv1; rua =mailto:a@example.com"
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            record,
        )

    def testParseSmtpTlsReportingUppercaseTagName(self):
        """RUA= is not the rua tag: tag names are case-sensitive (RFC 7405 %s)"""
        record = "v=TLSRPTv1; RUA=mailto:a@example.com"
        # RUA is treated as an unknown extension field, so the record has
        # no rua tag, which is an error
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            record,
        )

    def testParseSmtpTlsReportingGarbagePrefixedURI(self):
        """A URI with a garbage prefix like xhttps:// is rejected"""
        record = "v=TLSRPTv1; rua=xhttps://example.com/tlsrpt"
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            record,
        )

    def testParseSmtpTlsReportingSPF(self):
        """SPF in SMTP TLS Reporting raises SPFRecordFoundWhereTLSRPTShouldBe"""
        record = "v=spf1 -all"
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SPFRecordFoundWhereTLSRPTShouldBe,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            record,
        )

    def testParseSmtpTlsReportingInvalidURI(self):
        """Invalid URI raises SMTPTLSReportingSyntaxError"""
        record = "v=TLSRPTv1; rua=not_a_valid_uri"
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            record,
        )

    def testParseSmtpTlsReportingMissingRua(self):
        """Missing rua tag raises SMTPTLSReportingSyntaxError"""
        record = "v=TLSRPTv1"
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            record,
        )

    def testParseSmtpTlsReportingHttpsURI(self):
        """HTTPS URIs are accepted in SMTP TLS Reporting"""
        record = "v=TLSRPTv1; rua=https://tlsrpt.example.com/report"
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(record)
        self.assertIn("rua", result["tags"])

    def testCheckSmtpTlsReportingError(self):
        """check_smtp_tls_reporting returns error when record not found"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record"
        ) as mock_query:
            mock_query.side_effect = (
                checkdmarc.smtp_tls_reporting.SMTPTLSReportingRecordNotFound(
                    "Record not found"
                )
            )
            result = checkdmarc.smtp_tls_reporting.check_smtp_tls_reporting(
                "example.com"
            )
            self.assertFalse(result["valid"])

    def testTrailingFieldDelimiter(self):
        """A trailing field delimiter is legal per the RFC 8460 section 3
        ABNF; the empty final field it leaves is skipped"""
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(
            "v=TLSRPTv1; rua=mailto:tlsrpt@example.com;"
        )
        self.assertIn("mailto:tlsrpt@example.com", result["tags"]["rua"]["value"])

    def testWspBeforeFieldDelimiterWarns(self):
        """WSP before the ";" is legal per the RFC 8460 section 3 ABNF
        (field-delim = *WSP ";" *WSP) but warned about, because the
        section 3.1 prose discard rule keys on the literal "v=TLSRPTv1;" """
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(
            "v=TLSRPTv1 ; rua=mailto:tlsrpt@example.com"
        )
        self.assertIn("mailto:tlsrpt@example.com", result["tags"]["rua"]["value"])
        self.assertTrue(
            any("v=TLSRPTv1;" in w for w in result["warnings"]), result["warnings"]
        )

    def testHttpsUriWithSpaceRejected(self):
        """RFC 3986 URIs cannot contain raw spaces"""
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            "v=TLSRPTv1; rua=https://example.com/a b",
        )

    def testExtensionValueGrammarEnforced(self):
        """Unknown fields are ignored only when their value fits the
        RFC 8460 section 3 tlsrpt-ext-value grammar (no spaces, "=", or
        control characters)"""
        base = "v=TLSRPTv1; rua=mailto:tlsrpt@example.com; "
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(
            base + "ext=ok-1"
        )
        self.assertTrue(any("ext" in w for w in result["warnings"]))
        for bad in ("x=a b", "x=a=b"):
            self.assertRaises(
                checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
                checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
                base + bad,
            )

    def testMailtoUriTlsrptEncodingRules(self):
        """RFC 8460 section 3 requires "!" in URIs to be percent-encoded and
        defines no DMARC-style size suffix"""
        for bad in (
            "v=TLSRPTv1; rua=mailto:a!b@example.com",
            "v=TLSRPTv1; rua=mailto:a@example.com!10m",
        ):
            self.assertRaises(
                checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
                checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
                bad,
            )
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(
            "v=TLSRPTv1; rua=mailto:a%21b@example.com"
        )
        self.assertIn("mailto:a%21b@example.com", result["tags"]["rua"]["value"])

    def testMailtoLocalPartDotAtomRules(self):
        """The RFC 5322 addr-spec dot-atom requires nonempty atoms between
        dots, so a leading, trailing, or doubled dot in the local part is
        invalid while inner single dots are fine"""
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(
            "v=TLSRPTv1; rua=mailto:first.last@example.com"
        )
        self.assertIn("mailto:first.last@example.com", result["tags"]["rua"]["value"])
        for bad in (
            "v=TLSRPTv1; rua=mailto:.alerts@example.com",
            "v=TLSRPTv1; rua=mailto:alerts.@example.com",
            "v=TLSRPTv1; rua=mailto:a..b@example.com",
        ):
            self.assertRaises(
                checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
                checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
                bad,
            )

    def testHttpsUriIpv6Literal(self):
        """An https report URI with a bracketed IPv6 literal authority is a
        valid RFC 3986 URI and must be accepted"""
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(
            "v=TLSRPTv1; rua=https://[2001:db8::1]/tlsrpt"
        )
        self.assertIn("https://[2001:db8::1]/tlsrpt", result["tags"]["rua"]["value"])

    def testHttpsUriInvalidIpv6LiteralRejected(self):
        """A bracketed authority that is not a real IPv6 address (RFC 4291)
        is not a valid RFC 3986 host"""
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            "v=TLSRPTv1; rua=https://[::::]/tlsrpt",
        )

    def testHttpsUriSingleFragmentDelimiter(self):
        """RFC 3986 allows "#" exactly once, as the fragment delimiter"""
        result = checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record(
            "v=TLSRPTv1; rua=https://example.com/a#one"
        )
        self.assertIn("https://example.com/a#one", result["tags"]["rua"]["value"])
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            "v=TLSRPTv1; rua=https://example.com/a#one#two",
        )


class TestQuerySmtpTlsReportingRecord(unittest.TestCase):
    def testDiscoveryAcceptsWspBeforeDelimiter(self):
        """A record with WSP before the ";" is recognized at discovery"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            return_value=["v=TLSRPTv1 ; rua=mailto:tlsrpt@example.com"],
        ):
            result = checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record(
                "example.com"
            )
        self.assertEqual(result["record"], "v=TLSRPTv1 ; rua=mailto:tlsrpt@example.com")

    def testRecordFound(self):
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            return_value=["v=TLSRPTv1; rua=mailto:rua@example.com"],
        ):
            result = checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record(
                "example.com"
            )
        self.assertEqual(result["record"], "v=TLSRPTv1; rua=mailto:rua@example.com")

    def testRecordNotFound(self):
        """NoAnswer at both _smtp._tls and apex raises SMTPTLSReportingRecordNotFound"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            side_effect=dns.resolver.NoAnswer(),
        ):
            self.assertRaises(
                checkdmarc.smtp_tls_reporting.SMTPTLSReportingRecordNotFound,
                checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record,
                "example.com",
            )

    def testUnrelatedRecordDiscardedWithWarning(self):
        """An unrelated TXT record beside the TLSRPT record is discarded
        with a warning, and the TLSRPT record is still returned
        (RFC 8460 s3.1)"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            return_value=[
                "site-verification=token123",
                "v=TLSRPTv1; rua=mailto:rua@example.com",
            ],
        ):
            result = checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record(
                "example.com"
            )
        self.assertEqual(result["record"], "v=TLSRPTv1; rua=mailto:rua@example.com")
        self.assertTrue(
            any("site-verification=token123" in w for w in result["warnings"])
        )

    def testDiscoveryPrefixRequiresSemicolon(self):
        """Records not beginning with exactly v=TLSRPTv1; are discarded
        instead of being counted as TLSRPT records (RFC 8460 s3.1)"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            return_value=[
                "v=TLSRPTv1extra; junk",
                "v=TLSRPTv1",
                "v=TLSRPTv1; rua=mailto:rua@example.com",
            ],
        ):
            # must not raise MultipleSMTPTLSReportingRecords
            result = checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record(
                "example.com"
            )
        self.assertEqual(result["record"], "v=TLSRPTv1; rua=mailto:rua@example.com")
        self.assertTrue(any("v=TLSRPTv1extra" in w for w in result["warnings"]))

    def testOnlyUnrelatedRecordsRaisesNotFound(self):
        """With only unrelated TXT records present, the record is not found"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            return_value=["site-verification=token123"],
        ):
            self.assertRaises(
                checkdmarc.smtp_tls_reporting.SMTPTLSReportingRecordNotFound,
                checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record,
                "example.com",
            )

    def testMultipleRecordsStillFatal(self):
        """Two real TLSRPT records still raise MultipleSMTPTLSReportingRecords"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            return_value=[
                "v=TLSRPTv1; rua=mailto:a@example.com",
                "v=TLSRPTv1; rua=mailto:b@example.com",
            ],
        ):
            self.assertRaises(
                checkdmarc.smtp_tls_reporting.MultipleSMTPTLSReportingRecords,
                checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record,
                "example.com",
            )

    def testNXDOMAIN(self):
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            self.assertRaises(
                checkdmarc.smtp_tls_reporting.SMTPTLSReportingRecordNotFound,
                checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record,
                "example.com",
            )

    def testRecordAtApexIsWrongLocation(self):
        """A TLSRPT record published at the domain apex instead of the
        _smtp._tls subdomain raises SMTPTLSReportingRecordInWrongLocation"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            side_effect=[
                dns.resolver.NXDOMAIN(),
                ["v=TLSRPTv1; rua=mailto:tlsrpt@example.com"],
            ],
        ):
            self.assertRaises(
                checkdmarc.smtp_tls_reporting.SMTPTLSReportingRecordInWrongLocation,
                checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record,
                "example.com",
            )


class TestCheckSmtpTlsReportingSuccess(unittest.TestCase):
    def testFullSuccess(self):
        """check_smtp_tls_reporting end-to-end with valid record returns valid=True"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_smtp_tls_reporting_record",
            return_value={
                "record": "v=TLSRPTv1; rua=mailto:rua@example.com",
                "warnings": [],
            },
        ):
            result = checkdmarc.smtp_tls_reporting.check_smtp_tls_reporting(
                "example.com"
            )
        self.assertTrue(result["valid"])
        # narrow the SMTPTLSReportingSuccess | SMTPTLSReportingFailure union
        success = cast(Any, result)
        self.assertIn("rua", success["tags"])

    def testValidBesideUnrelatedRecord(self):
        """check_smtp_tls_reporting is valid when the TLSRPT record shares
        _smtp._tls with an unrelated TXT record (RFC 8460 s3.1)"""
        with patch(
            "checkdmarc.smtp_tls_reporting.query_dns",
            return_value=[
                "site-verification=token123",
                "v=TLSRPTv1; rua=mailto:rua@example.com",
            ],
        ):
            result = checkdmarc.smtp_tls_reporting.check_smtp_tls_reporting(
                "example.com"
            )
        self.assertTrue(result["valid"])
        success = cast(Any, result)
        self.assertEqual(success["tags"]["rua"]["value"], ["mailto:rua@example.com"])
        self.assertTrue(
            any("site-verification=token123" in w for w in success["warnings"])
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
