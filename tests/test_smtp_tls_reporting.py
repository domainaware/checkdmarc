"""Tests for checkdmarc.smtp_tls_reporting"""

import unittest
from unittest.mock import patch

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

    def testParseSmtpTlsReportingInvalidTag(self):
        """Invalid SMTP TLS tag raises InvalidSMTPTLSReportingTag"""
        record = "v=TLSRPTv1; xyz=foo"
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.InvalidSMTPTLSReportingTag,
            checkdmarc.smtp_tls_reporting.parse_smtp_tls_reporting_record,
            record,
        )

    def testParseSmtpTlsReportingDuplicateTag(self):
        """Duplicate SMTP TLS tag raises InvalidSMTPTLSReportingTag"""
        record = "v=TLSRPTv1; rua=mailto:a@example.com; rua=mailto:b@example.com"
        self.assertRaises(
            checkdmarc.smtp_tls_reporting.InvalidSMTPTLSReportingTag,
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
