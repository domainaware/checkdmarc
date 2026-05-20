"""Tests for checkdmarc.mta_sts"""

import unittest
from typing import Any, Optional, cast
from unittest.mock import MagicMock, patch

import dns.resolver

import checkdmarc.mta_sts


class Test(unittest.TestCase):
    def testParseMtaStsRecord(self):
        """parse_mta_sts_record parses a valid MTA-STS record"""
        record = "v=STSv1; id=20240101T010101"
        result = checkdmarc.mta_sts.parse_mta_sts_record(record)
        self.assertEqual(result["tags"]["v"], "STSv1")
        self.assertEqual(result["tags"]["id"], "20240101T010101")

    def testParseMtaStsRecordInvalidTag(self):
        """Invalid MTA-STS tag raises MTASTSRecordSyntaxError"""
        record = "v=STSv1; xyz=foo"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSRecordSyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_record,
            record,
        )

    def testParseMtaStsRecordSPF(self):
        """SPF record in MTA-STS raises SPFRecordFoundWhereMTASTSRecordShouldBe"""
        record = "v=spf1 -all"
        self.assertRaises(
            checkdmarc.mta_sts.SPFRecordFoundWhereMTASTSRecordShouldBe,
            checkdmarc.mta_sts.parse_mta_sts_record,
            record,
        )

    def testParseMtaStsRecordDuplicateTag(self):
        """Duplicate MTA-STS tag raises InvalidMTASTSTag"""
        record = "v=STSv1; id=foo; id=bar"
        self.assertRaises(
            checkdmarc.mta_sts.InvalidMTASTSTag,
            checkdmarc.mta_sts.parse_mta_sts_record,
            record,
        )

    def testParseMtaStsPolicy(self):
        """parse_mta_sts_policy parses a valid policy"""
        policy = "version: STSv1\r\nmode: enforce\r\nmax_age: 86400\r\nmx: mail.example.com\r\n"
        result = checkdmarc.mta_sts.parse_mta_sts_policy(policy)
        self.assertEqual(result["policy"]["mode"], "enforce")
        self.assertEqual(result["policy"]["max_age"], 86400)
        self.assertEqual(result["policy"]["mx"], ["mail.example.com"])

    def testParseMtaStsPolicyUnixLineEndings(self):
        """parse_mta_sts_policy handles Unix line endings"""
        policy = "version: STSv1\nmode: testing\nmax_age: 3600\nmx: *.example.com\n"
        result = checkdmarc.mta_sts.parse_mta_sts_policy(policy)
        self.assertEqual(result["policy"]["mode"], "testing")

    def testParseMtaStsPolicyMissingKey(self):
        """parse_mta_sts_policy raises error for missing required keys"""
        policy = "version: STSv1\r\nmode: enforce\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyInvalidMaxAge(self):
        """parse_mta_sts_policy raises error for negative max_age"""
        policy = (
            "version: STSv1\r\nmode: enforce\r\nmax_age: -1\r\nmx: mail.example.com\r\n"
        )
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyDecimalMaxAge(self):
        """parse_mta_sts_policy raises error for decimal max_age"""
        policy = "version: STSv1\r\nmode: enforce\r\nmax_age: 86400.5\r\nmx: mail.example.com\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyTooLargeMaxAge(self):
        """parse_mta_sts_policy raises error for max_age > 31557600"""
        policy = "version: STSv1\r\nmode: enforce\r\nmax_age: 99999999\r\nmx: mail.example.com\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyNonIntegerMaxAge(self):
        """parse_mta_sts_policy raises error for non-integer max_age"""
        policy = "version: STSv1\r\nmode: enforce\r\nmax_age: abc\r\nmx: mail.example.com\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyDuplicateKey(self):
        """parse_mta_sts_policy raises error for duplicate key"""
        policy = "version: STSv1\r\nmode: enforce\r\nmode: testing\r\nmax_age: 86400\r\nmx: mail.example.com\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyInvalidVersion(self):
        """parse_mta_sts_policy raises error for invalid version"""
        policy = "version: STSv2\r\nmode: enforce\r\nmax_age: 86400\r\nmx: mail.example.com\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyInvalidMode(self):
        """parse_mta_sts_policy raises error for invalid mode"""
        policy = "version: STSv1\r\nmode: invalid\r\nmax_age: 86400\r\nmx: mail.example.com\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyEnforceModeNoMx(self):
        """enforce mode without mx raises error"""
        policy = "version: STSv1\r\nmode: enforce\r\nmax_age: 86400\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyBadKeyValue(self):
        """parse_mta_sts_policy raises error for bad key:value pair"""
        policy = "version: STSv1\r\nnot_a_pair\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testParseMtaStsPolicyUnexpectedKey(self):
        """parse_mta_sts_policy raises error for unexpected key"""
        policy = "version: STSv1\r\nmode: enforce\r\nmax_age: 86400\r\nmx: mail.example.com\r\nbadkey: badvalue\r\n"
        self.assertRaises(
            checkdmarc.mta_sts.MTASTSPolicySyntaxError,
            checkdmarc.mta_sts.parse_mta_sts_policy,
            policy,
        )

    def testMxInMtaStsPatterns(self):
        """mx_in_mta_sts_patterns correctly matches hostnames"""
        self.assertTrue(
            checkdmarc.mta_sts.mx_in_mta_sts_patterns(
                "mail.example.com", ["mail.example.com"]
            )
        )
        self.assertTrue(
            checkdmarc.mta_sts.mx_in_mta_sts_patterns(
                "mail.example.com", ["*.example.com"]
            )
        )
        self.assertFalse(
            checkdmarc.mta_sts.mx_in_mta_sts_patterns(
                "mail.other.com", ["*.example.com"]
            )
        )

    def testCheckMtaStsError(self):
        """check_mta_sts returns error when record not found"""
        with patch("checkdmarc.mta_sts.query_mta_sts_record") as mock_query:
            mock_query.side_effect = checkdmarc.mta_sts.MTASTSRecordNotFound(
                "An MTA-STS DNS record does not exist."
            )
            result = checkdmarc.mta_sts.check_mta_sts("example.com")
            self.assertFalse(result["valid"])


class TestQueryMtaStsRecord(unittest.TestCase):
    def testRecordFound(self):
        with patch(
            "checkdmarc.mta_sts.query_dns",
            return_value=["v=STSv1; id=20240101T010101"],
        ):
            result = checkdmarc.mta_sts.query_mta_sts_record("example.com")
        self.assertEqual(result["record"], "v=STSv1; id=20240101T010101")

    def testNoRecordAnywhereRaisesNotFound(self):
        """No record at _mta-sts and no record at apex raises MTASTSRecordNotFound"""
        with patch("checkdmarc.mta_sts.query_dns", side_effect=dns.resolver.NoAnswer()):
            self.assertRaises(
                checkdmarc.mta_sts.MTASTSRecordNotFound,
                checkdmarc.mta_sts.query_mta_sts_record,
                "example.com",
            )

    def testApexFallbackNXDOMAIN(self):
        """If both _mta-sts and apex return NXDOMAIN, raise MTASTSRecordNotFound"""

        def fake_dns(target, rdtype, **kwargs):
            raise dns.resolver.NXDOMAIN()

        with patch("checkdmarc.mta_sts.query_dns", side_effect=fake_dns):
            self.assertRaises(
                checkdmarc.mta_sts.MTASTSRecordNotFound,
                checkdmarc.mta_sts.query_mta_sts_record,
                "example.com",
            )


class TestDownloadMtaStsPolicy(unittest.TestCase):
    @staticmethod
    def _make_session(
        *,
        content_type: Optional[str] = "text/plain",
        text: str = "version: STSv1",
        raise_exc: Optional[BaseException] = None,
    ):
        fake_session = MagicMock()
        response = MagicMock()
        response.text = text
        response.headers = (
            {"Content-Type": content_type} if content_type is not None else {}
        )
        if raise_exc is None:
            response.raise_for_status = MagicMock(return_value=None)
        else:
            response.raise_for_status = MagicMock(side_effect=raise_exc)
        fake_session.get.return_value = response
        return fake_session

    def testSuccess(self):
        with patch(
            "checkdmarc.mta_sts.requests.Session",
            return_value=self._make_session(),
        ):
            result = checkdmarc.mta_sts.download_mta_sts_policy("example.com")
        self.assertEqual(result["policy"], "version: STSv1")
        self.assertEqual(result["warnings"], [])

    def testWrongContentTypeWarns(self):
        with patch(
            "checkdmarc.mta_sts.requests.Session",
            return_value=self._make_session(content_type="text/html"),
        ):
            result = checkdmarc.mta_sts.download_mta_sts_policy("example.com")
        self.assertTrue(any("Content-Type" in w for w in result["warnings"]))

    def testMissingContentTypeWarns(self):
        with patch(
            "checkdmarc.mta_sts.requests.Session",
            return_value=self._make_session(content_type=None),
        ):
            result = checkdmarc.mta_sts.download_mta_sts_policy("example.com")
        self.assertTrue(
            any("Content-Type" in w and "missing" in w for w in result["warnings"])
        )

    def testHttpFailureRaises(self):
        with patch(
            "checkdmarc.mta_sts.requests.Session",
            return_value=self._make_session(raise_exc=Exception("HTTP 404")),
        ):
            self.assertRaises(
                checkdmarc.mta_sts.MTASTSPolicyDownloadError,
                checkdmarc.mta_sts.download_mta_sts_policy,
                "example.com",
            )


class TestCheckMtaStsSuccess(unittest.TestCase):
    def testFullSuccess(self):
        """check_mta_sts end-to-end with valid record and policy returns valid=True"""
        valid_policy = (
            "version: STSv1\r\n"
            "mode: enforce\r\n"
            "max_age: 86400\r\n"
            "mx: mail.example.com\r\n"
        )
        with patch(
            "checkdmarc.mta_sts.query_mta_sts_record",
            return_value={
                "record": "v=STSv1; id=20240101T010101",
                "warnings": [],
            },
        ):
            with patch(
                "checkdmarc.mta_sts.download_mta_sts_policy",
                return_value={"policy": valid_policy, "warnings": []},
            ):
                result = checkdmarc.mta_sts.check_mta_sts("example.com")
        self.assertTrue(result["valid"])
        # narrow the MTASTSCheckSuccess | MTASTSCheckFailure union for pyright
        success = cast(Any, result)
        self.assertEqual(success["policy"]["mode"], "enforce")


if __name__ == "__main__":
    unittest.main(verbosity=2)
