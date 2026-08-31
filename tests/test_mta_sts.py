"""Tests for checkdmarc.mta_sts"""

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

import dns.resolver
import requests

import checkdmarc.mta_sts


class Test(unittest.TestCase):
    def testParseMtaStsRecord(self):
        """parse_mta_sts_record parses a valid MTA-STS record"""
        record = "v=STSv1; id=20240101T010101"
        result = checkdmarc.mta_sts.parse_mta_sts_record(record)
        self.assertEqual(result["tags"]["v"], "STSv1")
        self.assertEqual(result["tags"]["id"], "20240101T010101")

    def testParseMtaStsRecordUnknownTagIgnored(self):
        """Unknown/extension fields are ignored with a warning, not
        rejected, per RFC 8461 sections 3.1-3.2"""
        record = "v=STSv1; id=abc; extension=foo"
        result = checkdmarc.mta_sts.parse_mta_sts_record(record)
        self.assertEqual(result["tags"]["id"], "abc")
        self.assertNotIn("extension", result["tags"])
        self.assertTrue(any("extension" in w for w in result["warnings"]))

    def testParseMtaStsRecordMissingIdTag(self):
        """A record without the required id tag raises a syntax error
        instead of parsing successfully (RFC 8461 section 3.1)"""
        record = "v=STSv1;"
        with self.assertRaises(checkdmarc.mta_sts.MTASTSRecordSyntaxError) as ctx:
            checkdmarc.mta_sts.parse_mta_sts_record(record)
        self.assertIn("id", str(ctx.exception))

    def testParseMtaStsRecordIdTooLong(self):
        """An id longer than 32 letters/digits raises InvalidSTSTagValue
        (RFC 8461 section 3.1: id is 1*32(ALPHA / DIGIT))"""
        record = "v=STSv1; id=" + "a" * 33
        self.assertRaises(
            checkdmarc.mta_sts.InvalidSTSTagValue,
            checkdmarc.mta_sts.parse_mta_sts_record,
            record,
        )

    def testParseMtaStsRecordNoSpacesAroundEquals(self):
        """The RFC 8461 section 3.1 grammar is case-sensitive and allows
        no whitespace around the equals sign"""
        for record in (
            "v =STSv1; id=abc",
            "v= STSv1; id=abc",
            "v=STSv1; id =abc",
            "V=STSv1; id=abc",
        ):
            with self.subTest(record=record):
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
        """A duplicated tag keeps the first value and warns, per
        RFC 8461 section 3.2 (all entries except the first are ignored)"""
        record = "v=STSv1; id=foo; id=bar"
        result = checkdmarc.mta_sts.parse_mta_sts_record(record)
        self.assertEqual(result["tags"]["id"], "foo")
        self.assertTrue(any("duplicate id" in w.lower() for w in result["warnings"]))

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
        """parse_mta_sts_policy raises an error naming the missing
        required key. Uses mode "none" (which does not require mx) so
        this exercises the missing-key check itself, not the
        enforce-needs-mx check."""
        policy = "version: STSv1\r\nmode: none\r\n"
        with self.assertRaises(checkdmarc.mta_sts.MTASTSPolicySyntaxError) as ctx:
            checkdmarc.mta_sts.parse_mta_sts_policy(policy)
        self.assertIn("max_age", str(ctx.exception))

    def testParseMtaStsPolicyEmpty(self):
        """An empty policy is missing every required key; defaults must
        not be fabricated for version, mode, or max_age"""
        with self.assertRaises(checkdmarc.mta_sts.MTASTSPolicySyntaxError) as ctx:
            checkdmarc.mta_sts.parse_mta_sts_policy("")
        self.assertIn("Missing required key", str(ctx.exception))

    def testParseMtaStsPolicyMixedLineEndings(self):
        """RFC 8461 section 3.2 allows each line to end with LF or CRLF,
        so a policy mixing both must parse"""
        policy = (
            "version: STSv1\r\nmode: enforce\nmax_age: 86400\r\nmx: mail.example.com\n"
        )
        result = checkdmarc.mta_sts.parse_mta_sts_policy(policy)
        self.assertEqual(result["policy"]["mode"], "enforce")
        self.assertEqual(result["policy"]["max_age"], 86400)
        self.assertEqual(result["policy"]["mx"], ["mail.example.com"])

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

    def testParseMtaStsPolicyInvalidMxValue(self):
        """parse_mta_sts_policy rejects an mx value that is not a hostname
        pattern, naming the line. The check used findall with an unanchored
        pattern, so any value containing a single allowed character passed
        and "not a hostname!" was accepted as an MX entry."""
        policy = (
            "version: STSv1\r\n"
            "mode: enforce\r\n"
            "mx: not a hostname!\r\n"
            "max_age: 86400\r\n"
        )
        with self.assertRaises(checkdmarc.mta_sts.MTASTSPolicySyntaxError) as ctx:
            checkdmarc.mta_sts.parse_mta_sts_policy(policy)
        self.assertIn("Line 3", str(ctx.exception))
        self.assertIn("Invalid mx value", str(ctx.exception))

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
        """A duplicated non-mx key keeps the first value and warns, per
        RFC 8461 section 3.2 (all entries except the first are ignored)"""
        policy = "version: STSv1\r\nmode: enforce\r\nmode: testing\r\nmax_age: 86400\r\nmx: mail.example.com\r\n"
        result = checkdmarc.mta_sts.parse_mta_sts_policy(policy)
        self.assertEqual(result["policy"]["mode"], "enforce")
        self.assertTrue(any("duplicate mode" in w.lower() for w in result["warnings"]))

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

    def testParseMtaStsPolicyUnknownKeyIgnored(self):
        """An unknown policy key is ignored with a warning, per RFC 8461
        section 3.2 (unknown fields SHALL be ignored)"""
        policy = "version: STSv1\r\nmode: enforce\r\nmax_age: 86400\r\nmx: mail.example.com\r\nfoo_ext: bar\r\n"
        result = checkdmarc.mta_sts.parse_mta_sts_policy(policy)
        self.assertEqual(result["policy"]["mode"], "enforce")
        self.assertTrue(any("foo_ext" in w for w in result["warnings"]))

    def testParseMtaStsPolicyStrictMaxAgeDigits(self):
        """max_age must be plain digits per RFC 8461 section 3.2
        (1*10 DIGIT); values int() accepts like "1_000" and "+5" are
        invalid, and the error names the line"""
        for bad_value in ("1_000", "+5"):
            with self.subTest(max_age=bad_value):
                policy = f"version: STSv1\r\nmode: none\r\nmax_age: {bad_value}\r\n"
                with self.assertRaises(
                    checkdmarc.mta_sts.MTASTSPolicySyntaxError
                ) as ctx:
                    checkdmarc.mta_sts.parse_mta_sts_policy(policy)
                self.assertIn("Line 3", str(ctx.exception))

    def testParseMtaStsPolicyInvalidMxPatterns(self):
        """mx values must match ["*."] Domain per RFC 8461 section 3.2;
        interior or partial wildcards and label junk are invalid"""
        for bad_mx in ("mail.*.example.com", "*example.com", "..--"):
            with self.subTest(mx=bad_mx):
                policy = (
                    "version: STSv1\r\n"
                    "mode: enforce\r\n"
                    "max_age: 86400\r\n"
                    f"mx: {bad_mx}\r\n"
                )
                with self.assertRaises(
                    checkdmarc.mta_sts.MTASTSPolicySyntaxError
                ) as ctx:
                    checkdmarc.mta_sts.parse_mta_sts_policy(policy)
                self.assertIn("Invalid mx value", str(ctx.exception))

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

    def testMxInMtaStsPatternsWildcardSingleLabelOnly(self):
        """RFC 8461 section 4.1: * matches only the entire left-most
        label, and matching is against the whole hostname, so uncovered
        hosts must not report as covered"""
        f = checkdmarc.mta_sts.mx_in_mta_sts_patterns
        # * must not cross label boundaries
        self.assertFalse(f("foo.bar.example.com", ["*.example.com"]))
        # a suffix in an attacker-controlled domain must not match
        self.assertFalse(f("mail.example.com.evil.com", ["*.example.com"]))
        # a non-wildcard pattern must match the whole hostname
        self.assertFalse(f("bad-example.com", ["example.com"]))
        # * must not match zero labels
        self.assertFalse(f("example.com", ["*.example.com"]))
        # single left-most label still matches
        self.assertTrue(f("smtp1.example.com", ["*.example.com"]))

    def testCheckMtaStsError(self):
        """check_mta_sts returns error when record not found"""
        with patch("checkdmarc.mta_sts.query_mta_sts_record") as mock_query:
            mock_query.side_effect = checkdmarc.mta_sts.MTASTSRecordNotFound(
                "An MTA-STS DNS record does not exist."
            )
            result = checkdmarc.mta_sts.check_mta_sts("example.com")
            self.assertFalse(result["valid"])

    def testCheckMtaStsRecordWithoutId(self):
        """check_mta_sts reports a record without the required id tag as
        valid=False instead of crashing with a KeyError"""
        with patch(
            "checkdmarc.mta_sts.query_mta_sts_record",
            return_value={"record": "v=STSv1;", "warnings": []},
        ):
            result = checkdmarc.mta_sts.check_mta_sts("example.com")
        self.assertFalse(result["valid"])
        failure = cast(Any, result)
        self.assertIn("id", failure["error"])


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

    def testUnrelatedTxtRecordDiscardedWithWarning(self):
        """RFC 8461 section 3.1: records not beginning with "v=STSv1;"
        are discarded; with exactly one MTA-STS record remaining, the
        lookup succeeds with a warning about the unrelated record"""
        with patch(
            "checkdmarc.mta_sts.query_dns",
            return_value=[
                "site-verification=12345",
                "v=STSv1; id=20240101T010101",
            ],
        ):
            result = checkdmarc.mta_sts.query_mta_sts_record("example.com")
        self.assertEqual(result["record"], "v=STSv1; id=20240101T010101")
        self.assertTrue(any("Unrelated" in w for w in result["warnings"]))

    def testWrongVersionPrefixDiscarded(self):
        """A record starting with "v=STSv12" does not begin with the
        "v=STSv1;" prefix from RFC 8461 section 3.1, so it is discarded
        instead of counting toward MultipleMTASTSRecords"""
        with patch(
            "checkdmarc.mta_sts.query_dns",
            return_value=[
                "v=STSv12; id=bogus",
                "v=STSv1; id=20240101T010101",
            ],
        ):
            result = checkdmarc.mta_sts.query_mta_sts_record("example.com")
        self.assertEqual(result["record"], "v=STSv1; id=20240101T010101")

    def testMultipleStsRecordsStillRaise(self):
        """Two records with the MTA-STS prefix raise MultipleMTASTSRecords"""
        with patch(
            "checkdmarc.mta_sts.query_dns",
            return_value=["v=STSv1; id=a1", "v=STSv1; id=b2"],
        ):
            self.assertRaises(
                checkdmarc.mta_sts.MultipleMTASTSRecords,
                checkdmarc.mta_sts.query_mta_sts_record,
                "example.com",
            )

    def testOnlyUnrelatedTxtRecordsRaiseNotFound(self):
        """TXT records at _mta-sts that are all unrelated mean no MTA-STS
        record exists"""
        with patch(
            "checkdmarc.mta_sts.query_dns",
            return_value=["site-verification=12345"],
        ):
            self.assertRaises(
                checkdmarc.mta_sts.MTASTSRecordNotFound,
                checkdmarc.mta_sts.query_mta_sts_record,
                "example.com",
            )

    def testSpfRecordAtMtaStsSubdomain(self):
        """An SPF record (and no MTA-STS record) at _mta-sts gives the
        redirected-to-base-domain diagnostic"""
        with patch(
            "checkdmarc.mta_sts.query_dns",
            return_value=["v=spf1 -all"],
        ):
            self.assertRaises(
                checkdmarc.mta_sts.SPFRecordFoundWhereMTASTSRecordShouldBe,
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
        content_type: str | None = "text/plain",
        text: str = "version: STSv1",
        status_code: int = 200,
        raise_exc: BaseException | None = None,
    ):
        fake_session = MagicMock()
        response = MagicMock()
        response.text = text
        response.status_code = status_code
        response.headers = (
            {"Content-Type": content_type} if content_type is not None else {}
        )
        if raise_exc is None:
            fake_session.get.return_value = response
        else:
            fake_session.get.side_effect = raise_exc
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
            return_value=self._make_session(
                raise_exc=requests.exceptions.ConnectionError("connection refused")
            ),
        ):
            self.assertRaises(
                checkdmarc.mta_sts.MTASTSPolicyDownloadError,
                checkdmarc.mta_sts.download_mta_sts_policy,
                "example.com",
            )

    def testNon200StatusRaises(self):
        """RFC 8461 section 3.3: a policy is only valid when the HTTP
        response code is exactly 200"""
        for status_code in (404, 301, 204):
            with self.subTest(status_code=status_code):
                with (
                    patch(
                        "checkdmarc.mta_sts.requests.Session",
                        return_value=self._make_session(status_code=status_code),
                    ),
                    self.assertRaises(
                        checkdmarc.mta_sts.MTASTSPolicyDownloadError
                    ) as ctx,
                ):
                    checkdmarc.mta_sts.download_mta_sts_policy("example.com")
                self.assertIn(str(status_code), str(ctx.exception))

    def testRedirectsNotFollowed(self):
        """RFC 8461 section 3.3: HTTP 3xx redirects MUST NOT be followed.
        The mock provides the HTTP boundary; the assertion is that the
        request is sent with redirects disabled."""
        fake_session = self._make_session()
        with patch(
            "checkdmarc.mta_sts.requests.Session",
            return_value=fake_session,
        ):
            checkdmarc.mta_sts.download_mta_sts_policy("example.com")
        self.assertIs(fake_session.get.call_args.kwargs["allow_redirects"], False)


class TestCheckMtaStsSuccess(unittest.TestCase):
    def testFullSuccess(self):
        """check_mta_sts end-to-end with valid record and policy returns valid=True"""
        valid_policy = (
            "version: STSv1\r\n"
            "mode: enforce\r\n"
            "max_age: 86400\r\n"
            "mx: mail.example.com\r\n"
        )
        with (
            patch(
                "checkdmarc.mta_sts.query_mta_sts_record",
                return_value={
                    "record": "v=STSv1; id=20240101T010101",
                    "warnings": [],
                },
            ),
            patch(
                "checkdmarc.mta_sts.download_mta_sts_policy",
                return_value={"policy": valid_policy, "warnings": []},
            ),
        ):
            result = checkdmarc.mta_sts.check_mta_sts("example.com")
        self.assertTrue(result["valid"])
        # narrow the MTASTSCheckSuccess | MTASTSCheckFailure union for pyright
        success = cast(Any, result)
        self.assertEqual(success["policy"]["mode"], "enforce")

    def testRecordWarningsSurfaceInResults(self):
        """Warnings from record parsing (here, an ignored extension
        field) appear in the check_mta_sts results"""
        valid_policy = (
            "version: STSv1\r\n"
            "mode: enforce\r\n"
            "max_age: 86400\r\n"
            "mx: mail.example.com\r\n"
        )
        with (
            patch(
                "checkdmarc.mta_sts.query_mta_sts_record",
                return_value={
                    "record": "v=STSv1; id=abc; extension=foo",
                    "warnings": [],
                },
            ),
            patch(
                "checkdmarc.mta_sts.download_mta_sts_policy",
                return_value={"policy": valid_policy, "warnings": []},
            ),
        ):
            result = checkdmarc.mta_sts.check_mta_sts("example.com")
        self.assertTrue(result["valid"])
        success = cast(Any, result)
        self.assertTrue(any("extension" in w for w in success["warnings"]))


class TestCheckMtaStsHttpTimeout(unittest.TestCase):
    def testPolicyDownloadUsesItsOwnHttpTimeout(self):
        """check_mta_sts's timeout parameter is the DNS timeout; the policy
        download request uses the HTTP default. The DNS timeout was
        previously passed straight through as the HTTP timeout, so tuning
        DNS timing silently changed HTTP behavior. Mocks at the requests
        SDK boundary: the assertion is on the timeout the HTTP request is
        sent with."""
        valid_policy = (
            "version: STSv1\r\n"
            "mode: enforce\r\n"
            "max_age: 86400\r\n"
            "mx: mail.example.com\r\n"
        )
        fake_session = TestDownloadMtaStsPolicy._make_session(text=valid_policy)
        with (
            patch(
                "checkdmarc.mta_sts.query_mta_sts_record",
                return_value={
                    "record": "v=STSv1; id=20240101T010101",
                    "warnings": [],
                },
            ),
            patch("checkdmarc.mta_sts.requests.Session", return_value=fake_session),
        ):
            result = checkdmarc.mta_sts.check_mta_sts("example.com", timeout=0.001)
        self.assertTrue(result["valid"])
        self.assertEqual(
            fake_session.get.call_args.kwargs["timeout"],
            checkdmarc.mta_sts.DEFAULT_HTTP_TIMEOUT,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
