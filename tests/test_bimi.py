"""Tests for checkdmarc.bimi"""

import os
import unittest
from unittest.mock import patch
from typing import Any, cast

import dns.resolver

import checkdmarc.bimi

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"

network_test = unittest.skipIf(
    OFFLINE_MODE, "Real-network test skipped on GitHub Actions"
)
mocked_only = unittest.skipUnless(
    OFFLINE_MODE, "Mocked counterpart skipped locally; network test covers this"
)


class Test(unittest.TestCase):
    @network_test
    def testBIMI(self):
        """Test BIMI checks"""
        domain = "chase.com"

        results = checkdmarc.bimi.check_bimi(domain)

        self.assertEqual(len(cast(Any, results)["warnings"]), 0)

    @mocked_only
    def testBIMIMocked(self):
        """check_bimi parses a no-logo record cleanly (mocked DNS)

        ``l=;`` is the BIMI declination form (issuer declares no logo),
        which exercises the parse path without triggering any HTTP fetches.
        """
        with patch(
            "checkdmarc.bimi._query_bimi_record", side_effect=["v=BIMI1; l=;", None]
        ):
            with patch("checkdmarc.bimi.query_dns", return_value=[]):
                results = checkdmarc.bimi.check_bimi("example.com")

        self.assertTrue(cast(Any, results)["valid"])
        self.assertEqual(len(cast(Any, results)["warnings"]), 0)


class TestLpsTag(unittest.TestCase):
    """parse_bimi_record handles the lps= tag (comma-separated local-parts)"""

    def testCommaSeparatedSelectors(self):
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; lps=news,billing,support")
        self.assertEqual(result["tags"]["lps"]["value"], ["news", "billing", "support"])

    def testSpacesAroundCommasAreStripped(self):
        result = checkdmarc.bimi.parse_bimi_record(
            "v=BIMI1; lps=news, billing, support"
        )
        self.assertEqual(result["tags"]["lps"]["value"], ["news", "billing", "support"])

    def testSelectorsLowercased(self):
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; lps=News,Billing")
        self.assertEqual(result["tags"]["lps"]["value"], ["news", "billing"])

    def testSelectorCharacters(self):
        """Per draft-bimi-14 § 4.3.14, local-part-text = ALPHA / DIGIT / '-' only"""
        result = checkdmarc.bimi.parse_bimi_record(
            "v=BIMI1; lps=sales-team,help-desk,info123"
        )
        self.assertEqual(
            result["tags"]["lps"]["value"],
            ["sales-team", "help-desk", "info123"],
        )

    def testSingleSelector(self):
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; lps=news")
        self.assertEqual(result["tags"]["lps"]["value"], ["news"])

    def testInvalidCharactersRejected(self):
        """Underscores and dots are not allowed in local-part-text"""
        self.assertRaises(
            checkdmarc.bimi.BIMISyntaxError,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; lps=help_desk",
        )
        self.assertRaises(
            checkdmarc.bimi.BIMISyntaxError,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; lps=info.support",
        )


class TestQueryBimiRecordPropagatesSpecificErrors(unittest.TestCase):
    """Regression coverage for the exception-handling fix in _query_bimi_record.

    Previously the broad ``except Exception`` clauses converted these specific
    BIMI subclasses into ``BIMIRecordNotFound`` (or swallowed them entirely),
    making them unreachable for callers.
    """

    def testMultipleRecordsPropagates(self):
        """Two v=BIMI1 records at the selector raise MultipleBIMIRecords (not BIMIRecordNotFound)"""
        with patch(
            "checkdmarc.bimi.query_dns",
            return_value=["v=BIMI1; l=https://a.example/a.svg", "v=BIMI1; l="],
        ):
            self.assertRaises(
                checkdmarc.bimi.MultipleBIMIRecords,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )

    def testUnrelatedRecordPropagates(self):
        """A v=BIMI1 record alongside an unrelated TXT raises UnrelatedTXTRecordFoundAtBIMI"""
        with patch(
            "checkdmarc.bimi.query_dns",
            return_value=["v=BIMI1; l=", "some other txt record"],
        ):
            self.assertRaises(
                checkdmarc.bimi.UnrelatedTXTRecordFoundAtBIMI,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )

    def testWrongLocationPropagates(self):
        """A v=BIMI1 record at the apex (not at the selector) raises BIMIRecordInWrongLocation.

        The selector returns NoAnswer, so the apex fallback runs and discovers
        the record there. Before the fix, the missing ``raise`` keyword caused
        this exception to be silently swallowed and the function returned None.
        """

        def fake_query_dns(target, rdtype, **kwargs):
            if target == "default._bimi.example.com":
                raise dns.resolver.NoAnswer()
            if target == "example.com":
                return ["v=BIMI1; l="]
            return []

        with patch("checkdmarc.bimi.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.bimi.BIMIRecordInWrongLocation,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )

    def testGenericExceptionStillConvertsToNotFound(self):
        """Non-BIMI exceptions are still wrapped as BIMIRecordNotFound"""
        with patch(
            "checkdmarc.bimi.query_dns", side_effect=RuntimeError("network down")
        ):
            self.assertRaises(
                checkdmarc.bimi.BIMIRecordNotFound,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )

    def testApexGenericExceptionConvertsToNotFound(self):
        """In the apex-fallback path, non-BIMI exceptions also wrap as BIMIRecordNotFound.

        Before the fix, the apex-fallback exception clause was missing ``raise``,
        so this exception was silently dropped and the function returned None.
        """

        def fake_query_dns(target, rdtype, **kwargs):
            if target == "default._bimi.example.com":
                raise dns.resolver.NoAnswer()
            raise RuntimeError("network down")

        with patch("checkdmarc.bimi.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.bimi.BIMIRecordNotFound,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
