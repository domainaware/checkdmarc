"""Tests for the top-level checkdmarc package"""

import json
import os
import unittest
from unittest.mock import patch
from typing import Any, cast

import checkdmarc
import checkdmarc.utils

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"

known_good_domains = ["fbi.gov", "pm.me", "ssa.gov"]

network_test = unittest.skipIf(
    OFFLINE_MODE, "Real-network test skipped on GitHub Actions"
)
mocked_only = unittest.skipUnless(
    OFFLINE_MODE, "Mocked counterpart skipped locally; network test covers this"
)


class Test(unittest.TestCase):
    @network_test
    def testKnownGood(self):
        """Domains with known good, SPF and DMARC records"""

        results = checkdmarc.check_domains(known_good_domains)
        if not isinstance(results, list):
            results = [results]
        for result in results:
            spf_result = cast(Any, result["spf"])
            dmarc_result = result["dmarc"]
            spf_error = None
            dmarc_error = None
            if "error" in spf_result:
                spf_error = spf_result["error"]
            if "error" in dmarc_result:
                dmarc_error = dmarc_result["error"]
            self.assertEqual(
                spf_result["valid"],
                True,
                "Known good domain {0} failed SPF check:\n\n{1}".format(
                    result["domain"], spf_error
                ),
            )
            self.assertEqual(
                dmarc_result["valid"],
                True,
                "Known good domain {0} failed DMARC check:\n\n{1}".format(
                    result["domain"], dmarc_error
                ),
            )

    @mocked_only
    def testKnownGoodMocked(self):
        """check_domains orchestrates per-check helpers and returns valid=True (mocked)

        The component check_* helpers each have their own focused tests; this
        covers the orchestration in check_domains for the multi-domain code path.
        """
        from contextlib import ExitStack

        check_returns = {
            "checkdmarc.test_dnssec": False,
            "checkdmarc.check_soa": {"valid": True, "values": {}},
            "checkdmarc.check_ns": {
                "hostnames": ["ns1.example.com"],
                "warnings": [],
            },
            "checkdmarc.check_mta_sts": {"valid": False, "error": "not found"},
            "checkdmarc.check_mx": {"hosts": [], "warnings": []},
            "checkdmarc.check_spf": {
                "record": "v=spf1 -all",
                "valid": True,
                "warnings": [],
            },
            "checkdmarc.check_dmarc": {
                "record": "v=DMARC1; p=reject",
                "valid": True,
                "warnings": [],
                "tags": {},
            },
            "checkdmarc.check_smtp_tls_reporting": {
                "valid": False,
                "error": "not found",
            },
            "checkdmarc.check_bimi": {"valid": True, "warnings": []},
        }
        with ExitStack() as stack:
            for target, return_value in check_returns.items():
                stack.enter_context(patch(target, return_value=return_value))
            results = checkdmarc.check_domains(known_good_domains)

        if not isinstance(results, list):
            results = [results]
        for result in results:
            self.assertTrue(cast(Any, result["spf"])["valid"])
            self.assertTrue(result["dmarc"]["valid"])

    def testResultsToJson(self):
        """results_to_json produces valid JSON"""
        results = cast(
            checkdmarc.DomainCheckResult,
            {"domain": "example.com", "valid": True},
        )
        json_str = checkdmarc.results_to_json(results)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["domain"], "example.com")

    def testResultsToJsonList(self):
        """results_to_json handles list of results"""
        results = cast(
            list[checkdmarc.DomainCheckResult],
            [
                {"domain": "example.com"},
                {"domain": "example.org"},
            ],
        )
        json_str = checkdmarc.results_to_json(results)
        parsed = json.loads(json_str)
        self.assertEqual(len(parsed), 2)

    def testResultsToCsvRows(self):
        """results_to_csv_rows converts results to CSV row dicts"""
        results = cast(
            checkdmarc.DomainCheckResult,
            {
                "domain": "example.com",
                "base_domain": "example.com",
                "dnssec": False,
                "ns": {"hostnames": ["ns1.example.com"], "warnings": []},
                "mx": {"hosts": [], "warnings": []},
                "mta_sts": {"valid": False, "error": "not found"},
                "spf": {
                    "record": "v=spf1 -all",
                    "valid": True,
                    "warnings": [],
                },
                "dmarc": {
                    "record": "v=DMARC1; p=reject",
                    "location": "example.com",
                    "valid": True,
                    "tags": {
                        "adkim": {"value": "r"},
                        "aspf": {"value": "r"},
                        "fo": {"value": ["0"]},
                        "p": {"value": "reject"},
                        "pct": {"value": 100},
                        "rf": {"value": ["afrf"]},
                        "ri": {"value": 86400},
                        "sp": {"value": "reject"},
                    },
                    "warnings": [],
                },
                "smtp_tls_reporting": {
                    "valid": False,
                    "error": "not found",
                },
            },
        )
        rows = checkdmarc.results_to_csv_rows(results)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["domain"], "example.com")

    def testCheckNsSuccess(self):
        """check_ns returns nameservers on success"""
        with patch("checkdmarc.get_nameservers") as mock_ns:
            mock_ns.return_value = {
                "hostnames": ["ns1.example.com"],
                "warnings": [],
            }
            result = checkdmarc.check_ns("example.com")
            self.assertIn("hostnames", result)
            self.assertEqual(len(result["hostnames"]), 1)

    def testCheckNsError(self):
        """check_ns returns error on DNS failure"""
        with patch("checkdmarc.get_nameservers") as mock_ns:
            mock_ns.side_effect = checkdmarc.utils.DNSException("DNS error")
            result = checkdmarc.check_ns("example.com")
            self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
