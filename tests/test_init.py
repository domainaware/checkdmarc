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


def _full_result(domain="example.com", *, with_bimi=False, with_errors=False):
    """Build a richly-populated DomainCheckResult covering CSV row branches."""
    result = {
        "domain": domain,
        "base_domain": domain,
        "dnssec": True,
        "ns": {"hostnames": ["ns1.example.com", "ns2.example.com"], "warnings": []},
        "mx": {
            "hosts": [
                {
                    "preference": 10,
                    "hostname": "mail.example.com",
                    "addresses": ["192.0.2.1"],
                    "starttls": True,
                    "tls": True,
                }
            ],
            "warnings": [],
        },
        "mta_sts": {
            "valid": True,
            "id": "20240101T010101",
            "policy": {
                "mode": "enforce",
                "max_age": 86400,
                "mx": ["mail.example.com"],
            },
            "warnings": [],
        },
        "spf": {
            "record": "v=spf1 -all",
            "valid": True,
            "warnings": [],
        },
        "dmarc": {
            "record": "v=DMARC1; p=reject; rua=mailto:rua@example.com; ruf=mailto:ruf@example.com",
            "location": domain,
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
                "rua": {"value": [{"scheme": "mailto", "address": "rua@example.com"}]},
                "ruf": {"value": [{"scheme": "mailto", "address": "ruf@example.com"}]},
            },
            "warnings": [],
        },
        "smtp_tls_reporting": {
            "valid": True,
            "tags": {
                "rua": {"value": ["mailto:tlsrpt@example.com"]},
            },
            "warnings": [],
        },
    }
    if with_bimi:
        result["bimi"] = {
            "valid": True,
            "selector": "default",
            "warnings": ["a bimi warning"],
            "tags": {
                "l": {"value": "https://example.com/logo.svg"},
                "a": {"value": "https://example.com/cert.pem"},
            },
        }
    if with_errors:
        result["ns"] = {"hostnames": [], "error": "DNS error"}
        result["mx"] = {"hosts": [], "error": "no MX"}
        result["mta_sts"] = {"valid": False, "error": "not found"}
        result["spf"] = {
            "record": "",
            "valid": False,
            "error": "spf error",
            "warnings": [],
        }
        result["dmarc"] = {
            "record": "",
            "location": "",
            "valid": False,
            "error": "dmarc error",
            "warnings": [],
        }
        result["smtp_tls_reporting"] = {"valid": False, "error": "not found"}
    return result


class TestResultsToCsvRowsBranches(unittest.TestCase):
    def testFullSuccessRow(self):
        rows = checkdmarc.results_to_csv_rows(
            cast(checkdmarc.DomainCheckResult, _full_result())
        )
        row = rows[0]
        self.assertEqual(row["domain"], "example.com")
        self.assertEqual(row["mta_sts_id"], "20240101T010101")
        self.assertEqual(row["mta_sts_mode"], "enforce")
        # DMARC rua / ruf flattened
        self.assertEqual(row["dmarc_rua"], "mailto:rua@example.com")
        self.assertEqual(row["dmarc_ruf"], "mailto:ruf@example.com")
        # TLS / STARTTLS extracted from mx hosts
        self.assertEqual(row["tls"], "True")
        self.assertEqual(row["starttls"], "True")
        self.assertEqual(row["smtp_tls_reporting_valid"], True)

    def testFullSuccessRowWithBimi(self):
        rows = checkdmarc.results_to_csv_rows(
            cast(checkdmarc.DomainCheckResult, _full_result(with_bimi=True))
        )
        row = rows[0]
        self.assertEqual(row["bimi_selector"], "default")
        self.assertIn("bimi_warnings", row)

    def testErrorBranches(self):
        """When sub-checks are in error state, the corresponding _error fields appear"""
        rows = checkdmarc.results_to_csv_rows(
            cast(checkdmarc.DomainCheckResult, _full_result(with_errors=True))
        )
        row = rows[0]
        self.assertEqual(row["ns_error"], "DNS error")
        self.assertEqual(row["mx_error"], "no MX")
        self.assertEqual(row["mta_sts_error"], "not found")
        self.assertEqual(row["spf_error"], "spf error")
        self.assertEqual(row["dmarc_error"], "dmarc error")
        self.assertFalse(row["smtp_tls_reporting_valid"])
        self.assertEqual(row["smtp_tls_reporting_error"], "not found")

    def testListOfResults(self):
        """A list input produces one row per result"""
        rows = checkdmarc.results_to_csv_rows(
            cast(
                list[checkdmarc.DomainCheckResult],
                [_full_result("a.example"), _full_result("b.example")],
            )
        )
        self.assertEqual(len(rows), 2)


class TestResultsToCsv(unittest.TestCase):
    def testCsvHeaderAndRow(self):
        csv_text = checkdmarc.results_to_csv(
            cast(checkdmarc.DomainCheckResult, _full_result())
        )
        # Header row is present and the example.com row follows
        self.assertIn("domain", csv_text.splitlines()[0])
        self.assertIn("example.com", csv_text)


class TestCheckDomainsBranches(unittest.TestCase):
    @staticmethod
    def _patch_checks(stack, *, wait=0.0):
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
        for target, return_value in check_returns.items():
            stack.enter_context(patch(target, return_value=return_value))

    def testSingleDomainUnwrap(self):
        """A single-domain input returns a single dict (not a list)"""
        from contextlib import ExitStack

        with ExitStack() as stack:
            self._patch_checks(stack)
            result = checkdmarc.check_domains(["example.com"])
        self.assertIsInstance(result, dict)
        self.assertEqual(cast(Any, result)["domain"], "example.com")

    def testDomainWithoutDotFilteredOut(self):
        """Inputs that don't contain a '.' are filtered out before any checks"""
        from contextlib import ExitStack

        with ExitStack() as stack:
            self._patch_checks(stack)
            # Passing only an entry without '.' means the domains list ends up empty
            result = checkdmarc.check_domains(["localhost"])
        # An empty list returns an empty list (not unwrapped)
        self.assertEqual(result, [])

    def testWaitInvokesSleep(self):
        """wait > 0 calls time.sleep between domains"""
        from contextlib import ExitStack

        with ExitStack() as stack:
            self._patch_checks(stack)
            with patch("checkdmarc.sleep") as mock_sleep:
                checkdmarc.check_domains(["a.example", "b.example"], wait=0.1)
        # Sleep is called once per domain when wait > 0
        self.assertEqual(mock_sleep.call_count, 2)


class TestCheckDomainsInputFiltering(unittest.TestCase):
    """Edge cases in check_domains' input list normalization"""

    @staticmethod
    def _patch_all_checks(stack):
        from contextlib import ExitStack  # noqa: F401

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
        for target, return_value in check_returns.items():
            stack.enter_context(patch(target, return_value=return_value))

    def testEmptyStringsStripped(self):
        """Empty-string domains are filtered out before any checks"""
        from contextlib import ExitStack

        with ExitStack() as stack:
            self._patch_all_checks(stack)
            result = checkdmarc.check_domains(["", "example.com", ""])
        # Result is the single example.com (unwrapped)
        self.assertEqual(cast(Any, result)["domain"], "example.com")

    def testMtaStsValidPolicyPropagatesMxPatterns(self):
        """A valid MTA-STS policy's mx patterns are forwarded to check_mx"""
        from contextlib import ExitStack

        check_returns = {
            "checkdmarc.test_dnssec": False,
            "checkdmarc.check_soa": {"valid": True, "values": {}},
            "checkdmarc.check_ns": {
                "hostnames": ["ns1.example.com"],
                "warnings": [],
            },
            "checkdmarc.check_mta_sts": {
                "valid": True,
                "id": "20240101T010101",
                "policy": {
                    "mode": "enforce",
                    "max_age": 86400,
                    "mx": ["mail.example.com"],
                },
                "warnings": [],
            },
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
            check_mx_mock = stack.enter_context(
                patch(
                    "checkdmarc.check_mx",
                    return_value={"hosts": [], "warnings": []},
                )
            )
            checkdmarc.check_domains(["example.com"])
        # check_mx was called with the patterns extracted from the MTA-STS policy
        self.assertEqual(
            check_mx_mock.call_args.kwargs["mta_sts_mx_patterns"],
            ["mail.example.com"],
        )


class TestResultsToCsvRowsExtraBranches(unittest.TestCase):
    """Branches in results_to_csv_rows not covered by the existing tests"""

    @staticmethod
    def _base_result_with_bimi(error=False):
        result = {
            "domain": "example.com",
            "base_domain": "example.com",
            "dnssec": True,
            "ns": {"hostnames": [], "warnings": []},
            "mx": {"hosts": [], "warnings": []},
            "mta_sts": {"valid": False, "error": "not found"},
            "spf": {"record": "v=spf1 -all", "valid": True, "warnings": []},
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
            "smtp_tls_reporting": {"valid": False, "error": "not found"},
            "bimi": {
                "valid": False if error else True,
                "selector": "default",
                "warnings": [],
                "tags": {
                    "l": {"value": "https://example.com/logo.svg"},
                    "a": {"value": "https://example.com/cert.pem"},
                },
            },
        }
        if error:
            result["bimi"]["error"] = "fetch failed"
        return result

    def testBimiErrorFlattensTagValues(self):
        """When the BIMI result is in error and tags are present, l/a tag
        values land as bimi_l / bimi_a columns"""
        rows = checkdmarc.results_to_csv_rows(
            cast(checkdmarc.DomainCheckResult, self._base_result_with_bimi(error=True))
        )
        row = rows[0]
        self.assertEqual(row["bimi_error"], "fetch failed")
        self.assertEqual(row["bimi_l"], "https://example.com/logo.svg")
        self.assertEqual(row["bimi_a"], "https://example.com/cert.pem")

    def testTlsKeyErrorPath(self):
        """When MX hosts lack 'starttls'/'tls' keys (e.g., skip_tls=True),
        the KeyError handler leaves tls/starttls as None"""
        result = self._base_result_with_bimi(error=False)
        del result["bimi"]
        # Add an MX host without starttls/tls keys
        result["mx"] = {
            "hosts": [
                {
                    "preference": 10,
                    "hostname": "mail.example.com",
                    "addresses": ["192.0.2.1"],
                }
            ],
            "warnings": [],
        }
        rows = checkdmarc.results_to_csv_rows(
            cast(checkdmarc.DomainCheckResult, result)
        )
        row = rows[0]
        # KeyError on starttls -> tls and starttls remain None
        self.assertIsNone(row["tls"])
        self.assertIsNone(row["starttls"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
