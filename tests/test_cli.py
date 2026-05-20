"""Tests for checkdmarc._cli

The CLI is driven by patching ``sys.argv`` and mocking ``check_domains`` so
the orchestration logic runs without any real DNS / SMTP traffic.
"""

import json
import os
import tempfile
import unittest
from unittest.mock import patch

import checkdmarc._cli


SAMPLE_RESULT = {
    "domain": "example.com",
    "base_domain": "example.com",
    "dnssec": False,
    "ns": {"hostnames": ["ns1.example.com"], "warnings": []},
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
}


def _run_cli(argv, *, check_returns=None):
    """Run checkdmarc._cli._main() with patched argv and a mocked check_domains.

    Returns the args check_domains was invoked with (or None if not called).
    """
    if check_returns is None:
        check_returns = SAMPLE_RESULT
    with patch("checkdmarc._cli.check_domains", return_value=check_returns) as mock:
        with patch("sys.argv", ["checkdmarc"] + argv):
            checkdmarc._cli._main()
    return mock


class TestCLI(unittest.TestCase):
    def testSingleDomainJsonStdout(self):
        """Default invocation runs check_domains and prints JSON"""
        with patch("builtins.print") as mock_print:
            mock_check = _run_cli(["example.com"])
        mock_check.assert_called_once()
        # The first positional arg to check_domains is the list of domains
        domains_arg = mock_check.call_args.args[0]
        self.assertEqual(domains_arg, ["example.com"])
        # Something resembling JSON was printed
        printed = mock_print.call_args.args[0]
        self.assertIn("example.com", printed)
        parsed = json.loads(printed)
        self.assertEqual(parsed["domain"], "example.com")

    def testCsvFormatStdout(self):
        """--format csv produces CSV output on stdout"""
        with patch("builtins.print") as mock_print:
            _run_cli(["--format", "csv", "example.com"])
        printed = mock_print.call_args.args[0]
        self.assertIn("example.com", printed)
        # CSV output should contain a comma in the header
        self.assertIn(",", printed)

    def testFlagsForwardedToCheckDomains(self):
        """--parked, --skip-tls, --descriptions, --wait, --retries, --timeout, --bimi-selector all forward"""
        mock_check = _run_cli(
            [
                "--parked",
                "--skip-tls",
                "--descriptions",
                "--wait",
                "0.5",
                "--retries",
                "7",
                "--timeout",
                "3.5",
                "--bimi-selector",
                "marketing",
                "example.com",
            ]
        )
        kwargs = mock_check.call_args.kwargs
        self.assertTrue(kwargs["parked"])
        self.assertTrue(kwargs["skip_tls"])
        self.assertTrue(kwargs["include_tag_descriptions"])
        self.assertEqual(kwargs["wait"], 0.5)
        self.assertEqual(kwargs["retries"], 7)
        self.assertEqual(kwargs["timeout"], 3.5)
        self.assertEqual(kwargs["bimi_selector"], "marketing")

    def testApprovedNameserversAndMx(self):
        """--ns and --mx forward as lists"""
        mock_check = _run_cli(
            [
                "--ns",
                "ns1.example.com",
                "ns2.example.com",
                "--mx",
                "mx1.example.com",
                "--",
                "example.com",
            ]
        )
        kwargs = mock_check.call_args.kwargs
        self.assertEqual(
            kwargs["approved_nameservers"],
            ["ns1.example.com", "ns2.example.com"],
        )
        self.assertEqual(kwargs["approved_mx_hostnames"], ["mx1.example.com"])

    def testNameserversForwarded(self):
        """-n / --nameserver list is passed to check_domains"""
        mock_check = _run_cli(
            ["--nameserver", "1.1.1.1", "8.8.8.8", "--", "example.com"]
        )
        kwargs = mock_check.call_args.kwargs
        self.assertEqual(kwargs["nameservers"], ["1.1.1.1", "8.8.8.8"])

    def testDebugFlagEnablesDebugLogging(self):
        """--debug raises the root logger to DEBUG"""
        import logging

        original = logging.getLogger().level
        try:
            _run_cli(["--debug", "example.com"])
            self.assertEqual(logging.getLogger().level, logging.DEBUG)
        finally:
            logging.getLogger().setLevel(original)

    def testDomainsReadFromFile(self):
        """A single positional arg that is a file path is read as a domain list"""
        with tempfile.NamedTemporaryFile(
            "w", delete=False, suffix=".txt"
        ) as domains_file:
            domains_file.write("example.com\nexample.org\n\nnot_a_domain\n")
            path = domains_file.name
        try:
            mock_check = _run_cli([path])
        finally:
            os.unlink(path)
        # File-based input is sorted, deduped, and stripped of entries
        # without a dot.
        domains_arg = mock_check.call_args.args[0]
        self.assertIn("example.com", domains_arg)
        self.assertIn("example.org", domains_arg)
        self.assertNotIn("not_a_domain", domains_arg)

    def testOutputJsonFileSilencesStdout(self):
        """--output <path.json> writes JSON to disk and skips stdout"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".json") as out_file:
            out_path = out_file.name
        try:
            with patch("builtins.print") as mock_print:
                _run_cli(["--output", out_path, "--", "example.com"])
            mock_print.assert_not_called()
            with open(out_path) as f:
                content = f.read()
            self.assertIn("example.com", content)
            json.loads(content)  # valid JSON
        finally:
            os.unlink(out_path)

    def testOutputCsvFile(self):
        """--output <path.csv> writes CSV to disk"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv") as out_file:
            out_path = out_file.name
        try:
            _run_cli(["--output", out_path, "--", "example.com"])
            with open(out_path) as f:
                content = f.read()
            self.assertIn("example.com", content)
            self.assertIn(",", content)
        finally:
            os.unlink(out_path)

    def testOutputBadExtensionLogsError(self):
        """--output <path.txt> logs an error and writes nothing"""
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as out_file:
            out_path = out_file.name
        try:
            with patch("checkdmarc._cli.logging") as mock_logging:
                _run_cli(["--output", out_path, "--", "example.com"])
            mock_logging.error.assert_called()
            # Nothing valid was written; the temp file is still its
            # original (empty) state.
            with open(out_path) as f:
                self.assertEqual(f.read(), "")
        finally:
            os.unlink(out_path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
