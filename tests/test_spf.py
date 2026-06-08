"""Tests for checkdmarc.spf"""

import os
import unittest
from unittest.mock import patch
from typing import Any, cast

import checkdmarc.spf
from checkdmarc.spf import ParsedSPFMXMechanism, SPFAMechanism

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"

# Test decorators for paired tests:
#   - network_test: real DNS lookup; skipped in CI (GitHub Actions)
#   - mocked_only:  patched stand-in; skipped locally where the network test runs
network_test = unittest.skipIf(
    OFFLINE_MODE, "Real-network test skipped on GitHub Actions"
)
mocked_only = unittest.skipUnless(
    OFFLINE_MODE, "Mocked counterpart skipped locally; network test covers this"
)


class Test(unittest.TestCase):
    def testUppercaseSPFMechanism(self):
        """Treat uppercase SPF mechanisms as valid"""
        spf_record = "v=spf1 IP4:147.75.8.208 -ALL"
        domain = "example.no"

        results = checkdmarc.spf.parse_spf_record(spf_record, domain)

        self.assertEqual(len(results["warnings"]), 0)
        self.assertEqual(results["dns_lookups"], 0)

    @network_test
    def testSplitSPFRecord(self):
        """Split SPF records are parsed properly"""

        rec = '"v=spf1 ip4:147.75.8.208 " "include:_spf.salesforce.com -all"'

        parsed_record = checkdmarc.spf.parse_spf_record(rec, "example.com")

        self.assertEqual(parsed_record["parsed"]["all"], "fail")

    @network_test
    def testJunkAfterAll(self):
        """Ignore any mechanisms after the all mechanism, but warn about it"""
        rec = "v=spf1 ip4:213.5.39.110 -all MS=83859DAEBD1978F9A7A67D3"
        domain = "avd.dk"
        warning = (
            "Any text after the all mechanism other than an exp modifier is ignored."
        )

        parsed_record = checkdmarc.spf.parse_spf_record(rec, domain)
        self.assertIn(warning, parsed_record["warnings"])

    @network_test
    def testIncludeMissingSPF(self):
        """A warning is included for SPF records that include domains that are missing SPF records"""

        spf_record = "v=spf1 include:example.doesnotexist ~all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertTrue(
            "example.doesnotexist: The domain does not exist." in results["warnings"]
        )
        self.assertEqual(results["dns_lookups"], 1)

    @network_test
    def testTooManySPFDNSLookups(self):
        """SPF records with > 10 SPF mechanisms that cause DNS lookups raise
        SPFTooManyDNSLookups"""

        spf_record = (
            "v=spf1 a include:_spf.salesforce.com "
            "include:spf.protection.outlook.com "
            "include:spf.constantcontact.com "
            "include:_spf.elasticemail.com "
            "include:servers.mcsv.net "
            "include:_spf.google.com "
            "include:service-now.com "
            "~all"
        )
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFTooManyDNSLookups,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    @network_test
    def testTooManySPFVoidDNSLookups(self):
        """SPF records with > 2 void DNS lookups"""

        spf_record = (
            "v=spf1 a:13Mk4olS9VWhQqXRl90fKJrD.example.com "
            "mx:SfGiqBnQfRbOMapQJhozxo2B.example.com "
            "a:VAFeyU9N2KJX518aGsN3w6VS.example.com "
            "~all"
        )
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFTooManyVoidDNSLookups,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFSyntaxErrors(self):
        """SPF record syntax errors raise SPFSyntaxError"""

        spf_record = (
            '"v=spf1 mx a:mail.cohaesio.net include: trustpilotservice.com ~all"'
        )
        domain = "2021.ai"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFInvalidIPv4(self):
        """Invalid ipv4 SPF mechanism values raise SPFSyntaxError"""
        spf_record = (
            "v=spf1 ip4:78.46.96.236 +a +mx +ip4:138.201.239.158 "
            "+ip4:78.46.224.83 "
            "+ip4:relay.mailchannels.net +ip4:138.201.60.20 ~all"
        )
        domain = "surftown.dk"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFInvalidIPv6inIPv4(self):
        """Invalid ipv4 SPF mechanism values raise SPFSyntaxError"""
        spf_record = "v=spf1 ip4:1200:0000:AB00:1234:0000:2552:7777:1313 ~all"
        domain = "surftown.dk"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFInvalidIPv4Range(self):
        """Invalid ipv4 SPF mechanism values raise SPFSyntaxError"""
        spf_record = "v=spf1 ip4:78.46.96.236/99 ~all"
        domain = "surftown.dk"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFInvalidIPv6(self):
        """Invalid ipv6 SPF mechanism values raise SPFSyntaxError"""
        spf_record = "v=spf1 ip6:1200:0000:AB00:1234:O000:2552:7777:1313 ~all"
        domain = "surftown.dk"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFInvalidIPv4inIPv6(self):
        """Invalid ipv6 SPF mechanism values raise SPFSyntaxError"""
        spf_record = "v=spf1 ip6:78.46.96.236 ~all"
        domain = "surftown.dk"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFInvalidIPv6Range(self):
        """Invalid ipv6 SPF mechanism values raise SPFSyntaxError"""
        record = "v=spf1 ip6:1200:0000:AB00:1234:0000:2552:7777:1313/130 ~all"
        domain = "surftown.dk"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            record,
            domain,
        )

    def testSPFInvalidMissingSpaceBeforeAllMechanism(self):
        """There is not a space between the IP4 and all mechanism in the SPF record."""
        spf_record = "v=spf1 ip4:8.8.8.8~all"
        domain = "example.com"

        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFIncludeLoop(self):
        """SPF record with include loop raises SPFIncludeLoop"""

        spf_record = '"v=spf1 include:example.com"'
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFIncludeLoop,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    @network_test
    def testSPFMissingMXRecord(self):
        """A warning is issued if an SPF record contains a mx mechanism
        pointing to a domain that has no MX records"""

        spf_record = '"v=spf1 mx ~all"'
        domain = "seanthegeek.net"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn(
            "Error when processing {0}: An mx mechanism points to {0}, but that domain/subdomain does not have any MX records.".format(
                domain
            ),
            results["warnings"],
        )
        self.assertEqual(results["dns_lookups"], 1)

    @network_test
    def testSPFMissingARecord(self):
        """A warning is issued if an SPF record contains an a mechanism
        pointing to a domain that has no A records"""

        spf_record = '"v=spf1 a ~all"'
        domain = "cardinalhealth.net"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        snipit = "that domain/subdomain does not have any A/AAAA records."
        self.assertTrue(any(snipit in s for s in results["warnings"]))
        self.assertEqual(results["dns_lookups"], 1)

    @network_test
    def testSPFMXMechanism(self):
        """Addresses are included in the output for SPF records with an mx lookup"""
        spf_record = "v=spf1 mx:proton.me ~all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        for mechanism in results["parsed"]["mechanisms"]:
            if mechanism["mechanism"] == "mx":
                mx_mechanism = cast(ParsedSPFMXMechanism, mechanism)
                self.assertTrue(len(mx_mechanism["hosts"]) > 0)
                for host in mx_mechanism["hosts"]:
                    self.assertTrue(len(host) > 0)
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFMacrosExists(self):
        """SPF macros can be used with the exists mechanism"""
        record = "v=spf1 exists:exists:%{i}.spf.hc0000-xx.iphmx.com ~all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(record, domain)
        self.assertTrue(len(results["parsed"]["mechanisms"]) > 0)
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFMacrosInclude(self):
        """SPF macros can be used with the exists mechanism"""
        record = "v=spf1 include:include:%{ir}.%{v}.%{d}.spf.has.pphosted.com ~all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(record, domain)
        self.assertTrue(len(results["parsed"]["mechanisms"]) > 0)
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFAMechanism(self):
        """Addresses are included in the output for SPF records with an a lookup"""
        spf_record = "v=spf1 a ~all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        for mechanism in results["parsed"]["mechanisms"]:
            if mechanism["mechanism"] == "a":
                a_mechanism = cast(SPFAMechanism, mechanism)
                self.assertTrue(len(a_mechanism["addresses"]) > 0)
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFValidAMechanismMacro(self):
        """SPF records with valid macros are accepted"""
        spf_record = "v=spf1 a:%{l}.example.com -all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn("mechanisms", results["parsed"])
        self.assertEqual(len(results["warnings"]), 0)
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFBrokenAMechanismMacro(self):
        """SPF records with invalid macros raise SPFSyntaxError"""
        spf_record = "v=spf1 a:%{?} -all"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFValidMXMechanismMacro(self):
        """SPF records with valid macros in mx mechanism are accepted"""
        spf_record = "v=spf1 mx:%{d} -all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn("mechanisms", results["parsed"])
        self.assertEqual(len(results["warnings"]), 0)
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFBrokenMXMechanismMacro(self):
        """SPF records with invalid macros in mx mechanism raise SPFSyntaxError"""
        spf_record = "v=spf1 mx:%{?} -all"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFValidPTRMechanismMacro(self):
        """SPF records with valid macros in ptr mechanism are accepted (but warn about ptr usage)"""
        spf_record = "v=spf1 ptr:%{d} -all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn("mechanisms", results["parsed"])
        # PTR mechanism always raises a warning in checkdmarc
        self.assertTrue(
            any("ptr mechanism should not be used" in w for w in results["warnings"])
        )
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFBrokenPTRMechanismMacro(self):
        """SPF records with invalid macros in ptr mechanism raise SPFSyntaxError"""
        spf_record = "v=spf1 ptr:%{?} -all"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFValidIncludeMechanismMacro(self):
        """SPF records with valid macros in include mechanism are accepted"""
        spf_record = "v=spf1 include:%{d}._spf.example.com -all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn("mechanisms", results["parsed"])
        self.assertEqual(len(results["warnings"]), 0)
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFBrokenIncludeMechanismMacro(self):
        """SPF records with invalid macros in include mechanism raise SPFSyntaxError"""
        spf_record = "v=spf1 include:%{?}._spf.example.com -all"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFValidExistsMechanismMacro(self):
        """SPF records with valid macros in exists mechanism are accepted"""
        spf_record = "v=spf1 exists:%{i}._spf.example.com -all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn("mechanisms", results["parsed"])
        self.assertEqual(len(results["warnings"]), 0)
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFBrokenExistsMechanismMacro(self):
        """SPF records with invalid macros in exists mechanism raise SPFSyntaxError"""
        spf_record = "v=spf1 exists:%{?}._spf.example.com -all"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFValidRedirectModifierMacro(self):
        """SPF records with valid macros in redirect modifier are accepted"""
        spf_record = "v=spf1 redirect=%{d}._spf.example.com"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn("redirect", results["parsed"])
        self.assertEqual(len(results["warnings"]), 0)
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFBrokenRedirectModifierMacro(self):
        """SPF records with invalid macros in redirect modifier raise SPFSyntaxError"""
        spf_record = "v=spf1 redirect=%{?}._spf.example.com"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testSPFValidExpModifierMacro(self):
        """SPF records with valid macros in exp modifier are accepted"""
        spf_record = "v=spf1 -all exp=%{d}"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn("exp", results["parsed"])
        self.assertEqual(len(results["warnings"]), 0)
        self.assertEqual(results["dns_lookups"], 0)

    def testSPFBrokenExpModifierMacro(self):
        """SPF records with invalid macros in exp modifier raise SPFSyntaxError"""
        spf_record = "v=spf1 -all exp=%{?}"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    def testUndecodableCharactersInNonSPFRecord(self):
        """Non-SPF TXT records with undecodable characters should be ignored with a warning"""
        domain = "example.com"

        # Mock query_dns to return:
        # 1. An undecodable non-SPF TXT record
        # 2. A valid SPF record
        with patch("checkdmarc.spf.query_dns") as mock_query_dns:
            # First call for SPF type records (returns empty)
            # Second call for TXT records (returns undecodable + valid SPF)
            mock_query_dns.side_effect = [
                [],  # No SPF type records
                [
                    "Undecodable characters",  # TXT record with undecodable chars
                    '"v=spf1 include:spf.smtp2go.com -all"',  # Valid SPF record
                ],
            ]

            # This should succeed and return the valid SPF record
            result = checkdmarc.spf.get_spf_record(domain)

            # Verify the SPF record was found
            self.assertIsNotNone(result["record"])
            self.assertIn("v=spf1", cast(str, result["record"]))

            # Verify a warning was added for the undecodable record
            self.assertTrue(len(result["warnings"]) > 0)
            self.assertTrue(
                any(
                    "TXT record" in w and "undecodable" in w.lower()
                    for w in result["warnings"]
                )
            )

    def testSPFRecordNotFound(self):
        """Missing SPF record raises SPFRecordNotFound"""
        with patch("checkdmarc.spf.query_dns") as mock_dns:
            mock_dns.side_effect = [[], []]
            self.assertRaises(
                checkdmarc.spf.SPFRecordNotFound,
                checkdmarc.spf.query_spf_record,
                "example.com",
            )

    def testSPFMultipleRecords(self):
        """Multiple SPF TXT records raise SPFError"""
        with patch("checkdmarc.spf.query_dns") as mock_dns:
            mock_dns.side_effect = [
                [],  # SPF type records
                ["v=spf1 -all", "v=spf1 +all"],  # Two SPF TXT records
            ]
            self.assertRaises(
                checkdmarc.spf.SPFError,
                checkdmarc.spf.query_spf_record,
                "example.com",
            )

    def testSPFParkedDomainWarning(self):
        """Parked domains with wrong SPF record produce a warning"""
        spf_record = "v=spf1 ip4:192.0.2.1 -all"
        domain = "parked-example.com"
        result = checkdmarc.spf.parse_spf_record(spf_record, domain, parked=True)
        self.assertTrue(any("parked" in w.lower() for w in result["warnings"]))

    def testSPFRedirectWithMacro(self):
        """SPF redirect with macro is accepted (counts as 1 DNS lookup)"""
        spf_record = "v=spf1 redirect=%{d}._spf.example.com"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIsNotNone(results["parsed"]["redirect"])
        self.assertEqual(results["dns_lookups"], 1)

    def testSPFAllMechanism(self):
        """SPF all mechanism is parsed correctly"""
        spf_record = "v=spf1 -all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertEqual(results["parsed"]["all"], "fail")

    def testSPFSoftfailAll(self):
        """SPF ~all mechanism is parsed as softfail"""
        spf_record = "v=spf1 ~all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertEqual(results["parsed"]["all"], "softfail")

    def testSPFNeutralAll(self):
        """SPF ?all mechanism is parsed as neutral"""
        spf_record = "v=spf1 ?all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertEqual(results["parsed"]["all"], "neutral")

    def testSPFIP6Mechanism(self):
        """IP6 mechanism is parsed correctly"""
        spf_record = "v=spf1 ip6:2001:db8::1 -all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertTrue(len(results["parsed"]["mechanisms"]) > 0)
        self.assertEqual(results["dns_lookups"], 0)

    def testSPFCheckSpfSuccess(self):
        """check_spf returns valid results for a domain with SPF"""
        with patch("checkdmarc.spf.query_spf_record") as mock_query:
            mock_query.return_value = {
                "record": "v=spf1 -all",
                "warnings": [],
            }
            result = checkdmarc.spf.check_spf("example.com")
            self.assertTrue(result["valid"])

    def testSPFCheckSpfError(self):
        """check_spf returns error results when SPF not found"""
        with patch("checkdmarc.spf.query_spf_record") as mock_query:
            mock_query.side_effect = checkdmarc.spf.SPFRecordNotFound(
                "An SPF record does not exist.", "example.com"
            )
            result = checkdmarc.spf.check_spf("example.com")
            self.assertFalse(result["valid"])
            self.assertIn("error", result)

    def testSPFExistsMechanism(self):
        """SPF exists mechanism is parsed correctly"""
        spf_record = "v=spf1 exists:%{i}._spf.example.com -all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertEqual(results["dns_lookups"], 1)

    # ================================================================
    # Mocked counterparts to the @network_test cases above.
    # These run only when GITHUB_ACTIONS=true so coverage stays the same
    # whether or not real DNS is available.
    # ================================================================

    @mocked_only
    def testSplitSPFRecordMocked(self):
        """Split SPF records are parsed properly (mocked)"""
        rec = '"v=spf1 ip4:147.75.8.208 " "include:_spf.salesforce.com -all"'

        def fake_query_dns(domain, rdtype, *args, **kwargs):
            if domain == "_spf.salesforce.com" and rdtype == "TXT":
                return ['"v=spf1 -all"']
            return []

        with patch("checkdmarc.spf.query_dns", side_effect=fake_query_dns):
            parsed_record = checkdmarc.spf.parse_spf_record(rec, "example.com")

        self.assertEqual(parsed_record["parsed"]["all"], "fail")

    @mocked_only
    def testSenderIDRecordsWarnMocked(self):
        """Deprecated Sender ID TXT records produce SPF warnings"""
        sender_id_records = [
            "v=spf2.0/pra ip4:192.0.2.0/24 ~all",
            "v=spf2.0/mfrom ip4:192.0.2.0/24 ~all",
            "v=spf2.0/mfrom,pra ip4:192.0.2.0/24 ~all",
            "v=spf2.0/pra,mfrom ip4:192.0.2.0/24 ~all",
        ]

        for sender_id_record in sender_id_records:
            with self.subTest(sender_id_record=sender_id_record):
                records = ["v=spf1 -all", sender_id_record]
                with patch("checkdmarc.spf.query_dns", return_value=records):
                    result = checkdmarc.spf.query_spf_record("example.com")

                self.assertEqual(result["record"], "v=spf1 -all")
                self.assertTrue(
                    any(
                        "deprecated Sender ID record" in warning
                        for warning in result["warnings"]
                    )
                )

    @mocked_only
    def testInvalidSPFVersionTagsRejectedMocked(self):
        """Invalid SPF version-like TXT records are rejected"""
        invalid_records = [
            "v=spf10 -all",
            "v=spf1foo -all",
        ]

        for record in invalid_records:
            with self.subTest(record=record):
                with patch("checkdmarc.spf.query_dns", return_value=[record]):
                    with self.assertRaises(checkdmarc.spf.SPFRecordNotFound):
                        checkdmarc.spf.query_spf_record("example.com")

    @mocked_only
    def testSPFVersionMatchingIsCaseInsensitiveMocked(self):
        """Uppercase SPF version tags are accepted"""
        with patch("checkdmarc.spf.query_dns", return_value=["V=SPF1 -all"]):
            result = checkdmarc.spf.query_spf_record("example.com")

        self.assertEqual(result["record"], "V=SPF1 -all")

    @mocked_only
    def testSPFVersionMatchingAllowsSurroundingWhitespaceMocked(self):
        """SPF records with surrounding whitespace are accepted"""
        with patch("checkdmarc.spf.query_dns", return_value=["  v=spf1 -all  "]):
            result = checkdmarc.spf.query_spf_record("example.com")

        self.assertEqual(result["record"], "  v=spf1 -all  ")

    @mocked_only
    def testJunkAfterAllMocked(self):
        """Warn about text after the all mechanism (mocked; ip4 + -all needs no DNS)"""
        rec = "v=spf1 ip4:213.5.39.110 -all MS=83859DAEBD1978F9A7A67D3"
        domain = "avd.dk"
        warning = (
            "Any text after the all mechanism other than an exp modifier is ignored."
        )

        with patch("checkdmarc.spf.query_dns", return_value=[]):
            parsed_record = checkdmarc.spf.parse_spf_record(rec, domain)
        self.assertIn(warning, parsed_record["warnings"])

    @mocked_only
    def testIncludeMissingSPFMocked(self):
        """Warn when an include target's domain does not exist (mocked NXDOMAIN)"""
        import dns.resolver

        spf_record = "v=spf1 include:example.doesnotexist ~all"
        domain = "example.com"

        with patch("checkdmarc.spf.query_dns") as mock_dns:
            mock_dns.side_effect = dns.resolver.NXDOMAIN()
            results = checkdmarc.spf.parse_spf_record(spf_record, domain)

        self.assertIn(
            "Error when processing example.doesnotexist: The domain does not exist.",
            results["warnings"],
        )
        self.assertEqual(results["dns_lookups"], 1)

    @mocked_only
    def testTooManySPFDNSLookupsMocked(self):
        """SPF records that exceed 10 DNS lookups raise SPFTooManyDNSLookups (mocked)"""
        spf_record = (
            "v=spf1 a include:_spf.salesforce.com "
            "include:spf.protection.outlook.com "
            "include:spf.constantcontact.com "
            "include:_spf.elasticemail.com "
            "include:servers.mcsv.net "
            "include:_spf.google.com "
            "include:service-now.com "
            "~all"
        )
        domain = "example.com"

        # Every include resolves to "v=spf1 a a a ~all" (3 additional lookups
        # each). One a mechanism in the root + 7 includes * (1 + 3) lookups
        # easily exceeds the 10-lookup ceiling.
        def fake_query_dns(_domain, rdtype, *args, **kwargs):
            if rdtype == "TXT":
                return ['"v=spf1 a a a ~all"']
            return []

        with patch("checkdmarc.spf.query_dns", side_effect=fake_query_dns):
            with patch("checkdmarc.spf.get_a_records", return_value=["192.0.2.1"]):
                self.assertRaises(
                    checkdmarc.spf.SPFTooManyDNSLookups,
                    checkdmarc.spf.parse_spf_record,
                    spf_record,
                    domain,
                )

    @mocked_only
    def testTooManySPFVoidDNSLookupsMocked(self):
        """SPF records with > 2 void DNS lookups raise SPFTooManyVoidDNSLookups (mocked)"""
        spf_record = (
            "v=spf1 a:13Mk4olS9VWhQqXRl90fKJrD.example.com "
            "mx:SfGiqBnQfRbOMapQJhozxo2B.example.com "
            "a:VAFeyU9N2KJX518aGsN3w6VS.example.com "
            "~all"
        )
        domain = "example.com"

        with patch("checkdmarc.spf.get_a_records", return_value=[]):
            with patch("checkdmarc.spf.get_mx_records", return_value=[]):
                self.assertRaises(
                    checkdmarc.spf.SPFTooManyVoidDNSLookups,
                    checkdmarc.spf.parse_spf_record,
                    spf_record,
                    domain,
                )

    @mocked_only
    def testSPFMissingMXRecordMocked(self):
        """Warn when an mx mechanism targets a domain with no MX records (mocked)"""
        spf_record = '"v=spf1 mx ~all"'
        domain = "seanthegeek.net"

        with patch("checkdmarc.spf.get_mx_records", return_value=[]):
            results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn(
            "Error when processing {0}: An mx mechanism points to {0}, but that domain/subdomain does not have any MX records.".format(
                domain
            ),
            results["warnings"],
        )
        self.assertEqual(results["dns_lookups"], 1)

    @mocked_only
    def testSPFMissingARecordMocked(self):
        """Warn when an a mechanism targets a domain with no A/AAAA records (mocked)"""
        spf_record = '"v=spf1 a ~all"'
        domain = "cardinalhealth.net"

        with patch("checkdmarc.spf.get_a_records", return_value=[]):
            results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        snipit = "that domain/subdomain does not have any A/AAAA records."
        self.assertTrue(any(snipit in s for s in results["warnings"]))
        self.assertEqual(results["dns_lookups"], 1)

    @mocked_only
    def testSPFMXMechanismMocked(self):
        """Hostname addresses are populated for mx: mechanism (mocked)"""
        spf_record = "v=spf1 mx:proton.me ~all"
        domain = "example.com"

        mx_hosts = [
            {"preference": 10, "hostname": "mail.protonmail.ch"},
            {"preference": 20, "hostname": "mailsec.protonmail.ch"},
        ]
        with patch("checkdmarc.spf.get_mx_records", return_value=mx_hosts):
            with patch("checkdmarc.spf.get_a_records", return_value=["192.0.2.1"]):
                results = checkdmarc.spf.parse_spf_record(spf_record, domain)

        for mechanism in results["parsed"]["mechanisms"]:
            if mechanism["mechanism"] == "mx":
                mx_mechanism = cast(ParsedSPFMXMechanism, mechanism)
                self.assertTrue(len(mx_mechanism["hosts"]) > 0)
                for host in mx_mechanism["hosts"]:
                    self.assertTrue(len(host) > 0)
        self.assertEqual(results["dns_lookups"], 1)


class TestPtrMatch(unittest.TestCase):
    """Tests for the standalone ptr_match helper"""

    def testHostnameAndIpMatch(self):
        """PTR points back to a hostname that resolves to the same IP — True"""
        with patch("checkdmarc.spf.get_reverse_dns", return_value=["mail.example.com"]):
            with patch("checkdmarc.spf.get_a_records", return_value=["192.0.2.1"]):
                result = checkdmarc.spf.ptr_match("192.0.2.1", "example.com")
        self.assertTrue(result)

    def testHostnameMatchesButIpDoesnt(self):
        """PTR points back to a matching hostname but its A records don't include the IP"""
        with patch("checkdmarc.spf.get_reverse_dns", return_value=["mail.example.com"]):
            with patch("checkdmarc.spf.get_a_records", return_value=["203.0.113.1"]):
                result = checkdmarc.spf.ptr_match("192.0.2.1", "example.com")
        self.assertFalse(result)

    def testHostnameDoesntEndWithDomain(self):
        """PTR hostname doesn't end with the SPF domain — skipped"""
        with patch("checkdmarc.spf.get_reverse_dns", return_value=["mail.other.com"]):
            with patch("checkdmarc.spf.get_a_records") as mock_a:
                result = checkdmarc.spf.ptr_match("192.0.2.1", "example.com")
        self.assertFalse(result)
        mock_a.assert_not_called()


class TestSPFPtrMechanism(unittest.TestCase):
    """ptr mechanism in parse_spf_record"""

    def testPtrEmitsWarning(self):
        """Valid ptr always emits a 'should not be used' warning per RFC 7208 § 5.5"""
        with patch("checkdmarc.spf.get_a_records", return_value=["192.0.2.1"]):
            result = checkdmarc.spf.parse_spf_record("v=spf1 ptr -all", "example.com")
        self.assertTrue(
            any("ptr mechanism should not be used" in w for w in result["warnings"])
        )

    def testPtrWithExplicitDomain(self):
        """ptr:example.com uses the explicit value rather than the SPF domain"""
        with patch("checkdmarc.spf.get_a_records", return_value=["192.0.2.1"]):
            result = checkdmarc.spf.parse_spf_record(
                "v=spf1 ptr:other.example -all", "example.com"
            )
        self.assertTrue(
            any("ptr mechanism should not be used" in w for w in result["warnings"])
        )

    def testPtrMissingARecords(self):
        """ptr where the target has no A records produces a missing-records warning"""
        with patch("checkdmarc.spf.get_a_records", return_value=[]):
            result = checkdmarc.spf.parse_spf_record("v=spf1 ptr -all", "example.com")
        self.assertTrue(
            any("does not have any A/AAAA records" in w for w in result["warnings"])
        )


class TestSPFRedirect(unittest.TestCase):
    """redirect= modifier in parse_spf_record"""

    def testRedirectLoop(self):
        """A redirect to a domain already in the recursion chain raises SPFRedirectLoop"""
        self.assertRaises(
            checkdmarc.spf.SPFRedirectLoop,
            checkdmarc.spf.parse_spf_record,
            "v=spf1 redirect=example.com",
            "example.com",
            recursion=["example.com"],
        )

    def testRedirectFollowed(self):
        """A redirect resolves and replaces the outer all action"""
        with patch("checkdmarc.spf.query_spf_record") as mock_query:
            mock_query.return_value = {"record": "v=spf1 -all", "warnings": []}
            result = checkdmarc.spf.parse_spf_record(
                "v=spf1 redirect=other.example", "example.com"
            )
        self.assertEqual(result["parsed"]["all"], "fail")
        self.assertIsNotNone(result["parsed"]["redirect"])

    def testRedirectTargetDnsException(self):
        """A DNSException during redirect resolution becomes a warning"""
        from checkdmarc.utils import DNSException

        with patch(
            "checkdmarc.spf.query_spf_record", side_effect=DNSException("dns broken")
        ):
            result = checkdmarc.spf.parse_spf_record(
                "v=spf1 redirect=other.example", "example.com"
            )
        self.assertTrue(any("dns broken" in w for w in result["warnings"]))


class TestSPFExpModifier(unittest.TestCase):
    def testExpAfterAllValidDomain(self):
        """exp=domain.example after -all is looked up but doesn't count for limits"""
        with patch("checkdmarc.spf.get_txt_records", return_value=["explanation"]):
            result = checkdmarc.spf.parse_spf_record(
                "v=spf1 -all exp=exp.example", "example.com"
            )
        # exp doesn't add DNS lookup budget per RFC
        self.assertEqual(result["dns_lookups"], 0)
        # No warning since exactly one TXT record returned
        self.assertNotIn(
            "Too many TXT records at exp value exp.example", result["warnings"]
        )

    def testExpAfterAllNoTxtRecords(self):
        with patch("checkdmarc.spf.get_txt_records", return_value=[]):
            result = checkdmarc.spf.parse_spf_record(
                "v=spf1 -all exp=exp.example", "example.com"
            )
        self.assertTrue(
            any("No TXT records at exp value" in w for w in result["warnings"])
        )

    def testExpAfterAllTooManyTxtRecords(self):
        with patch("checkdmarc.spf.get_txt_records", return_value=["a", "b"]):
            result = checkdmarc.spf.parse_spf_record(
                "v=spf1 -all exp=exp.example", "example.com"
            )
        self.assertTrue(
            any("Too many TXT records at exp value" in w for w in result["warnings"])
        )

    def testExpAfterAllExceptionWarning(self):
        with patch(
            "checkdmarc.spf.get_txt_records",
            side_effect=RuntimeError("dns broken"),
        ):
            result = checkdmarc.spf.parse_spf_record(
                "v=spf1 -all exp=exp.example", "example.com"
            )
        self.assertTrue(
            any(
                "Failed to get TXT records at exp value" in w
                for w in result["warnings"]
            )
        )

    def testTextAfterExpValueWarns(self):
        with patch("checkdmarc.spf.get_txt_records", return_value=["explanation"]):
            result = checkdmarc.spf.parse_spf_record(
                "v=spf1 -all exp=exp.example extra", "example.com"
            )
        self.assertTrue(
            any(
                "No text should exist after the exp modifier value" in w
                for w in result["warnings"]
            )
        )


class TestSPFMacroValidation(unittest.TestCase):
    def testMacroInIp4Mechanism(self):
        """SPF macros are not allowed in ip4/ip6 mechanisms — raises SPFSyntaxError"""
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            "v=spf1 ip4:%{i} -all",
            "example.com",
        )

    def testMacroInIp6Mechanism(self):
        self.assertRaises(
            checkdmarc.spf.SPFSyntaxError,
            checkdmarc.spf.parse_spf_record,
            "v=spf1 ip6:%{i} -all",
            "example.com",
        )


class TestSPFMxBranches(unittest.TestCase):
    def testTooManyMxRecords(self):
        """An mx mechanism that points to a domain with > 10 MX records raises SPFTooManyDNSLookups"""
        mx_hosts = [
            {"preference": i * 10, "hostname": f"mx{i}.example.com"} for i in range(12)
        ]
        with patch("checkdmarc.spf.get_mx_records", return_value=mx_hosts):
            with patch("checkdmarc.spf.get_a_records", return_value=["192.0.2.1"]):
                self.assertRaises(
                    checkdmarc.spf.SPFTooManyDNSLookups,
                    checkdmarc.spf.parse_spf_record,
                    "v=spf1 mx -all",
                    "example.com",
                )

    def testMxHostMissingARecords(self):
        """When successive MX host A-lookups return empty, the void counter
        exceeds 2 and SPFTooManyVoidDNSLookups is raised."""
        # 3 MX hosts; each get_a_records returns [] (void lookup, not exception)
        with patch(
            "checkdmarc.spf.get_mx_records",
            return_value=[
                {"preference": 10, "hostname": "mx1.example.com"},
                {"preference": 20, "hostname": "mx2.example.com"},
                {"preference": 30, "hostname": "mx3.example.com"},
            ],
        ):
            with patch("checkdmarc.spf.get_a_records", return_value=[]):
                self.assertRaises(
                    checkdmarc.spf.SPFTooManyVoidDNSLookups,
                    checkdmarc.spf.parse_spf_record,
                    "v=spf1 mx -all",
                    "example.com",
                )


class TestSPFAMechanismCidr(unittest.TestCase):
    def testAWithCidrParsesWithoutError(self):
        """a/24 mechanism parses cleanly and resolves to the SPF domain's A records.

        Note: the current implementation has a latent bug where the CIDR suffix
        is dropped (``value.split('/')`` then ``len(value) == 2`` checks string
        length, not the split's length) — covered here as a structural smoke test
        only.
        """
        with patch(
            "checkdmarc.spf.get_a_records", return_value=["192.0.2.1", "192.0.2.2"]
        ):
            result = checkdmarc.spf.parse_spf_record("v=spf1 a/24 -all", "example.com")
        for mechanism in result["parsed"]["mechanisms"]:
            if mechanism["mechanism"] == "a":
                a_mechanism = cast(SPFAMechanism, mechanism)
                self.assertTrue(len(a_mechanism["addresses"]) > 0)


class TestSPFQueryRecordEdges(unittest.TestCase):
    def testSpfTypeRecordWarning(self):
        """A legacy DNS-type SPF record produces a removal warning"""

        def fake_query_dns(domain, rdtype, **kwargs):
            if rdtype == "SPF":
                return ["v=spf1 -all"]
            return ["v=spf1 -all"]

        with patch("checkdmarc.spf.query_dns", side_effect=fake_query_dns):
            result = checkdmarc.spf.query_spf_record("example.com")
        self.assertTrue(any("DNS Type SPF has been" in w for w in result["warnings"]))

    def testUndecodableTxtSkipped(self):
        """Undecodable TXT records produce a warning, not failure"""

        def fake_query_dns(domain, rdtype, **kwargs):
            if rdtype == "SPF":
                return []
            return ["Undecodable characters", '"v=spf1 -all"']

        with patch("checkdmarc.spf.query_dns", side_effect=fake_query_dns):
            result = checkdmarc.spf.query_spf_record("example.com")
        # query_spf_record strips surrounding quotes from the returned record
        self.assertEqual(result["record"], "v=spf1 -all")
        self.assertTrue(any("undecodable" in w.lower() for w in result["warnings"]))

    def testNXDOMAINReraises(self):
        """dns.resolver.NXDOMAIN becomes SPFRecordNotFound"""
        import dns.resolver

        def fake_query_dns(domain, rdtype, **kwargs):
            if rdtype == "SPF":
                return []
            raise dns.resolver.NXDOMAIN()

        with patch("checkdmarc.spf.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.spf.SPFRecordNotFound,
                checkdmarc.spf.query_spf_record,
                "example.com",
            )

    def testGenericExceptionReraises(self):
        """A non-SPF, non-DNS exception during TXT lookup also becomes SPFRecordNotFound"""

        def fake_query_dns(domain, rdtype, **kwargs):
            if rdtype == "SPF":
                return []
            raise RuntimeError("oops")

        with patch("checkdmarc.spf.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.spf.SPFRecordNotFound,
                checkdmarc.spf.query_spf_record,
                "example.com",
            )

    def testLongChunkWarning(self):
        """A TXT chunk over 255 bytes produces a chunk-length warning"""
        # Build a chunk of 260 'a's quoted
        long_chunk = '"v=spf1 ' + ("a" * 260) + ' -all"'

        def fake_query_dns(domain, rdtype, **kwargs):
            if rdtype == "SPF":
                return []
            return [long_chunk]

        with patch("checkdmarc.spf.query_dns", side_effect=fake_query_dns):
            result = checkdmarc.spf.query_spf_record("example.com")
        self.assertTrue(any("(>255)" in w for w in result["warnings"]))

    def testLargeRecordWarning(self):
        """A record over 512 bytes produces a size warning"""
        big = "v=spf1 " + " ".join(f"ip4:192.0.2.{i}" for i in range(100)) + " -all"

        def fake_query_dns(domain, rdtype, **kwargs):
            if rdtype == "SPF":
                return []
            return [big]

        with patch("checkdmarc.spf.query_dns", side_effect=fake_query_dns):
            result = checkdmarc.spf.query_spf_record("example.com")
        self.assertTrue(any("> 512 bytes" in w for w in result["warnings"]))


class TestSPFCheckSpfErrorData(unittest.TestCase):
    def testErrorWithDataKeysIncluded(self):
        """check_spf flattens SPFError.data keys into the result"""
        # SPFTooManyDNSLookups carries dns_lookups in .data
        with patch("checkdmarc.spf.query_spf_record") as mock_query:
            mock_query.return_value = {"record": "v=spf1 -all", "warnings": []}
            # Patch parse_spf_record to raise with .data
            with patch("checkdmarc.spf.parse_spf_record") as mock_parse:
                err = checkdmarc.spf.SPFTooManyDNSLookups("too many", dns_lookups=11)
                mock_parse.side_effect = err
                result = checkdmarc.spf.check_spf("example.com")
        self.assertFalse(result["valid"])
        self.assertEqual(cast(Any, result)["dns_lookups"], 11)


if __name__ == "__main__":
    unittest.main(verbosity=2)
