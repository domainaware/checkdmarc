#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Automated tests"""

import os
import unittest
from unittest.mock import patch

import checkdmarc
import checkdmarc.bimi
import checkdmarc.dmarc
import checkdmarc.dnssec
import checkdmarc.spf
import checkdmarc.utils

known_good_domains = ["fbi.gov", "pm.me", "ssa.gov"]


class Test(unittest.TestCase):
    @unittest.skip
    def testKnownGood(self):
        """Domains with known good STARTTLS support, SPF and DMARC records"""

        results = checkdmarc.check_domains(known_good_domains)
        for result in results:
            spf_error = None
            dmarc_error = None
            for mx in result["mx"]["hosts"]:
                self.assertEqual(
                    mx["starttls"],
                    True,
                    "Host of known good domain {0} failed STARTTLS check: {1}"
                    "\n\n{0}".format(result["domain"], mx["hostname"]),
                )
            if "error" in result["spf"]:
                spf_error = result["spf"]["error"]
            if "error" in result["dmarc"]:
                dmarc_error = result["dmarc"]["error"]
            self.assertEqual(
                result["spf"]["valid"],
                True,
                "Known good domain {0} failed SPF check:\n\n{1}".format(
                    result["domain"], spf_error
                ),
            )
            self.assertEqual(
                result["dmarc"]["valid"],
                True,
                "Known good domain {0} failed DMARC check:\n\n{1}".format(
                    result["domain"], dmarc_error
                ),
            )

    def testDMARCMixedFormatting(self):
        """DMARC records with extra spaces and mixed case are still valid"""
        examples = [
            "v=DMARC1;p=ReJect",
            "v = DMARC1;p=reject;",
            "v = DMARC1\t;\tp=reject\t;",
            "v = DMARC1\t;\tp\t\t\t=\t\t\treject\t;",
            "V=DMARC1;p=reject;",
        ]

        for example in examples:
            parsed_record = checkdmarc.dmarc.parse_dmarc_record(example, "")
            self.assertIsInstance(parsed_record, dict)

    def testGetBaseDomain(self):
        subdomain = "foo.example.com"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "example.com"

        # Test reserved domains
        subdomain = "_dmarc.nonauth-rua.invalid.example"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "invalid.example"

        subdomain = "_dmarc.nonauth-rua.invalid.test"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "invalid.test"

        subdomain = "_dmarc.nonauth-rua.invalid.invalid"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "invalid.invalid"

        subdomain = "_dmarc.nonauth-rua.invalid.localhost"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "invalid.localhost"

        # Test newer PSL entries
        subdomain = "e3191.c.akamaiedge.net"
        result = checkdmarc.utils.get_base_domain(subdomain)
        assert result == "c.akamaiedge.net"

    def testUppercaseSPFMechanism(self):
        """Treat uppercase SPF mechanisms as valid"""
        spf_record = "v=spf1 IP4:147.75.8.208 -ALL"
        domain = "example.no"

        results = checkdmarc.spf.parse_spf_record(spf_record, domain)

        self.assertEqual(len(results["warnings"]), 0)
        self.assertEqual(results["dns_lookups"], 0)

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
    def testSplitSPFRecord(self):
        """Split SPF records are parsed properly"""

        rec = '"v=spf1 ip4:147.75.8.208 " "include:_spf.salesforce.com -all"'

        parsed_record = checkdmarc.spf.parse_spf_record(rec, "example.com")

        self.assertEqual(parsed_record["parsed"]["all"], "fail")

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
    def testJunkAfterAll(self):
        """Ignore any mechanisms after the all mechanism, but warn about it"""
        rec = "v=spf1 ip4:213.5.39.110 -all MS=83859DAEBD1978F9A7A67D3"
        domain = "avd.dk"
        warning = (
            "Any text after the all mechanism other than an exp modifier is ignored."
        )

        parsed_record = checkdmarc.spf.parse_spf_record(rec, domain)
        self.assertIn(warning, parsed_record["warnings"])

    @unittest.skip
    def testDNSSEC(self):
        """Test known good DNSSEC"""
        self.assertEqual(checkdmarc.dnssec.test_dnssec("fbi.gov"), True)

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
    def testIncludeMissingSPF(self):
        """A warning is included for SPF records that include domains that are missing SPF records"""

        spf_record = "v=spf1 include:example.doesnotexist ~all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertTrue(
            "example.doesnotexist: The domain does not exist." in results["warnings"]
        )
        self.assertEqual(results["dns_lookups"], 1)

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
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
            "~all"
        )
        domain = "example.com"
        self.assertRaises(
            checkdmarc.spf.SPFTooManyDNSLookups,
            checkdmarc.spf.parse_spf_record,
            spf_record,
            domain,
        )

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
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

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
    def testSPFMissingMXRecord(self):
        """A warning is issued if an SPF record contains a mx mechanism
        pointing to a domain that has no MX records"""

        spf_record = '"v=spf1 mx ~all"'
        domain = "seanthegeek.net"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn(
            "{0}: An mx mechanism points to {0}, but that domain/subdomain does not have any MX records.".format(
                domain
            ),
            results["warnings"],
        )
        self.assertEqual(results["dns_lookups"], 1)

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
    def testSPFMissingARecord(self):
        """A warning is issued if an SPF record contains an a mechanism
        pointing to a domain that has no A records"""

        spf_record = '"v=spf1 a ~all"'
        domain = "cardinalhealth.net"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        snipit = "that domain/subdomain does not have any A/AAAA records."
        self.assertTrue(any(snipit in s for s in results["warnings"]))
        self.assertEqual(results["dns_lookups"], 1)

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
    def testSPFMXMechanism(self):
        """Addresses are included in the output for SPF records with an mx lookup"""
        spf_record = "v=spf1 mx:proton.me ~all"
        domain = "example.com"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        for mechanism in results["parsed"]["mechanisms"]:
            if mechanism["mechanism"] == "mx":
                self.assertTrue(len(mechanism["hosts"]) > 0)
            for host in mechanism["hosts"]:
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
                self.assertTrue(len(mechanism["addresses"]) > 0)
        self.assertEqual(results["dns_lookups"], 1)

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
    def testDMARCPctLessThan100Warning(self):
        """A warning is issued if the DMARC pct value is less than 100"""

        snipit = "pct value is less than 100"
        dmarc_record = (
            "v=DMARC1; p=none; sp=none; fo=1; pct=50; adkim=r; "
            "aspf=r; rf=afrf; ri=86400; "
            "rua=mailto:eits.dmarcrua@energy.gov; "
            "ruf=mailto:eits.dmarcruf@energy.gov"
        )
        domain = "energy.gov"
        results = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(any(snipit in s for s in results["warnings"]))

    def testInvalidDMARCURI(self):
        """An invalid DMARC report URI raises InvalidDMARCReportURI"""

        dmarc_record = (
            "v=DMARC1; p=none; rua=reports@dmarc.cyber.dhs.gov,"
            "mailto:dmarcreports@usdoj.gov"
        )
        domain = "dea.gov"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCReportURI,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

        dmarc_record = (
            "v=DMARC1; p=none; rua=__"
            "mailto:reports@dmarc.cyber.dhs.gov,"
            "mailto:dmarcreports@usdoj.gov"
        )
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCReportURI,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testInvalidDMARCPolicyValue(self):
        """An invalid DMARC policy value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=foo; rua=mailto:dmarc@example.com"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    @unittest.skipUnless(os.path.exists("/etc/resolv.conf"), "no network")
    def testBIMI(self):
        """Test BIMI checks"""
        domain = "chase.com"

        results = checkdmarc.bimi.check_bimi(domain)

        self.assertEqual(len(results["warnings"]), 0)

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
            self.assertIn("v=spf1", result["record"])

            # Verify a warning was added for the undecodable record
            self.assertTrue(len(result["warnings"]) > 0)
            self.assertTrue(
                any(
                    "TXT record" in w and "undecodable" in w.lower()
                    for w in result["warnings"]
                )
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
