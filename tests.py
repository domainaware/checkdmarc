#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Automated tests"""

import json
import os
import unittest
from unittest.mock import patch

import dns.resolver

import checkdmarc
import checkdmarc.bimi
import checkdmarc.dmarc
import checkdmarc.dnssec
import checkdmarc.mta_sts
import checkdmarc.smtp_tls_reporting
import checkdmarc.soa
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

    def testDMARCbisNewTagNp(self):
        """DMARCbis np tag is parsed correctly"""
        dmarc_record = "v=DMARC1; p=reject; np=quarantine"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["np"]["value"], "quarantine")
        self.assertTrue(result["tags"]["np"]["explicit"])

    def testDMARCbisNewTagPsd(self):
        """DMARCbis psd tag is parsed correctly"""
        dmarc_record = "v=DMARC1; p=reject; psd=n"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["psd"]["value"], "n")
        self.assertTrue(result["tags"]["psd"]["explicit"])

    def testDMARCbisNewTagT(self):
        """DMARCbis t tag is parsed correctly"""
        dmarc_record = "v=DMARC1; p=reject; t=y"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["t"]["value"], "y")
        self.assertTrue(result["tags"]["t"]["explicit"])

    def testDMARCbisInvalidNpValue(self):
        """An invalid np tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; np=invalid"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCbisInvalidPsdValue(self):
        """An invalid psd tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; psd=x"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCbisInvalidTValue(self):
        """An invalid t tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; t=x"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCbisPctRemovedWarning(self):
        """A warning is issued when the removed pct tag is used"""
        dmarc_record = "v=DMARC1; p=reject; pct=100"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(
            any("pct tag was removed in DMARCbis" in w for w in result["warnings"])
        )

    def testDMARCbisRfRemovedWarning(self):
        """A warning is issued when the removed rf tag is used"""
        dmarc_record = "v=DMARC1; p=reject; rf=afrf"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(
            any("rf tag was removed in DMARCbis" in w for w in result["warnings"])
        )

    def testDMARCbisRiRemovedWarning(self):
        """A warning is issued when the removed ri tag is used"""
        dmarc_record = "v=DMARC1; p=reject; ri=3600"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(
            any("ri tag was removed in DMARCbis" in w for w in result["warnings"])
        )

    def testDMARCbisMissingPTagWarning(self):
        """A missing p tag results in a warning and defaults to none"""
        dmarc_record = "v=DMARC1; rua=mailto:dmarc@example.com"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["p"]["value"], "none")
        self.assertFalse(result["tags"]["p"]["explicit"])
        self.assertTrue(
            any("p tag is optional in DMARCbis" in w for w in result["warnings"])
        )

    def testDMARCbisNpDefaultsToSp(self):
        """The np tag defaults to the sp tag value when not explicit"""
        dmarc_record = "v=DMARC1; p=reject; sp=quarantine"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["np"]["value"], "quarantine")
        self.assertFalse(result["tags"]["np"]["explicit"])

    def testDMARCbisNpDefaultsToP(self):
        """The np tag defaults to the p tag value when sp is also absent"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["np"]["value"], "reject")
        self.assertFalse(result["tags"]["np"]["explicit"])

    def testDMARCbisPsdDefaultsToU(self):
        """The psd tag defaults to u when not explicit"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["psd"]["value"], "u")
        self.assertFalse(result["tags"]["psd"]["explicit"])

    def testDMARCbisTDefaultsToN(self):
        """The t tag defaults to n when not explicit"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["t"]["value"], "n")
        self.assertFalse(result["tags"]["t"]["explicit"])

    def testDMARCbisRemovedTagImplicitNoWarning(self):
        """No warning is issued for implicit (default) removed tags"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        removed_warnings = [w for w in result["warnings"] if "removed in DMARCbis" in w]
        self.assertEqual(len(removed_warnings), 0)

    def testDMARCbisBackwardCompatibility(self):
        """Old RFC 7489 records with all tags are still valid"""
        dmarc_record = (
            "v=DMARC1; p=none; sp=none; fo=1; pct=50; adkim=r; "
            "aspf=r; rf=afrf; ri=86400; "
            "rua=mailto:eits.dmarcrua@energy.gov; "
            "ruf=mailto:eits.dmarcruf@energy.gov"
        )
        domain = "energy.gov"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertIsInstance(result, dict)
        self.assertIn("tags", result)

    def testDMARCbisTreeWalkDiscovery(self):
        """DNS tree walk discovers DMARC records for parent domains"""
        # This tests that the tree walk works by using a mock
        with patch("checkdmarc.dmarc._query_dmarc_record") as mock_query:
            with patch("checkdmarc.dmarc.query_dns") as mock_root_dns:
                mock_root_dns.return_value = []
                # First call for sub.example.com returns None
                # Walk: example.com returns a record
                mock_query.side_effect = [
                    None,  # _dmarc.sub.example.com
                    "v=DMARC1; p=reject",  # _dmarc.example.com
                ]
                result = checkdmarc.dmarc.query_dmarc_record("sub.example.com")
                self.assertEqual(result["location"], "example.com")
                self.assertEqual(result["record"], "v=DMARC1; p=reject")

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

    # ================================================================
    # DMARC additional tests
    # ================================================================

    def testDMARCSyntaxError(self):
        """An invalid DMARC fo tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; fo=invalid_value"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCDuplicateTags(self):
        """Duplicate DMARC tags raise InvalidDMARCTag"""
        dmarc_record = "v=DMARC1; p=reject; p=none"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTag,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCInvalidTag(self):
        """An invalid DMARC tag raises InvalidDMARCTag"""
        dmarc_record = "v=DMARC1; p=reject; xyz=foo"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTag,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCSPFInDMARC(self):
        """An SPF record where a DMARC record should be raises SPFRecordFoundWhereDMARCRecordShouldBe"""
        record = "v=spf1 include:example.com -all"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.SPFRecordFoundWhereDMARCRecordShouldBe,
            checkdmarc.dmarc.parse_dmarc_record,
            record,
            domain,
        )

    def testDMARCPctZero(self):
        """pct=0 produces a warning about disabling enforcement"""
        dmarc_record = "v=DMARC1; p=reject; pct=0"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(any("pct value of 0" in w for w in result["warnings"]))

    def testDMARCPctOutOfRange(self):
        """pct value out of range raises DMARCSyntaxError"""
        dmarc_record = "v=DMARC1; p=reject; pct=150"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.DMARCSyntaxError,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCPctNegative(self):
        """Negative pct value raises DMARCSyntaxError"""
        dmarc_record = "v=DMARC1; p=reject; pct=-1"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.DMARCSyntaxError,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCPctNonInteger(self):
        """Non-integer pct value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; pct=abc"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCRiNonInteger(self):
        """Non-integer ri value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; ri=abc"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCFoRedundancy(self):
        """fo=0:1 produces a warning about redundancy"""
        dmarc_record = "v=DMARC1; p=reject; fo=0:1"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(any("redundant" in w.lower() for w in result["warnings"]))

    def testDMARCInvalidFoValue(self):
        """Invalid fo tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; fo=x"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCInvalidRfValue(self):
        """Invalid rf tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; rf=invalid"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCSpNoneWarning(self):
        """Explicit sp=none produces a warning"""
        dmarc_record = "v=DMARC1; p=reject; sp=none"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(any("sp tag value of none" in w for w in result["warnings"]))

    def testDMARCParkedDomainPolicyWarning(self):
        """Parked domains with p!=reject produce warnings"""
        dmarc_record = "v=DMARC1; p=none"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain, parked=True)
        self.assertTrue(any("parked" in w.lower() for w in result["warnings"]))

    def testDMARCParkedDomainSpWarning(self):
        """Parked domains with sp!=reject produce warnings"""
        dmarc_record = "v=DMARC1; p=reject; sp=none"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain, parked=True)
        self.assertTrue(
            any(
                "subdomain policy" in w.lower() and "parked" in w.lower()
                for w in result["warnings"]
            )
        )

    def testDMARCMissingRuaWarning(self):
        """Missing rua tag produces a best practice warning"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(any("rua" in w.lower() for w in result["warnings"]))

    def testDMARCPTagPosition(self):
        """p tag not immediately after v raises DMARCSyntaxError"""
        dmarc_record = "v=DMARC1; sp=none; p=reject"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.DMARCSyntaxError,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCTagDescriptions(self):
        """Tag descriptions are included when requested"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(
            dmarc_record, domain, include_tag_descriptions=True
        )
        for tag in result["tags"]:
            self.assertIn("description", result["tags"][tag])
            self.assertIn("name", result["tags"][tag])

    def testDMARCGetTagDescriptionString(self):
        """get_dmarc_tag_description returns value-specific descriptions"""
        details = checkdmarc.dmarc.get_dmarc_tag_description("p", "reject")
        self.assertIn("reject", details["description"].lower())

    def testDMARCGetTagDescriptionList(self):
        """get_dmarc_tag_description handles list values (fo tag)"""
        details = checkdmarc.dmarc.get_dmarc_tag_description("fo", ["0", "d"])
        self.assertIn("0:", details["description"])
        self.assertIn("d:", details["description"])

    def testDMARCGetTagDescriptionDefault(self):
        """get_dmarc_tag_description returns default value"""
        details = checkdmarc.dmarc.get_dmarc_tag_description("pct")
        self.assertEqual(details["default"], 100)

    def testDMARCGetTagDescriptionNoDefault(self):
        """get_dmarc_tag_description returns None for tags without default"""
        details = checkdmarc.dmarc.get_dmarc_tag_description("v")
        self.assertIsNone(details["default"])

    def testDMARCInvalidSpValue(self):
        """Invalid sp tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; sp=invalid"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testDMARCRecordStartsWithWhitespace(self):
        """DMARC record with leading whitespace raises DMARCRecordStartsWithWhitespace"""
        with patch("checkdmarc.dmarc.query_dns") as mock_dns:
            mock_dns.return_value = [" v=DMARC1; p=reject"]
            self.assertRaises(
                checkdmarc.dmarc.DMARCRecordStartsWithWhitespace,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )

    def testDMARCMultipleRecords(self):
        """Multiple DMARC records raise MultipleDMARCRecords"""
        with patch("checkdmarc.dmarc.query_dns") as mock_dns:
            mock_dns.return_value = [
                "v=DMARC1; p=reject",
                "v=DMARC1; p=none",
            ]
            self.assertRaises(
                checkdmarc.dmarc.MultipleDMARCRecords,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )

    def testDMARCUnrelatedRecords(self):
        """Unrelated TXT records at _dmarc raise UnrelatedTXTRecordFoundAtDMARC"""
        with patch("checkdmarc.dmarc.query_dns") as mock_dns:
            mock_dns.return_value = [
                "v=DMARC1; p=reject",
                "some random txt record",
            ]
            self.assertRaises(
                checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )

    def testDMARCUnrelatedRecordsIgnored(self):
        """Unrelated records are ignored when ignore_unrelated_records=True"""
        with patch("checkdmarc.dmarc.query_dns") as mock_dns:
            mock_dns.return_value = [
                "v=DMARC1; p=reject",
                "some random txt record",
            ]
            result = checkdmarc.dmarc._query_dmarc_record(
                "example.com", ignore_unrelated_records=True
            )
            self.assertEqual(result, "v=DMARC1; p=reject")

    def testDMARCRecordNotFoundNXDOMAIN(self):
        """NXDOMAIN during query raises DMARCRecordNotFound"""
        with patch("checkdmarc.dmarc.query_dns") as mock_dns:
            mock_dns.side_effect = dns.resolver.NXDOMAIN()
            self.assertRaises(
                checkdmarc.dmarc.DMARCRecordNotFound,
                checkdmarc.dmarc.query_dmarc_record,
                "nonexistent.example.com",
            )

    def testDMARCTreeWalkStopsAtTLD(self):
        """DNS tree walk does not query TLDs"""
        with patch("checkdmarc.dmarc._query_dmarc_record") as mock_query:
            with patch("checkdmarc.dmarc.query_dns") as mock_root_dns:
                mock_root_dns.return_value = []
                # All queries return None - should stop before TLD
                mock_query.return_value = None
                self.assertRaises(
                    checkdmarc.dmarc.DMARCRecordNotFound,
                    checkdmarc.dmarc.query_dmarc_record,
                    "sub.example.com",
                )
                # Should have been called for sub.example.com and example.com
                # but NOT for "com"
                queried_domains = [c.args[0] for c in mock_query.call_args_list]
                self.assertNotIn("com", queried_domains)

    def testDMARCTreeWalkLongDomain(self):
        """DNS tree walk limits queries for domains with many labels"""
        with patch("checkdmarc.dmarc._query_dmarc_record") as mock_query:
            with patch("checkdmarc.dmarc.query_dns") as mock_root_dns:
                mock_root_dns.return_value = []
                # For a 9-label domain, it should start from 7 labels (index 2)
                # Calls: original domain, then tree walk from d.e.f.g.example.com down
                mock_query.return_value = None
                domain = "a.b.c.d.e.f.g.example.com"
                self.assertRaises(
                    checkdmarc.dmarc.DMARCRecordNotFound,
                    checkdmarc.dmarc.query_dmarc_record,
                    domain,
                )

    def testDMARCCheckDmarcError(self):
        """check_dmarc returns error results when record not found"""
        with patch("checkdmarc.dmarc.query_dmarc_record") as mock_query:
            mock_query.side_effect = checkdmarc.dmarc.DMARCRecordNotFound(
                "A DMARC record does not exist."
            )
            result = checkdmarc.dmarc.check_dmarc("example.com")
            self.assertFalse(result["valid"])
            self.assertIn("error", result)

    def testDMARCCheckDmarcParseError(self):
        """check_dmarc returns error results when parsing fails"""
        with patch("checkdmarc.dmarc.query_dmarc_record") as mock_query:
            mock_query.return_value = {
                "record": "v=DMARC1; p=invalid",
                "location": "example.com",
                "warnings": [],
            }
            result = checkdmarc.dmarc.check_dmarc("example.com")
            self.assertFalse(result["valid"])

    def testDMARCCheckDmarcSuccess(self):
        """check_dmarc returns valid results for a good record"""
        with patch("checkdmarc.dmarc.query_dmarc_record") as mock_query:
            mock_query.return_value = {
                "record": "v=DMARC1; p=reject",
                "location": "example.com",
                "warnings": [],
            }
            result = checkdmarc.dmarc.check_dmarc("example.com")
            self.assertTrue(result["valid"])
            self.assertIn("tags", result)

    def testDMARCParseReportURI(self):
        """parse_dmarc_report_uri parses valid mailto URIs"""
        uri = checkdmarc.dmarc.parse_dmarc_report_uri("mailto:dmarc@example.com")
        self.assertEqual(uri["scheme"], "mailto")
        self.assertEqual(uri["address"], "dmarc@example.com")
        self.assertIsNone(uri["size_limit"])

    def testDMARCParseReportURIWithSize(self):
        """parse_dmarc_report_uri parses URIs with size limits"""
        uri = checkdmarc.dmarc.parse_dmarc_report_uri("mailto:dmarc@example.com!10m")
        self.assertEqual(uri["address"], "dmarc@example.com")
        self.assertIsNotNone(uri["size_limit"])

    def testDMARCInvalidReportURI(self):
        """Invalid DMARC report URI raises InvalidDMARCReportURI"""
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCReportURI,
            checkdmarc.dmarc.parse_dmarc_report_uri,
            "not_a_valid_uri",
        )

    def testDMARCRecordAtRoot(self):
        """DMARC record at root of domain produces warning"""
        with patch("checkdmarc.dmarc._query_dmarc_record") as mock_query:
            with patch("checkdmarc.dmarc.query_dns") as mock_dns:
                mock_query.return_value = "v=DMARC1; p=reject"
                mock_dns.return_value = ["v=DMARC1; p=reject"]
                result = checkdmarc.dmarc.query_dmarc_record("example.com")
                self.assertTrue(any("no effect" in w for w in result["warnings"]))

    # ================================================================
    # SPF additional tests
    # ================================================================

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
    # Utils tests
    # ================================================================

    def testNormalizeDomain(self):
        """normalize_domain handles various inputs correctly"""
        # Basic lowering
        self.assertEqual(
            checkdmarc.utils.normalize_domain("Example.COM"), "example.com"
        )
        # Zero-width character removal
        self.assertEqual(
            checkdmarc.utils.normalize_domain("exam\u200bple.com"),
            "example.com",
        )
        # Unicode normalization
        self.assertEqual(
            checkdmarc.utils.normalize_domain("example.com"), "example.com"
        )

    def testResultsToJson(self):
        """results_to_json produces valid JSON"""
        results = {"domain": "example.com", "valid": True}
        json_str = checkdmarc.results_to_json(results)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["domain"], "example.com")

    def testResultsToJsonList(self):
        """results_to_json handles list of results"""
        results = [
            {"domain": "example.com"},
            {"domain": "example.org"},
        ]
        json_str = checkdmarc.results_to_json(results)
        parsed = json.loads(json_str)
        self.assertEqual(len(parsed), 2)

    def testResultsToCsvRows(self):
        """results_to_csv_rows converts results to CSV row dicts"""
        results = {
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
        }
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

    # ================================================================
    # SOA tests
    # ================================================================

    def testSoaRnameToEmail(self):
        """soa_rname_to_email converts RNAME to email"""
        email = checkdmarc.soa.soa_rname_to_email("admin.example.com.")
        self.assertEqual(email, "admin@example.com")

    def testSoaRnameToEmailEscapedDot(self):
        """soa_rname_to_email handles escaped dots in local part"""
        email = checkdmarc.soa.soa_rname_to_email(r"first\.last.example.com.")
        self.assertEqual(email, "first.last@example.com")

    def testSoaRnameToEmailInvalid(self):
        """soa_rname_to_email raises ValueError for invalid RNAME"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.soa_rname_to_email,
            "nodotatall",
        )

    def testParseSoaString(self):
        """parse_soa_string parses a valid SOA record"""
        soa_record = (
            "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"
        )
        result = checkdmarc.soa.parse_soa_string(soa_record)
        self.assertEqual(result["primary_nameserver"], "ns1.example.com")
        self.assertEqual(result["serial"], 2024010101)
        self.assertEqual(result["refresh"], 3600)

    def testParseSoaStringEmpty(self):
        """parse_soa_string raises ValueError for empty string"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.parse_soa_string,
            "",
        )

    def testParseSoaStringWrongFields(self):
        """parse_soa_string raises ValueError for wrong number of fields"""
        self.assertRaises(
            ValueError,
            checkdmarc.soa.parse_soa_string,
            "ns1.example.com. admin.example.com. 12345",
        )

    def testCheckSoaSuccess(self):
        """check_soa returns parsed record on success"""
        with patch("checkdmarc.soa.get_soa_record") as mock_soa:
            mock_soa.return_value = (
                "ns1.example.com. admin.example.com. 2024010101 3600 900 604800 86400"
            )
            result = checkdmarc.soa.check_soa("example.com")
            self.assertIn("values", result)
            self.assertEqual(result["values"]["serial"], 2024010101)

    def testCheckSoaError(self):
        """check_soa returns error on failure"""
        with patch("checkdmarc.soa.get_soa_record") as mock_soa:
            mock_soa.side_effect = Exception("DNS error")
            result = checkdmarc.soa.check_soa("example.com")
            self.assertIn("error", result)

    # ================================================================
    # MTA-STS tests
    # ================================================================

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

    # ================================================================
    # SMTP TLS Reporting tests
    # ================================================================

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

    # ================================================================
    # DNSSEC tests (mocked)
    # ================================================================

    def testDnssecFalseWhenNoKey(self):
        """test_dnssec returns False when no DNSKEY found"""
        with patch("checkdmarc.dnssec.get_dnskey") as mock_key:
            mock_key.return_value = None
            result = checkdmarc.dnssec.test_dnssec("example.com")
            self.assertFalse(result)

    def testGetDnskeyCache(self):
        """get_dnskey uses cache"""
        from expiringdict import ExpiringDict

        cache = ExpiringDict(max_len=100, max_age_seconds=60)
        mock_key = {"test": "data"}
        cache["example.com"] = mock_key
        result = checkdmarc.dnssec.get_dnskey("example.com", cache=cache)
        self.assertEqual(result, mock_key)

    # ================================================================
    # _constants tests
    # ================================================================

    def testConstantsVersion(self):
        """Version string is defined"""
        self.assertIsNotNone(checkdmarc.__version__)
        self.assertIsInstance(checkdmarc.__version__, str)

    def testConstantsEnvironmentOverrides(self):
        """Environment variable overrides work for constants"""
        import checkdmarc._constants as constants

        self.assertIsInstance(constants.CACHE_MAX_LEN, int)
        self.assertIsInstance(constants.CACHE_MAX_AGE_SECONDS, int)
        self.assertIsInstance(constants.SYNTAX_ERROR_MARKER, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
