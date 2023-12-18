#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Automated tests"""

import unittest
from collections import OrderedDict

import checkdmarc
import checkdmarc.utils
import checkdmarc.spf
import checkdmarc.dmarc
import checkdmarc.dnssec

known_good_domains = [
    "fbi.gov",
    "pm.me"
]


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
                    mx["starttls"], True,
                    "Host of known good domain {0} failed STARTTLS check: {1}"
                    "\n\n{0}".format(result["domain"], mx["hostname"])
                )
            if "error" in result["spf"]:
                spf_error = result["spf"]["error"]
            if "error" in result["dmarc"]:
                dmarc_error = result["dmarc"]["error"]
            self.assertEqual(result["spf"]["valid"], True,
                             "Known good domain {0} failed SPF check:"
                             "\n\n{1}".format(result["domain"], spf_error))
            self.assertEqual(result["dmarc"]["valid"], True,
                             "Known good domain {0} failed DMARC check:"
                             "\n\n{1}".format(result["domain"], dmarc_error))

    def testDMARCMixedFormatting(self):
        """DMARC records with extra spaces and mixed case are still valid"""
        examples = [
            "v=DMARC1;p=ReJect",
            "v = DMARC1;p=reject;",
            "v = DMARC1\t;\tp=reject\t;",
            "v = DMARC1\t;\tp\t\t\t=\t\t\treject\t;",
            "V=DMARC1;p=reject;"
        ]

        for example in examples:
            parsed_record = checkdmarc.dmarc.parse_dmarc_record(example, "")
            self.assertIsInstance(parsed_record, OrderedDict)

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
        """Treat uppercase SPF"SPF mechanisms as valid"""
        spf_record = "v=spf1 IP4:147.75.8.208 -ALL"
        domain = "example.no"

        results = checkdmarc.spf.parse_spf_record(spf_record, domain)

        self.assertEqual(len(results["warnings"]), 0)

    def testSplitSPFRecord(self):
        """Split SPF records are parsed properly"""

        rec = '"v=spf1 ip4:147.75.8.208 " "include:_spf.salesforce.com -all"'

        parsed_record = checkdmarc.spf.parse_spf_record(rec, "example.com")

        self.assertEqual(parsed_record["parsed"]["all"], "fail")

    def testJunkAfterAll(self):
        """Ignore any mechanisms after the all mechanism, but warn about it"""
        rec = "v=spf1 ip4:213.5.39.110 -all MS=83859DAEBD1978F9A7A67D3"
        domain = "avd.dk"

        parsed_record = checkdmarc.spf.parse_spf_record(rec, domain)
        self.assertEqual(len(parsed_record["warnings"]), 1)

    @unittest.skip
    def testDNSSEC(self):
        """Test known good DNSSEC"""
        self.assertEqual(checkdmarc.dnssec.test_dnssec("fbi.gov"), True)

    def testIncludeMissingSPF(self):
        """SPF records that include domains that are missing SPF records
        raise SPFRecordNotFound"""

        spf_record = '"v=spf1 include:spf.comendosystems.com ' \
                     'include:bounce.peytz.dk include:etrack.indicia.dk ' \
                     'include:etrack1.com include:mail1.dialogportal.com ' \
                     'include:mail2.dialogportal.com a:mailrelay.jppol.dk ' \
                     'a:sendmail.jppol.dk ?all"'
        domain = "ekstrabladet.dk"
        self.assertRaises(checkdmarc.spf.SPFRecordNotFound,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testTooManySPFDNSLookups(self):
        """SPF records with > 10 SPF mechanisms that cause DNS lookups raise
        SPFTooManyDNSLookups"""

        spf_record = "v=spf1 a include:_spf.salesforce.com " \
                     "include:spf.protection.outlook.com " \
                     "include:spf.constantcontact.com " \
                     "include:_spf.elasticemail.com " \
                     "include:servers.mcsv.net " \
                     "include:_spf.google.com " \
                     "~all"
        domain = "example.com"
        self.assertRaises(checkdmarc.spf.SPFTooManyDNSLookups,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testTooManySPFVoidDNSLookups(self):
        """SPF records with > 2 void DNS lookups"""

        spf_record = "v=spf1 a:13Mk4olS9VWhQqXRl90fKJrD.example.com " \
                     "mx:SfGiqBnQfRbOMapQJhozxo2B.example.com " \
                     "a:VAFeyU9N2KJX518aGsN3w6VS.example.com " \
                     "~all"
        domain = "example.com"
        self.assertRaises(checkdmarc.spf.SPFTooManyVoidDNSLookups,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testSPFSyntaxErrors(self):
        """SPF record syntax errors raise SPFSyntaxError"""

        spf_record = '"v=spf1 mx a:mail.cohaesio.net ' \
                     'include: trustpilotservice.com ~all"'
        domain = "2021.ai"
        self.assertRaises(checkdmarc.spf.SPFSyntaxError,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testSPFInvalidIPv4(self):
        """Invalid ipv4 SPF mechanism values raise SPFSyntaxError"""
        spf_record = "v=spf1 ip4:78.46.96.236 +a +mx +ip4:138.201.239.158 " \
                     "+ip4:78.46.224.83 " \
                     "+ip4:relay.mailchannels.net +ip4:138.201.60.20 ~all"
        domain = "surftown.dk"
        self.assertRaises(checkdmarc.spf.SPFSyntaxError,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testSPFInvalidIPv6inIPv4(self):
        """Invalid ipv4 SPF mechanism values raise SPFSyntaxError"""
        spf_record = "v=spf1 ip4:1200:0000:AB00:1234:0000:2552:7777:1313 ~all"
        domain = "surftown.dk"
        self.assertRaises(checkdmarc.spf.SPFSyntaxError,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testSPFInvalidIPv4Range(self):
        """Invalid ipv4 SPF mechanism values raise SPFSyntaxError"""
        spf_record = "v=spf1 ip4:78.46.96.236/99 ~all"
        domain = "surftown.dk"
        self.assertRaises(checkdmarc.spf.SPFSyntaxError,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testSPFInvalidIPv6(self):
        """Invalid ipv6 SPF mechanism values raise SPFSyntaxError"""
        spf_record = "v=spf1 ip6:1200:0000:AB00:1234:O000:2552:7777:1313 ~all"
        domain = "surftown.dk"
        self.assertRaises(checkdmarc.spf.SPFSyntaxError,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testSPFInvalidIPv4inIPv6(self):
        """Invalid ipv6 SPF mechanism values raise SPFSyntaxError"""
        spf_record = "v=spf1 ip6:78.46.96.236 ~all"
        domain = "surftown.dk"
        self.assertRaises(checkdmarc.spf.SPFSyntaxError,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testSPFInvalidIPv6Range(self):
        """Invalid ipv6 SPF mechanism values raise SPFSyntaxError"""
        record = "v=spf1 ip6:1200:0000:AB00:1234:0000:2552:7777:1313/130 ~all"
        domain = "surftown.dk"
        self.assertRaises(checkdmarc.spf.SPFSyntaxError,
                          checkdmarc.spf.parse_spf_record, record, domain)

    def testSPFIncludeLoop(self):
        """SPF record with include loop raises SPFIncludeLoop"""

        spf_record = '"v=spf1 include:example.com"'
        domain = "example.com"
        self.assertRaises(checkdmarc.spf.SPFIncludeLoop,
                          checkdmarc.spf.parse_spf_record, spf_record, domain)

    def testSPFMissingMXRecord(self):
        """A warning is issued if an SPF record contains a mx mechanism
        pointing to a domain that has no MX records"""

        spf_record = '"v=spf1 mx ~all"'
        domain = "seanthegeek.net"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn("{0} does not have any MX records".format(domain),
                      results["warnings"])

    def testSPFMissingARecord(self):
        """A warning is issued if an SPF record contains a mx mechanism
        pointing to a domain that has no A records"""

        spf_record = '"v=spf1 a ~all"'
        domain = "cardinalhealth.net"
        results = checkdmarc.spf.parse_spf_record(spf_record, domain)
        self.assertIn("cardinalhealth.net does not have any A/AAAA records",
                      results["warnings"])

    def testDMARCPctLessThan100Warning(self):
        """A warning is issued if the DMARC pvt value is less than 100"""

        dmarc_record = "v=DMARC1; p=none; sp=none; fo=1; pct=50; adkim=r; " \
                       "aspf=r; rf=afrf; ri=86400; " \
                       "rua=mailto:eits.dmarcrua@energy.gov; " \
                       "ruf=mailto:eits.dmarcruf@energy.gov"
        domain = "energy.gov"
        results = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertIn("pct value is less than 100",
                      results["warnings"][0])

    def testInvalidDMARCURI(self):
        """An invalid DMARC report URI raises InvalidDMARCReportURI"""

        dmarc_record = "v=DMARC1; p=none; rua=reports@dmarc.cyber.dhs.gov," \
                       "mailto:dmarcreports@usdoj.gov"
        domain = "dea.gov"
        self.assertRaises(checkdmarc.dmarc.InvalidDMARCReportURI,
                          checkdmarc.dmarc.parse_dmarc_record, dmarc_record,
                          domain)

        dmarc_record = "v=DMARC1; p=none; rua=__" \
                       "mailto:reports@dmarc.cyber.dhs.gov," \
                       "mailto:dmarcreports@usdoj.gov"
        self.assertRaises(checkdmarc.dmarc.InvalidDMARCReportURI,
                          checkdmarc.dmarc.parse_dmarc_record, dmarc_record,
                          domain)

    def testInvalidDMARCPolicyValue(self):
        """An invalid DMARC policy value raises InvalidDMARCTagValue """
        dmarc_record = "v=DMARC1; p=foo; rua=mailto:dmarc@example.com"
        domain = "example.com"
        self.assertRaises(checkdmarc.dmarc.InvalidDMARCTagValue,
                          checkdmarc.dmarc.parse_dmarc_record,
                          dmarc_record,
                          domain)


if __name__ == "__main__":
    unittest.main(verbosity=2)
