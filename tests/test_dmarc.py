"""Tests for checkdmarc.dmarc"""

import unittest
from unittest.mock import patch

import dns.resolver

import checkdmarc.dmarc


class Test(unittest.TestCase):
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

    @unittest.skip(reason="This test will be used once DMARCbis is released")
    def testDMARCbisMissingPTagWarning(self):
        """A missing p tag results in a warning and defaults to none"""
        dmarc_record = "v=DMARC1; rua=mailto:dmarc@example.com"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["p"]["value"], "none")
        self.assertFalse(result["tags"]["p"]["explicit"])
        warning = (
            "A missing p tag is equivalent to p=none in DMARCbis, "
            "but a p tag is required in older versions of DMARC."
        )

        self.assertTrue(any(warning in w for w in result["warnings"]))

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
