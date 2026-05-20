"""Tests for checkdmarc.dmarc"""

import unittest
from typing import Any, cast
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

    def testRFC9989NewTagNp(self):
        """RFC9989 np tag is parsed correctly"""
        dmarc_record = "v=DMARC1; p=reject; np=quarantine"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["np"]["value"], "quarantine")
        self.assertTrue(result["tags"]["np"]["explicit"])

    def testRFC9989NewTagPsd(self):
        """RFC9989 psd tag is parsed correctly"""
        dmarc_record = "v=DMARC1; p=reject; psd=n"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["psd"]["value"], "n")
        self.assertTrue(result["tags"]["psd"]["explicit"])

    def testRFC9989NewTagT(self):
        """RFC9989 t tag is parsed correctly"""
        dmarc_record = "v=DMARC1; p=reject; t=y"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["t"]["value"], "y")
        self.assertTrue(result["tags"]["t"]["explicit"])

    def testRFC9989InvalidNpValue(self):
        """An invalid np tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; np=invalid"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testRFC9989InvalidPsdValue(self):
        """An invalid psd tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; psd=x"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testRFC9989InvalidTValue(self):
        """An invalid t tag value raises InvalidDMARCTagValue"""
        dmarc_record = "v=DMARC1; p=reject; t=x"
        domain = "example.com"
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCTagValue,
            checkdmarc.dmarc.parse_dmarc_record,
            dmarc_record,
            domain,
        )

    def testRFC9989PctRemovedWarning(self):
        """A warning is issued when the removed pct tag is used"""
        dmarc_record = "v=DMARC1; p=reject; pct=100"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(
            any("pct tag was removed in RFC 9989" in w for w in result["warnings"])
        )

    def testRFC9989RfRemovedWarning(self):
        """A warning is issued when the removed rf tag is used"""
        dmarc_record = "v=DMARC1; p=reject; rf=afrf"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(
            any("rf tag was removed in RFC 9989" in w for w in result["warnings"])
        )

    def testRFC9989RiRemovedWarning(self):
        """A warning is issued when the removed ri tag is used"""
        dmarc_record = "v=DMARC1; p=reject; ri=3600"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertTrue(
            any("ri tag was removed in RFC 9989" in w for w in result["warnings"])
        )

    def testRFC9989MissingPTagWarning(self):
        """A missing p tag results in a warning and defaults to none"""
        dmarc_record = "v=DMARC1; rua=mailto:dmarc@example.com"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["p"]["value"], "none")
        self.assertFalse(result["tags"]["p"]["explicit"])
        warning = (
            "A missing p tag is equivalent to p=none in RFC 9989, "
            "but a p tag is required in older versions of DMARC."
        )

        self.assertTrue(any(warning in w for w in result["warnings"]))

    def testRFC9989NpDefaultsToSp(self):
        """The np tag defaults to the sp tag value when not explicit"""
        dmarc_record = "v=DMARC1; p=reject; sp=quarantine"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["np"]["value"], "quarantine")
        self.assertFalse(result["tags"]["np"]["explicit"])

    def testRFC9989NpDefaultsToP(self):
        """The np tag defaults to the p tag value when sp is also absent"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["np"]["value"], "reject")
        self.assertFalse(result["tags"]["np"]["explicit"])

    def testRFC9989PsdDefaultsToU(self):
        """The psd tag defaults to u when not explicit"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["psd"]["value"], "u")
        self.assertFalse(result["tags"]["psd"]["explicit"])

    def testRFC9989TDefaultsToN(self):
        """The t tag defaults to n when not explicit"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["t"]["value"], "n")
        self.assertFalse(result["tags"]["t"]["explicit"])

    def testRFC9989RemovedTagImplicitNoWarning(self):
        """No warning is issued for implicit (default) removed tags"""
        dmarc_record = "v=DMARC1; p=reject"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        removed_warnings = [w for w in result["warnings"] if "removed in RFC 9989" in w]
        self.assertEqual(len(removed_warnings), 0)

    def testRFC9989BackwardCompatibility(self):
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

    def testRFC9989TreeWalkDiscovery(self):
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

    def testDMARCUnknownTagIgnored(self):
        """RFC 9989: unknown tags MUST be ignored (with a warning)"""
        dmarc_record = "v=DMARC1; p=reject; xyz=foo"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, "example.com")
        self.assertNotIn("xyz", result["tags"])
        self.assertTrue(any("Unknown DMARC tag 'xyz'" in w for w in result["warnings"]))

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

    def testDMARCPctRemovedNotValidated(self):
        """pct values that would have been rejected pre-9989 now just warn"""
        for value in ("0", "150", "-1", "abc"):
            dmarc_record = f"v=DMARC1; p=reject; pct={value}"
            result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, "example.com")
            self.assertNotIn("pct", result["tags"])
            self.assertTrue(
                any("pct tag was removed in RFC 9989" in w for w in result["warnings"]),
                f"expected removed-tag warning for pct={value}",
            )

    def testDMARCRiRemovedNotValidated(self):
        """ri values that would have been rejected pre-9989 now just warn"""
        dmarc_record = "v=DMARC1; p=reject; ri=abc"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, "example.com")
        self.assertNotIn("ri", result["tags"])
        self.assertTrue(
            any("ri tag was removed in RFC 9989" in w for w in result["warnings"])
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

    def testDMARCRfRemovedNotValidated(self):
        """rf values that would have been rejected pre-9989 now just warn"""
        dmarc_record = "v=DMARC1; p=reject; rf=invalid"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, "example.com")
        self.assertNotIn("rf", result["tags"])
        self.assertTrue(
            any("rf tag was removed in RFC 9989" in w for w in result["warnings"])
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

    def testDMARCPTagPositionWarns(self):
        """p not immediately after v: RFC 9989 allows it but older readers may not"""
        dmarc_record = "v=DMARC1; sp=none; p=reject"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, "example.com")
        self.assertEqual(result["tags"]["p"]["value"], "reject")
        self.assertTrue(
            any(
                "p tag does not immediately follow the v tag" in w
                for w in result["warnings"]
            )
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
        details = checkdmarc.dmarc.get_dmarc_tag_description("adkim")
        self.assertEqual(details["default"], "r")

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

    def testDMARCTreeWalkIncludesTLD(self):
        """RFC 9989 tree walk includes single-label parents (PSDs publish there)"""
        with patch("checkdmarc.dmarc._query_dmarc_record") as mock_query:
            with patch("checkdmarc.dmarc.query_dns") as mock_root_dns:
                mock_root_dns.return_value = []
                # All queries return None — should walk all the way to the TLD
                mock_query.return_value = None
                self.assertRaises(
                    checkdmarc.dmarc.DMARCRecordNotFound,
                    checkdmarc.dmarc.query_dmarc_record,
                    "sub.example.com",
                )
                queried_domains = [c.args[0] for c in mock_query.call_args_list]
                # sub.example.com (initial), example.com (walk), com (walk to TLD)
                self.assertIn("com", queried_domains)
                self.assertIn("example.com", queried_domains)

    def testDMARCTreeWalkSkipsApexFallback(self):
        """Tree-walk parent queries call _query_dmarc_record with apex_fallback=False"""
        with patch("checkdmarc.dmarc._query_dmarc_record") as mock_query:
            with patch("checkdmarc.dmarc.query_dns", return_value=[]):
                mock_query.return_value = None
                self.assertRaises(
                    checkdmarc.dmarc.DMARCRecordNotFound,
                    checkdmarc.dmarc.query_dmarc_record,
                    "sub.example.com",
                )
        # The first call (original domain) uses the default apex_fallback=True;
        # subsequent walk calls must pass apex_fallback=False.
        walk_calls = mock_query.call_args_list[1:]
        for call in walk_calls:
            self.assertEqual(call.kwargs.get("apex_fallback"), False)

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


class TestQueryDmarcRecordEdges(unittest.TestCase):
    """_query_dmarc_record apex fallback and exception branches"""

    def testApexFallbackWrongLocation(self):
        """A v=DMARC1 record at the apex (no record at _dmarc) raises DMARCRecordInWrongLocation"""

        def fake_query_dns(target, rdtype, **kwargs):
            if target.startswith("_dmarc."):
                raise dns.resolver.NoAnswer()
            return ["v=DMARC1; p=reject"]

        with patch("checkdmarc.dmarc.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.dmarc.DMARCRecordInWrongLocation,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )

    def testApexFallbackNoAnswer(self):
        """NoAnswer at both _dmarc and apex returns None (record not found)"""

        with patch("checkdmarc.dmarc.query_dns", side_effect=dns.resolver.NoAnswer()):
            result = checkdmarc.dmarc._query_dmarc_record("example.com")
        self.assertIsNone(result)

    def testApexFallbackNXDOMAIN(self):
        """NoAnswer at _dmarc, then NXDOMAIN at apex raises DMARCRecordNotFound"""

        def fake_query_dns(target, rdtype, **kwargs):
            if target.startswith("_dmarc."):
                raise dns.resolver.NoAnswer()
            raise dns.resolver.NXDOMAIN()

        with patch("checkdmarc.dmarc.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.dmarc.DMARCRecordNotFound,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )

    def testApexFallbackGenericException(self):
        """NoAnswer at _dmarc, then a generic Exception at apex raises DMARCRecordNotFound"""

        def fake_query_dns(target, rdtype, **kwargs):
            if target.startswith("_dmarc."):
                raise dns.resolver.NoAnswer()
            raise RuntimeError("oops")

        with patch("checkdmarc.dmarc.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.dmarc.DMARCRecordNotFound,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )

    def testGenericExceptionAtSelectorWraps(self):
        """A non-DNS, non-DMARC exception at the selector wraps as DMARCError"""

        with patch("checkdmarc.dmarc.query_dns", side_effect=RuntimeError("oops")):
            self.assertRaises(
                checkdmarc.dmarc.DMARCError,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )


class TestQueryDmarcRecordTreeWalk(unittest.TestCase):
    """query_dmarc_record DNS tree walk branches"""

    def testWalkSucceedsAtParent(self):
        """If the subdomain has no record, the walk finds one at the parent"""
        with patch("checkdmarc.dmarc._query_dmarc_record") as mock_query:
            with patch("checkdmarc.dmarc.query_dns", return_value=[]):
                mock_query.side_effect = [
                    None,  # sub.example.com
                    "v=DMARC1; p=reject",  # example.com
                ]
                result = checkdmarc.dmarc.query_dmarc_record("sub.example.com")
        self.assertEqual(result["location"], "example.com")

    def testWalkContinuesPastDMARCRecordNotFound(self):
        """A DMARCRecordNotFound at one parent doesn't stop the walk."""
        with patch("checkdmarc.dmarc._query_dmarc_record") as mock_query:
            with patch("checkdmarc.dmarc.query_dns", return_value=[]):
                mock_query.side_effect = [
                    None,  # original
                    checkdmarc.dmarc.DMARCRecordNotFound("nope"),  # first parent
                    "v=DMARC1; p=reject",  # second parent
                ]
                result = checkdmarc.dmarc.query_dmarc_record("a.b.example.com")
        self.assertIsNotNone(result["record"])

    def testWalkReraisesDMARCError(self):
        """A non-NotFound DMARCError during tree walk propagates"""
        with patch("checkdmarc.dmarc._query_dmarc_record") as mock_query:
            with patch("checkdmarc.dmarc.query_dns", return_value=[]):
                mock_query.side_effect = [
                    None,  # original
                    checkdmarc.dmarc.MultipleDMARCRecords("multiple at parent"),
                ]
                self.assertRaises(
                    checkdmarc.dmarc.MultipleDMARCRecords,
                    checkdmarc.dmarc.query_dmarc_record,
                    "sub.example.com",
                )

    def testRootRecordsNXDOMAINRaises(self):
        """An NXDOMAIN looking up the apex TXT records raises DMARCRecordNotFound"""

        def fake_query_dns(target, rdtype, **kwargs):
            raise dns.resolver.NXDOMAIN()

        with patch("checkdmarc.dmarc._query_dmarc_record", return_value=None):
            with patch("checkdmarc.dmarc.query_dns", side_effect=fake_query_dns):
                self.assertRaises(
                    checkdmarc.dmarc.DMARCRecordNotFound,
                    checkdmarc.dmarc.query_dmarc_record,
                    "example.com",
                )

    def testShortDomainNotFoundErrorString(self):
        """A 2-label not-found error has the short message"""
        with patch("checkdmarc.dmarc._query_dmarc_record", return_value=None):
            with patch("checkdmarc.dmarc.query_dns", return_value=[]):
                with self.assertRaises(checkdmarc.dmarc.DMARCRecordNotFound) as ctx:
                    checkdmarc.dmarc.query_dmarc_record("example.com")
        # Short domain: message ends with "exist."
        self.assertTrue(str(ctx.exception).endswith("exist."))

    def testLongDomainNotFoundErrorString(self):
        """A multi-label not-found error has the parent-walk message"""
        with patch("checkdmarc.dmarc._query_dmarc_record", return_value=None):
            with patch("checkdmarc.dmarc.query_dns", return_value=[]):
                with self.assertRaises(checkdmarc.dmarc.DMARCRecordNotFound) as ctx:
                    checkdmarc.dmarc.query_dmarc_record("sub.example.com")
        self.assertIn("parent domains", str(ctx.exception))


class TestCheckWildcardDmarcReportAuthorization(unittest.TestCase):
    def testWildcardFound(self):
        with patch("checkdmarc.dmarc.query_dns", return_value=["v=DMARC1"]):
            self.assertTrue(
                checkdmarc.dmarc.check_wildcard_dmarc_report_authorization(
                    "example.com"
                )
            )

    def testNoWildcardReturnsFalse(self):
        with patch("checkdmarc.dmarc.query_dns", return_value=[]):
            self.assertFalse(
                checkdmarc.dmarc.check_wildcard_dmarc_report_authorization(
                    "example.com"
                )
            )

    def testUnrelatedRecordRaises(self):
        with patch(
            "checkdmarc.dmarc.query_dns",
            return_value=["v=DMARC1", "some other txt"],
        ):
            self.assertRaises(
                checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC,
                checkdmarc.dmarc.check_wildcard_dmarc_report_authorization,
                "example.com",
            )

    def testUnrelatedRecordIgnored(self):
        with patch(
            "checkdmarc.dmarc.query_dns",
            return_value=["v=DMARC1", "some other txt"],
        ):
            self.assertTrue(
                checkdmarc.dmarc.check_wildcard_dmarc_report_authorization(
                    "example.com", ignore_unrelated_records=True
                )
            )

    def testDnsExceptionReturnsFalse(self):
        with patch("checkdmarc.dmarc.query_dns", side_effect=dns.resolver.NoAnswer()):
            self.assertFalse(
                checkdmarc.dmarc.check_wildcard_dmarc_report_authorization(
                    "example.com"
                )
            )


class TestVerifyDmarcReportDestination(unittest.TestCase):
    def testSameBaseDomainReturnsSilently(self):
        """If source and destination share a base domain, no verification needed"""
        with patch("checkdmarc.dmarc.query_dns") as mock_dns:
            checkdmarc.dmarc.verify_dmarc_report_destination(
                "example.com", "example.com"
            )
        mock_dns.assert_not_called()

    def testWildcardAuthorizationShortCircuits(self):
        """A wildcard at the destination satisfies the check without per-source lookup"""
        with patch(
            "checkdmarc.dmarc.check_wildcard_dmarc_report_authorization",
            return_value=True,
        ):
            checkdmarc.dmarc.verify_dmarc_report_destination(
                "example.com", "other.example.org"
            )

    def testSpecificAuthorizationRecordFound(self):
        """A specific source._report._dmarc.dest record satisfies the check"""
        with patch(
            "checkdmarc.dmarc.check_wildcard_dmarc_report_authorization",
            return_value=False,
        ):
            with patch("checkdmarc.dmarc.query_dns", return_value=["v=DMARC1"]):
                # No exception => verification passed
                checkdmarc.dmarc.verify_dmarc_report_destination(
                    "example.com", "other.example.org"
                )

    def testNoAuthorizationRecordRaises(self):
        """Missing authorization record raises UnverifiedDMARCURIDestination"""
        with patch(
            "checkdmarc.dmarc.check_wildcard_dmarc_report_authorization",
            return_value=False,
        ):
            with patch("checkdmarc.dmarc.query_dns", return_value=[]):
                self.assertRaises(
                    checkdmarc.dmarc.UnverifiedDMARCURIDestination,
                    checkdmarc.dmarc.verify_dmarc_report_destination,
                    "example.com",
                    "other.example.org",
                )

    def testUnrelatedRecordsBecomeUnverifiedDestination(self):
        """Unrelated TXT records at the authorization location are wrapped in the catch-all"""
        with patch(
            "checkdmarc.dmarc.check_wildcard_dmarc_report_authorization",
            return_value=False,
        ):
            with patch(
                "checkdmarc.dmarc.query_dns",
                return_value=["v=DMARC1", "unrelated txt"],
            ):
                # The unrelated-records branch raises UnrelatedTXTRecordFoundAtDMARC,
                # which is then caught by the broad `except Exception` and re-raised
                # as UnverifiedDMARCURIDestination.
                self.assertRaises(
                    checkdmarc.dmarc.UnverifiedDMARCURIDestination,
                    checkdmarc.dmarc.verify_dmarc_report_destination,
                    "example.com",
                    "other.example.org",
                )


class TestParseDmarcRecordReportBranches(unittest.TestCase):
    """Branches in parse_dmarc_record's rua/ruf handling"""

    def testRuaSizeLimitWarning(self):
        with patch(
            "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
        ):
            with patch(
                "checkdmarc.dmarc.get_mx_records",
                return_value=[{"preference": 10, "hostname": "mx.example.com"}],
            ):
                result = checkdmarc.dmarc.parse_dmarc_record(
                    "v=DMARC1; p=reject; rua=mailto:dmarc@example.com!10m",
                    "example.com",
                )
        self.assertTrue(
            any(
                "size limit (`!size`) on rua URI" in w and "obsolete in RFC 9989" in w
                for w in result["warnings"]
            )
        )

    def testRuaCrossDomainCallsVerify(self):
        """A rua= URI whose domain differs from the policy domain triggers verify_dmarc_report_destination"""
        with patch(
            "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
        ) as mock_verify:
            with patch(
                "checkdmarc.dmarc.get_mx_records",
                return_value=[{"preference": 10, "hostname": "mx.elsewhere.com"}],
            ):
                checkdmarc.dmarc.parse_dmarc_record(
                    "v=DMARC1; p=reject; rua=mailto:dmarc@elsewhere.com",
                    "example.com",
                )
        mock_verify.assert_called_once()

    def testRuaMissingMxWarning(self):
        """An rua= destination with no MX records produces a warning"""
        with patch(
            "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
        ):
            with patch("checkdmarc.dmarc.get_mx_records", return_value=[]):
                result = checkdmarc.dmarc.parse_dmarc_record(
                    "v=DMARC1; p=reject; rua=mailto:dmarc@elsewhere.com",
                    "example.com",
                )
        self.assertTrue(any("no MX records" in w for w in result["warnings"]))

    def testRuaMxLookupExceptionWarning(self):
        """A DNSException retrieving MX records becomes a warning"""
        from checkdmarc.utils import DNSException

        with patch(
            "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
        ):
            with patch(
                "checkdmarc.dmarc.get_mx_records",
                side_effect=DNSException("dns broken"),
            ):
                result = checkdmarc.dmarc.parse_dmarc_record(
                    "v=DMARC1; p=reject; rua=mailto:dmarc@elsewhere.com",
                    "example.com",
                )
        self.assertTrue(
            any("Failed to retrieve MX records" in w for w in result["warnings"])
        )

    def testManyRuaUrisWarning(self):
        """More than 2 rua URIs produce a best-practice warning"""
        rua_list = ",".join(f"mailto:dmarc{i}@example.com" for i in range(3))
        with patch(
            "checkdmarc.dmarc.get_mx_records",
            return_value=[{"preference": 10, "hostname": "mx.example.com"}],
        ):
            result = checkdmarc.dmarc.parse_dmarc_record(
                f"v=DMARC1; p=reject; rua={rua_list}",
                "example.com",
            )
        self.assertTrue(any("more than two rua URIs" in w for w in result["warnings"]))

    def testRufBranchesCovered(self):
        """ruf= triggers the same set of warnings as rua= when problematic"""
        from checkdmarc.utils import DNSException

        with patch(
            "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
        ):
            with patch(
                "checkdmarc.dmarc.get_mx_records",
                side_effect=DNSException("dns broken"),
            ):
                result = checkdmarc.dmarc.parse_dmarc_record(
                    "v=DMARC1; p=reject; "
                    "rua=mailto:dmarc@example.com; "
                    "ruf=mailto:forensic@elsewhere.com!5m",
                    "example.com",
                )
        # ruf produces both the size-limit warning and the missing-MX warning
        self.assertTrue(
            any(
                "size limit (`!size`) on ruf URI" in w and "obsolete in RFC 9989" in w
                for w in result["warnings"]
            )
        )
        self.assertTrue(any("ruf email address" in w for w in result["warnings"]))

    def testManyRufUrisWarning(self):
        """More than 2 ruf URIs produce a best-practice warning"""
        ruf_list = ",".join(f"mailto:forensic{i}@example.com" for i in range(3))
        with patch(
            "checkdmarc.dmarc.get_mx_records",
            return_value=[{"preference": 10, "hostname": "mx.example.com"}],
        ):
            result = checkdmarc.dmarc.parse_dmarc_record(
                f"v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf={ruf_list}",
                "example.com",
            )
        self.assertTrue(any("more than two ruf URIs" in w for w in result["warnings"]))


class TestGetDmarcRecord(unittest.TestCase):
    """get_dmarc_record both descriptions branches"""

    def testWithoutDescriptions(self):
        with patch(
            "checkdmarc.dmarc.query_dmarc_record",
            return_value={
                "record": "v=DMARC1; p=reject",
                "location": "example.com",
                "warnings": [],
            },
        ):
            result = checkdmarc.dmarc.get_dmarc_record("example.com")
        self.assertEqual(result["record"], "v=DMARC1; p=reject")
        self.assertEqual(result["location"], "example.com")
        self.assertIn("parsed", result)

    def testWithDescriptions(self):
        with patch(
            "checkdmarc.dmarc.query_dmarc_record",
            return_value={
                "record": "v=DMARC1; p=reject",
                "location": "example.com",
                "warnings": [],
            },
        ):
            result = checkdmarc.dmarc.get_dmarc_record(
                "example.com", include_tag_descriptions=True
            )
        for tag in result["parsed"]["tags"]:
            self.assertIn("description", result["parsed"]["tags"][tag])


class TestCheckDmarcErrorWithTarget(unittest.TestCase):
    def testErrorDataTargetFlattened(self):
        """An UnrelatedTXTRecordFoundAtDMARC with data['target'] is flattened onto the result"""
        with patch(
            "checkdmarc.dmarc.query_dmarc_record",
            return_value={
                "record": "v=DMARC1; p=reject",
                "location": "example.com",
                "warnings": [],
            },
        ):
            err = checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC(
                "unrelated at apex",
                data={"target": "_dmarc.example.com"},
            )
            with patch("checkdmarc.dmarc.parse_dmarc_record", side_effect=err):
                result = checkdmarc.dmarc.check_dmarc("example.com")
        self.assertFalse(result["valid"])
        # target key flattened from error.data
        self.assertEqual(cast(Any, result)["target"], "_dmarc.example.com")


if __name__ == "__main__":
    unittest.main(verbosity=2)
