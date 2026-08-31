"""Tests for checkdmarc.dmarc"""

import unittest
from typing import Any, cast
from unittest.mock import patch

import dns.exception
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
        with (
            patch("checkdmarc.dmarc._query_dmarc_record") as mock_query,
            patch("checkdmarc.dmarc.query_dns") as mock_root_dns,
        ):
            mock_root_dns.return_value = []
            # First call for sub.example.com returns None
            # Walk: example.com returns a record, then the walk continues
            # to the TLD per RFC 9989 section 4.10 step 7
            mock_query.side_effect = [
                None,  # _dmarc.sub.example.com
                "v=DMARC1; p=reject",  # _dmarc.example.com
                None,  # _dmarc.com
            ]
            result = checkdmarc.dmarc.query_dmarc_record("sub.example.com")
            self.assertEqual(result["location"], "example.com")
            self.assertEqual(result["record"], "v=DMARC1; p=reject")

    def testDMARCBareVersionTagIsValid(self):
        """A bare v=DMARC1 record is valid per the RFC 9989 section 4.8
        ABNF (zero tags), with p defaulting to none"""
        for record in ("v=DMARC1", "v=DMARC1;"):
            result = checkdmarc.dmarc.parse_dmarc_record(record, "example.com")
            self.assertEqual(result["tags"]["p"]["value"], "none")
            self.assertFalse(result["tags"]["p"]["explicit"])

    def testDMARCVersionValueCaseSensitive(self):
        """The DMARC1 version value is case sensitive per RFC 9989
        section 4.7, so v=dmarc1 is a syntax error"""
        self.assertRaises(
            checkdmarc.dmarc.DMARCSyntaxError,
            checkdmarc.dmarc.parse_dmarc_record,
            "v=dmarc1; p=reject",
            "example.com",
        )

    def testDMARCPercentEncodedReportURI(self):
        """A percent-encoded mailto URI (mandatory encoding for commas per
        RFC 9989 section 4.8) parses instead of failing the grammar"""
        with patch(
            "checkdmarc.dmarc.get_mx_records",
            return_value=[{"preference": 10, "hostname": "mx.example.com"}],
        ):
            result = checkdmarc.dmarc.parse_dmarc_record(
                "v=DMARC1; p=none; rua=mailto:a%2Cb@example.com",
                "example.com",
            )
        rua = cast(Any, result["tags"]["rua"]["value"])
        self.assertEqual(rua[0]["scheme"], "mailto")
        self.assertEqual(rua[0]["address"], "a%2cb@example.com")

    def testDMARCLongUnknownTagIgnored(self):
        """An unknown tag name longer than five letters (1*ALPHA in the
        RFC 9989 section 4.8 ABNF) lexes and is ignored with a warning"""
        result = checkdmarc.dmarc.parse_dmarc_record(
            "v=DMARC1; p=reject; foobar=baz", "example.com"
        )
        self.assertNotIn("foobar", result["tags"])
        self.assertTrue(
            any("Unknown DMARC tag 'foobar'" in w for w in result["warnings"])
        )

    def testDMARCNonMailtoReportURIKeptWithWarning(self):
        """A non-mailto report URI is valid per RFC 9989 section 4.7; it is
        kept in the parsed output with a warning that mailto-only receivers
        will ignore it"""
        result = checkdmarc.dmarc.parse_dmarc_record(
            "v=DMARC1; p=none; rua=https://dmarc.example.com/submit",
            "example.com",
        )
        rua = cast(Any, result["tags"]["rua"]["value"])
        self.assertEqual(rua[0]["scheme"], "https")
        self.assertEqual(rua[0]["address"], "https://dmarc.example.com/submit")
        self.assertTrue(
            any("only required to support mailto" in w for w in result["warnings"])
        )

    def testDMARCParseNonMailtoReportURI(self):
        """parse_dmarc_report_uri returns the scheme and full URI for a
        non-mailto URI instead of raising"""
        uri = checkdmarc.dmarc.parse_dmarc_report_uri(
            "https://dmarc.example.com/submit"
        )
        self.assertEqual(uri["scheme"], "https")
        self.assertEqual(uri["address"], "https://dmarc.example.com/submit")
        self.assertIsNone(uri["size_limit"])

    def testDMARCReportURIFragmentRules(self):
        """RFC 3986 allows "#" exactly once, as the fragment delimiter, so
        a report URI with a second "#" is rejected while a single-fragment
        URI parses"""
        uri = checkdmarc.dmarc.parse_dmarc_report_uri(
            "https://dmarc.example.com/submit#reports"
        )
        self.assertEqual(uri["address"], "https://dmarc.example.com/submit#reports")
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCReportURI,
            checkdmarc.dmarc.parse_dmarc_report_uri,
            "https://dmarc.example.com/submit#one#two",
        )

    def testDMARCInvalidAlignmentModeFallsBack(self):
        """Invalid adkim/aspf values fall back to the default r with a
        warning, per the RFC 9989 section 4.8 discard rule"""
        result = checkdmarc.dmarc.parse_dmarc_record(
            "v=DMARC1; p=reject; adkim=x; aspf=q", "example.com"
        )
        self.assertEqual(result["tags"]["adkim"]["value"], "r")
        self.assertFalse(result["tags"]["adkim"]["explicit"])
        self.assertEqual(result["tags"]["aspf"]["value"], "r")
        self.assertFalse(result["tags"]["aspf"]["explicit"])
        self.assertTrue(
            any("not a valid adkim tag value" in w for w in result["warnings"])
        )
        self.assertTrue(
            any("not a valid aspf tag value" in w for w in result["warnings"])
        )

    def testDMARCValidAlignmentModesAccepted(self):
        """Valid adkim/aspf values (r and s) are kept as-is"""
        result = checkdmarc.dmarc.parse_dmarc_record(
            "v=DMARC1; p=reject; adkim=s; aspf=s", "example.com"
        )
        self.assertEqual(result["tags"]["adkim"]["value"], "s")
        self.assertEqual(result["tags"]["aspf"]["value"], "s")

    def testDMARCDNSFilterToleratesWhitespaceAndCase(self):
        """The DNS-stage filter accepts whitespace around = and an
        uppercase V, consistent with the parser and the RFC 9989
        section 4.8 ABNF"""
        for record in ("v = DMARC1; p=reject", "V=DMARC1; p=reject"):
            with patch("checkdmarc.dmarc.query_dns", return_value=[record]):
                result = checkdmarc.dmarc._query_dmarc_record("example.com")
            self.assertEqual(result, record)

    def testDMARCDNSFilterRejectsWrongVersionValue(self):
        """A record with a case-mangled or extended version value is not a
        DMARC record and is treated as unrelated"""
        for record in ("v=dmarc1; p=reject", "v=DMARC10; p=reject"):
            with patch("checkdmarc.dmarc.query_dns", return_value=[record]):
                self.assertRaises(
                    checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC,
                    checkdmarc.dmarc._query_dmarc_record,
                    "example.com",
                )

    def testDMARCApexNXDOMAINKeepsFoundRecord(self):
        """An NXDOMAIN on the courtesy apex TXT query does not discard a
        DMARC record that was already found at _dmarc"""
        with (
            patch(
                "checkdmarc.dmarc._query_dmarc_record",
                return_value="v=DMARC1; p=reject",
            ),
            patch(
                "checkdmarc.dmarc.query_dns",
                side_effect=dns.resolver.NXDOMAIN(),
            ),
        ):
            result = checkdmarc.dmarc.query_dmarc_record("example.com")
        self.assertEqual(result["record"], "v=DMARC1; p=reject")
        self.assertEqual(result["location"], "example.com")

    def testDMARCGrammarSyntaxError(self):
        """A record the grammar cannot parse raises DMARCSyntaxError

        The message points at the offending position so the user can see
        where the record went wrong.
        """
        with self.assertRaises(checkdmarc.dmarc.DMARCSyntaxError) as ctx:
            checkdmarc.dmarc.parse_dmarc_record("v=DMARC1; p", "example.com")
        message = str(ctx.exception)
        self.assertIn("Expected", message)
        self.assertIn(checkdmarc.dmarc.SYNTAX_ERROR_MARKER, message)

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

    def testDMARCFoMutuallyExclusive(self):
        """fo=0:1 is invalid (0 and 1 are mutually exclusive per RFC 9989
        section 4.7) and falls back to the default fo=0 with a warning"""
        dmarc_record = "v=DMARC1; p=reject; fo=0:1"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["fo"]["value"], "0")
        self.assertFalse(result["tags"]["fo"]["explicit"])
        self.assertTrue(any("mutually exclusive" in w for w in result["warnings"]))

    def testDMARCFoDuplicateValues(self):
        """Duplicate fo values are invalid (RFC 9989 section 4.8 allows each
        value at most once) and fall back to the default fo=0 with a warning"""
        dmarc_record = "v=DMARC1; p=reject; fo=d:d"
        domain = "example.com"
        result = checkdmarc.dmarc.parse_dmarc_record(dmarc_record, domain)
        self.assertEqual(result["tags"]["fo"]["value"], "0")
        self.assertFalse(result["tags"]["fo"]["explicit"])
        self.assertTrue(any("at most once" in w for w in result["warnings"]))

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
        with (
            patch("checkdmarc.dmarc._query_dmarc_record") as mock_query,
            patch("checkdmarc.dmarc.query_dns") as mock_root_dns,
        ):
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
        with (
            patch("checkdmarc.dmarc._query_dmarc_record") as mock_query,
            patch("checkdmarc.dmarc.query_dns", return_value=[]),
        ):
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
        with (
            patch("checkdmarc.dmarc._query_dmarc_record") as mock_query,
            patch("checkdmarc.dmarc.query_dns") as mock_root_dns,
        ):
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
        with (
            patch("checkdmarc.dmarc._query_dmarc_record") as mock_query,
            patch("checkdmarc.dmarc.query_dns") as mock_dns,
        ):
            mock_query.return_value = "v=DMARC1; p=reject"
            mock_dns.return_value = ["v=DMARC1; p=reject"]
            result = checkdmarc.dmarc.query_dmarc_record("example.com")
            self.assertTrue(any("no effect" in w for w in result["warnings"]))


class TestReportUriRfc3986(unittest.TestCase):
    def testMalformedNonMailtoUriRejected(self):
        """A non-mailto value that is not an RFC 3986 URI (raw space) is an
        error, not preserved as a valid report URI"""
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCReportURI,
            checkdmarc.dmarc.parse_dmarc_report_uri,
            "foo:bad space",
        )

    def testMalformedPercentEscapeRejected(self):
        """A URI with a malformed percent-escape is not a valid RFC 3986 URI"""
        self.assertRaises(
            checkdmarc.dmarc.InvalidDMARCReportURI,
            checkdmarc.dmarc.parse_dmarc_report_uri,
            "https://dmarc.example.com/%zz",
        )

    def testWellFormedHttpsUriKept(self):
        """A well-formed non-mailto URI is preserved (RFC 9989 section 4.7)"""
        result = checkdmarc.dmarc.parse_dmarc_report_uri(
            "https://dmarc.example.com/submit"
        )
        self.assertEqual(result["scheme"], "https")


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

    def testApexFallbackDNSException(self):
        """NoAnswer at _dmarc, then a DNS error at apex raises DMARCRecordNotFound"""

        def fake_query_dns(target, rdtype, **kwargs):
            if target.startswith("_dmarc."):
                raise dns.resolver.NoAnswer()
            raise dns.exception.DNSException("dns down")

        with patch("checkdmarc.dmarc.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.dmarc.DMARCRecordNotFound,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )

    def testDNSExceptionAtSelectorWraps(self):
        """A DNS error at the selector wraps as DMARCError"""

        with patch(
            "checkdmarc.dmarc.query_dns",
            side_effect=dns.exception.DNSException("dns down"),
        ):
            self.assertRaises(
                checkdmarc.dmarc.DMARCError,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )

    def testNonDNSExceptionAtSelectorPropagates(self):
        """A non-DNS error (e.g. a programming bug) at the selector is not masked"""

        with patch("checkdmarc.dmarc.query_dns", side_effect=RuntimeError("oops")):
            self.assertRaises(
                RuntimeError,
                checkdmarc.dmarc._query_dmarc_record,
                "example.com",
            )


class TestQueryDmarcRecordTreeWalk(unittest.TestCase):
    """query_dmarc_record DNS tree walk branches"""

    def testWalkSucceedsAtParent(self):
        """If the subdomain has no record, the walk finds one at the parent"""
        with (
            patch("checkdmarc.dmarc._query_dmarc_record") as mock_query,
            patch("checkdmarc.dmarc.query_dns", return_value=[]),
        ):
            mock_query.side_effect = [
                None,  # sub.example.com
                "v=DMARC1; p=reject",  # example.com
                None,  # com (the walk continues to the TLD)
            ]
            result = checkdmarc.dmarc.query_dmarc_record("sub.example.com")
        self.assertEqual(result["location"], "example.com")

    def testWalkContinuesPastDMARCRecordNotFound(self):
        """A DMARCRecordNotFound at one parent doesn't stop the walk."""
        with (
            patch("checkdmarc.dmarc._query_dmarc_record") as mock_query,
            patch("checkdmarc.dmarc.query_dns", return_value=[]),
        ):
            mock_query.side_effect = [
                None,  # original
                checkdmarc.dmarc.DMARCRecordNotFound("nope"),  # first parent
                "v=DMARC1; p=reject",  # second parent
                None,  # third parent (the walk continues to the TLD)
            ]
            result = checkdmarc.dmarc.query_dmarc_record("a.b.example.com")
        self.assertIsNotNone(result["record"])

    def testWalkReraisesDMARCError(self):
        """A non-NotFound DMARCError during tree walk propagates"""
        with (
            patch("checkdmarc.dmarc._query_dmarc_record") as mock_query,
            patch("checkdmarc.dmarc.query_dns", return_value=[]),
        ):
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

        with (
            patch("checkdmarc.dmarc._query_dmarc_record", return_value=None),
            patch("checkdmarc.dmarc.query_dns", side_effect=fake_query_dns),
        ):
            self.assertRaises(
                checkdmarc.dmarc.DMARCRecordNotFound,
                checkdmarc.dmarc.query_dmarc_record,
                "example.com",
            )

    def testShortDomainNotFoundErrorString(self):
        """A 2-label not-found error has the short message"""
        with (
            patch("checkdmarc.dmarc._query_dmarc_record", return_value=None),
            patch("checkdmarc.dmarc.query_dns", return_value=[]),
            self.assertRaises(checkdmarc.dmarc.DMARCRecordNotFound) as ctx,
        ):
            checkdmarc.dmarc.query_dmarc_record("example.com")
        # Short domain: message ends with "exist."
        self.assertTrue(str(ctx.exception).endswith("exist."))

    def testLongDomainNotFoundErrorString(self):
        """A multi-label not-found error has the parent-walk message"""
        with (
            patch("checkdmarc.dmarc._query_dmarc_record", return_value=None),
            patch("checkdmarc.dmarc.query_dns", return_value=[]),
            self.assertRaises(checkdmarc.dmarc.DMARCRecordNotFound) as ctx,
        ):
            checkdmarc.dmarc.query_dmarc_record("sub.example.com")
        self.assertIn("parent domains", str(ctx.exception))

    def testWalkAfterTransientApexError(self):
        """A transient DNS error on the apex queries doesn't stop the tree
        walk, and NoAnswer at a walked parent means no record there"""

        def fake_query_dns(target, rdtype, **kwargs):
            if target == "_dmarc.sub.example.com":
                raise dns.resolver.NoAnswer()
            if target == "sub.example.com":
                raise dns.exception.DNSException("timeout")
            if target == "_dmarc.example.com":
                return ["v=DMARC1; p=reject"]
            if target == "_dmarc.com":
                raise dns.resolver.NoAnswer()
            return []

        with patch("checkdmarc.dmarc.query_dns", side_effect=fake_query_dns):
            result = checkdmarc.dmarc.query_dmarc_record("sub.example.com")
        self.assertEqual(result["location"], "example.com")
        self.assertEqual(result["record"], "v=DMARC1; p=reject")


class TestTreeWalkOrganizationalDomainSelection(unittest.TestCase):
    """RFC 9989 section 4.10.2 Organizational Domain selection during the
    section 4.10 DNS tree walk, verified against the RFC's own worked
    examples for the starting domain a.mail.example.com"""

    @staticmethod
    def _fake_query_dns(answers):
        """Builds a query_dns replacement serving DMARC records from
        ``answers`` (keyed by _dmarc target name), NXDOMAIN for other
        _dmarc names, and an empty answer for apex TXT queries"""

        def fake_query_dns(target, rdtype, **kwargs):
            if target in answers:
                return answers[target]
            if target.startswith("_dmarc."):
                raise dns.resolver.NXDOMAIN()
            return []

        return fake_query_dns

    def testFewestLabelsSelected(self):
        """With records at both mail.example.com and example.com and no psd
        tags, the record at the name with the fewest labels is selected
        (the first worked example in RFC 9989 section 4.10.2)"""
        answers = {
            "_dmarc.mail.example.com": ["v=DMARC1; p=none"],
            "_dmarc.example.com": ["v=DMARC1; p=reject"],
        }
        with patch(
            "checkdmarc.dmarc.query_dns",
            side_effect=self._fake_query_dns(answers),
        ) as mock_dns:
            result = checkdmarc.dmarc.query_dmarc_record("a.mail.example.com")
        self.assertEqual(result["location"], "example.com")
        self.assertEqual(result["record"], "v=DMARC1; p=reject")
        # The walk must have continued to the TLD before selecting
        queried = [c.args[0] for c in mock_dns.call_args_list]
        self.assertIn("_dmarc.com", queried)

    def testPsdNStopsWalkAndWins(self):
        """A psd=n record marks the Organizational Domain and stops the
        walk (the second worked example in RFC 9989 section 4.10.2)"""
        answers = {
            "_dmarc.mail.example.com": ["v=DMARC1; p=quarantine; psd=n"],
            "_dmarc.example.com": ["v=DMARC1; p=reject"],
        }
        with patch(
            "checkdmarc.dmarc.query_dns",
            side_effect=self._fake_query_dns(answers),
        ) as mock_dns:
            result = checkdmarc.dmarc.query_dmarc_record("a.mail.example.com")
        self.assertEqual(result["location"], "mail.example.com")
        self.assertEqual(result["record"], "v=DMARC1; p=quarantine; psd=n")
        # The walk stops at the psd=n record (RFC 9989 section 4.10 step 6)
        queried = [c.args[0] for c in mock_dns.call_args_list]
        self.assertNotIn("_dmarc.example.com", queried)
        self.assertNotIn("_dmarc.com", queried)

    def testPsdYWithoutOrgRecordAppliesPsdRecord(self):
        """With only a psd=y record at the PSD, the Organizational Domain
        is one label below it and, having no record of its own, the PSD
        record applies (the third worked example in RFC 9989
        section 4.10.2)"""
        answers = {
            "_dmarc.com": ["v=DMARC1; p=reject; psd=y"],
        }
        with patch(
            "checkdmarc.dmarc.query_dns",
            side_effect=self._fake_query_dns(answers),
        ):
            result = checkdmarc.dmarc.query_dmarc_record("a.mail.example.com")
        self.assertEqual(result["location"], "com")
        self.assertEqual(result["record"], "v=DMARC1; p=reject; psd=y")
        self.assertTrue(
            any(
                "Organizational Domain" in w and "example.com" in w
                for w in result["warnings"]
            )
        )

    def testPsdYSelectsRecordOneLabelBelow(self):
        """A psd=y record puts the Organizational Domain one label below;
        the record found there is the one that applies"""
        answers = {
            "_dmarc.example.com": ["v=DMARC1; p=reject"],
            "_dmarc.com": ["v=DMARC1; p=none; psd=y"],
        }
        with patch(
            "checkdmarc.dmarc.query_dns",
            side_effect=self._fake_query_dns(answers),
        ):
            result = checkdmarc.dmarc.query_dmarc_record("a.mail.example.com")
        self.assertEqual(result["location"], "example.com")
        self.assertEqual(result["record"], "v=DMARC1; p=reject")


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
        with (
            patch(
                "checkdmarc.dmarc.check_wildcard_dmarc_report_authorization",
                return_value=False,
            ),
            patch("checkdmarc.dmarc.query_dns", return_value=["v=DMARC1"]),
        ):
            # No exception => verification passed
            checkdmarc.dmarc.verify_dmarc_report_destination(
                "example.com", "other.example.org"
            )

    def testNoAuthorizationRecordRaises(self):
        """Missing authorization record raises UnverifiedDMARCURIDestination"""
        with (
            patch(
                "checkdmarc.dmarc.check_wildcard_dmarc_report_authorization",
                return_value=False,
            ),
            patch("checkdmarc.dmarc.query_dns", return_value=[]),
        ):
            self.assertRaises(
                checkdmarc.dmarc.UnverifiedDMARCURIDestination,
                checkdmarc.dmarc.verify_dmarc_report_destination,
                "example.com",
                "other.example.org",
            )

    def testUnrelatedRecordsBesideAuthorizationDiscarded(self):
        """Unrelated TXT records beside a valid authorization record are
        discarded per RFC 9990 section 4 steps 6-8, so verification passes"""
        with (
            patch(
                "checkdmarc.dmarc.check_wildcard_dmarc_report_authorization",
                return_value=False,
            ),
            patch(
                "checkdmarc.dmarc.query_dns",
                return_value=["unrelated txt", "v=DMARC1"],
            ),
        ):
            # No exception => verification passed despite the unrelated record
            checkdmarc.dmarc.verify_dmarc_report_destination(
                "example.com", "other.example.org"
            )

    def testDnsErrorBecomesUnverifiedDestination(self):
        """A DNS failure querying the authorization record means the
        destination can't be confirmed"""
        with (
            patch(
                "checkdmarc.dmarc.check_wildcard_dmarc_report_authorization",
                return_value=False,
            ),
            patch(
                "checkdmarc.dmarc.query_dns",
                side_effect=dns.exception.DNSException("dns down"),
            ),
        ):
            self.assertRaises(
                checkdmarc.dmarc.UnverifiedDMARCURIDestination,
                checkdmarc.dmarc.verify_dmarc_report_destination,
                "example.com",
                "other.example.org",
            )

    def testOnlyUnrelatedRecordsRaisesNotFound(self):
        """Only unrelated TXT records at the authorization location means
        the authorization record was not found"""
        with (
            patch(
                "checkdmarc.dmarc.check_wildcard_dmarc_report_authorization",
                return_value=False,
            ),
            patch(
                "checkdmarc.dmarc.query_dns",
                return_value=["unrelated txt"],
            ),
        ):
            self.assertRaises(
                checkdmarc.dmarc.UnverifiedDMARCURIDestination,
                checkdmarc.dmarc.verify_dmarc_report_destination,
                "example.com",
                "other.example.org",
            )


class TestParseDmarcRecordReportBranches(unittest.TestCase):
    """Branches in parse_dmarc_record's rua/ruf handling"""

    def testRuaSizeLimitWarning(self):
        with (
            patch(
                "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
            ),
            patch(
                "checkdmarc.dmarc.get_mx_records",
                return_value=[{"preference": 10, "hostname": "mx.example.com"}],
            ),
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
        with (
            patch(
                "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
            ) as mock_verify,
            patch(
                "checkdmarc.dmarc.get_mx_records",
                return_value=[{"preference": 10, "hostname": "mx.elsewhere.com"}],
            ),
        ):
            checkdmarc.dmarc.parse_dmarc_record(
                "v=DMARC1; p=reject; rua=mailto:dmarc@elsewhere.com",
                "example.com",
            )
        mock_verify.assert_called_once()

    def testRuaMissingMxWarning(self):
        """An rua= destination with no MX records produces a warning"""
        with (
            patch(
                "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
            ),
            patch("checkdmarc.dmarc.get_mx_records", return_value=[]),
        ):
            result = checkdmarc.dmarc.parse_dmarc_record(
                "v=DMARC1; p=reject; rua=mailto:dmarc@elsewhere.com",
                "example.com",
            )
        self.assertTrue(any("no MX records" in w for w in result["warnings"]))

    def testRuaMxLookupExceptionWarning(self):
        """A DNSException retrieving MX records becomes a warning"""
        from checkdmarc.utils import DNSException

        with (
            patch(
                "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
            ),
            patch(
                "checkdmarc.dmarc.get_mx_records",
                side_effect=DNSException("dns broken"),
            ),
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

        with (
            patch(
                "checkdmarc.dmarc.verify_dmarc_report_destination", return_value=None
            ),
            patch(
                "checkdmarc.dmarc.get_mx_records",
                side_effect=DNSException("dns broken"),
            ),
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


class TestDmarcRecordNotFound(unittest.TestCase):
    def testMessageAndDataArePreserved(self):
        """DMARCRecordNotFound keeps its message and carries the data
        attribute its parent class defines. Its __init__ previously never
        called the parent constructor, so the message survived only through
        a CPython quirk and the data attribute did not exist at all."""
        error = checkdmarc.dmarc.DMARCRecordNotFound(
            "A DMARC record does not exist for this domain"
        )
        self.assertEqual(str(error), "A DMARC record does not exist for this domain")
        self.assertIsNone(error.data)

    def testTimeoutIsRounded(self):
        """A DNS timeout value is rounded to one decimal place in the
        DMARCRecordNotFound message"""
        error = checkdmarc.dmarc.DMARCRecordNotFound(
            dns.exception.Timeout(timeout=5.6789)
        )
        self.assertIn("5.7", str(error))
        self.assertNotIn("5.6789", str(error))


if __name__ == "__main__":
    unittest.main(verbosity=2)
