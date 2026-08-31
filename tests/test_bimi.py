"""Tests for checkdmarc.bimi"""

import os
import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import requests
from cryptography import x509

import checkdmarc.bimi

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"

network_test = unittest.skipIf(
    OFFLINE_MODE, "Real-network test skipped on GitHub Actions"
)
mocked_only = unittest.skipUnless(
    OFFLINE_MODE, "Mocked counterpart skipped locally; network test covers this"
)


VALID_SVG = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" '
    'baseProfile="tiny-ps" viewBox="0 0 64 64">'
    "<title>Example Brand</title>"
    "</svg>"
)


def _fake_response(content: bytes, *, raise_for_status_exc=None):
    """Build a MagicMock that quacks like a requests.Response."""
    resp = MagicMock()
    resp.content = content
    if raise_for_status_exc is None:
        resp.raise_for_status = MagicMock(return_value=None)
    else:
        resp.raise_for_status = MagicMock(side_effect=raise_for_status_exc)
    return resp


class Test(unittest.TestCase):
    @network_test
    def testBIMI(self):
        """Test BIMI checks"""
        domain = "chase.com"

        results = checkdmarc.bimi.check_bimi(domain)

        self.assertEqual(len(cast(Any, results)["warnings"]), 0)

    @mocked_only
    def testBIMIMocked(self):
        """check_bimi parses a no-logo record cleanly (mocked DNS)

        ``l=;`` is the BIMI declination form (issuer declares no logo),
        which exercises the parse path without triggering any HTTP fetches.
        """
        with (
            patch(
                "checkdmarc.bimi._query_bimi_record", side_effect=["v=BIMI1; l=;", None]
            ),
            patch("checkdmarc.bimi.query_dns", return_value=[]),
        ):
            results = checkdmarc.bimi.check_bimi("example.com")

        self.assertTrue(cast(Any, results)["valid"])
        self.assertEqual(len(cast(Any, results)["warnings"]), 0)


class TestBimiRecordAtRoot(unittest.TestCase):
    def testBimiRecordAtRootProducesWarning(self):
        """A BIMI record published at the domain root (instead of under
        <selector>._bimi) has no effect and produces a warning, matching the
        equivalent DMARC root-record check."""
        with (
            patch("checkdmarc.bimi._query_bimi_record", return_value="v=BIMI1; l=;"),
            patch("checkdmarc.bimi.query_dns", return_value=["v=BIMI1; l=;"]),
        ):
            result = checkdmarc.bimi.query_bimi_record("example.com")
        self.assertTrue(any("no effect" in w for w in result["warnings"]))


class TestLpsTag(unittest.TestCase):
    """parse_bimi_record handles the lps= tag (comma-separated local-parts)"""

    def testCommaSeparatedSelectors(self):
        result = checkdmarc.bimi.parse_bimi_record(
            "v=BIMI1; l=; lps=news,billing,support"
        )
        self.assertEqual(result["tags"]["lps"]["value"], ["news", "billing", "support"])

    def testSpacesAroundCommasAreStripped(self):
        result = checkdmarc.bimi.parse_bimi_record(
            "v=BIMI1; l=; lps=news, billing, support"
        )
        self.assertEqual(result["tags"]["lps"]["value"], ["news", "billing", "support"])

    def testSelectorsLowercased(self):
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; l=; lps=News,Billing")
        self.assertEqual(result["tags"]["lps"]["value"], ["news", "billing"])

    def testSelectorCharacters(self):
        """Per draft-bimi-14 § 4.3.14, local-part-text = ALPHA / DIGIT / '-' only"""
        result = checkdmarc.bimi.parse_bimi_record(
            "v=BIMI1; l=; lps=sales-team,help-desk,info123"
        )
        self.assertEqual(
            result["tags"]["lps"]["value"],
            ["sales-team", "help-desk", "info123"],
        )

    def testSingleSelector(self):
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; l=; lps=news")
        self.assertEqual(result["tags"]["lps"]["value"], ["news"])

    def testEmptyValueParsesToEmptyList(self):
        """lps= with no value means zero prefixes (the local-part always
        matches), so it parses to an empty list, not [""]"""
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; l=; lps=")
        self.assertEqual(result["tags"]["lps"]["value"], [])

    def testInvalidCharactersRejected(self):
        """Underscores and dots are not allowed in local-part-text"""
        self.assertRaises(
            checkdmarc.bimi.BIMISyntaxError,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=; lps=help_desk",
        )
        self.assertRaises(
            checkdmarc.bimi.BIMISyntaxError,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=; lps=info.support",
        )


class TestQueryBimiRecordPropagatesSpecificErrors(unittest.TestCase):
    """Regression coverage for the exception-handling fix in _query_bimi_record.

    Previously the broad ``except Exception`` clauses converted these specific
    BIMI subclasses into ``BIMIRecordNotFound`` (or swallowed them entirely),
    making them unreachable for callers.
    """

    def testMultipleRecordsPropagates(self):
        """Two v=BIMI1 records at the selector raise MultipleBIMIRecords (not BIMIRecordNotFound)"""
        with patch(
            "checkdmarc.bimi.query_dns",
            return_value=["v=BIMI1; l=https://a.example/a.svg", "v=BIMI1; l="],
        ):
            self.assertRaises(
                checkdmarc.bimi.MultipleBIMIRecords,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )

    def testUnrelatedRecordDiscardedWithWarning(self):
        """A v=BIMI1 record beside an unrelated TXT record is still used;
        the unrelated record is discarded with a warning, per section 7.2
        step 4 of the BIMI draft (non-BIMI records must be discarded)."""
        warnings = []
        with patch(
            "checkdmarc.bimi.query_dns",
            return_value=["some other txt record", "v=BIMI1; l="],
        ):
            record = checkdmarc.bimi._query_bimi_record(
                "example.com", warnings=warnings
            )
        self.assertEqual(record, "v=BIMI1; l=")
        self.assertTrue(any("Unrelated TXT records" in w for w in warnings))

    def testWrongLocationPropagates(self):
        """A v=BIMI1 record at the apex (not at the selector) raises BIMIRecordInWrongLocation.

        The selector returns NoAnswer, so the apex fallback runs and discovers
        the record there. Before the fix, the missing ``raise`` keyword caused
        this exception to be silently swallowed and the function returned None.
        """

        def fake_query_dns(target, rdtype, **kwargs):
            if target == "default._bimi.example.com":
                raise dns.resolver.NoAnswer()
            if target == "example.com":
                return ["v=BIMI1; l="]
            return []

        with patch("checkdmarc.bimi.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.bimi.BIMIRecordInWrongLocation,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )

    def testDNSExceptionConvertsToNotFound(self):
        """A DNS-layer error is wrapped as BIMIRecordNotFound"""
        with patch(
            "checkdmarc.bimi.query_dns",
            side_effect=dns.exception.DNSException("network down"),
        ):
            self.assertRaises(
                checkdmarc.bimi.BIMIRecordNotFound,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )

    def testNonDNSExceptionPropagates(self):
        """A non-DNS error (e.g. a programming bug) is not masked as BIMIRecordNotFound"""
        with patch(
            "checkdmarc.bimi.query_dns", side_effect=RuntimeError("network down")
        ):
            self.assertRaises(
                RuntimeError,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )

    def testApexGenericExceptionConvertsToNotFound(self):
        """In the apex-fallback path, non-BIMI exceptions also wrap as BIMIRecordNotFound.

        Before the fix, the apex-fallback exception clause was missing ``raise``,
        so this exception was silently dropped and the function returned None.
        """

        def fake_query_dns(target, rdtype, **kwargs):
            if target == "default._bimi.example.com":
                raise dns.resolver.NoAnswer()
            raise dns.exception.DNSException("network down")

        with patch("checkdmarc.bimi.query_dns", side_effect=fake_query_dns):
            self.assertRaises(
                checkdmarc.bimi.BIMIRecordNotFound,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )


class TestGetSvgMetadata(unittest.TestCase):
    def testValidSvg(self):
        metadata = checkdmarc.bimi.get_svg_metadata(VALID_SVG)
        self.assertEqual(metadata["svg_version"], "1.2")
        self.assertEqual(metadata["base_profile"], "tiny-ps")
        self.assertEqual(metadata["title"], "Example Brand")
        self.assertEqual(metadata["width"], 64.0)
        self.assertEqual(metadata["height"], 64.0)
        self.assertIn("sha256", metadata)

    def testValidSvgBytes(self):
        """Bytes input is decoded transparently"""
        metadata = checkdmarc.bimi.get_svg_metadata(VALID_SVG.encode("utf-8"))
        self.assertEqual(metadata["svg_version"], "1.2")

    def testInvalidSvgRaisesValueError(self):
        self.assertRaises(ValueError, checkdmarc.bimi.get_svg_metadata, "not an svg")

    def testFilesizeMeasuresRawBytes(self):
        """filesize reports the byte length of the file as served, which is
        what counts against the SVG Tiny PS 32 KB cap — not the Python
        object size of a decoded string."""
        padded = (VALID_SVG + " " * (24114 - len(VALID_SVG))).encode("utf-8")
        self.assertEqual(len(padded), 24114)
        metadata = checkdmarc.bimi.get_svg_metadata(padded)
        self.assertEqual(metadata["filesize"], "24.114 KB")

    def testSha256HashesRawBytes(self):
        """sha256 is computed over the raw response bytes, so it can be
        compared byte for byte against the certificate's embedded logotype
        hash. Multibyte UTF-8 must be hashed as served, not re-encoded."""
        import hashlib

        svg_bytes = VALID_SVG.replace("Example Brand", "Exämple Bränd").encode("utf-8")
        metadata = checkdmarc.bimi.get_svg_metadata(svg_bytes)
        self.assertEqual(metadata["sha256"], hashlib.sha256(svg_bytes).hexdigest())

    def testMalformedBytesAreNotSanitized(self):
        """The exact bytes that get hashed are the bytes that must validate
        as XML: a byte no decode could keep must fail parsing instead of
        being silently dropped so that a sanitized document validates while
        the hash describes the unsanitized file"""
        svg_bytes = VALID_SVG.encode("utf-8").replace(b"<title>", b"<!--\xff--><title>")
        self.assertRaises(ValueError, checkdmarc.bimi.get_svg_metadata, svg_bytes)

    def testUtf16SvgParses(self):
        """The XML parser reads the declared encoding from the raw bytes, so
        a UTF-16 SVG parses instead of being garbled by a forced UTF-8
        decode"""
        svg_bytes = (
            '<?xml version="1.0" encoding="utf-16"?>' + VALID_SVG.split("?>", 1)[1]
        ).encode("utf-16")
        metadata = checkdmarc.bimi.get_svg_metadata(svg_bytes)
        self.assertEqual(metadata["svg_version"], "1.2")


class TestCheckSvgRequirements(unittest.TestCase):
    @staticmethod
    def _base_metadata(**overrides):
        meta = {
            "svg_version": "1.2",
            "base_profile": "tiny-ps",
            "title": "Brand",
            "filesize": "5.0 KB",
        }
        meta.update(overrides)
        return meta

    def testValid(self):
        errors = checkdmarc.bimi.check_svg_requirements(self._base_metadata())
        self.assertEqual(errors, [])

    def testWrongVersion(self):
        errors = checkdmarc.bimi.check_svg_requirements(
            self._base_metadata(svg_version="1.1")
        )
        self.assertTrue(any("SVG version must be 1.2" in e for e in errors))

    def testMissingBaseProfile(self):
        meta = self._base_metadata()
        del meta["base_profile"]
        errors = checkdmarc.bimi.check_svg_requirements(meta)
        self.assertTrue(any("missing a base profile" in e for e in errors))

    def testWrongBaseProfile(self):
        errors = checkdmarc.bimi.check_svg_requirements(
            self._base_metadata(base_profile="full")
        )
        self.assertTrue(any("base profile must be tiny-ps" in e for e in errors))

    def testMissingTitle(self):
        meta = self._base_metadata()
        del meta["title"]
        errors = checkdmarc.bimi.check_svg_requirements(meta)
        self.assertTrue(any("must have a title element" in e for e in errors))

    def testForbiddenXYAttributes(self):
        errors = checkdmarc.bimi.check_svg_requirements(
            self._base_metadata(x="0", y="0")
        )
        self.assertEqual(sum("cannot include" in e for e in errors), 2)

    def testTooLarge(self):
        errors = checkdmarc.bimi.check_svg_requirements(
            self._base_metadata(filesize="64.0 KB")
        )
        self.assertTrue(any("32 KB" in e for e in errors))


class TestQueryBimiRecordSuccess(unittest.TestCase):
    def testRecordFound(self):
        with patch(
            "checkdmarc.bimi.query_dns",
            return_value=["v=BIMI1; l=https://example.com/logo.svg"],
        ):
            result = checkdmarc.bimi._query_bimi_record("example.com")
        self.assertEqual(result, "v=BIMI1; l=https://example.com/logo.svg")

    def testNoAnswerReturnsNone(self):
        """No TXT records at the selector or apex returns None (record not found)"""
        with patch("checkdmarc.bimi.query_dns", side_effect=dns.resolver.NoAnswer()):
            result = checkdmarc.bimi._query_bimi_record("example.com")
        self.assertIsNone(result)

    def testVersionTagWhitespaceTolerated(self):
        """Discovery recognizes a record with spaces around the '=' in the
        version tag; the ABNF (v *WSP "=" *WSP BIMI1) allows them, and the
        record grammar already accepts them."""
        with patch(
            "checkdmarc.bimi.query_dns",
            return_value=["v = BIMI1; l=;"],
        ):
            result = checkdmarc.bimi._query_bimi_record("example.com")
        self.assertEqual(result, "v = BIMI1; l=;")
        # The same record also parses
        parsed = checkdmarc.bimi.parse_bimi_record("v = BIMI1; l=;")
        self.assertIn("l", parsed["tags"])


class TestParseBimiRecord(unittest.TestCase):
    def testUnknownTagIgnoredWithWarning(self):
        """Unknown tags are ignored with a warning instead of failing the
        record, per section 4.3 of the BIMI draft ("unknown tags MUST be
        ignored"). Tag names longer than three characters must also lex."""
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; l=; a=; foo=bar")
        self.assertNotIn("foo", result["tags"])
        self.assertTrue(
            any("Unknown BIMI record tag foo" in w for w in result["warnings"])
        )
        # A tag name of any length is tolerated
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; l=; longtagname=value")
        self.assertTrue(
            any("Unknown BIMI record tag longtagname" in w for w in result["warnings"])
        )

    def testDuplicateTag(self):
        """Duplicate l= tags raise InvalidBIMITag"""
        self.assertRaises(
            checkdmarc.bimi.InvalidBIMITag,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=https://a.example/a.svg; l=https://b.example/b.svg",
        )

    def testSPFRecordRaises(self):
        self.assertRaises(
            checkdmarc.bimi.SPFRecordFoundWhereBIMIRecordShouldBe,
            checkdmarc.bimi.parse_bimi_record,
            "v=spf1 -all",
        )

    def testSyntaxError(self):
        self.assertRaises(
            checkdmarc.bimi.BIMISyntaxError,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1 garbage",
        )

    def testRawSpaceInLocationURIRejected(self):
        """A raw (unencoded) space is not legal in a URI, so an l= value
        containing one is rejected"""
        self.assertRaises(
            checkdmarc.bimi.InvalidBIMIIndicatorURI,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=https://a.example/my logo.svg",
        )

    def testUnencodedCommaInLocationURIRejected(self):
        """Commas within a URI must be percent-encoded per the bimi-uri
        definition in section 4.3 of the BIMI draft"""
        self.assertRaises(
            checkdmarc.bimi.InvalidBIMIIndicatorURI,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=https://a.example/logo,v2.svg",
        )

    def testUnencodedCommaInEvidenceURIRejected(self):
        """The same bimi-uri rules apply to the a= tag value"""
        self.assertRaises(
            checkdmarc.bimi.InvalidBIMITagValue,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=; a=https://a.example/evidence,1.pem",
        )

    def testNonHTTPSLocationURIRejected(self):
        """Only HTTPS is a supported transport for the l= tag"""
        self.assertRaises(
            checkdmarc.bimi.InvalidBIMIIndicatorURI,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=http://a.example/logo.svg",
        )

    def testPercentEncodedCommaInLocationURIAccepted(self):
        """A percent-encoded comma is fine"""
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(VALID_SVG.encode("utf-8"))
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://a.example/logo%2Cv2.svg"
            )
        self.assertIn("image", result)

    def testLogoFetchedAndParsed(self):
        """l= tag triggers an HTTP fetch and SVG metadata is included"""
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(VALID_SVG.encode("utf-8"))
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg"
            )
        self.assertIn("image", result)
        self.assertEqual(result["image"]["svg_version"], "1.2")

    def testLogoFetchFailure(self):
        """A failed l= fetch produces an image error entry, not a raised exception"""
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(
            b"", raise_for_status_exc=requests.exceptions.HTTPError("404 Not Found")
        )
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/missing.svg"
            )
        self.assertIn("error", result["image"])

    def testCertificateErrorPathDoesNotCrashHashCheck(self):
        """get_certificate_metadata's error path returns metadata without a
        logotype_sha256 key; the logotype comparison must not raise KeyError
        and must not report a false mismatch"""
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(VALID_SVG.encode("utf-8"))
        with (
            patch("checkdmarc.bimi.requests.Session", return_value=fake_session),
            patch(
                "checkdmarc.bimi.get_certificate_metadata",
                return_value={
                    "valid": False,
                    "validation_errors": ["could not process the certificate"],
                },
            ),
        ):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg; "
                "a=https://example.com/logo.pem"
            )
        self.assertIn("image", result)
        self.assertFalse(
            any("does not match" in w for w in result["warnings"]),
            result["warnings"],
        )

    def testUriMalformedPercentEscapeRejected(self):
        """A non-hex percent escape like %zz is not valid RFC 3986
        percent-encoding, so the l= URI is rejected"""
        self.assertRaises(
            checkdmarc.bimi.InvalidBIMIIndicatorURI,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=https://example.com/logo%zz.svg",
        )

    def testUriMultipleFragmentDelimitersRejected(self):
        """RFC 3986 allows "#" exactly once, as the fragment delimiter, so
        an l= URI with a second "#" is rejected"""
        self.assertRaises(
            checkdmarc.bimi.InvalidBIMIIndicatorURI,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=https://example.com/logo.svg#one#two",
        )

    def testLogoProcessingFailure(self):
        """A ValueError while parsing a fetched image produces an image error
        entry, not a raised exception"""
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(b"<svg/>")
        with (
            patch("checkdmarc.bimi.requests.Session", return_value=fake_session),
            patch(
                "checkdmarc.bimi.get_svg_metadata",
                side_effect=ValueError("bad XML"),
            ),
        ):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg"
            )
        self.assertIn("Failed to process BIMI image", result["image"]["error"])
        self.assertIn("bad XML", result["image"]["error"])

    def testCertificateFetchFailure(self):
        """A failed a= fetch produces a certificate error entry"""
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(
            b"",
            raise_for_status_exc=requests.exceptions.HTTPError("connection refused"),
        )
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=; a=https://example.com/cert.pem"
            )
        self.assertIn("error", result["certificate"])

    def testInvalidAvpValue(self):
        self.assertRaises(
            checkdmarc.bimi.BIMISyntaxError,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; l=; avp=bogus",
        )

    def testValidAvp(self):
        """avp=brand parses cleanly"""
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; l=; avp=brand")
        self.assertEqual(result["tags"]["avp"]["value"], "brand")

    def testInvalidDmarcWarning(self):
        """parsed_dmarc_record with valid=False adds a warning"""
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(VALID_SVG.encode("utf-8"))
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg",
                parsed_dmarc_record=cast(Any, {"valid": False}),
            )
        self.assertTrue(any("DMARC" in w for w in result["warnings"]))

    def testWeakDmarcPolicyWarning(self):
        """A valid DMARC record with p=none triggers warnings about policy"""
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(VALID_SVG.encode("utf-8"))
        dmarc = cast(
            Any,
            {
                "valid": True,
                "tags": {
                    "p": {"value": "none"},
                    "sp": {"value": "none"},
                    "pct": {"value": 50},
                },
            },
        )
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg",
                parsed_dmarc_record=dmarc,
            )
        # DMARC p and sp flag warnings; pct does not, because the pct=100
        # requirement only applies when p=quarantine (BIMI draft section
        # 7.1 step 9), and here p=none.
        self.assertTrue(any("DMARC policy" in w for w in result["warnings"]))
        self.assertTrue(any("subdomain policy" in w for w in result["warnings"]))
        self.assertFalse(any("pct tag" in w for w in result["warnings"]))

    def _parse_with_dmarc_policy(self, p, pct):
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(VALID_SVG.encode("utf-8"))
        dmarc = cast(
            Any,
            {
                "valid": True,
                "tags": {
                    "p": {"value": p},
                    "sp": {"value": p},
                    "pct": {"value": pct},
                },
            },
        )
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            return checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg",
                parsed_dmarc_record=dmarc,
            )

    def testPctWarningForQuarantineWithPartialPct(self):
        """p=quarantine with pct!=100 warns: BIMI draft section 7.1 step 9
        requires pct=100 when the policy is quarantine"""
        result = self._parse_with_dmarc_policy("quarantine", 50)
        self.assertTrue(any("pct tag" in w for w in result["warnings"]))

    def testNoPctWarningForReject(self):
        """p=reject satisfies BIMI regardless of pct; no pct warning"""
        result = self._parse_with_dmarc_policy("reject", 50)
        self.assertFalse(any("pct" in w for w in result["warnings"]))

    def testNoPctWarningForQuarantineWithFullPct(self):
        """p=quarantine with pct=100 satisfies BIMI; no pct warning"""
        result = self._parse_with_dmarc_policy("quarantine", 100)
        self.assertFalse(any("pct" in w for w in result["warnings"]))

    def testMissingLTagIsError(self):
        """A record without the l= tag is an error: l= is REQUIRED per
        section 4.3 of the BIMI draft, and declining to participate is
        expressed with an empty value (l=;) per section 4.3.1 — not by
        omitting the tag."""
        with self.assertRaises(checkdmarc.bimi.BIMISyntaxError) as ctx:
            checkdmarc.bimi.parse_bimi_record("v=BIMI1;")
        self.assertIn("required l tag", str(ctx.exception))

    def testMissingLTagMakesCheckBimiInvalid(self):
        """check_bimi reports a record without l= as invalid"""
        with (
            patch("checkdmarc.bimi._query_bimi_record", return_value="v=BIMI1;"),
            patch("checkdmarc.bimi.query_dns", return_value=[]),
        ):
            result = checkdmarc.bimi.check_bimi("example.com")
        self.assertFalse(cast(Any, result)["valid"])
        self.assertIn("required l tag", cast(Any, result)["error"])

    def testEmptyLogoTagSkipsDmarcPolicyWarnings(self):
        """An empty l tag declines to publish a logo, so DMARC policy
        warnings do not apply. The check previously compared the tag's dict
        to the empty string, which is always unequal, so the warnings fired
        anyway."""
        dmarc = cast(
            Any,
            {"valid": True, "tags": {"p": {"value": "none"}, "sp": {"value": "none"}}},
        )
        result = checkdmarc.bimi.parse_bimi_record(
            "v=BIMI1; l=;", parsed_dmarc_record=dmarc
        )
        self.assertFalse(any("DMARC" in w for w in result["warnings"]))

    def testWordMarkOidHasLabel(self):
        """The wordMark OID maps to its label. A trailing comma previously
        made the OID_LABELS key a one-element tuple, so a certificate's
        wordMark attribute was labeled with the raw dotted OID string."""
        oid = x509.ObjectIdentifier("1.3.6.1.4.1.53087.1.6")
        self.assertEqual(checkdmarc.bimi.OID_LABELS.get(oid), "wordMark")


class TestExtractLogoFromCertificate(unittest.TestCase):
    @staticmethod
    def _fake_cert():
        """Build a MagicMock that satisfies isinstance(x, x509.Certificate)."""
        from cryptography import x509

        return MagicMock(spec=x509.Certificate)

    def testNoLogotypeExtension(self):
        """A cert with no logotype extension returns None"""
        from cryptography.x509 import ExtensionNotFound

        cert = self._fake_cert()
        cert.extensions.get_extension_for_oid.side_effect = ExtensionNotFound(
            "no ext", MagicMock()
        )
        result = checkdmarc.bimi.extract_logo_from_certificate(cert)
        self.assertIsNone(result)

    def testNoDataMarkerInExtension(self):
        """An extension whose value contains no 'data:' marker returns None"""
        cert = self._fake_cert()
        ext = MagicMock()
        ext.value.value = b"\x00\x01\x02\x03 not a data uri"
        cert.extensions.get_extension_for_oid.return_value = ext
        result = checkdmarc.bimi.extract_logo_from_certificate(cert)
        self.assertIsNone(result)

    def testNoBase64Marker(self):
        """data: URI without ';base64,' returns None"""
        cert = self._fake_cert()
        ext = MagicMock()
        ext.value.value = b"\x00data:image/svg+xml,<svg/>"
        cert.extensions.get_extension_for_oid.return_value = ext
        result = checkdmarc.bimi.extract_logo_from_certificate(cert)
        self.assertIsNone(result)

    def testBase64SvgExtracted(self):
        """A base64 data URI with raw SVG content is decoded and returned"""
        import base64

        svg_bytes = VALID_SVG.encode("utf-8")
        b64 = base64.b64encode(svg_bytes).decode("ascii")
        cert = self._fake_cert()
        ext = MagicMock()
        ext.value.value = b"\x00data:image/svg+xml;base64," + b64.encode("ascii")
        cert.extensions.get_extension_for_oid.return_value = ext
        result = checkdmarc.bimi.extract_logo_from_certificate(cert)
        self.assertEqual(result, svg_bytes)


class TestCheckBimi(unittest.TestCase):
    def testRecordNotFoundError(self):
        with patch(
            "checkdmarc.bimi.query_bimi_record",
            side_effect=checkdmarc.bimi.BIMIRecordNotFound("nope"),
        ):
            result = checkdmarc.bimi.check_bimi("example.com")
        self.assertFalse(cast(Any, result)["valid"])
        self.assertIn("error", cast(Any, result))


class TestSvgMetadataForbiddenAttributes(unittest.TestCase):
    """SVG x/y attributes on the root <svg> are forbidden by BIMI; they
    should be captured in metadata so check_svg_requirements can flag them."""

    def testRootXYAttributesCaptured(self):
        svg = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" '
            'baseProfile="tiny-ps" viewBox="0 0 64 64" x="0" y="0">'
            "<title>Brand</title>"
            "</svg>"
        )
        metadata = checkdmarc.bimi.get_svg_metadata(svg)
        self.assertEqual(metadata["x"], "0")
        self.assertEqual(metadata["y"], "0")
        errors = checkdmarc.bimi.check_svg_requirements(metadata)
        self.assertTrue(any("cannot include x" in e for e in errors))
        self.assertTrue(any("cannot include y" in e for e in errors))


class TestExtractLogoFromPemBytes(unittest.TestCase):
    """extract_logo_from_certificate accepts a PEM bundle as bytes too"""

    def testBytesInputInspectsLeafCertificate(self):
        """When given bytes, extract_logo_from_certificate loads the PEM
        bundle and inspects the first certificate — PEM bundles list the
        leaf (end-entity) certificate first, followed by intermediates."""
        import base64

        from cryptography.x509 import ExtensionNotFound

        svg_bytes = VALID_SVG.encode("utf-8")
        b64 = base64.b64encode(svg_bytes).decode("ascii")
        leaf_ext = MagicMock()
        leaf_ext.value.value = b"\x00data:image/svg+xml;base64," + b64.encode("ascii")
        fake_certs = [MagicMock(), MagicMock()]
        # The leaf (first) cert carries the logotype; the intermediate does not
        fake_certs[0].extensions.get_extension_for_oid.return_value = leaf_ext
        fake_certs[1].extensions.get_extension_for_oid.side_effect = ExtensionNotFound(
            "no ext", MagicMock()
        )
        with patch(
            "checkdmarc.bimi.load_pem_x509_certificates",
            return_value=fake_certs,
        ):
            result = checkdmarc.bimi.extract_logo_from_certificate(b"-----PEM-----")
        self.assertEqual(result, svg_bytes)


class TestBIMIRecordNotFoundWithTimeout(unittest.TestCase):
    def testTimeoutKwargRounded(self):
        """Constructing BIMIRecordNotFound with a dns.exception.Timeout
        rounds the timeout kwarg in-place (line 441)."""
        timeout = dns.exception.Timeout(timeout=2.345678)
        # Construction should run the rounding side effect without raising
        checkdmarc.bimi.BIMIRecordNotFound(timeout)
        self.assertEqual(timeout.kwargs["timeout"], 2.3)


class TestQueryBimiRecordBaseDomainFallback(unittest.TestCase):
    """query_bimi_record's base-domain fallback when the subdomain has no record"""

    def testFallbackToBaseDomain(self):
        """If the subdomain has no record, the function retries at the base domain"""
        with (
            patch("checkdmarc.bimi._query_bimi_record") as mock_query,
            patch("checkdmarc.bimi.query_dns", return_value=[]),
        ):
            mock_query.side_effect = [
                None,  # sub.example.com (no record)
                "v=BIMI1; l=https://example.com/logo.svg",  # example.com
            ]
            result = checkdmarc.bimi.query_bimi_record("sub.example.com")
        self.assertEqual(result["location"], "example.com")

    def testApexNXDOMAINRaises(self):
        """NXDOMAIN on the apex TXT lookup raises BIMIRecordNotFound"""
        with (
            patch(
                "checkdmarc.bimi._query_bimi_record",
                return_value="v=BIMI1; l=",
            ),
            patch(
                "checkdmarc.bimi.query_dns",
                side_effect=dns.resolver.NXDOMAIN(),
            ),
        ):
            self.assertRaises(
                checkdmarc.bimi.BIMIRecordNotFound,
                checkdmarc.bimi.query_bimi_record,
                "example.com",
            )

    def testSubdomainWithoutBaseRecord(self):
        """A subdomain whose base domain also has no record yields a more
        descriptive BIMIRecordNotFound message."""
        with (
            patch("checkdmarc.bimi._query_bimi_record", return_value=None),
            patch("checkdmarc.bimi.query_dns", return_value=[]),
            self.assertRaises(checkdmarc.bimi.BIMIRecordNotFound) as ctx,
        ):
            checkdmarc.bimi.query_bimi_record("sub.example.com")
        self.assertIn("subdomain or its base domain", str(ctx.exception))

    def testFallbackKeepsCustomSelector(self):
        """The organizational-domain fallback keeps the caller's selector:
        per section 7.2 step 6 of the BIMI draft, a custom selector that
        does not exist falls back to <selector>._bimi.<org domain>, not to
        default._bimi.<org domain>."""
        queried = []

        def fake_query_dns(target, rdtype, **kwargs):
            queried.append(target)
            if target == "brand._bimi.sub.example.com":
                raise dns.resolver.NoAnswer()
            if target == "brand._bimi.example.com":
                return ["v=BIMI1; l=;"]
            return []

        with patch("checkdmarc.bimi.query_dns", side_effect=fake_query_dns):
            result = checkdmarc.bimi.query_bimi_record(
                "sub.example.com", selector="brand"
            )
        self.assertIn("brand._bimi.example.com", queried)
        self.assertNotIn("default._bimi.example.com", queried)
        self.assertEqual(result["location"], "example.com")
        self.assertEqual(result["record"], "v=BIMI1; l=;")

    def testOnlyUnrelatedRecordsFallBackToOrgDomain(self):
        """When the selector holds only unrelated TXT records, they are
        discarded with a warning and discovery continues to the
        organizational domain (BIMI draft section 7.2 steps 4 and 6)."""

        def fake_query_dns(target, rdtype, **kwargs):
            if target == "default._bimi.sub.example.com":
                return ["verification=token"]
            if target == "default._bimi.example.com":
                return ["v=BIMI1; l=;"]
            return []

        with patch("checkdmarc.bimi.query_dns", side_effect=fake_query_dns):
            result = checkdmarc.bimi.query_bimi_record("sub.example.com")
        self.assertEqual(result["location"], "example.com")
        self.assertEqual(result["record"], "v=BIMI1; l=;")
        self.assertTrue(any("Unrelated TXT records" in w for w in result["warnings"]))


class TestParseBimiRecordExtraBranches(unittest.TestCase):
    def testIncludeTagDescriptions(self):
        """include_tag_descriptions=True attaches name+description to each tag"""
        result = checkdmarc.bimi.parse_bimi_record(
            "v=BIMI1; l=;", include_tag_descriptions=True
        )
        for tag in result["tags"]:
            self.assertIn("name", result["tags"][tag])
            self.assertIn("description", result["tags"][tag])

    def testNonSquareSvgWarning(self):
        """An SVG with non-square dimensions produces a warning"""
        non_square = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" '
            'baseProfile="tiny-ps" viewBox="0 0 64 128">'
            "<title>Brand</title>"
            "</svg>"
        )
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(non_square.encode("utf-8"))
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg"
            )
        self.assertTrue(any("square" in w for w in result["warnings"]))

    def testGenericTitleWarning(self):
        """A placeholder title like 'Untitled' triggers the generic-title warning"""
        svg_with_generic_title = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" '
            'baseProfile="tiny-ps" viewBox="0 0 64 64">'
            "<title>Untitled</title>"
            "</svg>"
        )
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(
            svg_with_generic_title.encode("utf-8")
        )
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg"
            )
        self.assertTrue(any("template placeholder" in w for w in result["warnings"]))

    def testTitleAsDictExtractsText(self):
        """An SVG whose <title> has nested content (xmltodict yields dict)
        still extracts the title text for the placeholder check"""
        # xmltodict treats elements with attributes/children as dicts with
        # #text holding the text content.
        svg_dict_title = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<svg xmlns="http://www.w3.org/2000/svg" version="1.2" '
            'baseProfile="tiny-ps" viewBox="0 0 64 64">'
            '<title id="t1">untitled</title>'
            "</svg>"
        )
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(svg_dict_title.encode("utf-8"))
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg"
            )
        self.assertTrue(any("template placeholder" in w for w in result["warnings"]))

    def testSvgValidationErrorsAttached(self):
        """When the SVG fails check_svg_requirements, errors land on the image dict"""
        invalid_svg = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<svg xmlns="http://www.w3.org/2000/svg" version="1.0" '
            'viewBox="0 0 64 64">'
            "<title>Brand</title>"
            "</svg>"
        )
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(invalid_svg.encode("utf-8"))
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg"
            )
        self.assertIn("validation_errors", result["image"])

    def testValidCertHashMatchWarning(self):
        """When the l= image hash matches the cert's embedded logotype,
        the mismatch warning is NOT emitted"""
        svg_bytes = VALID_SVG.encode("utf-8")
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(svg_bytes)
        # The certificate metadata's logotype_sha256 matches the SVG's sha256
        import hashlib

        svg_sha = hashlib.sha256(svg_bytes).hexdigest()
        with (
            patch("checkdmarc.bimi.requests.Session", return_value=fake_session),
            patch(
                "checkdmarc.bimi.get_certificate_metadata",
                return_value={
                    "valid": True,
                    "logotype_sha256": svg_sha,
                },
            ),
        ):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg; "
                "a=https://example.com/cert.pem"
            )
        # No mismatch warning because the hashes match
        self.assertFalse(any("does not match" in w for w in result["warnings"]))

    def testHashMismatchWarning(self):
        """When the hash doesn't match, the mismatch warning is emitted"""
        svg_bytes = VALID_SVG.encode("utf-8")
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(svg_bytes)
        with (
            patch("checkdmarc.bimi.requests.Session", return_value=fake_session),
            patch(
                "checkdmarc.bimi.get_certificate_metadata",
                return_value={
                    "valid": True,
                    "logotype_sha256": "0" * 64,
                },
            ),
        ):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/logo.svg; "
                "a=https://example.com/cert.pem"
            )
        self.assertTrue(
            any(
                "does not match the image embedded in the certificate" in w
                for w in result["warnings"]
            )
        )

    def testTagOrderDoesNotAffectHashCheck(self):
        """The image-vs-certificate logotype hash comparison happens after
        all tags are read, so a= before l= behaves identically to l= before
        a= (tags other than v= may appear in any order per section 4.3 of
        the BIMI draft) and no spurious warnings fire."""
        import hashlib

        svg_bytes = VALID_SVG.encode("utf-8")
        svg_sha = hashlib.sha256(svg_bytes).hexdigest()

        def fake_get(url, timeout=None):
            if url.endswith(".svg"):
                return _fake_response(svg_bytes)
            return _fake_response(b"-----PEM-----")

        for record in (
            "v=BIMI1; a=https://example.com/cert.pem; l=https://example.com/logo.svg",
            "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/cert.pem",
        ):
            fake_session = MagicMock()
            fake_session.get.side_effect = fake_get
            with (
                patch("checkdmarc.bimi.requests.Session", return_value=fake_session),
                patch(
                    "checkdmarc.bimi.get_certificate_metadata",
                    return_value={"valid": True, "logotype_sha256": svg_sha},
                ),
            ):
                result = checkdmarc.bimi.parse_bimi_record(record)
            self.assertFalse(
                any("does not match" in w for w in result["warnings"]), record
            )
            self.assertFalse(
                any("will not display" in w for w in result["warnings"]), record
            )

    def testTagOrderDoesNotHideHashMismatch(self):
        """A real hash mismatch is detected even when a= appears before l="""
        svg_bytes = VALID_SVG.encode("utf-8")

        def fake_get(url, timeout=None):
            if url.endswith(".svg"):
                return _fake_response(svg_bytes)
            return _fake_response(b"-----PEM-----")

        fake_session = MagicMock()
        fake_session.get.side_effect = fake_get
        with (
            patch("checkdmarc.bimi.requests.Session", return_value=fake_session),
            patch(
                "checkdmarc.bimi.get_certificate_metadata",
                return_value={"valid": True, "logotype_sha256": "0" * 64},
            ),
        ):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; a=https://example.com/cert.pem; "
                "l=https://example.com/logo.svg"
            )
        self.assertTrue(
            any(
                "does not match the image embedded in the certificate" in w
                for w in result["warnings"]
            )
        )


# ============================================================
# VMC certificate metadata tests
# ============================================================
#
# These build a self-signed x509 certificate at runtime via the cryptography
# library and feed its PEM bytes to get_certificate_metadata. The verifier
# rejects every self-signed cert (no recognized CA chain), so all tests run
# through the VerificationError -> "not issued by a recognized MVA" branch
# regardless of what else they test. That's expected; the goal here is
# coverage of the surrounding validation logic (extensions, mark types,
# subject fields, time bounds).


def _build_cert(
    *,
    subject_attrs=None,
    san_dns=None,
    extensions=None,
    not_valid_before=None,
    not_valid_after=None,
    custom_oid_subject_attrs=None,
):
    """Build a self-signed x509 cert and return its PEM bytes."""
    from datetime import datetime, timedelta, timezone

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    name_attrs = []
    for label, value in subject_attrs or []:
        oid = getattr(NameOID, label, None)
        if oid is None:
            continue
        name_attrs.append(x509.NameAttribute(oid, value))
    for oid, value in custom_oid_subject_attrs or []:
        name_attrs.append(x509.NameAttribute(oid, value))

    subject = issuer = x509.Name(name_attrs)
    if not_valid_before is None:
        not_valid_before = datetime.now(timezone.utc) - timedelta(days=1)
    if not_valid_after is None:
        not_valid_after = datetime.now(timezone.utc) + timedelta(days=90)

    # Reuse a single key across tests to avoid the cost of generating a new
    # 2048-bit RSA key per cert.
    if not hasattr(_build_cert, "_key"):
        _build_cert._key = rsa.generate_private_key(  # type: ignore[attr-defined]
            public_exponent=65537, key_size=2048
        )
    key = _build_cert._key  # type: ignore[attr-defined]

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False,
        )
    for ext, critical in extensions or []:
        builder = builder.add_extension(ext, critical=critical)

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.PEM)


def _full_subject_attrs(mark_type="Registered Mark"):
    """Subject attributes covering all "All" required fields for a given mark type."""
    # NameOID labels that map cleanly to BIMI's "All" required fields
    name_attrs = [
        ("ORGANIZATION_NAME", "Example Corp"),
        ("STREET_ADDRESS", "123 Main St"),
        ("COUNTRY_NAME", "US"),
        ("BUSINESS_CATEGORY", "Private Organization"),
        ("SERIAL_NUMBER", "1234567"),
        ("JURISDICTION_COUNTRY_NAME", "US"),
        ("STATE_OR_PROVINCE_NAME", "CA"),  # satisfies either-or with locality
    ]
    # Custom OIDs: markType + per-mark-type required fields
    custom_attrs = [(checkdmarc.bimi.OID_MARK_TYPE, mark_type)]
    if mark_type in ("Registered Mark", "Modified Registered Mark"):
        custom_attrs.append(
            (checkdmarc.bimi.OID_TRADEMARK_COUNTRY_OR_REGION_NAME, "US")
        )
        custom_attrs.append((checkdmarc.bimi.OID_TRADEMARK_IDENTIFIER, "TM-12345"))
    elif mark_type == "Government Mark":
        custom_attrs.append((checkdmarc.bimi.OID_STATUTE_COUNTRY_NAME, "US"))
        custom_attrs.append((checkdmarc.bimi.OID_STATUTE_CITATION, "Title 1 § 100"))
    return name_attrs, custom_attrs


def _logotype_extension(svg_bytes: bytes):
    """Build an UnrecognizedExtension carrying a base64 SVG data URI."""
    import base64

    from cryptography import x509

    b64 = base64.b64encode(svg_bytes).decode("ascii")
    ext_value = b"\x00\x00\x00data:image/svg+xml;base64," + b64.encode("ascii")
    return x509.UnrecognizedExtension(checkdmarc.bimi.OID_LOGOTYPE, ext_value)


class TestGetCertificateMetadata(unittest.TestCase):
    """Coverage for get_certificate_metadata against synthesized x509 certs"""

    def testMissingRequiredExtensions(self):
        """A cert missing SAN and logotype gets two required-extension errors"""
        name_attrs, custom_attrs = _full_subject_attrs()
        pem = _build_cert(
            subject_attrs=name_attrs, custom_oid_subject_attrs=custom_attrs
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        errs = result["validation_errors"]
        self.assertTrue(any("subjectAlternativeName" in e for e in errs))
        self.assertTrue(any("logotype" in e for e in errs))

    def testForbiddenExtensionRejected(self):
        """A cert with NameConstraints is marked invalid"""
        from cryptography import x509

        name_attrs, custom_attrs = _full_subject_attrs()
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            extensions=[
                (
                    x509.NameConstraints(
                        permitted_subtrees=[x509.DNSName("example.com")],
                        excluded_subtrees=None,
                    ),
                    True,
                ),
                (_logotype_extension(VALID_SVG.encode("utf-8")), False),
            ],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(
            any("forbidden extension" in e for e in result["validation_errors"])
        )
        self.assertFalse(result["valid"])

    def testPilotIdentifierAfterCutoffRejected(self):
        """A cert issued on/after 2025-03-15 with Pilot identifier is rejected"""
        from datetime import datetime, timedelta, timezone

        from cryptography import x509

        name_attrs, custom_attrs = _full_subject_attrs()
        cutoff = datetime(2025, 4, 1, tzinfo=timezone.utc)
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            not_valid_before=cutoff,
            not_valid_after=cutoff + timedelta(days=365),
            extensions=[
                (
                    x509.UnrecognizedExtension(
                        checkdmarc.bimi.OID_PILOT_IDENTIFIER_EXTENSION, b"pilot"
                    ),
                    False,
                ),
                (_logotype_extension(VALID_SVG.encode("utf-8")), False),
            ],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(
            any("Pilot identifier" in e for e in result["validation_errors"])
        )

    def testExpiredCertWarning(self):
        """An expired cert is marked invalid"""
        from datetime import datetime, timedelta, timezone

        name_attrs, custom_attrs = _full_subject_attrs()
        past = datetime.now(timezone.utc) - timedelta(days=400)
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            not_valid_before=past,
            not_valid_after=past + timedelta(days=30),
            extensions=[
                (_logotype_extension(VALID_SVG.encode("utf-8")), False),
            ],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(result["expired"])
        self.assertTrue(any("expired on" in e for e in result["validation_errors"]))

    def testNotYetValidCertRejected(self):
        """A cert whose not_valid_before is in the future is rejected"""
        from datetime import datetime, timedelta, timezone

        name_attrs, custom_attrs = _full_subject_attrs()
        future = datetime.now(timezone.utc) + timedelta(days=30)
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            not_valid_before=future,
            not_valid_after=future + timedelta(days=365),
            extensions=[
                (_logotype_extension(VALID_SVG.encode("utf-8")), False),
            ],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(
            any("not valid until" in e for e in result["validation_errors"])
        )

    def testExpiringSoonWarning(self):
        """A cert expiring within 14 days produces a warning"""
        from datetime import datetime, timedelta, timezone

        name_attrs, custom_attrs = _full_subject_attrs()
        # Expires in 5 days
        soon = datetime.now(timezone.utc) + timedelta(days=5)
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            not_valid_after=soon,
            extensions=[
                (_logotype_extension(VALID_SVG.encode("utf-8")), False),
            ],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(any("will expire in" in w for w in result["warnings"]))

    def testExpiringInLessThanADayWarning(self):
        """A cert expiring in under a day produces a different warning"""
        from datetime import datetime, timedelta, timezone

        name_attrs, custom_attrs = _full_subject_attrs()
        soon = datetime.now(timezone.utc) + timedelta(hours=12)
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            not_valid_after=soon,
            extensions=[
                (_logotype_extension(VALID_SVG.encode("utf-8")), False),
            ],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(any("less than a day" in w for w in result["warnings"]))

    def testDomainMismatchRejected(self):
        """When the requested domain doesn't appear in SAN, the cert is rejected"""
        name_attrs, custom_attrs = _full_subject_attrs()
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["other.example.com"],
            extensions=[(_logotype_extension(VALID_SVG.encode("utf-8")), False)],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem, domain="example.com")
        self.assertTrue(
            any(
                "does not match the certificate domain" in e
                for e in result["validation_errors"]
            )
        )
        # Regression: the local list was rebound to a comma-joined string to
        # build the error message, so the public domains field (declared
        # list[str] | None) held a str on this exact branch
        self.assertIsInstance(result["domains"], list)

    def testMissingMarkType(self):
        """A subject without a markType field is rejected"""
        name_attrs, _ = _full_subject_attrs()
        pem = _build_cert(
            subject_attrs=name_attrs,
            san_dns=["example.com"],
            extensions=[(_logotype_extension(VALID_SVG.encode("utf-8")), False)],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(
            any("markType is missing" in e for e in result["validation_errors"])
        )

    def testInvalidMarkType(self):
        """A markType outside MARK_TYPES is rejected"""
        name_attrs, _ = _full_subject_attrs()
        custom = [(checkdmarc.bimi.OID_MARK_TYPE, "Bogus Mark")]
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom,
            san_dns=["example.com"],
            extensions=[(_logotype_extension(VALID_SVG.encode("utf-8")), False)],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(
            any(
                "not a valid subject markType" in e for e in result["validation_errors"]
            )
        )

    def testMissingRequiredSubjectField(self):
        """A markType with missing required fields is rejected"""
        # Strip the trademark fields to trigger missing-required errors
        name_attrs = [
            ("ORGANIZATION_NAME", "Example Corp"),
            ("COUNTRY_NAME", "US"),
        ]
        custom = [(checkdmarc.bimi.OID_MARK_TYPE, "Registered Mark")]
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom,
            san_dns=["example.com"],
            extensions=[(_logotype_extension(VALID_SVG.encode("utf-8")), False)],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(
            any("missing the required field" in e for e in result["validation_errors"])
        )

    def testEitherOrFieldMissing(self):
        """Neither localityName nor stateOrProvinceName triggers an either-or error"""
        name_attrs, custom_attrs = _full_subject_attrs()
        # Strip both locality and state to break the either-or rule
        name_attrs = [
            (label, value)
            for (label, value) in name_attrs
            if label not in ("LOCALITY_NAME", "STATE_OR_PROVINCE_NAME")
        ]
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            extensions=[(_logotype_extension(VALID_SVG.encode("utf-8")), False)],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(
            any("At least one of" in e for e in result["validation_errors"])
        )

    def testCrossMarkTypeFieldRejected(self):
        """A Registered Mark cert with Government-Mark-only fields is rejected"""
        name_attrs, custom_attrs = _full_subject_attrs("Registered Mark")
        # Add a Government Mark only field
        custom_attrs.append((checkdmarc.bimi.OID_STATUTE_CITATION, "Wrong type field"))
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            extensions=[(_logotype_extension(VALID_SVG.encode("utf-8")), False)],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(
            any(
                "Government Mark certificates" in e for e in result["validation_errors"]
            )
        )

    def testValidLogotypeExtracted(self):
        """A cert with a logotype extension exposes a logotype_sha256"""
        import hashlib

        name_attrs, custom_attrs = _full_subject_attrs()
        svg = VALID_SVG.encode("utf-8")
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            extensions=[(_logotype_extension(svg), False)],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem, domain="example.com")
        self.assertEqual(result["logotype_sha256"], hashlib.sha256(svg).hexdigest())

    def testPriorUseMarkWithoutSourceURL(self):
        """A recent Prior Use Mark must carry a priorUseMarkSourceURL

        Certificates with this mark type issued on or after 2025-04-15 are
        required to say where the prior use is evidenced.
        """
        from datetime import datetime, timezone

        name_attrs, custom_attrs = _full_subject_attrs(mark_type="Prior Use Mark")
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            not_valid_before=datetime(2025, 4, 15, tzinfo=timezone.utc),
            extensions=[(_logotype_extension(VALID_SVG.encode("utf-8")), False)],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertTrue(
            any("priorUseMarkSourceURL" in e for e in result["validation_errors"]),
            f"Expected a priorUseMarkSourceURL error, got: "
            f"{result['validation_errors']}",
        )

    def testPriorUseMarkWithSourceURLAccepted(self):
        """The same certificate with the source URL present raises no such error"""
        from datetime import datetime, timezone

        name_attrs, custom_attrs = _full_subject_attrs(mark_type="Prior Use Mark")
        custom_attrs = custom_attrs + [
            (
                checkdmarc.bimi.OID_PRIOR_USE_MARK_SOURCE_URL,
                "https://example.com/prior-use",
            )
        ]
        pem = _build_cert(
            subject_attrs=name_attrs,
            custom_oid_subject_attrs=custom_attrs,
            san_dns=["example.com"],
            not_valid_before=datetime(2025, 4, 15, tzinfo=timezone.utc),
            extensions=[(_logotype_extension(VALID_SVG.encode("utf-8")), False)],
        )
        result = checkdmarc.bimi.get_certificate_metadata(pem)
        self.assertFalse(
            any("priorUseMarkSourceURL" in e for e in result["validation_errors"]),
            f"Unexpected priorUseMarkSourceURL error: {result['validation_errors']}",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
