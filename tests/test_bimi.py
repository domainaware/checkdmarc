"""Tests for checkdmarc.bimi"""

import os
import unittest
from unittest.mock import MagicMock, patch
from typing import Any, cast

import dns.resolver

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
        with patch(
            "checkdmarc.bimi._query_bimi_record", side_effect=["v=BIMI1; l=;", None]
        ):
            with patch("checkdmarc.bimi.query_dns", return_value=[]):
                results = checkdmarc.bimi.check_bimi("example.com")

        self.assertTrue(cast(Any, results)["valid"])
        self.assertEqual(len(cast(Any, results)["warnings"]), 0)


class TestLpsTag(unittest.TestCase):
    """parse_bimi_record handles the lps= tag (comma-separated local-parts)"""

    def testCommaSeparatedSelectors(self):
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; lps=news,billing,support")
        self.assertEqual(result["tags"]["lps"]["value"], ["news", "billing", "support"])

    def testSpacesAroundCommasAreStripped(self):
        result = checkdmarc.bimi.parse_bimi_record(
            "v=BIMI1; lps=news, billing, support"
        )
        self.assertEqual(result["tags"]["lps"]["value"], ["news", "billing", "support"])

    def testSelectorsLowercased(self):
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; lps=News,Billing")
        self.assertEqual(result["tags"]["lps"]["value"], ["news", "billing"])

    def testSelectorCharacters(self):
        """Per draft-bimi-14 § 4.3.14, local-part-text = ALPHA / DIGIT / '-' only"""
        result = checkdmarc.bimi.parse_bimi_record(
            "v=BIMI1; lps=sales-team,help-desk,info123"
        )
        self.assertEqual(
            result["tags"]["lps"]["value"],
            ["sales-team", "help-desk", "info123"],
        )

    def testSingleSelector(self):
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; lps=news")
        self.assertEqual(result["tags"]["lps"]["value"], ["news"])

    def testInvalidCharactersRejected(self):
        """Underscores and dots are not allowed in local-part-text"""
        self.assertRaises(
            checkdmarc.bimi.BIMISyntaxError,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; lps=help_desk",
        )
        self.assertRaises(
            checkdmarc.bimi.BIMISyntaxError,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; lps=info.support",
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

    def testUnrelatedRecordPropagates(self):
        """A v=BIMI1 record alongside an unrelated TXT raises UnrelatedTXTRecordFoundAtBIMI"""
        with patch(
            "checkdmarc.bimi.query_dns",
            return_value=["v=BIMI1; l=", "some other txt record"],
        ):
            self.assertRaises(
                checkdmarc.bimi.UnrelatedTXTRecordFoundAtBIMI,
                checkdmarc.bimi._query_bimi_record,
                "example.com",
            )

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

    def testGenericExceptionStillConvertsToNotFound(self):
        """Non-BIMI exceptions are still wrapped as BIMIRecordNotFound"""
        with patch(
            "checkdmarc.bimi.query_dns", side_effect=RuntimeError("network down")
        ):
            self.assertRaises(
                checkdmarc.bimi.BIMIRecordNotFound,
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
            raise RuntimeError("network down")

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


class TestParseBimiRecord(unittest.TestCase):
    def testUnknownTagSyntaxError(self):
        """The grammar rejects unknown tags as BIMISyntaxError before
        the InvalidBIMITag check has a chance to run."""
        self.assertRaises(
            checkdmarc.bimi.BIMISyntaxError,
            checkdmarc.bimi.parse_bimi_record,
            "v=BIMI1; xyz=foo",
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
            b"", raise_for_status_exc=Exception("404 Not Found")
        )
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            result = checkdmarc.bimi.parse_bimi_record(
                "v=BIMI1; l=https://example.com/missing.svg"
            )
        self.assertIn("error", result["image"])

    def testCertificateFetchFailure(self):
        """A failed a= fetch produces a certificate error entry"""
        fake_session = MagicMock()
        fake_session.get.return_value = _fake_response(
            b"", raise_for_status_exc=Exception("connection refused")
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
        result = checkdmarc.bimi.parse_bimi_record("v=BIMI1; avp=brand")
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
        # DMARC p, sp, and pct all flag warnings
        self.assertTrue(any("DMARC policy" in w for w in result["warnings"]))
        self.assertTrue(any("subdomain policy" in w for w in result["warnings"]))
        self.assertTrue(any("pct tag" in w for w in result["warnings"]))


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
