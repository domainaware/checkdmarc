"""Tests for checkdmarc.bimi"""

import os
import unittest
from unittest.mock import MagicMock, patch
from typing import Any, cast

import dns.exception
import dns.resolver
import requests

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
            b"", raise_for_status_exc=requests.exceptions.HTTPError("404 Not Found")
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

    def testBytesInputDelegatesToPemLoader(self):
        """When given bytes, extract_logo_from_certificate loads the PEM and
        operates on the second cert (index 1) of the bundle."""
        from cryptography.x509 import ExtensionNotFound

        fake_certs = [MagicMock(), MagicMock()]
        fake_certs[1].extensions.get_extension_for_oid.side_effect = ExtensionNotFound(
            "no ext", MagicMock()
        )
        with patch(
            "checkdmarc.bimi.load_pem_x509_certificates",
            return_value=fake_certs,
        ):
            result = checkdmarc.bimi.extract_logo_from_certificate(b"-----PEM-----")
        # Second cert is inspected; missing extension -> None
        self.assertIsNone(result)


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
        with patch("checkdmarc.bimi._query_bimi_record") as mock_query:
            with patch("checkdmarc.bimi.query_dns", return_value=[]):
                mock_query.side_effect = [
                    None,  # sub.example.com (no record)
                    "v=BIMI1; l=https://example.com/logo.svg",  # example.com
                ]
                result = checkdmarc.bimi.query_bimi_record("sub.example.com")
        self.assertEqual(result["location"], "example.com")

    def testApexNXDOMAINRaises(self):
        """NXDOMAIN on the apex TXT lookup raises BIMIRecordNotFound"""
        with patch(
            "checkdmarc.bimi._query_bimi_record",
            return_value="v=BIMI1; l=",
        ):
            with patch(
                "checkdmarc.bimi.query_dns",
                side_effect=dns.resolver.NXDOMAIN(),
            ):
                self.assertRaises(
                    checkdmarc.bimi.BIMIRecordNotFound,
                    checkdmarc.bimi.query_bimi_record,
                    "example.com",
                )

    def testSubdomainWithoutBaseRecord(self):
        """A subdomain whose base domain also has no record yields a more
        descriptive BIMIRecordNotFound message."""
        with patch("checkdmarc.bimi._query_bimi_record", return_value=None):
            with patch("checkdmarc.bimi.query_dns", return_value=[]):
                with self.assertRaises(checkdmarc.bimi.BIMIRecordNotFound) as ctx:
                    checkdmarc.bimi.query_bimi_record("sub.example.com")
        self.assertIn("subdomain or its base domain", str(ctx.exception))


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
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            with patch(
                "checkdmarc.bimi.get_certificate_metadata",
                return_value={
                    "valid": True,
                    "logotype_sha256": svg_sha,
                },
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
        with patch("checkdmarc.bimi.requests.Session", return_value=fake_session):
            with patch(
                "checkdmarc.bimi.get_certificate_metadata",
                return_value={
                    "valid": True,
                    "logotype_sha256": "0" * 64,
                },
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
        self.assertTrue(any("serviceAlternativeName" in e for e in errs))
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
