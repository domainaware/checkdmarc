"""Tests for checkdmarc.utils"""

import unittest
from unittest.mock import MagicMock, patch

import dns.resolver
from expiringdict import ExpiringDict

import checkdmarc.utils


class Test(unittest.TestCase):
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

    def testNormalizeDomain(self):
        """normalize_domain handles various inputs correctly"""
        # Basic lowering
        self.assertEqual(
            checkdmarc.utils.normalize_domain("Example.COM"), "example.com"
        )
        # Zero-width character removal
        self.assertEqual(
            checkdmarc.utils.normalize_domain("exam​ple.com"),
            "example.com",
        )
        # Unicode normalization
        self.assertEqual(
            checkdmarc.utils.normalize_domain("example.com"), "example.com"
        )


def _fake_resolver():
    """Build a resolver mock that exposes the attributes query_dns reads."""
    resolver = MagicMock()
    resolver.nameservers = []
    resolver.lifetime = 5.0
    resolver.timeout = 5.0
    return resolver


def _fake_txt_answer(records):
    """Build a list of mock RR objects whose .strings is a tuple of bytes chunks."""
    answers = []
    for r in records:
        rr = MagicMock()
        if isinstance(r, bytes):
            rr.strings = (r,)
        else:
            # Allow tuple-of-bytes for split TXT records
            rr.strings = r
        answers.append(rr)
    return answers


def _fake_text_answer(records):
    """Build mock RRs that report .to_text() like dnspython's non-TXT answers."""
    answers = []
    for r in records:
        rr = MagicMock()
        rr.to_text.return_value = r
        answers.append(rr)
    return answers


class TestQueryDns(unittest.TestCase):
    """Direct tests for the query_dns function via mocked Resolver.resolve."""

    def testTxtRecordPlain(self):
        """TXT records are decoded and concatenated"""
        fake_resolver = _fake_resolver()
        fake_resolver.nameservers = []
        fake_resolver.resolve.return_value = _fake_txt_answer([b"hello world"])
        result = checkdmarc.utils.query_dns(
            "example.com", "TXT", resolver=fake_resolver, cache=ExpiringDict(10, 60)
        )
        self.assertEqual(result, ["hello world"])

    def testTxtRecordQuotedSegments(self):
        """quoted_txt_segments=True preserves the per-chunk quoting"""
        fake_resolver = _fake_resolver()
        fake_resolver.nameservers = []
        fake_resolver.resolve.return_value = _fake_txt_answer([(b"v=spf1 ", b"-all")])
        result = checkdmarc.utils.query_dns(
            "example.com",
            "TXT",
            quoted_txt_segments=True,
            resolver=fake_resolver,
            cache=ExpiringDict(10, 60),
        )
        self.assertEqual(result, ['"v=spf1 ""-all"'])

    def testTxtRecordUndecodable(self):
        """Bytes that don't decode as UTF-8 are reported as 'Undecodable characters'"""
        fake_resolver = _fake_resolver()
        fake_resolver.nameservers = []
        fake_resolver.resolve.return_value = _fake_txt_answer([b"\xff\xfe\x00"])
        result = checkdmarc.utils.query_dns(
            "example.com", "TXT", resolver=fake_resolver, cache=ExpiringDict(10, 60)
        )
        self.assertEqual(result, ["Undecodable characters"])

    def testNonTxtRecord(self):
        """Non-TXT records return text via .to_text() with trailing dots stripped"""
        fake_resolver = _fake_resolver()
        fake_resolver.nameservers = []
        fake_resolver.resolve.return_value = _fake_text_answer(
            ["ns1.example.com.", "ns2.example.com."]
        )
        result = checkdmarc.utils.query_dns(
            "example.com", "NS", resolver=fake_resolver, cache=ExpiringDict(10, 60)
        )
        self.assertEqual(result, ["ns1.example.com", "ns2.example.com"])

    def testCacheHit(self):
        """A populated cache short-circuits the DNS lookup"""
        cache = ExpiringDict(max_len=10, max_age_seconds=60)
        cache["example.com_TXT_False"] = ["cached value"]
        fake_resolver = _fake_resolver()
        result = checkdmarc.utils.query_dns(
            "example.com", "TXT", resolver=fake_resolver, cache=cache
        )
        self.assertEqual(result, ["cached value"])
        fake_resolver.resolve.assert_not_called()

    def testRetryOnTransientError(self):
        """LifetimeTimeout is retried up to ``retries`` times"""
        fake_resolver = _fake_resolver()
        fake_resolver.nameservers = []
        fake_resolver.resolve.side_effect = [
            dns.resolver.LifetimeTimeout(),
            _fake_text_answer(["ns1.example.com."]),
        ]
        result = checkdmarc.utils.query_dns(
            "example.com",
            "NS",
            resolver=fake_resolver,
            retries=1,
            cache=ExpiringDict(10, 60),
        )
        self.assertEqual(result, ["ns1.example.com"])
        self.assertEqual(fake_resolver.resolve.call_count, 2)

    def testRetryGivesUp(self):
        """A persistent transient error is re-raised once retries are exhausted"""
        fake_resolver = _fake_resolver()
        fake_resolver.nameservers = []
        fake_resolver.resolve.side_effect = dns.resolver.LifetimeTimeout()
        self.assertRaises(
            dns.resolver.LifetimeTimeout,
            checkdmarc.utils.query_dns,
            "example.com",
            "NS",
            resolver=fake_resolver,
            retries=0,
            cache=ExpiringDict(10, 60),
        )

    def testRetryTxtRecord(self):
        """Retry path also fires for TXT records"""
        fake_resolver = _fake_resolver()
        fake_resolver.nameservers = []
        fake_resolver.resolve.side_effect = [
            dns.resolver.LifetimeTimeout(),
            _fake_txt_answer([b"v=spf1 -all"]),
        ]
        result = checkdmarc.utils.query_dns(
            "example.com",
            "TXT",
            resolver=fake_resolver,
            retries=1,
            cache=ExpiringDict(10, 60),
        )
        self.assertEqual(result, ["v=spf1 -all"])

    def testNameserversBuildResolver(self):
        """Passing nameservers without a resolver builds one with that list"""
        with patch("dns.resolver.Resolver") as mock_resolver_cls:
            instance = MagicMock()
            instance.nameservers = ["1.1.1.1"]
            instance.resolve.return_value = _fake_text_answer(["ns.example.com."])
            mock_resolver_cls.return_value = instance
            result = checkdmarc.utils.query_dns(
                "example.com",
                "NS",
                nameservers=["1.1.1.1"],
                cache=ExpiringDict(10, 60),
            )
        self.assertEqual(result, ["ns.example.com"])
        # nameservers was assigned to the Resolver instance
        self.assertEqual(instance.nameservers, ["1.1.1.1"])

    def testMultiNameserverLifetimeScaling(self):
        """Multiple nameservers extend the resolver lifetime"""
        with patch("dns.resolver.Resolver") as mock_resolver_cls:
            instance = MagicMock()
            instance.nameservers = ["1.1.1.1", "8.8.8.8"]
            instance.resolve.return_value = _fake_text_answer(["ns.example.com."])
            mock_resolver_cls.return_value = instance
            checkdmarc.utils.query_dns(
                "example.com",
                "NS",
                nameservers=["1.1.1.1", "8.8.8.8"],
                timeout=2.0,
                cache=ExpiringDict(10, 60),
            )
        # lifetime is timeout * nameserver count
        self.assertEqual(instance.lifetime, 4.0)


class TestGetReverseDns(unittest.TestCase):
    def testReverseSuccess(self):
        with patch("checkdmarc.utils.query_dns", return_value=["host.example.com"]):
            result = checkdmarc.utils.get_reverse_dns("192.0.2.1")
        self.assertEqual(result, ["host.example.com"])

    def testReverseNXDOMAIN(self):
        """NXDOMAIN on a reverse lookup yields an empty list (not an error)"""
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NXDOMAIN()):
            result = checkdmarc.utils.get_reverse_dns("192.0.2.1")
        self.assertEqual(result, [])

    def testReverseOtherErrorRaises(self):
        """A generic exception is wrapped in DNSException"""
        with patch("checkdmarc.utils.query_dns", side_effect=RuntimeError("boom")):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_reverse_dns,
                "192.0.2.1",
            )


class TestGetTxtRecords(unittest.TestCase):
    def testSuccess(self):
        with patch("checkdmarc.utils.query_dns", return_value=["v=spf1 -all", "other"]):
            result = checkdmarc.utils.get_txt_records("example.com")
        self.assertEqual(result, ["v=spf1 -all", "other"])

    def testNXDOMAIN(self):
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NXDOMAIN()):
            self.assertRaises(
                checkdmarc.utils.DNSExceptionNXDOMAIN,
                checkdmarc.utils.get_txt_records,
                "example.com",
            )

    def testNoAnswer(self):
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NoAnswer()):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_txt_records,
                "example.com",
            )

    def testGenericError(self):
        with patch("checkdmarc.utils.query_dns", side_effect=RuntimeError("boom")):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_txt_records,
                "example.com",
            )


class TestGetSoaRecord(unittest.TestCase):
    def testSuccess(self):
        with patch(
            "checkdmarc.utils.query_dns",
            return_value=[
                "ns1.example.com. admin.example.com. 1 3600 900 604800 86400"
            ],
        ):
            result = checkdmarc.utils.get_soa_record("example.com")
        self.assertIn("ns1.example.com", result)

    def testNXDOMAIN(self):
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NXDOMAIN()):
            self.assertRaises(
                checkdmarc.utils.DNSExceptionNXDOMAIN,
                checkdmarc.utils.get_soa_record,
                "example.com",
            )

    def testNoAnswer(self):
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NoAnswer()):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_soa_record,
                "example.com",
            )

    def testGenericError(self):
        with patch("checkdmarc.utils.query_dns", side_effect=RuntimeError("boom")):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_soa_record,
                "example.com",
            )


class TestGetNameservers(unittest.TestCase):
    def testSuccess(self):
        with patch(
            "checkdmarc.utils.query_dns",
            return_value=["ns1.example.com", "ns2.example.com"],
        ):
            result = checkdmarc.utils.get_nameservers("example.com")
        self.assertEqual(result["hostnames"], ["ns1.example.com", "ns2.example.com"])
        self.assertEqual(result["warnings"], [])

    def testApprovedFilteringWarning(self):
        """Nameservers not matching any approved substring produce warnings"""
        with patch(
            "checkdmarc.utils.query_dns",
            return_value=["ns1.example.com", "evil.example.org"],
        ):
            result = checkdmarc.utils.get_nameservers(
                "example.com", approved_nameservers=["example.com"]
            )
        self.assertTrue(any("Unapproved nameserver" in w for w in result["warnings"]))

    def testNXDOMAIN(self):
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NXDOMAIN()):
            self.assertRaises(
                checkdmarc.utils.DNSExceptionNXDOMAIN,
                checkdmarc.utils.get_nameservers,
                "example.com",
            )

    def testNoAnswerReturnsEmpty(self):
        """NoAnswer is swallowed and returns an empty result"""
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NoAnswer()):
            result = checkdmarc.utils.get_nameservers("example.com")
        self.assertEqual(result["hostnames"], [])

    def testGenericError(self):
        with patch("checkdmarc.utils.query_dns", side_effect=RuntimeError("boom")):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_nameservers,
                "example.com",
            )


class TestGetARecords(unittest.TestCase):
    def testIPv4Success(self):
        # First call returns A, second AAAA; merged + sorted
        with patch(
            "checkdmarc.utils.query_dns",
            side_effect=[["192.0.2.1"], ["2001:db8::1"]],
        ):
            result = checkdmarc.utils.get_a_records("example.com")
        self.assertEqual(sorted(result), ["192.0.2.1", "2001:db8::1"])

    def testNXDOMAIN(self):
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NXDOMAIN()):
            self.assertRaises(
                checkdmarc.utils.DNSExceptionNXDOMAIN,
                checkdmarc.utils.get_a_records,
                "example.com",
            )

    def testNoAnswer(self):
        """NoAnswer on one rdtype is swallowed; the other rdtype's results are returned"""
        with patch(
            "checkdmarc.utils.query_dns",
            side_effect=[dns.resolver.NoAnswer(), ["2001:db8::1"]],
        ):
            result = checkdmarc.utils.get_a_records("example.com")
        self.assertEqual(result, ["2001:db8::1"])

    def testGenericError(self):
        with patch("checkdmarc.utils.query_dns", side_effect=RuntimeError("boom")):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_a_records,
                "example.com",
            )


class TestGetMxRecords(unittest.TestCase):
    def testSuccess(self):
        with patch(
            "checkdmarc.utils.query_dns",
            return_value=["20 mx2.example.com.", "10 mx1.example.com."],
        ):
            result = checkdmarc.utils.get_mx_records("example.com")
        # Sorted by preference
        self.assertEqual(result[0]["hostname"], "mx1.example.com")
        self.assertEqual(result[0]["preference"], 10)
        self.assertEqual(result[1]["preference"], 20)

    def testNullMXReturnsEmpty(self):
        """RFC 7505 'null MX' ('0 ') means the domain doesn't accept mail"""
        with patch("checkdmarc.utils.query_dns", return_value=["0 "]):
            result = checkdmarc.utils.get_mx_records("example.com")
        self.assertEqual(result, [])

    def testNXDOMAIN(self):
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NXDOMAIN()):
            self.assertRaises(
                checkdmarc.utils.DNSExceptionNXDOMAIN,
                checkdmarc.utils.get_mx_records,
                "example.com",
            )

    def testNoAnswerReturnsEmpty(self):
        with patch("checkdmarc.utils.query_dns", side_effect=dns.resolver.NoAnswer()):
            result = checkdmarc.utils.get_mx_records("example.com")
        self.assertEqual(result, [])

    def testGenericError(self):
        with patch("checkdmarc.utils.query_dns", side_effect=RuntimeError("boom")):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_mx_records,
                "example.com",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
