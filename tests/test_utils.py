"""Tests for checkdmarc.utils"""

import os
import unittest
from typing import cast
from unittest.mock import MagicMock, patch

import dns.exception
import dns.message
import dns.nameserver
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import httpx
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
            checkdmarc.utils.normalize_domain("exam\u200bple.com"),
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

    def testRetryTxtGivesUp(self):
        """A persistent transient error on a TXT lookup is re-raised

        TXT records take their own branch through query_dns, so exhausting
        the retries there needs its own check.
        """
        fake_resolver = _fake_resolver()
        fake_resolver.nameservers = []
        fake_resolver.resolve.side_effect = dns.resolver.LifetimeTimeout()
        self.assertRaises(
            dns.resolver.LifetimeTimeout,
            checkdmarc.utils.query_dns,
            "example.com",
            "TXT",
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
        """A DNS-layer error is wrapped in DNSException"""
        with patch(
            "checkdmarc.utils.query_dns",
            side_effect=dns.exception.DNSException("DNS lookup failed"),
        ):
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
        with patch(
            "checkdmarc.utils.query_dns",
            side_effect=dns.exception.DNSException("DNS lookup failed"),
        ):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_txt_records,
                "example.com",
            )

    def testNonDNSErrorPropagates(self):
        """A non-DNS error (e.g. a programming bug) is not swallowed as DNSException"""
        # The DNS wrappers normalize DNS-layer failures to DNSException, but an
        # unexpected error type must surface instead of being hidden.
        with patch("checkdmarc.utils.query_dns", side_effect=KeyError("bug")):
            self.assertRaises(
                KeyError,
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
        with patch(
            "checkdmarc.utils.query_dns",
            side_effect=dns.exception.DNSException("DNS lookup failed"),
        ):
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
        with patch(
            "checkdmarc.utils.query_dns",
            side_effect=dns.exception.DNSException("DNS lookup failed"),
        ):
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
        with patch(
            "checkdmarc.utils.query_dns",
            side_effect=dns.exception.DNSException("DNS lookup failed"),
        ):
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
        with patch(
            "checkdmarc.utils.query_dns",
            side_effect=dns.exception.DNSException("DNS lookup failed"),
        ):
            self.assertRaises(
                checkdmarc.utils.DNSException,
                checkdmarc.utils.get_mx_records,
                "example.com",
            )


class TestEncryptedDnsNameservers(unittest.TestCase):
    """Tests for the DNS over HTTPS and DNS over TLS transports selected by
    the form of each ``nameservers`` entry. The end-to-end tests mock at the
    dnspython SDK boundary (``dns.query.https`` / ``dns.query.tls``) and
    assert on the answer query_dns parses back out of a real DNS response
    message, so the whole chain — entry mapping, resolver, nameserver
    object, transport call — is exercised."""

    def setUp(self):
        # The DoH session is process-wide state; keep test ordering from
        # leaking a client (or a PID) between tests.
        self._old_session = checkdmarc.utils._DOH_SESSION
        self._old_pid = checkdmarc.utils._DOH_SESSION_PID
        checkdmarc.utils._DOH_SESSION = None
        checkdmarc.utils._DOH_SESSION_PID = None

        def restore():
            session = checkdmarc.utils._DOH_SESSION
            if session is not None and session is not self._old_session:
                session.close()
            checkdmarc.utils._DOH_SESSION = self._old_session
            checkdmarc.utils._DOH_SESSION_PID = self._old_pid

        self.addCleanup(restore)

    @staticmethod
    def _ptr_responder(captured: list, answer: str = "dns.example."):
        """Builds a dns.query stand-in that answers any PTR query with
        ``answer``, recording the keyword arguments it was called with."""

        def responder(request, *args, **kwargs):
            captured.append(kwargs)
            response = dns.message.make_response(request)
            # find_rrset(create=True) rather than appending to
            # response.answer, so the message's rrset index is updated too —
            # dnspython looks the answer up through that index.
            rrset = response.find_rrset(
                response.answer,
                request.question[0].name,
                dns.rdataclass.IN,
                dns.rdatatype.PTR,
                create=True,
            )
            rrset.add(dns.rdata.from_text("IN", "PTR", answer), 300)
            return response

        return responder

    def test_plain_ip_entries_are_passed_through_untouched(self):
        """An IP address is handed to dnspython as the same string object,
        leaving its own Do53 enrichment (and port defaulting) in charge."""
        entries = ["1.1.1.1", "2606:4700:4700::1111"]
        mapped = checkdmarc.utils._nameservers_to_resolver_input(entries)
        self.assertEqual(len(mapped), 2)
        for original, result in zip(entries, mapped):
            self.assertIs(result, original)

    def test_nameserver_objects_are_passed_through_untouched(self):
        """A caller-built dns.nameserver.Nameserver object — allowed by the
        public nameservers parameter's type — is passed through as-is."""
        ns = dns.nameserver.Do53Nameserver("1.1.1.1")
        (mapped,) = checkdmarc.utils._nameservers_to_resolver_input([ns])
        self.assertIs(mapped, ns)

    def _map_doh(self, entry: str) -> checkdmarc.utils._SessionDoHNameserver:
        """Maps one entry and asserts it produced a DoH nameserver."""
        (mapped,) = checkdmarc.utils._nameservers_to_resolver_input([entry])
        self.assertIsInstance(mapped, checkdmarc.utils._SessionDoHNameserver)
        return cast(checkdmarc.utils._SessionDoHNameserver, mapped)

    def _map_dot(self, entry: str) -> dns.nameserver.DoTNameserver:
        """Maps one entry and asserts it produced a DoT nameserver."""
        (mapped,) = checkdmarc.utils._nameservers_to_resolver_input([entry])
        self.assertIsInstance(mapped, dns.nameserver.DoTNameserver)
        return cast(dns.nameserver.DoTNameserver, mapped)

    def test_https_entry_becomes_a_session_doh_nameserver(self):
        """An https:// entry maps to the DoH nameserver subclass that
        queries through checkdmarc's own httpx client."""
        url = "https://cloudflare-dns.com/dns-query"
        self.assertEqual(self._map_doh(url).url, url)

    def test_uppercase_scheme_is_recognized(self):
        """The scheme is compared as urlsplit reports it, which is
        lowercased, so HTTPS:// selects DoH rather than falling through to
        dnspython as an unusable string."""
        self._map_doh("HTTPS://cloudflare-dns.com/dns-query")

    def test_tls_entry_defaults_to_port_853_with_no_hostname(self):
        """tls://<ip> alone uses DoTNameserver's default port and performs
        no certificate-identity substitution."""
        mapped = self._map_dot("tls://9.9.9.9")
        self.assertEqual(mapped.address, "9.9.9.9")
        self.assertEqual(mapped.port, 853)
        self.assertIsNone(mapped.hostname)

    def test_tls_entry_port_and_hostname_are_parsed(self):
        """tls://ip:port#hostname sets both the port and the TLS
        certificate identity."""
        mapped = self._map_dot("tls://9.9.9.9:8853#dns.quad9.net")
        self.assertEqual(mapped.address, "9.9.9.9")
        self.assertEqual(mapped.port, 8853)
        self.assertEqual(mapped.hostname, "dns.quad9.net")

    def test_bracketed_ipv6_tls_entry_is_parsed(self):
        """An IPv6 address is bracketed so the colon before the port is
        unambiguous; the brackets are not part of the address."""
        mapped = self._map_dot("tls://[2620:fe::fe]:853#dns.quad9.net")
        self.assertEqual(mapped.address, "2620:fe::fe")
        self.assertEqual(mapped.port, 853)

    def test_mixed_list_preserves_order_and_types(self):
        """Transports can be mixed in one nameservers list, and the
        configured order is the failover order dnspython will use."""
        mapped = checkdmarc.utils._nameservers_to_resolver_input(
            [
                "1.1.1.1",
                "https://cloudflare-dns.com/dns-query",
                "tls://9.9.9.9#dns.quad9.net",
            ]
        )
        self.assertEqual(mapped[0], "1.1.1.1")
        self.assertIsInstance(mapped[1], checkdmarc.utils._SessionDoHNameserver)
        self.assertIsInstance(mapped[2], dns.nameserver.DoTNameserver)

    def test_tls_entry_without_a_host_is_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            checkdmarc.utils._nameservers_to_resolver_input(["tls://"])
        self.assertIn("tls://", str(ctx.exception))

    def test_tls_entry_with_a_hostname_instead_of_an_ip_is_rejected(self):
        """DoTNameserver takes an IP address, not a name — it has no
        resolver of its own to bootstrap with. The certificate identity is
        supplied by the #hostname suffix instead."""
        with self.assertRaises(ValueError) as ctx:
            checkdmarc.utils._nameservers_to_resolver_input(["tls://dns.quad9.net"])
        self.assertIn("tls://dns.quad9.net", str(ctx.exception))

    def test_tls_entry_with_an_invalid_port_is_rejected(self):
        """urlsplit only validates the port when it is read, so the
        ValueError it raises there is re-raised naming the entry."""
        with self.assertRaises(ValueError) as ctx:
            checkdmarc.utils._nameservers_to_resolver_input(["tls://9.9.9.9:notaport"])
        self.assertIn("tls://9.9.9.9:notaport", str(ctx.exception))

    def test_tls_entry_with_a_path_is_rejected(self):
        """tls://9.9.9.9/dns.quad9.net — a plausible slash-for-# typo —
        must fail at configuration time naming the entry, not parse
        "successfully" with no TLS certificate identity and then fail at
        query time with an opaque certificate error. Userinfo and query
        components are rejected the same way."""
        for entry in (
            "tls://9.9.9.9/dns.quad9.net",
            "tls://user@9.9.9.9",
            "tls://9.9.9.9?hostname=dns.quad9.net",
        ):
            with self.subTest(entry=entry):
                with self.assertRaises(ValueError) as ctx:
                    checkdmarc.utils._nameservers_to_resolver_input([entry])
                self.assertIn(entry, str(ctx.exception))

    def test_unsplittable_entry_is_left_for_dnspython_to_reject(self):
        """urlsplit itself raises on some malformed input (an unbalanced
        IPv6 bracket). Such an entry is passed through rather than reported
        as a DoH/DoT problem, and dnspython rejects it with its own message
        about what a nameserver may be."""
        entry = "https://[::1"
        (mapped,) = checkdmarc.utils._nameservers_to_resolver_input([entry])
        self.assertIs(mapped, entry)
        with self.assertRaises(ValueError):
            dns.resolver.Resolver(configure=False).nameservers = [entry]

    def test_doh_query_returns_answers_through_a_shared_httpx_client(self):
        """An https:// nameserver resolves through dns.query.https, and the
        session it is given is the module's shared client, an httpx.Client
        with trust_env left on — httpx's documented switch for honoring
        HTTP_PROXY/HTTPS_PROXY/NO_PROXY and SSL_CERT_FILE, which is what a
        proxy-only network needs. dnspython's stock DoH nameserver passes no
        session at all, and the client dns.query.https builds for itself has
        a custom transport, which disables environment proxies. Asserting
        identity with the shared client also observes the connection-reuse
        half of the claim: a fresh per-query client would satisfy every
        other assertion here."""
        captured: list = []
        with patch("dns.query.https", side_effect=self._ptr_responder(captured)):
            records = checkdmarc.utils.query_dns(
                "1.0.0.1.in-addr.arpa",
                "PTR",
                cache=ExpiringDict(max_len=10, max_age_seconds=60),
                nameservers=["https://dns.example/dns-query"],
                timeout=2,
            )
        self.assertEqual(records, ["dns.example"])
        self.assertEqual(len(captured), 1)
        session = captured[0]["session"]
        self.assertIsInstance(session, httpx.Client)
        self.assertIs(session.trust_env, True)
        self.assertIs(session, checkdmarc.utils._DOH_SESSION)

    def test_dot_query_returns_answers_and_passes_the_tls_hostname(self):
        """A tls:// nameserver resolves through dns.query.tls, and the
        #hostname suffix reaches it as server_hostname — the name the
        server's certificate is checked against."""
        captured: list = []
        with patch("dns.query.tls", side_effect=self._ptr_responder(captured)):
            records = checkdmarc.utils.query_dns(
                "1.0.0.1.in-addr.arpa",
                "PTR",
                cache=ExpiringDict(max_len=10, max_age_seconds=60),
                nameservers=["tls://9.9.9.9#dns.quad9.net"],
                timeout=2,
            )
        self.assertEqual(records, ["dns.example"])
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["server_hostname"], "dns.quad9.net")
        self.assertEqual(captured[0]["port"], 853)

    def test_doh_session_is_reused_within_a_process(self):
        """Consecutive calls hand back the same client, so DoH lookups
        reuse the connection instead of renegotiating TLS per query."""
        first = checkdmarc.utils._get_doh_session()
        self.assertIs(checkdmarc.utils._get_doh_session(), first)

    def test_doh_session_is_rebuilt_after_a_fork(self):
        """A forked worker in an embedding application inherits the module
        globals, including the parent's open sockets. Recording the creating
        PID makes the child build its own client rather than share the
        parent's."""
        parent_session = checkdmarc.utils._get_doh_session()
        checkdmarc.utils._DOH_SESSION_PID = os.getpid() + 1
        child_session = checkdmarc.utils._get_doh_session()
        self.addCleanup(parent_session.close)
        self.assertIsNot(child_session, parent_session)
        self.assertEqual(checkdmarc.utils._DOH_SESSION_PID, os.getpid())


if __name__ == "__main__":
    unittest.main(verbosity=2)
