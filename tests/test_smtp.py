"""Tests for checkdmarc.smtp

All SMTP socket activity is mocked: many home/business networks block
outbound port 25, so these tests stub out smtplib and the lower-level
DNS helpers entirely.
"""

import socket
import ssl
import smtplib
import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from expiringdict import ExpiringDict

import checkdmarc.smtp


class TestTestTLS(unittest.TestCase):
    """Coverage for checkdmarc.smtp.test_tls (port 465 / SMTP_SSL)"""

    def testSuccess(self):
        """A clean SMTP_SSL session reports tls=True and populates the cache"""
        cache = ExpiringDict(max_len=10, max_age_seconds=60)
        fake_server = MagicMock()
        fake_server.__enter__.return_value = fake_server
        with patch("smtplib.SMTP_SSL", return_value=fake_server):
            result = checkdmarc.smtp.test_tls("mail.example.com", cache=cache)
        self.assertTrue(result)
        self.assertEqual(cache["mail.example.com"], {"tls": True, "error": None})

    def testCacheHitSuccess(self):
        """Cached success returns without touching the network"""
        cache = ExpiringDict(max_len=10, max_age_seconds=60)
        cache["mail.example.com"] = {"tls": True, "error": None}
        with patch("smtplib.SMTP_SSL") as mock_ssl:
            result = checkdmarc.smtp.test_tls("mail.example.com", cache=cache)
        self.assertTrue(result)
        mock_ssl.assert_not_called()

    def testCacheHitError(self):
        """Cached error raises SMTPError without touching the network"""
        cache = ExpiringDict(max_len=10, max_age_seconds=60)
        cache["mail.example.com"] = {"tls": False, "error": "Cached failure"}
        with patch("smtplib.SMTP_SSL") as mock_ssl:
            self.assertRaises(
                checkdmarc.smtp.SMTPError,
                checkdmarc.smtp.test_tls,
                "mail.example.com",
                cache=cache,
            )
        mock_ssl.assert_not_called()

    def testDNSResolutionFailed(self):
        """socket.gaierror surfaces as SMTPError 'DNS resolution failed' and is cached"""
        cache = ExpiringDict(max_len=10, max_age_seconds=60)
        with patch("smtplib.SMTP_SSL", side_effect=socket.gaierror):
            with self.assertRaises(checkdmarc.smtp.SMTPError) as ctx:
                checkdmarc.smtp.test_tls("mail.example.com", cache=cache)
        self.assertIn("DNS resolution failed", str(ctx.exception))
        # First-write into an empty ExpiringDict must succeed — see the
        # `if cache is not None:` checks in smtp.py (an empty dict is falsy).
        entry = cast(dict, cache["mail.example.com"])
        self.assertEqual(entry["error"], "DNS resolution failed")

    def testConnectionRefused(self):
        """ConnectionRefusedError surfaces as SMTPError 'Connection refused'"""
        with patch("smtplib.SMTP_SSL", side_effect=ConnectionRefusedError):
            with self.assertRaises(checkdmarc.smtp.SMTPError) as ctx:
                checkdmarc.smtp.test_tls("mail.example.com")
        self.assertEqual(str(ctx.exception), "Connection refused")

    def testConnectionReset(self):
        """ConnectionResetError surfaces as SMTPError 'Connection reset'"""
        with patch("smtplib.SMTP_SSL", side_effect=ConnectionResetError):
            self.assertRaises(
                checkdmarc.smtp.SMTPError,
                checkdmarc.smtp.test_tls,
                "mail.example.com",
            )

    def testConnectionAborted(self):
        """ConnectionAbortedError surfaces as SMTPError 'Connection aborted'"""
        with patch("smtplib.SMTP_SSL", side_effect=ConnectionAbortedError):
            self.assertRaises(
                checkdmarc.smtp.SMTPError,
                checkdmarc.smtp.test_tls,
                "mail.example.com",
            )

    def testTimeout(self):
        """TimeoutError surfaces as SMTPError 'Connection timed out'"""
        with patch("smtplib.SMTP_SSL", side_effect=TimeoutError):
            with self.assertRaises(checkdmarc.smtp.SMTPError) as ctx:
                checkdmarc.smtp.test_tls("mail.example.com")
        self.assertEqual(str(ctx.exception), "Connection timed out")

    def testSSLError(self):
        """ssl.SSLError surfaces as SMTPError 'SSL error: ...'"""
        with patch("smtplib.SMTP_SSL", side_effect=ssl.SSLError("bad handshake")):
            with self.assertRaises(checkdmarc.smtp.SMTPError) as ctx:
                checkdmarc.smtp.test_tls("mail.example.com")
        self.assertIn("SSL error", str(ctx.exception))

    def testSMTPConnectError554(self):
        """SMTPConnectError 554 surfaces with 'Not allowed' message"""
        err = smtplib.SMTPConnectError(554, "Not allowed")
        with patch("smtplib.SMTP_SSL", side_effect=err):
            with self.assertRaises(checkdmarc.smtp.SMTPError) as ctx:
                checkdmarc.smtp.test_tls("mail.example.com")
        self.assertIn("554", str(ctx.exception))
        self.assertIn("Not allowed", str(ctx.exception))

    def testSMTPConnectErrorOther(self):
        """SMTPConnectError with non-554 code surfaces with the error code"""
        err = smtplib.SMTPConnectError(421, "Service not available")
        with patch("smtplib.SMTP_SSL", side_effect=err):
            with self.assertRaises(checkdmarc.smtp.SMTPError) as ctx:
                checkdmarc.smtp.test_tls("mail.example.com")
        self.assertIn("421", str(ctx.exception))

    def testSMTPHeloError(self):
        """SMTPHeloError surfaces with 'HELO error: ...'"""
        err = smtplib.SMTPHeloError(500, "Bad HELO")
        with patch("smtplib.SMTP_SSL", side_effect=err):
            with self.assertRaises(checkdmarc.smtp.SMTPError) as ctx:
                checkdmarc.smtp.test_tls("mail.example.com")
        self.assertIn("HELO error", str(ctx.exception))

    def testOSError(self):
        """OSError surfaces as SMTPError"""
        with patch("smtplib.SMTP_SSL", side_effect=OSError("Network unreachable")):
            self.assertRaises(
                checkdmarc.smtp.SMTPError,
                checkdmarc.smtp.test_tls,
                "mail.example.com",
            )

    def testGenericException(self):
        """Unanticipated exceptions still surface as SMTPError"""
        with patch("smtplib.SMTP_SSL", side_effect=RuntimeError("oops")):
            self.assertRaises(
                checkdmarc.smtp.SMTPError,
                checkdmarc.smtp.test_tls,
                "mail.example.com",
            )


class TestTestSTARTTLS(unittest.TestCase):
    """Coverage for checkdmarc.smtp.test_starttls (port 25 / STARTTLS)"""

    def testSuccessWithSTARTTLS(self):
        """STARTTLS extension is offered, used, and the success is cached"""
        cache = ExpiringDict(max_len=10, max_age_seconds=60)
        fake_server = MagicMock()
        fake_server.__enter__.return_value = fake_server
        fake_server.has_extn.return_value = True
        with patch("smtplib.SMTP", return_value=fake_server):
            result = checkdmarc.smtp.test_starttls("mail.example.com", cache=cache)
        self.assertTrue(result)
        fake_server.starttls.assert_called_once()
        # First-write into an empty ExpiringDict must succeed — see the
        # `if cache is not None:` check in smtp.py (an empty dict is falsy).
        self.assertEqual(cache["mail.example.com"], {"starttls": True, "error": None})

    def testNoSTARTTLSExtension(self):
        """Server reachable but no STARTTLS extension returns False"""
        fake_server = MagicMock()
        fake_server.__enter__.return_value = fake_server
        fake_server.has_extn.return_value = False
        with patch("smtplib.SMTP", return_value=fake_server):
            result = checkdmarc.smtp.test_starttls("mail.example.com")
        self.assertFalse(result)
        fake_server.starttls.assert_not_called()

    def testCacheHitSuccess(self):
        """Cached STARTTLS success returns without touching the network"""
        cache = ExpiringDict(max_len=10, max_age_seconds=60)
        cache["mail.example.com"] = {"starttls": True, "error": None}
        with patch("smtplib.SMTP") as mock_smtp:
            result = checkdmarc.smtp.test_starttls("mail.example.com", cache=cache)
        self.assertTrue(result)
        mock_smtp.assert_not_called()

    def testCacheHitError(self):
        """Cached STARTTLS error raises SMTPError"""
        cache = ExpiringDict(max_len=10, max_age_seconds=60)
        cache["mail.example.com"] = {"starttls": False, "error": "Cached failure"}
        self.assertRaises(
            checkdmarc.smtp.SMTPError,
            checkdmarc.smtp.test_starttls,
            "mail.example.com",
            cache=cache,
        )

    def testDNSResolutionFailed(self):
        """socket.gaierror surfaces as 'DNS resolution failed'"""
        with patch("smtplib.SMTP", side_effect=socket.gaierror):
            with self.assertRaises(checkdmarc.smtp.SMTPError) as ctx:
                checkdmarc.smtp.test_starttls("mail.example.com")
        self.assertIn("DNS resolution failed", str(ctx.exception))

    def testConnectionRefused(self):
        """ConnectionRefusedError surfaces as 'Connection refused'"""
        with patch("smtplib.SMTP", side_effect=ConnectionRefusedError):
            self.assertRaises(
                checkdmarc.smtp.SMTPError,
                checkdmarc.smtp.test_starttls,
                "mail.example.com",
            )

    def testTimeout(self):
        """TimeoutError surfaces as 'Connection timed out'"""
        with patch("smtplib.SMTP", side_effect=TimeoutError):
            self.assertRaises(
                checkdmarc.smtp.SMTPError,
                checkdmarc.smtp.test_starttls,
                "mail.example.com",
            )

    def testSMTPConnectError554(self):
        """SMTPConnectError 554 surfaces with 'Not allowed' message"""
        err = smtplib.SMTPConnectError(554, "Not allowed")
        with patch("smtplib.SMTP", side_effect=err):
            with self.assertRaises(checkdmarc.smtp.SMTPError) as ctx:
                checkdmarc.smtp.test_starttls("mail.example.com")
        self.assertIn("554", str(ctx.exception))


class TestGetMxHosts(unittest.TestCase):
    """Coverage for checkdmarc.smtp.get_mx_hosts"""

    @staticmethod
    def _mx(hostname, preference=10):
        return {"preference": preference, "hostname": hostname}

    def _patch_dns(
        self,
        mx_records,
        *,
        a_records=None,
        reverse=None,
        dnssec=False,
        tlsa=None,
    ):
        """Return a list of patch context managers seeding the DNS helpers."""
        return [
            patch("checkdmarc.smtp.get_mx_records", return_value=mx_records),
            patch(
                "checkdmarc.smtp.get_a_records",
                return_value=a_records if a_records is not None else ["192.0.2.1"],
            ),
            patch(
                "checkdmarc.smtp.get_reverse_dns",
                return_value=reverse if reverse is not None else [],
            ),
            patch("checkdmarc.smtp.test_dnssec", return_value=dnssec),
            patch(
                "checkdmarc.smtp.get_tlsa_records",
                return_value=tlsa if tlsa is not None else [],
            ),
        ]

    def testSuccessSkipTLS(self):
        """A clean single-MX domain returns no warnings when skip_tls=True"""
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            a_records=["192.0.2.1"],
            reverse=["mail.example.com"],
        )
        for p in patches:
            p.start()
        try:
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        finally:
            for p in patches:
                p.stop()
        self.assertEqual(len(result["hosts"]), 1)
        self.assertEqual(result["hosts"][0]["hostname"], "mail.example.com")
        self.assertEqual(result["warnings"], [])

    def testDuplicateHostname(self):
        """Duplicate MX hostnames produce one warning"""
        patches = self._patch_dns(
            [
                self._mx("mail.example.com", preference=10),
                self._mx("mail.example.com", preference=20),
            ],
            reverse=["mail.example.com"],
        )
        for p in patches:
            p.start()
        try:
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        finally:
            for p in patches:
                p.stop()
        self.assertTrue(
            any("listed in multiple MX records" in w for w in result["warnings"])
        )

    def testUnapprovedHostname(self):
        """An MX outside approved_hostnames triggers a warning"""
        patches = self._patch_dns(
            [self._mx("mail.evil.example")],
            reverse=["mail.evil.example"],
        )
        for p in patches:
            p.start()
        try:
            result = checkdmarc.smtp.get_mx_hosts(
                "example.com",
                skip_tls=True,
                approved_hostnames=["good.example.com"],
            )
        finally:
            for p in patches:
                p.stop()
        self.assertTrue(any("Unapproved MX hostname" in w for w in result["warnings"]))

    def testMtaStsPatternMismatch(self):
        """An MX that is not in the MTA-STS patterns triggers a warning"""
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            reverse=["mail.example.com"],
        )
        for p in patches:
            p.start()
        try:
            result = checkdmarc.smtp.get_mx_hosts(
                "example.com",
                skip_tls=True,
                mta_sts_mx_patterns=["*.other.example"],
            )
        finally:
            for p in patches:
                p.stop()
        self.assertTrue(
            any("not included in the MTA-STS policy" in w for w in result["warnings"])
        )

    def testNoAddresses(self):
        """An MX with no A/AAAA records produces a warning"""
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            a_records=[],
            reverse=[],
        )
        for p in patches:
            p.start()
        try:
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        finally:
            for p in patches:
                p.stop()
        self.assertTrue(
            any(
                "does not have any A or AAAA DNS records" in w
                for w in result["warnings"]
            )
        )

    def testNoReverseDNS(self):
        """An address with no reverse DNS produces a warning"""
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            a_records=["192.0.2.1"],
            reverse=[],
        )
        for p in patches:
            p.start()
        try:
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        finally:
            for p in patches:
                p.stop()
        self.assertTrue(
            any("reverse DNS" in w and "PTR" in w for w in result["warnings"])
        )

    def testParkedWithMx(self):
        """parked=True with MX records produces a parked-domain warning"""
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            reverse=["mail.example.com"],
        )
        for p in patches:
            p.start()
        try:
            result = checkdmarc.smtp.get_mx_hosts(
                "example.com", skip_tls=True, parked=True
            )
        finally:
            for p in patches:
                p.stop()
        self.assertIn("MX records found on parked domains", result["warnings"])

    def testStarttlsSupported(self):
        """When STARTTLS is supported, host['starttls'] and host['tls'] are True"""
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            reverse=["mail.example.com"],
        )
        for p in patches:
            p.start()
        try:
            with patch("checkdmarc.smtp.test_starttls", return_value=True):
                result = checkdmarc.smtp.get_mx_hosts("example.com")
        finally:
            for p in patches:
                p.stop()
        host = cast(Any, result["hosts"][0])
        self.assertTrue(host["starttls"])
        self.assertTrue(host["tls"])

    def testStarttlsFallsBackToTLS(self):
        """When STARTTLS is not supported, test_tls is consulted"""
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            reverse=["mail.example.com"],
        )
        for p in patches:
            p.start()
        try:
            with patch("checkdmarc.smtp.test_starttls", return_value=False):
                with patch("checkdmarc.smtp.test_tls", return_value=True):
                    result = checkdmarc.smtp.get_mx_hosts("example.com")
        finally:
            for p in patches:
                p.stop()
        host = cast(Any, result["hosts"][0])
        self.assertFalse(host["starttls"])
        self.assertTrue(host["tls"])
        self.assertTrue(
            any("STARTTLS is not supported" in w for w in result["warnings"])
        )

    def testNeitherTlsSupported(self):
        """When neither STARTTLS nor SMTP_SSL works, both warnings are recorded"""
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            reverse=["mail.example.com"],
        )
        for p in patches:
            p.start()
        try:
            with patch("checkdmarc.smtp.test_starttls", return_value=False):
                with patch("checkdmarc.smtp.test_tls", return_value=False):
                    result = checkdmarc.smtp.get_mx_hosts("example.com")
        finally:
            for p in patches:
                p.stop()
        self.assertTrue(
            any("STARTTLS is not supported" in w for w in result["warnings"])
        )
        self.assertTrue(
            any("SSL/TLS is not supported" in w for w in result["warnings"])
        )

    def testTlsTestRaisesSmtpError(self):
        """SMTPError from test_starttls is captured as a warning, not raised"""
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            reverse=["mail.example.com"],
        )
        for p in patches:
            p.start()
        try:
            with patch(
                "checkdmarc.smtp.test_starttls",
                side_effect=checkdmarc.smtp.SMTPError("Connection refused"),
            ):
                result = checkdmarc.smtp.get_mx_hosts("example.com")
        finally:
            for p in patches:
                p.stop()
        self.assertTrue(any("Connection refused" in w for w in result["warnings"]))

    def testTlsaRecordsPopulated(self):
        """TLSA records found for an MX host are attached to the result"""
        tlsa = [{"name": "_25._tcp.mail.example.com", "data": "tlsa-data"}]
        patches = self._patch_dns(
            [self._mx("mail.example.com")],
            reverse=["mail.example.com"],
            tlsa=tlsa,
        )
        for p in patches:
            p.start()
        try:
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        finally:
            for p in patches:
                p.stop()
        host = cast(Any, result["hosts"][0])
        self.assertEqual(host["tlsa"], tlsa)


class TestCheckMx(unittest.TestCase):
    """Coverage for checkdmarc.smtp.check_mx"""

    def testSuccess(self):
        """check_mx returns get_mx_hosts results on success"""
        with patch("checkdmarc.smtp.get_mx_hosts") as mock_mx:
            mock_mx.return_value = {"hosts": [], "warnings": []}
            result = checkdmarc.smtp.check_mx("example.com")
        self.assertIn("hosts", result)
        self.assertIn("warnings", result)

    def testDNSException(self):
        """check_mx converts DNSException into an error result"""
        from checkdmarc.utils import DNSException

        with patch("checkdmarc.smtp.get_mx_hosts", side_effect=DNSException("no MX")):
            result = checkdmarc.smtp.check_mx("example.com")
        self.assertEqual(result["hosts"], [])
        self.assertIn("error", result)


class TestTLSCacheWritesOnError(unittest.TestCase):
    """test_tls writes to the cache on every exception branch when a cache is supplied"""

    def _make_cache(self):
        return ExpiringDict(max_len=10, max_age_seconds=60)

    def _run_and_check_cache(self, exc):
        cache = self._make_cache()
        with patch("smtplib.SMTP_SSL", side_effect=exc):
            with self.assertRaises(checkdmarc.smtp.SMTPError):
                checkdmarc.smtp.test_tls("mail.example.com", cache=cache)
        entry = cast(dict, cache["mail.example.com"])
        self.assertFalse(entry["tls"])
        self.assertIsNotNone(entry["error"])

    def testConnectionRefusedCached(self):
        self._run_and_check_cache(ConnectionRefusedError())

    def testConnectionResetCached(self):
        self._run_and_check_cache(ConnectionResetError())

    def testConnectionAbortedCached(self):
        self._run_and_check_cache(ConnectionAbortedError())

    def testTimeoutCached(self):
        self._run_and_check_cache(TimeoutError())

    def testBlockingIOErrorCached(self):
        self._run_and_check_cache(BlockingIOError("would block"))

    def testSSLErrorCached(self):
        self._run_and_check_cache(ssl.SSLError("bad handshake"))

    def testSMTPConnectErrorCached(self):
        self._run_and_check_cache(smtplib.SMTPConnectError(421, "Try later"))

    def testSMTPHeloErrorCached(self):
        self._run_and_check_cache(smtplib.SMTPHeloError(500, "Bad HELO"))

    def testSMTPExceptionCached(self):
        """SMTPException (the base class) hits a distinct handler"""
        self._run_and_check_cache(smtplib.SMTPException("(550, b'denied')"))

    def testSMTPExceptionWithBareMessage(self):
        """An SMTPException whose message isn't a tuple-formatted string falls
        through the inner try/except ValueError branch"""
        cache = self._make_cache()
        with patch("smtplib.SMTP_SSL", side_effect=smtplib.SMTPException("denied")):
            with self.assertRaises(checkdmarc.smtp.SMTPError):
                checkdmarc.smtp.test_tls("mail.example.com", cache=cache)
        entry = cast(dict, cache["mail.example.com"])
        # Even when the inner int() ValueError fires, the message is cached.
        self.assertIsNotNone(entry["error"])

    def testOSErrorCached(self):
        self._run_and_check_cache(OSError("Network unreachable"))

    def testGenericExceptionCached(self):
        self._run_and_check_cache(RuntimeError("oops"))


class TestSTARTTLSCacheAndExtraBranches(unittest.TestCase):
    """test_starttls cache-on-error coverage and remaining exception handlers"""

    def _make_cache(self):
        return ExpiringDict(max_len=10, max_age_seconds=60)

    def _run_and_check_cache(self, exc):
        cache = self._make_cache()
        with patch("smtplib.SMTP", side_effect=exc):
            with self.assertRaises(checkdmarc.smtp.SMTPError):
                checkdmarc.smtp.test_starttls("mail.example.com", cache=cache)
        entry = cast(dict, cache["mail.example.com"])
        self.assertFalse(entry["starttls"])
        self.assertIsNotNone(entry["error"])

    def testDNSResolutionCached(self):
        self._run_and_check_cache(socket.gaierror())

    def testConnectionRefusedCached(self):
        self._run_and_check_cache(ConnectionRefusedError())

    def testConnectionResetCached(self):
        self._run_and_check_cache(ConnectionResetError())

    def testConnectionAbortedCached(self):
        self._run_and_check_cache(ConnectionAbortedError())

    def testTimeoutCached(self):
        self._run_and_check_cache(TimeoutError())

    def testBlockingIOErrorCached(self):
        self._run_and_check_cache(BlockingIOError("would block"))

    def testSSLErrorCached(self):
        self._run_and_check_cache(ssl.SSLError("bad handshake"))

    def testSMTPConnectErrorCached(self):
        self._run_and_check_cache(smtplib.SMTPConnectError(421, "Try later"))

    def testSMTPHeloErrorCached(self):
        self._run_and_check_cache(smtplib.SMTPHeloError(500, "Bad HELO"))

    def testSMTPExceptionCached(self):
        self._run_and_check_cache(smtplib.SMTPException("(550, b'denied')"))

    def testOSErrorCached(self):
        self._run_and_check_cache(OSError("Network unreachable"))

    def testGenericExceptionCached(self):
        self._run_and_check_cache(RuntimeError("oops"))


class TestGetMxHostsEdgeCases(unittest.TestCase):
    """Branches of get_mx_hosts not covered by TestGetMxHosts"""

    @staticmethod
    def _mx(hostname, preference=10):
        return {"preference": preference, "hostname": hostname}

    def testDnssecExceptionLogged(self):
        """A DNSSEC test that raises is swallowed (logged) and dnssec stays False"""
        from contextlib import ExitStack

        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_mx_records",
                    return_value=[self._mx("mail.example.com")],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.test_dnssec", side_effect=RuntimeError("oops"))
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_a_records", return_value=["192.0.2.1"])
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_reverse_dns",
                    return_value=["mail.example.com"],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_tlsa_records", return_value=[])
            )
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        host = cast(Any, result["hosts"][0])
        self.assertFalse(host["dnssec"])

    def testMsv1InvalidHostnameWarningHasHint(self):
        """A hostname ending in .msv1.invalid gets the Office 365 TXT-record hint"""
        from contextlib import ExitStack
        from checkdmarc.utils import DNSException

        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_mx_records",
                    return_value=[self._mx("mail.msv1.invalid")],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.test_dnssec", return_value=False)
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_a_records",
                    side_effect=DNSException("no records"),
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_tlsa_records", return_value=[])
            )
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        self.assertTrue(any("Office 365" in w for w in result["warnings"]))

    def testReverseDnsMismatchWarning(self):
        """Reverse DNS resolves to a hostname whose A records don't include the MX address"""
        from contextlib import ExitStack

        # A->192.0.2.1, PTR->ptr.example.com, ptr.example.com->A->203.0.113.1 (mismatch)
        a_record_results = [["192.0.2.1"], ["203.0.113.1"]]
        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_mx_records",
                    return_value=[self._mx("mail.example.com")],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.test_dnssec", return_value=False)
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_a_records", side_effect=a_record_results)
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_reverse_dns",
                    return_value=["ptr.example.com"],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_tlsa_records", return_value=[])
            )
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        self.assertTrue(any("do not resolve to" in w for w in result["warnings"]))

    def testReverseDnsAResolutionFails(self):
        """A DNSException when re-resolving the PTR hostname becomes a warning"""
        from contextlib import ExitStack
        from checkdmarc.utils import DNSException

        # First get_a_records (the MX) succeeds; second (the PTR) raises
        a_record_results = [["192.0.2.1"], DNSException("re-resolution failed")]
        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_mx_records",
                    return_value=[self._mx("mail.example.com")],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.test_dnssec", return_value=False)
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_a_records", side_effect=a_record_results)
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_reverse_dns",
                    return_value=["ptr.example.com"],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_tlsa_records", return_value=[])
            )
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        self.assertTrue(any("re-resolution failed" in w for w in result["warnings"]))

    def testReverseDnsLookupRaises(self):
        """A DNSException from get_reverse_dns is swallowed; the PTR list becomes empty"""
        from contextlib import ExitStack
        from checkdmarc.utils import DNSException

        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_mx_records",
                    return_value=[self._mx("mail.example.com")],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.test_dnssec", return_value=False)
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_a_records", return_value=["192.0.2.1"])
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_reverse_dns",
                    side_effect=DNSException("ptr lookup failed"),
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_tlsa_records", return_value=[])
            )
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=True)
        # An empty PTR list produces the "no reverse DNS records" warning
        self.assertTrue(
            any("reverse DNS" in w and "PTR" in w for w in result["warnings"])
        )

    def testStarttlsRaisesDnsException(self):
        """test_starttls raising DNSException becomes a warning and tls/starttls=False"""
        from contextlib import ExitStack
        from checkdmarc.utils import DNSException

        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_mx_records",
                    return_value=[self._mx("mail.example.com")],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.test_dnssec", return_value=False)
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_a_records", return_value=["192.0.2.1"])
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_reverse_dns",
                    return_value=["mail.example.com"],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_tlsa_records", return_value=[])
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.test_starttls",
                    side_effect=DNSException("dns broken"),
                )
            )
            result = checkdmarc.smtp.get_mx_hosts("example.com")
        host = cast(Any, result["hosts"][0])
        self.assertFalse(host["starttls"])
        self.assertFalse(host["tls"])

    def testWindowsSkipsTls(self):
        """On Windows, test_tls is skipped and a warning logged via stdlib logging"""
        from contextlib import ExitStack

        with ExitStack() as stack:
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_mx_records",
                    return_value=[self._mx("mail.example.com")],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.test_dnssec", return_value=False)
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_a_records", return_value=["192.0.2.1"])
            )
            stack.enter_context(
                patch(
                    "checkdmarc.smtp.get_reverse_dns",
                    return_value=["mail.example.com"],
                )
            )
            stack.enter_context(
                patch("checkdmarc.smtp.get_tlsa_records", return_value=[])
            )
            stack.enter_context(patch("platform.system", return_value="Windows"))
            stack.enter_context(patch("checkdmarc.smtp.test_starttls"))
            stack.enter_context(patch("checkdmarc.smtp.test_tls"))
            result = checkdmarc.smtp.get_mx_hosts("example.com", skip_tls=False)
        # When skip_tls flips to True via the Windows branch, no tls/starttls keys
        # are added to the host dict.
        host = cast(Any, result["hosts"][0])
        self.assertNotIn("tls", host)
        self.assertNotIn("starttls", host)


if __name__ == "__main__":
    unittest.main(verbosity=2)
