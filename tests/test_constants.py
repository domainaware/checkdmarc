"""Tests for checkdmarc._constants"""

import importlib
import os
import unittest
from unittest.mock import patch

import checkdmarc


class Test(unittest.TestCase):
    def testConstantsVersion(self):
        """Version string is defined"""
        self.assertIsNotNone(checkdmarc.__version__)
        self.assertIsInstance(checkdmarc.__version__, str)

    def testConstantsEnvironmentOverrides(self):
        """Environment variable overrides work for constants"""
        import checkdmarc._constants as constants

        self.assertIsInstance(constants.CACHE_MAX_LEN, int)
        self.assertIsInstance(constants.CACHE_MAX_AGE_SECONDS, int)
        self.assertIsInstance(constants.SYNTAX_ERROR_MARKER, str)


class TestEnvironmentOverrideBranches(unittest.TestCase):
    """Each cache-size / cache-age constant honors an env var of the same
    name. The branches re-import the module under a patched environment
    and assert the overridden value lands on the constant.
    """

    @staticmethod
    def _reload_with_env(env_overrides):
        """Reload checkdmarc._constants with the given env-var overrides applied."""
        import checkdmarc._constants as constants

        new_env = {**os.environ, **env_overrides}
        with patch.dict(os.environ, new_env, clear=True):
            importlib.reload(constants)
        return constants

    def tearDown(self):
        """Restore the module to its baseline state so test ordering doesn't matter"""
        import checkdmarc._constants as constants

        importlib.reload(constants)

    def testCacheMaxLenOverride(self):
        constants = self._reload_with_env({"CACHE_MAX_LEN": "42"})
        self.assertEqual(constants.CACHE_MAX_LEN, 42)
        # Per-subsystem caches default to the umbrella value when their
        # own override isn't set
        self.assertEqual(constants.DNS_CACHE_MAX_LEN, 42)
        self.assertEqual(constants.DNSSEC_CACHE_MAX_LEN, 42)
        self.assertEqual(constants.SMTP_CACHE_MAX_LEN, 42)

    def testCacheMaxAgeOverride(self):
        constants = self._reload_with_env({"CACHE_MAX_AGE_SECONDS": "60"})
        self.assertEqual(constants.CACHE_MAX_AGE_SECONDS, 60)
        self.assertEqual(constants.DNS_CACHE_MAX_AGE_SECONDS, 60)
        self.assertEqual(constants.DNSSEC_CACHE_MAX_AGE_SECONDS, 60)
        self.assertEqual(constants.SMTP_CACHE_MAX_AGE_SECONDS, 60)

    def testDnsCacheOverridesIndependent(self):
        """Per-subsystem env vars take precedence over the umbrella default"""
        constants = self._reload_with_env(
            {
                "DNS_CACHE_MAX_LEN": "100",
                "DNS_CACHE_MAX_AGE_SECONDS": "30",
            }
        )
        self.assertEqual(constants.DNS_CACHE_MAX_LEN, 100)
        self.assertEqual(constants.DNS_CACHE_MAX_AGE_SECONDS, 30)

    def testDnssecCacheOverridesIndependent(self):
        constants = self._reload_with_env(
            {
                "DNSSEC_CACHE_MAX_LEN": "200",
                "DNSSEC_CACHE_MAX_AGE_SECONDS": "120",
            }
        )
        self.assertEqual(constants.DNSSEC_CACHE_MAX_LEN, 200)
        self.assertEqual(constants.DNSSEC_CACHE_MAX_AGE_SECONDS, 120)

    def testSmtpCacheOverridesIndependent(self):
        constants = self._reload_with_env(
            {
                "SMTP_CACHE_MAX_LEN": "300",
                "SMTP_CACHE_MAX_AGE_SECONDS": "180",
            }
        )
        self.assertEqual(constants.SMTP_CACHE_MAX_LEN, 300)
        self.assertEqual(constants.SMTP_CACHE_MAX_AGE_SECONDS, 180)


if __name__ == "__main__":
    unittest.main(verbosity=2)
