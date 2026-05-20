"""Tests for checkdmarc.bimi"""

import os
import unittest
from unittest.mock import patch
from typing import Any, cast

import checkdmarc.bimi

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"

network_test = unittest.skipIf(
    OFFLINE_MODE, "Real-network test skipped on GitHub Actions"
)
mocked_only = unittest.skipUnless(
    OFFLINE_MODE, "Mocked counterpart skipped locally; network test covers this"
)


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


if __name__ == "__main__":
    unittest.main(verbosity=2)
