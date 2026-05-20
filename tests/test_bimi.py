"""Tests for checkdmarc.bimi"""

import os
import unittest
from typing import Any, cast

import checkdmarc.bimi

OFFLINE_MODE = os.environ.get("GITHUB_ACTIONS", "false").lower() == "true"


class Test(unittest.TestCase):
    @unittest.skipIf(OFFLINE_MODE, "No network access in GitHub Actions")
    def testBIMI(self):
        """Test BIMI checks"""
        domain = "chase.com"

        results = checkdmarc.bimi.check_bimi(domain)

        self.assertEqual(len(cast(Any, results)["warnings"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
