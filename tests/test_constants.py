"""Tests for checkdmarc._constants"""

import unittest

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
