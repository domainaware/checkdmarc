# -*- coding: utf-8 -*-
"""Constant values"""

from __future__ import annotations
import platform

__version__ = "5.0.0"

OS = platform.system()
OS_RELEASE = platform.release()
USER_AGENT = f"Mozilla/5.0 (({OS} {OS_RELEASE})) checkdmarc/{__version__}"
SYNTAX_ERROR_MARKER = "➞"
