# -*- coding: utf-8 -*-
"""Constant values"""

from __future__ import annotations
import platform

"""Copyright 2019-2023 Sean Whalen

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License."""

__version__ = "5.1.0"

OS = platform.system()
OS_RELEASE = platform.release()
USER_AGENT = f"Mozilla/5.0 (({OS} {OS_RELEASE})) checkdmarc/{__version__}"
SYNTAX_ERROR_MARKER = "➞"
