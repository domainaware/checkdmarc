# -*- coding: utf-8 -*-
"""Constant values"""

from __future__ import annotations
import platform
import os

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

__version__ = "5.13.0"

OS = platform.system()
OS_RELEASE = platform.release()
USER_AGENT = f"Mozilla/5.0 (({OS} {OS_RELEASE})) checkdmarc/{__version__}"
SYNTAX_ERROR_MARKER = "➞"
DEFAULT_HTTP_TIMEOUT = 2.0
CACHE_MAX_LEN = 200000
CACHE_MAX_AGE_SECONDS = 1800

env = os.environ

if "CACHE_MAX_LEN" in env:
    CACHE_MAX_LEN = int(env["CACHE_MAX_LEN"])
if "CACHE_MAX_AGE_SECONDS" in env:
    CACHE_MAX_AGE_SECONDS = int(env["CACHE_MAX_AGE_SECONDS"])

DNS_CACHE_MAX_LEN = CACHE_MAX_LEN
if "DNS_CACHE_MAX_LEN" in env:
    DNS_CACHE_MAX_LEN = int(env["DNS_CACHE_MAX_LEN"])
DNS_CACHE_MAX_AGE_SECONDS = CACHE_MAX_AGE_SECONDS
if "DNS_CACHE_MAX_AGE_SECONDS" in env:
    DNS_CACHE_MAX_AGE_SECONDS = int(env["DNS_CACHE_MAX_AGE_SECONDS"])

DNSSEC_CACHE_MAX_LEN = CACHE_MAX_LEN
if "DNSSEC_CACHE_MAX_LEN" in env:
    DNSSEC_CACHE_MAX_LEN = int(env["DNSSEC_CACHE_MAX_LEN"])
DNSSEC_CACHE_MAX_AGE_SECONDS = CACHE_MAX_AGE_SECONDS
if "DNSSEC_CACHE_MAX_AGE_SECONDS" in env:
    DNSSEC_CACHE_MAX_AGE_SECONDS = int(env["DNSSEC_CACHE_MAX_AGE_SECONDS"])

SMTP_CACHE_MAX_LEN = CACHE_MAX_LEN
if "SMTP_CACHE_MAX_LEN" in env:
    SMTP_CACHE_MAX_LEN = int(env["SMTP_CACHE_MAX_LEN"])
SMTP_CACHE_MAX_AGE_SECONDS = CACHE_MAX_AGE_SECONDS
if "SMTP_CACHE_MAX_AGE_SECONDS" in env:
    SMTP_CACHE_MAX_AGE_SECONDS = int(env["SMTP_CACHE_MAX_AGE_SECONDS"])
