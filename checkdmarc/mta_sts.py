# -*- coding: utf-8 -*-
"""SMTP MTA Strict Transport Security (MTA-STS) validation"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict

import dns
from pyleri import (Grammar,
                    Regex,
                    Sequence,
                    List,
                    )

from checkdmarc.utils import query_dns, WSP_REGEX

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


STS_VERSION_REGEX_STRING = fr"v{WSP_REGEX}*={WSP_REGEX}*DMARC1{WSP_REGEX}*;"
STS_TAG_VALUE_REGEX_STRING = fr"([a-z]{{1,2}}){WSP_REGEX}*={WSP_REGEX}*(.+)"


class _STSWarning(Exception):
    """Raised when a non-fatal STS error occurs"""


class STSError(Exception):
    """Raised when a fatal STS error occurs"""
    def __init__(self, msg: str, data: dict = None):
        """
       Args:
           msg (str): The error message
           data (dict): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class STSRecordNotFound(STSError):
    """Raised when an STS record could not be found"""
    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class STSRecordSyntaxError(STSError):
    """Raised when an STS DNS record syntax error is found"""


class InvalidSTSTag(STSRecordSyntaxError):
    """Raised when an invalid STS tag is found"""


class InvalidSTSTagValue(STSRecordSyntaxError):
    """Raised when an invalid STS tag value is found"""


class UnrelatedTXTRecordFoundAtSTS(STSError):
    """Raised when a TXT record unrelated to STS is found"""


class SPFRecordFoundWhereSTSRecordShouldBe(UnrelatedTXTRecordFoundAtSTS):
    """Raised when an SPF record is found where an STS record should be;
        most likely, the ``selector_STS`` subdomain
        record does not actually exist, and the request for ``TXT`` records was
        redirected to the base domain"""


class STSRecordInWrongLocation(STSError):
    """Raised when an STS record is found at the root of a domain"""


class MultipleSTSRecords(STSError):
    """Raised when multiple STS records are found"""


class STSPolicyError(STSError):
    """Raised when the STS policy cannot be obtained or parsed"""


class STSPolicySyntaxError(STSPolicyError):
    """Raised when a syntax error is found in an STS policy"""


class _STSGrammar(Grammar):
    """Defines Pyleri grammar for STS records"""
    version_tag = Regex(STS_VERSION_REGEX_STRING, re.IGNORECASE)
    tag_value = Regex(STS_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = Sequence(
        version_tag,
        List(
            tag_value,
            delimiter=Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"),
            opt=True))


def query_sts_record(domain: str,
                     nameservers: list[str] = None,
                     resolver: dns.resolver.Resolver = None,
                     timeout: float = 2.0) -> OrderedDict:
    """
    Queries DNS for an STS record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``record`` - the unparsed STS record string
                     - ``warnings`` - warning conditions found

     Raises:
        :exc:`checkdmarc.STSRecordNotFound`
        :exc:`checkdmarc.STSRecordInWrongLocation`
        :exc:`checkdmarc.MultipleSTSRecords`

    """
    logging.debug(f"Checking for a STS record on {domain}")
    warnings = []
    domain = domain.lower()
    target = f"_mta-sts.{domain}"
    sts_record = None
    sts_record_count = 0
    unrelated_records = []

    try:
        records = query_dns(target, "TXT", nameservers=nameservers,
                            resolver=resolver, timeout=timeout)
        for record in records:
            if record.startswith("v=STSv1"):
                sts_record_count += 1
            else:
                unrelated_records.append(record)

        if sts_record_count > 1:
            raise MultipleSTSRecords(
                "Multiple STS records are not permitted")
        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            raise UnrelatedTXTRecordFoundAtSTS(
                "Unrelated TXT records were discovered. These should be "
                "removed, as some receivers may not expect to find "
                "unrelated TXT records "
                f"at {target}\n\n{ur_str}")
        sts_record = records[0]

    except dns.resolver.NoAnswer:
        try:
            records = query_dns(domain, "TXT",
                                nameservers=nameservers, resolver=resolver,
                                timeout=timeout)
            for record in records:
                if record.startswith("v=STS1"):
                    raise STSRecordInWrongLocation(
                        "The STS record must be located at "
                        f"{target}, not {domain}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise STSRecordNotFound(
                f"The domain {domain} does not exist")
        except Exception as error:
            STSRecordNotFound(error)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as error:
        raise STSRecordNotFound(error)
    try:
        root_records = query_dns(domain, "TXT",
                                 nameservers=nameservers, resolver=resolver,
                                 timeout=timeout)
        for root_record in root_records:
            if root_record.startswith("v=STSv1"):
                warnings.append(f"STS record at root of {domain} "
                                "has no effect")
    except Exception:
        pass

    if sts_record is None:
        raise STSRecordNotFound(
            "A STS record does not exist for this domain or its base domain")

    return OrderedDict([("record", sts_record),
                        ("warnings", warnings)])
