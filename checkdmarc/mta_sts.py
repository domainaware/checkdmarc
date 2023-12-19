# -*- coding: utf-8 -*-
"""SMTP MTA Strict Transport Security (MTA-STS) validation"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict

import dns
import requests
from pyleri import (Grammar,
                    Regex,
                    Sequence,
                    List,
                    )

from checkdmarc.utils import query_dns, WSP_REGEX
from checkdmarc._constants import SYNTAX_ERROR_MARKER, USER_AGENT

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


STS_VERSION_REGEX_STRING = fr"v{WSP_REGEX}*={WSP_REGEX}*STSv1{WSP_REGEX}*;"
STS_TAG_VALUE_REGEX_STRING = fr"([a-z]{{1,2}}){WSP_REGEX}*={WSP_REGEX}*([\
a-z0-9]+)"


class _MTASTSWarning(Exception):
    """Raised when a non-fatal MTA-STS error occurs"""


class MTASTSError(Exception):
    """Raised when a fatal MTA-STS error occurs"""
    def __init__(self, msg: str, data: dict = None):
        """
       Args:
           msg (str): The error message
           data (dict): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class MTASTSRecordNotFound(MTASTSError):
    """Raised when an MTA-STS record could not be found"""
    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class MTASTSRecordSyntaxError(MTASTSError):
    """Raised when an MTA-STS DNS record syntax error is found"""


class InvalidSTSTag(MTASTSRecordSyntaxError):
    """Raised when an invalid MTA-STS tag is found"""


class InvalidSTSTagValue(MTASTSRecordSyntaxError):
    """Raised when an invalid MTA-STS tag value is found"""


class UnrelatedTXTRecordFoundAtMTASTS(MTASTSError):
    """Raised when a TXT record unrelated to MTA-STS is found"""


class SPFRecordFoundWhereSTSRecordShouldBe(UnrelatedTXTRecordFoundAtMTASTS):
    """Raised when an SPF record is found where an MTA-STS record should be;
        most likely, the ``selector_STS`` subdomain
        record does not actually exist, and the request for ``TXT`` records was
        redirected to the base domain"""


class MTASTSRecordInWrongLocation(MTASTSError):
    """Raised when an MTA-STS record is found at the root of a domain"""


class MultipleMTASTSRecords(MTASTSError):
    """Raised when multiple MTA-STS records are found"""


class MTASTSPolicyError(MTASTSError):
    """Raised when the MTA-STS policy cannot be obtained or parsed"""


class STSPolicySyntaxError(MTASTSPolicyError):
    """Raised when a syntax error is found in an MTA-STS policy"""


class _STSGrammar(Grammar):
    """Defines Pyleri grammar for MTA-STS records"""
    version_tag = Regex(STS_VERSION_REGEX_STRING, re.IGNORECASE)
    tag_value = Regex(STS_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = Sequence(
        version_tag,
        List(
            tag_value,
            delimiter=Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"),
            opt=True))


mta_sts_tags = OrderedDict(
    v=OrderedDict(name="Version",
                  required=True,
                  description='Currently, only "STSv1" is supported.'),
    id=OrderedDict(name="id",
                   required=True,
                   description='A short string used to track policy '
                               'updates.  This string MUST uniquely identify '
                               'a given instance of a policy, such that '
                               'senders can determine when the policy has '
                               'been updated by comparing to the "id" of a '
                               'previously seen policy. There is no implied '
                               'ordering of "id" fields between revisions.')
)

STS_TAG_VALUE_REGEX = re.compile(STS_TAG_VALUE_REGEX_STRING, re.IGNORECASE)


def query_mta_sts_record(domain: str,
                         nameservers: list[str] = None,
                         resolver: dns.resolver.Resolver = None,
                         timeout: float = 2.0) -> OrderedDict:
    """
    Queries DNS for an MTA-STS record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``record`` - the unparsed MTA-STS record string
                     - ``warnings`` - warning conditions found

     Raises:
        :exc:`checkdmarc.STSRecordNotFound`
        :exc:`checkdmarc.STSRecordInWrongLocation`
        :exc:`checkdmarc.MultipleSTSRecords`

    """
    logging.debug(f"Checking for a MTA-STS record on {domain}")
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
            raise MultipleMTASTSRecords(
                "Multiple MTA-STS records are not permitted")
        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            raise UnrelatedTXTRecordFoundAtMTASTS(
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
                    raise MTASTSRecordInWrongLocation(
                        "The MTA-STS record must be located at "
                        f"{target}, not {domain}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise MTASTSRecordNotFound(
                f"The domain {domain} does not exist")
        except Exception as error:
            MTASTSRecordNotFound(error)

    if sts_record is None:
        raise MTASTSRecordNotFound(
            "A MTA-STS DNS record does not exist for this domain")

    return OrderedDict([("record", sts_record),
                        ("warnings", warnings)])


def parse_mta_sts_record(
        record: str,
        include_tag_descriptions: bool = False,
        syntax_error_marker: str = SYNTAX_ERROR_MARKER) -> OrderedDict:
    """
    Parses an MTA-STS record

    Args:
        record (str): A MTA-STS record
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``tags`` - An ``OrderedDict`` of MTA-STS tags

           - ``value`` - The MTA-STS tag value
           - ``description`` - A description of the tag/value

         - ``warnings`` - A ``list`` of warnings

         .. note::
            ``description`` is only included if
            ``include_tag_descriptions`` is set to ``True``

    Raises:
        :exc:`checkdmarc.STSSyntaxError`
        :exc:`checkdmarc.InvalidSTSTag`
        :exc:`checkdmarc.InvalidSTSTagValue`

    """
    logging.debug("Parsing the MTA-STS record")
    spf_in_dmarc_error_msg = "Found a SPF record where a MTA-STS record " \
                             "should be; most likely, the _mta-sts " \
                             "subdomain record does not actually exist, " \
                             "and the request for TXT records was " \
                             "redirected to the base domain"
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereSTSRecordShouldBe(spf_in_dmarc_error_msg)
    sts_syntax_checker = _STSGrammar()
    parsed_record = sts_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        expecting = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting)))
        marked_record = (record[:parsed_record.pos] + syntax_error_marker +
                         record[parsed_record.pos:])
        expecting = " or ".join(expecting)
        raise MTASTSRecordSyntaxError(f"Error: Expected {expecting} "
                                      f"at position {parsed_record.pos} "
                                      f"(marked with {syntax_error_marker}) "
                                      f"in: {marked_record}")

    pairs = STS_TAG_VALUE_REGEX.findall(record)
    tags = OrderedDict()

    for pair in pairs:
        tag = pair[0].lower().strip()
        tag_value = str(pair[1].strip())
        if tag not in mta_sts_tags:
            raise InvalidSTSTag(f"{tag} is not a valid MTA-STS record tag")
        tags[tag] = OrderedDict(value=tag_value)
        if include_tag_descriptions:
            tags[tag]["description"] = mta_sts_tags[tag]["description"]

    return OrderedDict(tags=tags, warnings=warnings)


def download_mta_sts_policy(domain: str) -> OrderedDict:
    """
    Downloads a domains MTA-HTS policy

    Args:
        domain (str): A domain name

    Returns:

    """
    warnings = []
    headers = {"User-Agent": USER_AGENT}
    session = requests.Session()
    session.headers = headers
    expected_content_type = "text/plain"
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    logging.debug(f"Attempting to download HTA-MTS policy from {url}")
    try:
        response = session.get(url)
        response.raise_for_status()
        if "Content-Type" in response.headers:
            content_type = response.headers["Content-Type"]
            if content_type != expected_content_type:
                warnings.append(f"Content-Type header should be "
                                f"{expected_content_type} not {content_type}")
        else:
            warnings.append("The Content-Type header is missing. It should "
                            f"be set to {expected_content_type}")

    except Exception as e:
        raise MTASTSPolicyError(str(e))

    return OrderedDict(policy=response.text, warnings=warnings)


def parse_mta_sts_policy(policy: str):
    """
    Parses an MTA-STS policy

    Args:
        policy:

    Returns:

    """
