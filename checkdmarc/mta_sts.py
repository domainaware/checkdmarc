# -*- coding: utf-8 -*-
"""SMTP MTA Strict Transport Security (MTA-STS) validation"""

from __future__ import annotations

import logging
import re
from typing import Optional, Union, TypedDict, Literal
from collections.abc import Sequence

import dns.resolver
import dns.exception
from dns.nameserver import Nameserver
import requests
import pyleri

from checkdmarc._constants import DEFAULT_HTTP_TIMEOUT, SYNTAX_ERROR_MARKER, USER_AGENT
from checkdmarc.utils import WSP_REGEX, normalize_domain, query_dns

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


MTA_STS_VERSION_REGEX_STRING = rf"v{WSP_REGEX}*={WSP_REGEX}*STSv1{WSP_REGEX}*;"
MTA_STS_TAG_VALUE_REGEX_STRING = rf"([a-z]{{1,2}}){WSP_REGEX}*={WSP_REGEX}*([\
a-z0-9]+)"

MTA_STS_MX_REGEX_STRING = r"[a-z0-9\-*.]+"
MTA_STS_MX_REGEX = re.compile(MTA_STS_MX_REGEX_STRING, re.IGNORECASE)


class MTASTSError(Exception):
    """Raised when a fatal MTA-STS error occurs"""

    def __init__(self, msg: str, data: Optional[dict] = None):
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


class InvalidMTASTSTag(MTASTSRecordSyntaxError):
    """Raised when an invalid MTA-STS tag is found"""


class InvalidSTSTagValue(MTASTSRecordSyntaxError):
    """Raised when an invalid MTA-STS tag value is found"""


class UnrelatedTXTRecordFoundAtMTASTS(MTASTSError):
    """Raised when a TXT record unrelated to MTA-STS is found"""


class SPFRecordFoundWhereMTASTSRecordShouldBe(UnrelatedTXTRecordFoundAtMTASTS):
    """Raised when an SPF record is found where an MTA-STS record should be;
    most likely, the ``_mta-sts`` subdomain
    record does not actually exist, and the request for ``TXT`` records was
    redirected to the base domain"""


class MTASTSRecordInWrongLocation(MTASTSError):
    """Raised when an MTA-STS record is found at the root of a domain"""


class MultipleMTASTSRecords(MTASTSError):
    """Raised when multiple MTA-STS records are found"""


class MTASTSPolicyError(MTASTSError):
    """Raised when the MTA-STS policy cannot be downloaded or parsed"""


class MTASTSPolicyDownloadError(MTASTSPolicyError):
    """Raised when the MTA-STS policy cannot be downloaded"""


class MTASTSPolicySyntaxError(MTASTSPolicyError):
    """Raised when a syntax error is found in an MTA-STS policy"""


class MTASTSQueryResults(TypedDict):
    record: str
    warnings: list[str]


# Tags is a dict mapping tag names to tag values (simple strings in MTA-STS)
MTASTSTags = dict[str, str]
MTASTSTagsWithDescription = dict[
    str, str
]  # Currently no difference, kept for API compat


class ParsedMTASTSRecord(TypedDict):
    tags: Union[MTASTSTags, MTASTSTagsWithDescription]
    warnings: list[str]


class MTASTSFailure(TypedDict):
    valid: bool
    error: str


class MTASTSSuccess(TypedDict):
    valid: bool
    tags: Union[MTASTSTags, MTASTSTagsWithDescription]
    warnings: list[str]


MTASTSResults = Union[MTASTSSuccess, MTASTSFailure]


class DownloadedMTASTSPolicy(TypedDict):
    policy: str
    warnings: list[str]


class ParsedMTASTSPolicy(TypedDict):
    version: Literal["STSv1"]
    mode: Union[Literal["enforce"], Literal["testing"], Literal["none"]]
    max_age: int
    mx: list[str]


class MTASTSPolicyParsingResults(TypedDict):
    policy: ParsedMTASTSPolicy
    warnings: list[str]


class MTASTSCheckSuccess(TypedDict):
    valid: Literal[True]
    id: str
    policy: ParsedMTASTSPolicy
    warnings: list[str]


class MTASTSCheckFailure(TypedDict):
    valid: Literal[False]
    error: str


MTASTSCheckResults = Union[MTASTSCheckSuccess, MTASTSCheckFailure]


class _STSGrammar(pyleri.Grammar):
    """Defines Pyleri grammar for MTA-STS records"""

    version_tag = pyleri.Regex(MTA_STS_VERSION_REGEX_STRING, re.IGNORECASE)
    tag_value = pyleri.Regex(MTA_STS_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = pyleri.Sequence(
        version_tag,
        pyleri.List(
            tag_value, delimiter=pyleri.Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"), opt=True
        ),
    )


mta_sts_tags = {
    "v": {
        "name": "Version",
        "required": True,
        "description": 'Currently, only "STSv1" is supported.',
    },
    "id": {
        "name": "id",
        "required": True,
        "description": "A short string used to track policy "
        "updates.  This string MUST uniquely identify "
        "a given instance of a policy, such that "
        "senders can determine when the policy has "
        'been updated by comparing to the "id" of a '
        "previously seen policy. There is no implied "
        'ordering of "id" fields between revisions.',
    },
}

STS_TAG_VALUE_REGEX = re.compile(MTA_STS_TAG_VALUE_REGEX_STRING, re.IGNORECASE)


def query_mta_sts_record(
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> MTASTSQueryResults:
    """
    Queries DNS for an MTA-STS record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout


    Returns:
        dict: a ``dict`` with the following keys:
                     - ``record`` - the unparsed MTA-STS record string
                     - ``warnings`` - warning conditions found

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSRecordNotFound`
        :exc:`checkdmarc.mta_sts.MTASTSRecordInWrongLocation`
        :exc:`checkdmarc.mta_sts.MultipleMTASTSRecords`

    """
    domain = normalize_domain(domain)
    logging.debug(f"Checking for an MTA-STS record on {domain}")
    warnings = []
    target = f"_mta-sts.{domain}"
    txt_prefix = "v=STSv1"
    sts_record = None
    sts_record_count = 0
    unrelated_records = []

    try:
        records = query_dns(
            target,
            "TXT",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
        for record in records:
            if record.startswith(txt_prefix):
                sts_record_count += 1
            else:
                unrelated_records.append(record)

        if sts_record_count > 1:
            raise MultipleMTASTSRecords("Multiple MTA-STS records are not permitted.")
        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            raise UnrelatedTXTRecordFoundAtMTASTS(
                "Unrelated TXT records were discovered. These should be "
                "removed, as some receivers may not expect to find "
                "unrelated TXT records "
                f"at {target}\n\n{ur_str}"
            )
        sts_record = records[0]

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        try:
            records = query_dns(
                domain,
                "TXT",
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                timeout_retries=timeout_retries,
            )
            for record in records:
                if record.startswith(txt_prefix):
                    raise MTASTSRecordInWrongLocation(
                        f"The MTA-STS record must be located at {target}, not {domain}."
                    )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise MTASTSRecordNotFound("The domain does not exist.")
        except Exception as error:
            raise MTASTSRecordNotFound(error)
    except Exception as error:
        raise MTASTSRecordNotFound(error)

    if sts_record is None:
        raise MTASTSRecordNotFound("An MTA-STS DNS record does not exist.")

    results: MTASTSQueryResults = {"record": sts_record, "warnings": warnings}

    return results


def parse_mta_sts_record(
    record: str,
    *,
    include_tag_descriptions: bool = False,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> ParsedMTASTSRecord:
    """
    Parses an MTA-STS record

    Args:
        record (str): A MTA-STS record
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        dict: a ``dict`` with the following keys:
         - ``tags`` - a ``dict`` of MTA-STS tags

           - ``value`` - The MTA-STS tag value
           - ``description`` - A description of the tag/value

         - ``warnings`` - A ``list`` of warnings

         .. note::
            ``description`` is only included if
            ``include_tag_descriptions`` is set to ``True``

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSRecordSyntaxError`
        :exc:`checkdmarc.mta_sts.InvalidMTASTSTag`
        :exc:`checkdmarc.mta_sts.InvalidSTSTagValue`
        :exc:`checkdmarc.mta_sts.SPFRecordFoundWhereMTASTSRecordShouldBe`

    """
    logging.debug("Parsing the MTA-STS record")
    spf_in_dmarc_error_msg = (
        "Found a SPF record where a MTA-STS record "
        "should be; most likely, the _mta-sts "
        "subdomain record does not actually exist, "
        "and the request for TXT records was "
        "redirected to the base domain"
    )
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereMTASTSRecordShouldBe(spf_in_dmarc_error_msg)
    sts_syntax_checker = _STSGrammar()
    parsed_record = sts_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        expecting = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting))
        )
        marked_record = (
            record[: parsed_record.pos]
            + syntax_error_marker
            + record[parsed_record.pos :]
        )
        expecting = " or ".join(expecting)
        raise MTASTSRecordSyntaxError(
            f"Error: Expected {expecting} "
            f"at position {parsed_record.pos} "
            f"(marked with {syntax_error_marker}) "
            f"in: {marked_record}"
        )

    pairs: list[tuple[str, str]] = STS_TAG_VALUE_REGEX.findall(record)
    tags = {}

    seen_tags: list[str] = []
    duplicate_tags: list[str] = []
    for pair in pairs:
        tag = pair[0].lower().strip()
        tag_value = str(pair[1].strip())
        if tag not in mta_sts_tags:
            raise InvalidMTASTSTag(f"{tag} is not a valid MTA-STS record tag.")
        # Check for duplicate tags
        if tag in seen_tags:
            if tag not in duplicate_tags:
                duplicate_tags.append(tag)
        else:
            seen_tags.append(tag)
            tags[tag] = tag_value
        if len(duplicate_tags):
            duplicate_tags_str = ",".join(duplicate_tags)
            raise InvalidMTASTSTag(
                f"Duplicate {duplicate_tags_str} tags are not permitted"
            )

    results: ParsedMTASTSRecord = {"tags": tags, "warnings": warnings}

    return results


def download_mta_sts_policy(
    domain: str, *, http_timeout: float = DEFAULT_HTTP_TIMEOUT
) -> DownloadedMTASTSPolicy:
    """
    Downloads a domains MTA-HTS policy

    Args:
        domain (str): A domain name
        http_timeout (float): HTTP timeout in seconds

    Returns:
        dict: a ``dict`` with the following keys:
                     - ``policy`` - The unparsed policy string
                     - ``warnings`` - A list of any warning conditions found

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSPolicyDownloadError`
    """
    warnings = []
    headers = {"User-Agent": USER_AGENT}
    session = requests.Session()
    session.headers = headers  # pyright: ignore[reportAttributeAccessIssue]
    expected_content_type = "text/plain"
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    logging.debug(f"Attempting to download HTA-MTS policy from {url}")
    try:
        response = session.get(url, timeout=http_timeout)
        response.raise_for_status()
        if "Content-Type" in response.headers:
            content_type = response.headers["Content-Type"].split(";")[0]
            content_type = content_type.strip()
            if content_type != expected_content_type:
                warnings.append(
                    f"Content-Type header should be "
                    f"{expected_content_type} not {content_type}"
                )
        else:
            warnings.append(
                "The Content-Type header is missing. It should "
                f"be set to {expected_content_type}"
            )

    except Exception as e:
        raise MTASTSPolicyDownloadError(str(e))

    results: DownloadedMTASTSPolicy = {"policy": response.text, "warnings": warnings}

    return results


def parse_mta_sts_policy(policy: str) -> MTASTSPolicyParsingResults:
    """
    Parses an MTA-STS policy

    Args:
        policy (str): The policy

     Returns:
        dict: a ``dict`` with the following keys:
                     - ``policy`` - The parsed policy
                     - ``warnings`` - A list of any warning conditions found

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSPolicySyntaxError`
    """
    parsed_policy: ParsedMTASTSPolicy = {
        "version": "STSv1",  # Will be verified below
        "mode": "none",  # Will be set below
        "max_age": 0,  # Will be set below
        "mx": [],  # Will be set below
    }
    warnings = []
    mx = []
    versions = ["STSv1"]
    modes = ["enforce", "testing", "none"]
    required_keys = ["version", "mode", "max_age"]
    acceptable_keys = required_keys.copy()
    acceptable_keys.append("mx")
    if "\n" in policy and "\r\n" not in policy:
        policy = policy.replace("\n", "\r\n")
    lines = policy.split("\r\n")
    for i in range(len(lines)):
        line = i + 1
        if lines[i] == "":
            continue
        key_value = lines[i].split(":")
        if len(key_value) != 2:
            raise MTASTSPolicySyntaxError(f"Line {line}: Not a key: value pair.")
        key = key_value[0].strip()
        value = key_value[1].strip()
        if key not in acceptable_keys:
            raise MTASTSPolicySyntaxError(f"Line {line}: Unexpected key: {key}")
        if key in parsed_policy and key != "mx":
            MTASTSPolicySyntaxError(f"Line {line}: Duplicate key: {key}")
        elif key == "version" and value not in versions:
            MTASTSPolicySyntaxError(f"Line {line}: Invalid version: {value}")
        elif key == "mode" and value not in modes:
            MTASTSPolicySyntaxError(f"Line {line}: Invalid mode: {value}")
        elif key == "max_age":
            error_msg = "max_age must be an integer value between 0 and 31557600."
            if "." in value:
                raise MTASTSPolicySyntaxError(error_msg)
            try:
                value = int(value)
                if value < 0 or value > 31557600:
                    raise MTASTSPolicySyntaxError(error_msg)
            except ValueError:
                MTASTSPolicySyntaxError(error_msg)
        if key != "mx":
            parsed_policy[key] = value
        else:
            value = str(value)
            if len(MTA_STS_MX_REGEX.findall(value)) == 0:
                raise MTASTSPolicySyntaxError(f"Line {line}: Invalid mx value: {value}")
            mx.append(value)
    for required_key in required_keys:
        if required_key not in parsed_policy:
            raise MTASTSPolicySyntaxError(f"Missing required key: {required_key}.")

    if parsed_policy["mode"] != "none" and len(mx) == 0:
        raise MTASTSPolicySyntaxError(
            f"{parsed_policy['mode']} mode requires at least one mx value."
        )
    parsed_policy["mx"] = mx

    results: MTASTSPolicyParsingResults = {
        "policy": parsed_policy,
        "warnings": warnings,
    }
    return results


def check_mta_sts(
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> MTASTSCheckResults:
    """
    Returns a dictionary with a parsed MTA-STS policy or an error.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout


    Returns:
        dict: a ``dict`` with the following keys:

                       - ``id`` - The SIS-MTA DNS record ID
                       - ``policy`` - The parsed MTA-STS policy
                       - ``valid`` - True
                       - ``warnings`` - A ``list`` of warnings

                    If an error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - Tne error message
                      - ``valid`` - False
    """
    domain = normalize_domain(domain)
    try:
        mta_sts_record = query_mta_sts_record(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
        warnings = mta_sts_record["warnings"]
        mta_sts_record = parse_mta_sts_record(mta_sts_record["record"])
        id_value = mta_sts_record["tags"]["id"]
        policy = download_mta_sts_policy(domain, http_timeout=timeout)
        warnings += policy["warnings"]
        policy = parse_mta_sts_policy(policy["policy"])
        warnings += policy["warnings"]

        mta_sts_results: MTASTSCheckSuccess = {
            "valid": True,
            "id": id_value,
            "policy": policy["policy"],
            "warnings": warnings,
        }
        return mta_sts_results
    except MTASTSError as error:
        mta_sts_results_failure: MTASTSCheckFailure = {
            "valid": False,
            "error": str(error),
        }
        return mta_sts_results_failure


def mx_in_mta_sts_patterns(mx_hostname: str, mta_sts_mx_patterns: list[str]) -> bool:
    """
    Tests is a given MX hostname is covered by a given list of MX patterns
    from an MTA-STS policy:

    Args:
        mx_hostname (str): The MX hostname to test
        mta_sts_mx_patterns (str): The list of MTA-STS MX patterns

    Returns: True if the MX hostname is included, false if not
    """
    for pattern in mta_sts_mx_patterns:
        regex_pattern = pattern.replace(r".", r"\.")
        regex_pattern = regex_pattern.replace(r"*", r"[a-z0-9\-.]+")
        if len(re.findall(regex_pattern, mx_hostname, re.IGNORECASE)) > 0:
            return True
    return False
