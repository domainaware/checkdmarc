"""SMTP MTA Strict Transport Security (MTA-STS) validation"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Literal, TypedDict, cast

import dns.exception
import dns.resolver
import pyleri
import requests
from dns.nameserver import Nameserver

from checkdmarc._constants import (
    DEFAULT_DNS_MAX_RETRIES,
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
    SYNTAX_ERROR_MARKER,
    USER_AGENT,
)
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

logger = logging.getLogger(__name__)


# RFC 8461 section 3.1: the record must begin with the case-sensitive
# literal "v=STSv1;" — no spaces around the equals sign. The trailing
# whitespace here is the start of the field delimiter (*WSP ";" *WSP).
MTA_STS_VERSION_REGEX_STRING = rf"v=STSv1;{WSP_REGEX}*"
# RFC 8461 section 3.1: a field name is 1-32 letters, digits, underscores,
# hyphens, or dots (starting with a letter or digit), followed directly by
# "=" (no surrounding spaces) and a value of any visible ASCII characters
# except "=" and ";". This is wide enough to accept extension fields,
# which are ignored with a warning rather than rejected.
MTA_STS_TAG_VALUE_REGEX_STRING = (
    r"([A-Za-z0-9][A-Za-z0-9_\-.]{0,31})=([\x21-\x3A\x3C\x3E-\x7E]+)"
)

# RFC 8461 section 3.2: an mx value is ["*."] Domain, where Domain is
# dot-separated labels of letters, digits, and interior hyphens (RFC 5321
# section 4.1.2). A wildcard is only allowed as the complete left-most
# label, so "mail.*.example.com" and "*example.com" are invalid.
MTA_STS_MX_REGEX_STRING = (
    r"(?:\*\.)?"
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?)*"
)
MTA_STS_MX_REGEX = re.compile(MTA_STS_MX_REGEX_STRING)

# RFC 8461 section 3.1: an id value is 1-32 letters or digits
MTA_STS_ID_REGEX = re.compile(r"[A-Za-z0-9]{1,32}")


class MTASTSError(Exception):
    """Raised when a fatal MTA-STS error occurs"""

    def __init__(self, msg: str, data: dict | None = None):
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
    """Raised when an invalid MTA-STS tag is found

    .. note::
        No longer raised: RFC 8461 sections 3.1-3.2 say unknown fields
        are ignored, so parsing now warns instead. The class remains
        defined for backwards compatibility."""


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


class MTASTSQueryResult(TypedDict):
    record: str
    warnings: list[str]


# Deprecated alias for MTASTSQueryResult
MTASTSQueryResults = MTASTSQueryResult


# Tags is a dict mapping tag names to tag values (simple strings in MTA-STS)
MTASTSTags = dict[str, str]
MTASTSTagsWithDescription = dict[
    str, str
]  # Currently no difference, kept for API compat


class ParsedMTASTSRecord(TypedDict):
    tags: MTASTSTags | MTASTSTagsWithDescription
    warnings: list[str]


class MTASTSFailure(TypedDict):
    valid: bool
    error: str


class MTASTSSuccess(TypedDict):
    valid: bool
    tags: MTASTSTags | MTASTSTagsWithDescription
    warnings: list[str]


MTASTSResults = MTASTSSuccess | MTASTSFailure


class DownloadedMTASTSPolicy(TypedDict):
    policy: str
    warnings: list[str]


class ParsedMTASTSPolicy(TypedDict):
    version: Literal["STSv1"]
    mode: Literal["enforce", "testing", "none"]
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


MTASTSCheckResult = MTASTSCheckSuccess | MTASTSCheckFailure
# Deprecated alias for MTASTSCheckResult
MTASTSCheckResults = MTASTSCheckResult


class _STSGrammar(pyleri.Grammar):
    """Defines Pyleri grammar for MTA-STS records

    RFC 8461 section 3.1 defines the record as a case-sensitive
    "v=STSv1" version tag followed by semicolon-delimited fields, with
    an optional trailing semicolon. No IGNORECASE flag: the field names
    and the version value are case-sensitive literals in the ABNF."""

    version_tag = pyleri.Regex(MTA_STS_VERSION_REGEX_STRING)
    tag_value = pyleri.Regex(MTA_STS_TAG_VALUE_REGEX_STRING)
    START = pyleri.Sequence(
        version_tag,
        pyleri.List(
            tag_value, delimiter=pyleri.Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"), opt=True
        ),
    )


MTA_STS_TAGS = {
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

# Deprecated alias for MTA_STS_TAGS
mta_sts_tags = MTA_STS_TAGS

STS_TAG_VALUE_REGEX = re.compile(MTA_STS_TAG_VALUE_REGEX_STRING)

_SPF_IN_MTA_STS_ERROR_MSG = (
    "Found an SPF record where an MTA-STS record "
    "should be; most likely, the _mta-sts "
    "subdomain record does not actually exist, "
    "and the request for TXT records was "
    "redirected to the base domain."
)


def query_mta_sts_record(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> MTASTSQueryResult:
    """
    Queries DNS for an MTA-STS record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors


    Returns:
        dict: a ``dict`` with the following keys:
                     - ``record`` - the unparsed MTA-STS record string
                     - ``warnings`` - warning conditions found

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSRecordNotFound`
        :exc:`checkdmarc.mta_sts.MTASTSRecordInWrongLocation`
        :exc:`checkdmarc.mta_sts.MultipleMTASTSRecords`
        :exc:`checkdmarc.mta_sts.UnrelatedTXTRecordFoundAtMTASTS`

    """
    domain = normalize_domain(domain)
    logger.debug(f"Checking for an MTA-STS record on {domain}")
    warnings = []
    target = f"_mta-sts.{domain}"
    # RFC 8461 section 3.1: records that do not begin with the exact
    # string "v=STSv1;" are discarded, not treated as errors
    txt_prefix = "v=STSv1;"
    sts_record = None
    sts_records = []
    unrelated_records = []

    try:
        records = query_dns(
            target,
            "TXT",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        for record in records:
            if record.startswith(txt_prefix):
                sts_records.append(record)
            else:
                unrelated_records.append(record)

        if len(sts_records) > 1:
            raise MultipleMTASTSRecords("Multiple MTA-STS records are not permitted.")
        if len(sts_records) == 0:
            # No MTA-STS record here at all. An SPF record at _mta-sts
            # usually means the query was redirected to the base domain,
            # so give that specific diagnostic.
            for record in unrelated_records:
                if record.lower().startswith("v=spf1"):
                    raise SPFRecordFoundWhereMTASTSRecordShouldBe(
                        _SPF_IN_MTA_STS_ERROR_MSG
                    )
            raise MTASTSRecordNotFound("An MTA-STS DNS record does not exist.")
        # Exactly one MTA-STS record: RFC 8461 section 3.1 says unrelated
        # TXT records are discarded, so they only warrant a warning
        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            warnings.append(
                "Unrelated TXT records were discovered and ignored. "
                "These should be removed, as some receivers may not "
                "expect to find unrelated TXT records "
                f"at {target}\n\n{ur_str}"
            )
        sts_record = sts_records[0]

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        try:
            records = query_dns(
                domain,
                "TXT",
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                retries=retries,
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
        except dns.exception.DNSException as error:
            raise MTASTSRecordNotFound(error)
    except dns.exception.DNSException as error:
        raise MTASTSRecordNotFound(error)

    if sts_record is None:
        raise MTASTSRecordNotFound("An MTA-STS DNS record does not exist.")

    results: MTASTSQueryResult = {"record": sts_record, "warnings": warnings}

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
        record (str): An MTA-STS record
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The marker for pointing out syntax errors

    Returns:
        dict: a ``dict`` with the following keys:
         - ``tags`` - a ``dict`` mapping each MTA-STS tag to its string value
         - ``warnings`` - A ``list`` of warnings

         .. note::
            ``include_tag_descriptions`` is accepted for API consistency
            with the other record parsers, but MTA-STS tag values are plain
            strings and no descriptions are currently added

    Raises:
        :exc:`checkdmarc.mta_sts.MTASTSRecordSyntaxError`
        :exc:`checkdmarc.mta_sts.InvalidSTSTagValue`
        :exc:`checkdmarc.mta_sts.SPFRecordFoundWhereMTASTSRecordShouldBe`

    """
    logger.debug("Parsing the MTA-STS record")
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereMTASTSRecordShouldBe(_SPF_IN_MTA_STS_ERROR_MSG)
    sts_syntax_checker = _STSGrammar()
    grammar_result = sts_syntax_checker.parse(record)
    if not grammar_result.is_valid:
        expecting = [str(x).strip('"') for x in list(grammar_result.expecting)]
        marked_record = (
            record[: grammar_result.pos]
            + syntax_error_marker
            + record[grammar_result.pos :]
        )
        expecting_str = " or ".join(expecting)
        raise MTASTSRecordSyntaxError(
            f"Error: Expected {expecting_str} "
            f"at position {grammar_result.pos} "
            f"(marked with {syntax_error_marker}) "
            f"in: {marked_record}"
        )

    pairs: list[tuple[str, str]] = STS_TAG_VALUE_REGEX.findall(record)
    tags = {}

    for pair in pairs:
        # Tag names are case-sensitive in the RFC 8461 section 3.1
        # grammar, so do not lowercase them
        tag = pair[0]
        tag_value = pair[1]
        if tag not in MTA_STS_TAGS:
            # RFC 8461 sections 3.1 and 3.2: unknown fields (such as
            # extension fields) SHALL be ignored, not rejected
            warnings.append(f"Unknown MTA-STS tag {tag} was ignored.")
            continue
        if tag in tags:
            # RFC 8461 section 3.2: when a non-repeated field is
            # duplicated, all entries except the first SHALL be ignored
            warnings.append(
                f"The MTA-STS record has duplicate {tag} tags. "
                "Only the first value is used."
            )
            continue
        if tag == "id" and MTA_STS_ID_REGEX.fullmatch(tag_value) is None:
            raise InvalidSTSTagValue(
                "The id value must be 1-32 letters or digits (RFC 8461 section 3.1)."
            )
        tags[tag] = tag_value

    # RFC 8461 section 3.1: the v and id fields are required
    for tag_name, tag_info in MTA_STS_TAGS.items():
        if tag_info["required"] and tag_name not in tags:
            raise MTASTSRecordSyntaxError(
                f"The MTA-STS record is missing the required {tag_name} tag."
            )

    results: ParsedMTASTSRecord = {"tags": tags, "warnings": warnings}

    return results


def download_mta_sts_policy(
    domain: str, *, http_timeout: float = DEFAULT_HTTP_TIMEOUT
) -> DownloadedMTASTSPolicy:
    """
    Downloads a domain's MTA-STS policy

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
    logger.debug(f"Attempting to download MTA-STS policy from {url}")
    try:
        # RFC 8461 section 3.3: HTTP 3xx redirects MUST NOT be followed,
        # and the policy is only valid if the response code is exactly 200
        response = session.get(url, timeout=http_timeout, allow_redirects=False)
        if response.status_code != 200:
            raise MTASTSPolicyDownloadError(
                "The MTA-STS policy fetch returned HTTP "
                f"{response.status_code}. RFC 8461 section 3.3 requires "
                "an HTTP 200 response, and redirects must not be followed."
            )
        if "Content-Type" in response.headers:
            content_type = response.headers["Content-Type"].split(";")[0]
            content_type = content_type.strip()
            if content_type != expected_content_type:
                warnings.append(
                    f"The Content-Type header should be "
                    f"{expected_content_type}, not {content_type}"
                )
        else:
            warnings.append(
                "The Content-Type header is missing. It should "
                f"be set to {expected_content_type}"
            )

    except requests.RequestException as e:
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
    warnings = []
    mx = []
    versions = ["STSv1"]
    modes = ["enforce", "testing", "none"]
    required_keys = ["version", "mode", "max_age"]
    known_keys = required_keys + ["mx"]
    # Collected values; required keys are checked against seen_keys after
    # the loop, so a missing key is reported instead of silently defaulted
    values: dict[str, str | int] = {}
    seen_keys: set[str] = set()
    # RFC 8461 section 3.2: each line may end with either LF or CRLF, so
    # mixed line endings within one policy file are acceptable
    lines = policy.splitlines()
    for i in range(len(lines)):
        line_number = i + 1
        if lines[i] == "":
            continue
        # Split on the first colon only, so values containing colons
        # (allowed in extension values) still form a key: value pair
        key_value = lines[i].split(":", 1)
        if len(key_value) != 2:
            raise MTASTSPolicySyntaxError(f"Line {line_number}: Not a key: value pair.")
        key = key_value[0].strip()
        value = key_value[1].strip()
        if key not in known_keys:
            # RFC 8461 section 3.2: unknown fields (such as extension
            # fields) SHALL be ignored, not rejected
            warnings.append(f"Line {line_number}: Unknown key {key} was ignored.")
            continue
        if key in seen_keys and key != "mx":
            # RFC 8461 section 3.2: when a non-repeated field is
            # duplicated, all entries except the first SHALL be ignored
            warnings.append(
                f"Line {line_number}: Duplicate {key} key. "
                "Only the first value is used."
            )
            continue
        seen_keys.add(key)
        if key == "version" and value not in versions:
            raise MTASTSPolicySyntaxError(
                f"Line {line_number}: Invalid version: {value}"
            )
        elif key == "mode" and value not in modes:
            raise MTASTSPolicySyntaxError(f"Line {line_number}: Invalid mode: {value}")
        elif key == "max_age":
            error_msg = (
                f"Line {line_number}: max_age must be an integer value "
                "between 0 and 31557600."
            )
            # RFC 8461 section 3.2: max_age is 1-10 plain digits, so
            # values int() would accept, like "1_000" or "+5", are invalid
            if re.fullmatch(r"[0-9]{1,10}", value) is None:
                raise MTASTSPolicySyntaxError(error_msg)
            max_age = int(value)
            if max_age > 31557600:
                raise MTASTSPolicySyntaxError(error_msg)
            values[key] = max_age
            continue
        if key != "mx":
            values[key] = value
        else:
            # fullmatch against the ["*."] Domain pattern from RFC 8461
            # section 3.2; an unanchored search accepts any value
            # containing a single legal character, e.g. "not a hostname!"
            if MTA_STS_MX_REGEX.fullmatch(value) is None:
                raise MTASTSPolicySyntaxError(
                    f"Line {line_number}: Invalid mx value: {value}"
                )
            mx.append(value)
    # RFC 8461 section 3.2: version, mode, and max_age are each required
    # exactly once
    for required_key in required_keys:
        if required_key not in seen_keys:
            raise MTASTSPolicySyntaxError(f"Missing required key: {required_key}.")

    if values["mode"] != "none" and len(mx) == 0:
        raise MTASTSPolicySyntaxError(
            f"{values['mode']} mode requires at least one mx value."
        )
    # The loop above validated each value against its allowed literals,
    # so this narrowing from plain str/int values is safe
    parsed_policy = cast(
        ParsedMTASTSPolicy,
        {
            "version": values["version"],
            "mode": values["mode"],
            "max_age": values["max_age"],
            "mx": mx,
        },
    )

    results: MTASTSPolicyParsingResults = {
        "policy": parsed_policy,
        "warnings": warnings,
    }
    return results


def check_mta_sts(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> MTASTSCheckResult:
    """
    Returns a dictionary with a parsed MTA-STS policy or an error.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors


    Returns:
        dict: a ``dict`` with the following keys:

                       - ``id`` - The MTA-STS DNS record ID
                       - ``policy`` - The parsed MTA-STS policy
                       - ``valid`` - True
                       - ``warnings`` - A ``list`` of warnings

                    If an error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - The error message
                      - ``valid`` - False
    """
    domain = normalize_domain(domain)
    try:
        query_results = query_mta_sts_record(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        warnings = query_results["warnings"]
        parsed_record = parse_mta_sts_record(query_results["record"])
        warnings += parsed_record["warnings"]
        id_value = parsed_record["tags"]["id"]
        # The timeout parameter is the DNS timeout; the policy download uses
        # its own HTTP default, as the BIMI check does for its downloads
        download_results = download_mta_sts_policy(domain)
        warnings += download_results["warnings"]
        parsed_policy = parse_mta_sts_policy(download_results["policy"])
        warnings += parsed_policy["warnings"]

        mta_sts_results: MTASTSCheckSuccess = {
            "valid": True,
            "id": id_value,
            "policy": parsed_policy["policy"],
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
    Tests whether a given MX hostname is covered by a given list of MX
    patterns from an MTA-STS policy.

    Args:
        mx_hostname (str): The MX hostname to test
        mta_sts_mx_patterns (list): The list of MTA-STS MX patterns

    Returns: True if the MX hostname is included, False if not
    """
    for pattern in mta_sts_mx_patterns:
        # RFC 8461 section 4.1: a wildcard may only match the entire
        # left-most label, so "*.example.com" matches "mail.example.com"
        # but not "example.com" or "foo.bar.example.com". The whole
        # hostname must match the whole pattern (fullmatch, not a
        # substring search), so "example.com" does not match
        # "bad-example.com" or "mail.example.com.evil.com".
        if pattern.startswith("*."):
            regex_pattern = r"[A-Za-z0-9\-]+" + re.escape(pattern[1:])
        else:
            regex_pattern = re.escape(pattern)
        if re.fullmatch(regex_pattern, mx_hostname, re.IGNORECASE) is not None:
            return True
    return False
