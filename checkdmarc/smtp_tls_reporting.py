# -*- coding: utf-8 -*-

"""SMTP TLS Reporting"""

from __future__ import annotations

import logging
import re
from typing import Optional, TypedDict, Union, Literal
from collections.abc import Sequence

import dns.exception
import dns.resolver
from dns.nameserver import Nameserver
import pyleri

from checkdmarc._constants import SYNTAX_ERROR_MARKER
from checkdmarc.utils import (
    HTTPS_REGEX,
    MAILTO_REGEX_STRING,
    WSP_REGEX,
    normalize_domain,
    query_dns,
)

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

SMTPTLSREPORTING_VERSION_REGEX_STRING = (
    rf"v{WSP_REGEX}*=" rf"{WSP_REGEX}*TLSRPTv1{WSP_REGEX}*;"
)
SMTPTLSREPORTING_URI_REGEX_STRING = rf"({MAILTO_REGEX_STRING}|{HTTPS_REGEX})"

SMTPTLSREPORTING_TAG_VALUE_REGEX_STRING = (
    rf"([a-z]{{1,3}}){WSP_REGEX}*={WSP_REGEX}*" rf"([^\s;]+)"
)
SMTPTLSREPORTING_TAG_VALUE_REGEX = re.compile(
    SMTPTLSREPORTING_TAG_VALUE_REGEX_STRING, re.IGNORECASE
)

SMTPTLSREPORTING_URI_REGEX = re.compile(
    SMTPTLSREPORTING_URI_REGEX_STRING, re.IGNORECASE
)


class SMTPTLSReportingError(Exception):
    """Raised when a fatal SMTP TLS Reporting error occurs"""

    def __init__(self, msg: str, data: Optional[dict] = None):
        """
        Args:
            msg (str): The error message
            data (dict): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class SMTPTLSReportingRecordNotFound(SMTPTLSReportingError):
    """Raised when an SMTP TLS Reporting record could not be found"""

    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class SMTPTLSReportingSyntaxError(SMTPTLSReportingError):
    """Raised when an SMTP TLS Reporting syntax error is found"""


class InvalidSMTPTLSReportingTag(SMTPTLSReportingSyntaxError):
    """Raised when an invalid SMTP TLS Reporting tag is found"""


class InvalidSMTPTLSReportingTagValue(SMTPTLSReportingSyntaxError):
    """Raised when an invalid SMTP TLS Reporting tag value is found"""


class UnrelatedTXTRecordFoundAtTLSRPT(SMTPTLSReportingError):
    """Raised when a TXT record unrelated to SMTP TLS Reporting is found"""


class SPFRecordFoundWhereTLSRPTShouldBe(UnrelatedTXTRecordFoundAtTLSRPT):
    """Raised when an SPF record is found where an SMTP TLS Reporting record
    should be;
    most likely, the ``_smtp._tls.SMTPTLSReporting`` subdomain
    record does not actually exist, and the request for ``TXT`` records was
    redirected to the base domain"""


class SMTPTLSReportingRecordInWrongLocation(SMTPTLSReportingError):
    """Raised when an SMTP TLS Reporting record is found at the root of a
    domain"""


class MultipleSMTPTLSReportingRecords(SMTPTLSReportingError):
    """Raised when multiple SMTP TLS Reporting records are found"""


class _SMTPTLSReportingGrammar(pyleri.Grammar):
    """Defines Pyleri grammar for SMTP TLS Reporting records"""

    version_tag = pyleri.Regex(SMTPTLSREPORTING_VERSION_REGEX_STRING)
    tag_value = pyleri.Regex(SMTPTLSREPORTING_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = pyleri.Sequence(
        version_tag,
        pyleri.List(
            tag_value, delimiter=pyleri.Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"), opt=True
        ),
    )


class SMTPTLSReportingQueryResults(TypedDict):
    record: str
    warnings: list[str]


class SMTPTLSReportingTagValue(TypedDict):
    value: Union[str, list[str]]


class _SMTPTLSReportingTagValueOptional(TypedDict, total=False):
    description: str


class SMTPTLSReportingTagValueWithDescription(
    SMTPTLSReportingTagValue, _SMTPTLSReportingTagValueOptional
):
    pass


# Tags is a dict mapping tag names to tag values
SMTPTLSReportingTags = dict[str, SMTPTLSReportingTagValue]
SMTPTLSReportingTagsWithDescription = dict[str, SMTPTLSReportingTagValueWithDescription]


class ParsedSMTPTLSReportingRecord(TypedDict):
    tags: Union[SMTPTLSReportingTags, SMTPTLSReportingTagsWithDescription]
    warnings: list[str]


class SMTPTLSReportingFailure(TypedDict):
    valid: Literal[False]
    error: str


class SMTPTLSReportingSuccess(TypedDict):
    valid: Literal[True]
    tags: Union[SMTPTLSReportingTags, SMTPTLSReportingTagsWithDescription]
    warnings: list[str]


SMTPTLSReportingResults = Union[SMTPTLSReportingSuccess, SMTPTLSReportingFailure]

smtp_rpt_tags = {
    "v": {"name": "Version", "description": "Must be TLSRPTv1", "required": True},
    "rua": {
        "name": "Aggregate Reporting URIs",
        "description": "A URI specifying the endpoint to which aggregate "
        "information about policy validation results should be "
        'sent. Two URI schemes are supported: "mailto" and '
        '"https".  As with DMARC the Policy Domain can specify a '
        "comma-separated list of URIs.",
        "required": False,
    },
}


def query_smtp_tls_reporting_record(
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> SMTPTLSReportingQueryResults:
    """
    Queries DNS for an SMTP TLS Reporting record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout

    Returns:
        dict: a ``dict`` with the following keys:
                     - ``record`` - the unparsed SMTP TLS Reporting record
                     - ``warnings`` - warning conditions found

    Raises:
        :exc:`checkdmarc.smtp_tls_reporting.SMTPTLSReportingRecordNotFound`
        :exc:`checkdmarc.smtp_tls_reporting.SMTPTLSReportingRecordInWrongLocation`
        :exc:`checkdmarc.smtp_tls_reporting.MultipleSMTPTLSReportingRecords`

    """
    domain = normalize_domain(domain)
    logging.debug(f"Checking for an SMTP TLS Reporting record on {domain}")
    warnings = []
    target = f"_smtp._tls.{domain}"
    txt_prefix = "v=TLSRPTv1"
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
            raise MultipleSMTPTLSReportingRecords(
                "Multiple SMTP TLS Reporting records are not permitted."
            )
        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            raise UnrelatedTXTRecordFoundAtTLSRPT(
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
                    raise SMTPTLSReportingRecordInWrongLocation(
                        "The SMTP TLS Reporting record must be located at "
                        f"{target}, not {domain}"
                    )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise SMTPTLSReportingRecordNotFound("The domain does not exist.")
        except Exception as error:
            raise SMTPTLSReportingRecordNotFound(error)
    except Exception as error:
        raise SMTPTLSReportingRecordNotFound(error)

    if sts_record is None:
        raise SMTPTLSReportingRecordNotFound(
            "An SMTP TLS Reporting record does not exist."
        )

    results: SMTPTLSReportingQueryResults = {"record": sts_record, "warnings": warnings}

    return results


def parse_smtp_tls_reporting_record(
    record: str,
    *,
    include_tag_descriptions: bool = False,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> ParsedSMTPTLSReportingRecord:
    """
    Parses an SMTP TLS Reporting record

    Args:
        record (str): A SMTP TLS Reporting record
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        dict: a ``dict`` with the following keys:
         - ``tags`` - a ``dict`` of SMTP TLS Reporting tags

           - ``value`` - The SMTP TLS Reporting tag value
           - ``description`` - A description of the tag/value

         - ``warnings`` - A ``list`` of warnings

         .. note::
            ``description`` is only included if
            ``include_tag_descriptions`` is set to ``True``

    Raises:
        :exc:`checkdmarc.smtp_tls_reporting.SMTPTLSReportingSyntaxError`
        :exc:`checkdmarc.smtp_tls_reporting.InvalidSMTPTLSReportingTag`
        :exc:`checkdmarc.smtp_tls_reporting.InvalidSMTPTLSReportingTagValue`
        :exc:`checkdmarc.smtp_tls_reporting.SPFRecordFoundWhereTLSRPTShouldBe`
    """
    logging.debug("Parsing the SMTP TLS Reporting record")
    spf_in_smtp_error_msg = (
        "Found a SPF record where a SMTP TLS Reporting "
        "record should be; most likely, the _smtp._tls "
        "subdomain record does not actually exist, "
        "and the request for TXT records was "
        "redirected to the base domain"
    )
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereTLSRPTShouldBe(spf_in_smtp_error_msg)
    smtp_tls_syntax_checker = _SMTPTLSReportingGrammar()
    parsed_record = smtp_tls_syntax_checker.parse(record)
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
        raise SMTPTLSReportingSyntaxError(
            f"Error: Expected {expecting} "
            f"at position {parsed_record.pos} "
            f"(marked with"
            f" {syntax_error_marker}) "
            f"in: {marked_record}"
        )

    pairs: list[tuple[str, str]] = SMTPTLSREPORTING_TAG_VALUE_REGEX.findall(record)
    tags = {}

    seen_tags: list[str] = []
    duplicate_tags: list[str] = []
    for pair in pairs:
        tag = pair[0].lower().strip()
        tag_value = str(pair[1].strip())
        if tag not in smtp_rpt_tags:
            raise InvalidSMTPTLSReportingTag(
                f"{tag} is not a valid SMTP TLS Reporting record tag."
            )
        # Check for duplicate tags
        if tag in seen_tags:
            if tag not in duplicate_tags:
                duplicate_tags.append(tag)
        else:
            seen_tags.append(tag)
        if len(duplicate_tags):
            duplicate_tags_str = ",".join(duplicate_tags)
            raise InvalidSMTPTLSReportingTag(
                f"Duplicate {duplicate_tags_str} tags are not permitted"
            )
        tags[tag] = {"value": tag_value}
        if include_tag_descriptions:
            tags[tag]["description"] = smtp_rpt_tags[tag]["description"]
    if "rua" not in tags:
        SMTPTLSReportingSyntaxError("The record is missing the required rua tag.")
    tags["rua"]["value"] = tags["rua"]["value"].split(",")
    for uri in tags["rua"]["value"]:
        if len(SMTPTLSREPORTING_URI_REGEX.findall(uri)) != 1:
            raise SMTPTLSReportingSyntaxError(
                f"{uri} is not a valid SMTP TLS reporting URI."
            )
    results: ParsedSMTPTLSReportingRecord = {"tags": tags, "warnings": warnings}

    return results


def check_smtp_tls_reporting(
    domain: str,
    *,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> SMTPTLSReportingResults:
    """
    Returns a dictionary with a parsed SMTP-TLS Reporting policy or an error.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout

    Returns:
        dict: a ``dict`` with the following keys:

                       - ``valid`` - True
                         ``tags`` - A dictionary of tags and values
                       - ``warnings`` - A ``list`` of warnings

                    If an error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - Tne error message
                      - ``valid`` - False
    """
    domain = normalize_domain(domain)
    try:
        smtp_tls_reporting_record = query_smtp_tls_reporting_record(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
        warnings = smtp_tls_reporting_record["warnings"]
        smtp_tls_reporting_record = parse_smtp_tls_reporting_record(
            smtp_tls_reporting_record["record"]
        )
        warnings += smtp_tls_reporting_record["warnings"]
        tags = smtp_tls_reporting_record["tags"]
        smtp_tls_reporting_results: SMTPTLSReportingResults = {
            "valid": True,
            "tags": tags,
            "warnings": warnings,
        }
        smtp_tls_reporting_results["tags"] = tags
        smtp_tls_reporting_results["warnings"] = warnings
    except SMTPTLSReportingError as error:
        failure: SMTPTLSReportingFailure = {"valid": False, "error": str(error)}
        return failure

    return smtp_tls_reporting_results
