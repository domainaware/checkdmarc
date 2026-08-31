"""SMTP TLS Reporting"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Literal, TypedDict

import dns.exception
import dns.resolver
import pyleri
from dns.nameserver import Nameserver

from checkdmarc._constants import (
    DEFAULT_DNS_MAX_RETRIES,
    DEFAULT_DNS_TIMEOUT,
    SYNTAX_ERROR_MARKER,
)
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

logger = logging.getLogger(__name__)

# The RFC 8460 section 3 grammar uses RFC 7405 %s (case-sensitive) strings,
# so "v=TLSRPTv1" must appear exactly, with no whitespace around the "=".
SMTPTLSREPORTING_VERSION_REGEX_STRING = r"v=TLSRPTv1"
SMTPTLSREPORTING_URI_REGEX_STRING = rf"({MAILTO_REGEX_STRING}|{HTTPS_REGEX})"

# One tag=value field. The name side covers both the "rua" tag and RFC 8460
# section 3 extension names: a letter or digit followed by up to 31 more
# letters, digits, underscores, hyphens, or dots (digits may come first).
# The value side is any run of characters up to the next ";", starting with
# something other than whitespace, ";", or "=". Field names are
# case-sensitive per the RFC 7405 %s strings in the grammar, so this regex
# is compiled without re.IGNORECASE.
SMTPTLSREPORTING_TAG_VALUE_REGEX_STRING = (
    r"([A-Za-z0-9][A-Za-z0-9_.\-]{0,31})=" r"([^\s;=][^;]*)"
)
SMTPTLSREPORTING_TAG_VALUE_REGEX = re.compile(SMTPTLSREPORTING_TAG_VALUE_REGEX_STRING)

# Fields are separated by ";" with optional whitespace on either side
# (RFC 8460 section 3: field-delim = *WSP ";" *WSP)
SMTPTLSREPORTING_FIELD_DELIMITER_REGEX_STRING = rf"{WSP_REGEX}*;{WSP_REGEX}*"
SMTPTLSREPORTING_FIELD_DELIMITER_REGEX = re.compile(
    SMTPTLSREPORTING_FIELD_DELIMITER_REGEX_STRING
)

# URIs in a rua value are separated by commas with optional whitespace on
# either side (RFC 8460 section 3: tlsrpt-uri *(*WSP "," *WSP tlsrpt-uri))
SMTPTLSREPORTING_URI_DELIMITER_REGEX = re.compile(rf"{WSP_REGEX}*,{WSP_REGEX}*")

SMTPTLSREPORTING_URI_REGEX = re.compile(
    SMTPTLSREPORTING_URI_REGEX_STRING, re.IGNORECASE
)


class SMTPTLSReportingError(Exception):
    """Raised when a fatal SMTP TLS Reporting error occurs"""

    def __init__(self, msg: str, data: dict | None = None):
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
    """Raised when an invalid SMTP TLS Reporting tag is found

    .. deprecated::
        No longer raised. RFC 8460 section 3 requires parsers to ignore
        unknown fields, so they now produce a warning instead. Kept for
        backwards compatibility with code that catches it."""


class InvalidSMTPTLSReportingTagValue(SMTPTLSReportingSyntaxError):
    """Raised when an invalid SMTP TLS Reporting tag value is found"""


class UnrelatedTXTRecordFoundAtTLSRPT(SMTPTLSReportingError):
    """Raised when a TXT record unrelated to SMTP TLS Reporting is found

    .. deprecated::
        No longer raised during DNS queries. RFC 8460 section 3.1 says
        non-matching TXT records are discarded, so they now produce a
        warning instead. Kept because
        :exc:`SPFRecordFoundWhereTLSRPTShouldBe` subclasses it and for
        backwards compatibility with code that catches it."""


class SPFRecordFoundWhereTLSRPTShouldBe(UnrelatedTXTRecordFoundAtTLSRPT):
    """Raised when an SPF record is found where an SMTP TLS Reporting record
    should be;
    most likely, the ``_smtp._tls`` subdomain
    record does not actually exist, and the request for ``TXT`` records was
    redirected to the base domain"""


class SMTPTLSReportingRecordInWrongLocation(SMTPTLSReportingError):
    """Raised when an SMTP TLS Reporting record is found at the root of a
    domain"""


class MultipleSMTPTLSReportingRecords(SMTPTLSReportingError):
    """Raised when multiple SMTP TLS Reporting records are found"""


class _SMTPTLSReportingGrammar(pyleri.Grammar):
    """Defines Pyleri grammar for SMTP TLS Reporting records"""

    # RFC 8460 section 3:
    # tlsrpt-record = tlsrpt-version 1*(field-delim tlsrpt-field) [field-delim]
    # The version tag must come first, at least one field must follow, and a
    # trailing delimiter is allowed (List with opt=True).
    version_tag = pyleri.Regex(SMTPTLSREPORTING_VERSION_REGEX_STRING)
    tag_value = pyleri.Regex(SMTPTLSREPORTING_TAG_VALUE_REGEX_STRING)
    START = pyleri.Sequence(
        version_tag,
        pyleri.Regex(SMTPTLSREPORTING_FIELD_DELIMITER_REGEX_STRING),
        pyleri.List(
            tag_value,
            delimiter=pyleri.Regex(SMTPTLSREPORTING_FIELD_DELIMITER_REGEX_STRING),
            mi=1,
            opt=True,
        ),
    )


class SMTPTLSReportingQueryResult(TypedDict):
    record: str
    warnings: list[str]


# Deprecated alias for SMTPTLSReportingQueryResult
SMTPTLSReportingQueryResults = SMTPTLSReportingQueryResult


class SMTPTLSReportingTagValue(TypedDict):
    value: str | list[str]


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
    tags: SMTPTLSReportingTags | SMTPTLSReportingTagsWithDescription
    warnings: list[str]


class SMTPTLSReportingFailure(TypedDict):
    valid: Literal[False]
    error: str


class SMTPTLSReportingSuccess(TypedDict):
    valid: Literal[True]
    tags: SMTPTLSReportingTags | SMTPTLSReportingTagsWithDescription
    warnings: list[str]


SMTPTLSReportingResult = SMTPTLSReportingSuccess | SMTPTLSReportingFailure
# Deprecated alias for SMTPTLSReportingResult
SMTPTLSReportingResults = SMTPTLSReportingResult

SMTP_TLS_REPORTING_TAGS = {
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


# Deprecated alias for SMTP_TLS_REPORTING_TAGS
smtp_rpt_tags = SMTP_TLS_REPORTING_TAGS


def query_smtp_tls_reporting_record(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> SMTPTLSReportingQueryResult:
    """
    Queries DNS for an SMTP TLS Reporting record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

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
    logger.debug(f"Checking for an SMTP TLS Reporting record on {domain}")
    warnings = []
    target = f"_smtp._tls.{domain}"
    # RFC 8460 section 3.1: records that do not begin with "v=TLSRPTv1;" are
    # discarded. The trailing ";" is part of the rule, and the section 3
    # grammar requires at least one field after the version tag, so a record
    # that is exactly "v=TLSRPTv1" is not a TLSRPT record either.
    txt_prefix = "v=TLSRPTv1;"
    tlsrpt_record = None
    tlsrpt_records = []
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
                tlsrpt_records.append(record)
            else:
                unrelated_records.append(record)

        # RFC 8460 section 3.1: non-matching records are discarded, not
        # fatal, so warn about them and move on. If exactly one TLSRPT
        # record remains, the domain supports TLSRPT.
        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            warnings.append(
                "Unrelated TXT records were discovered and ignored. "
                "These should be removed, as some receivers may not "
                "expect to find unrelated TXT records "
                f"at {target}\n\n{ur_str}"
            )
        if len(tlsrpt_records) > 1:
            raise MultipleSMTPTLSReportingRecords(
                "Multiple SMTP TLS Reporting records are not permitted."
            )
        if len(tlsrpt_records) == 1:
            tlsrpt_record = tlsrpt_records[0]

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
                    raise SMTPTLSReportingRecordInWrongLocation(
                        "The SMTP TLS Reporting record must be located at "
                        f"{target}, not {domain}."
                    )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise SMTPTLSReportingRecordNotFound("The domain does not exist.")
        except dns.exception.DNSException as error:
            raise SMTPTLSReportingRecordNotFound(error)
    except dns.exception.DNSException as error:
        raise SMTPTLSReportingRecordNotFound(error)

    if tlsrpt_record is None:
        raise SMTPTLSReportingRecordNotFound(
            "An SMTP TLS Reporting record does not exist."
        )

    results: SMTPTLSReportingQueryResult = {
        "record": tlsrpt_record,
        "warnings": warnings,
    }

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
        record (str): An SMTP TLS Reporting record
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The marker for pointing out syntax errors

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
        :exc:`checkdmarc.smtp_tls_reporting.SPFRecordFoundWhereTLSRPTShouldBe`
    """
    logger.debug("Parsing the SMTP TLS Reporting record")
    spf_in_tlsrpt_error_msg = (
        "Found an SPF record where an SMTP TLS Reporting "
        "record should be; most likely, the _smtp._tls "
        "subdomain record does not actually exist, "
        "and the request for TXT records was "
        "redirected to the base domain."
    )
    warnings = []
    record = record.strip('"').strip()
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereTLSRPTShouldBe(spf_in_tlsrpt_error_msg)
    smtp_tls_syntax_checker = _SMTPTLSReportingGrammar()
    grammar_result = smtp_tls_syntax_checker.parse(record)
    if not grammar_result.is_valid:
        expecting = [str(x).strip('"') for x in list(grammar_result.expecting)]
        marked_record = (
            record[: grammar_result.pos]
            + syntax_error_marker
            + record[grammar_result.pos :]
        )
        expecting_str = " or ".join(expecting)
        raise SMTPTLSReportingSyntaxError(
            f"Error: Expected {expecting_str} "
            f"at position {grammar_result.pos} "
            f"(marked with"
            f" {syntax_error_marker}) "
            f"in: {marked_record}"
        )

    # The grammar has already validated the record's shape, so split it into
    # fields on the RFC 8460 section 3 field delimiter. The first field is
    # always the version tag.
    fields = SMTPTLSREPORTING_FIELD_DELIMITER_REGEX.split(record)
    # description is an optional key, so this type also covers plain tag
    # values when include_tag_descriptions is False
    tags: SMTPTLSReportingTagsWithDescription = {"v": {"value": "TLSRPTv1"}}
    if include_tag_descriptions:
        tags["v"]["description"] = SMTP_TLS_REPORTING_TAGS["v"]["description"]
    for field in fields[1:]:
        if field == "":
            # A trailing delimiter leaves an empty final field
            continue
        tag, _, tag_value = field.partition("=")
        if tag in SMTP_TLS_REPORTING_TAGS:
            if tag in tags:
                # RFC 8460 does not forbid repeating a tag, so keep the
                # record valid; use the first value and warn.
                warnings.append(
                    f"The record contains more than one {tag} tag. Only "
                    f"the first {tag} value is used; the duplicates "
                    "should be removed."
                )
                continue
            tags[tag] = {"value": tag_value}
            if include_tag_descriptions:
                tags[tag]["description"] = SMTP_TLS_REPORTING_TAGS[tag]["description"]
        else:
            # RFC 8460 section 3: parsers MUST accept records with unknown
            # fields, which SHALL be ignored. Field names are
            # case-sensitive, so this also covers e.g. RUA=.
            warnings.append(
                f"Unknown tag {tag} was ignored, as required by RFC 8460 section 3."
            )
    if "rua" not in tags:
        raise SMTPTLSReportingSyntaxError("The record is missing the required rua tag.")
    # RFC 8460 section 3 allows whitespace around the commas that separate
    # rua URIs: tlsrpt-uri *(*WSP "," *WSP tlsrpt-uri)
    uris = SMTPTLSREPORTING_URI_DELIMITER_REGEX.split(str(tags["rua"]["value"]))
    tags["rua"]["value"] = uris
    for uri in uris:
        # fullmatch anchors the check so that a URI with a bogus prefix
        # (e.g. xhttps://...) does not pass on a partial match
        if SMTPTLSREPORTING_URI_REGEX.fullmatch(uri) is None:
            raise SMTPTLSReportingSyntaxError(
                f"{uri} is not a valid SMTP TLS Reporting URI."
            )
    results: ParsedSMTPTLSReportingRecord = {"tags": tags, "warnings": warnings}

    return results


def check_smtp_tls_reporting(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> SMTPTLSReportingResult:
    """
    Returns a dictionary with a parsed SMTP TLS Reporting record or an error.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: a ``dict`` with the following keys:

                       - ``valid`` - True
                       - ``tags`` - A dictionary of tags and values
                       - ``warnings`` - A ``list`` of warnings

                    If an error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - The error message
                      - ``valid`` - False
    """
    domain = normalize_domain(domain)
    try:
        query_results = query_smtp_tls_reporting_record(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        warnings = query_results["warnings"]
        parsed_record = parse_smtp_tls_reporting_record(query_results["record"])
        warnings += parsed_record["warnings"]
        tags = parsed_record["tags"]
        smtp_tls_reporting_results: SMTPTLSReportingResult = {
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
