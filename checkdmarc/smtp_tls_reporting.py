# -*- coding: utf-8 -*-

"""SMTP TLS Reporting"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict

import dns
from pyleri import Grammar, Regex, Sequence, List

from checkdmarc._constants import SYNTAX_ERROR_MARKER
from checkdmarc.utils import (
    WSP_REGEX,
    MAILTO_REGEX_STRING,
    HTTPS_REGEX,
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


class _SMTPTLSReportingWarning(Exception):
    """Raised when a non-fatal SMTP TLS Reporting error occurs"""


class SMTPTLSReportingError(Exception):
    """Raised when a fatal SMTP TLS Reporting error occurs"""

    def __init__(self, msg: str, data: dict = None):
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


class _SMTPTLSReportingGrammar(Grammar):
    """Defines Pyleri grammar for SMTP TLS Reporting records"""

    version_tag = Regex(SMTPTLSREPORTING_VERSION_REGEX_STRING)
    tag_value = Regex(SMTPTLSREPORTING_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = Sequence(
        version_tag,
        List(tag_value, delimiter=Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"), opt=True),
    )


smtp_rpt_tags = OrderedDict(
    v=OrderedDict(name="Version", description="Must be TLSRPTv1", required=True),
    rua=OrderedDict(
        name="Aggregate Reporting URIs",
        description="A URI specifying the endpoint to which aggregate "
        "information about policy validation results should be "
        'sent. Two URI schemes are supported: "mailto" and '
        '"https".  As with DMARC the Policy Domain can specify a '
        "comma-separated list of URIs.",
        required=False,
    ),
)


def query_smtp_tls_reporting_record(
    domain: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> OrderedDict:
    """
    Queries DNS for an SMTP TLS Reporting record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
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
            target, "TXT", nameservers=nameservers, resolver=resolver, timeout=timeout
        )
        for record in records:
            if record.startswith(txt_prefix):
                sts_record_count += 1
            else:
                unrelated_records.append(record)

        if sts_record_count > 1:
            raise MultipleSMTPTLSReportingRecords(
                "Multiple SMTP TLS Reporting records are not permitted"
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
            raise SMTPTLSReportingRecordNotFound(f"The domain {domain} does not exist")
        except Exception as error:
            raise SMTPTLSReportingRecordNotFound(error)
    except Exception as error:
        raise SMTPTLSReportingRecordNotFound(error)

    if sts_record is None:
        raise SMTPTLSReportingRecordNotFound(
            "An SMTP TLS Reporting DNS record does not exist for this domain"
        )

    return OrderedDict([("record", sts_record), ("warnings", warnings)])


def parse_smtp_tls_reporting_record(
    record: str,
    *,
    include_tag_descriptions: bool = False,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> OrderedDict:
    """
    Parses an SMTP TLS Reporting record

    Args:
        record (str): A SMTP TLS Reporting record
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``tags`` - An ``OrderedDict`` of SMTP TLS Reporting tags

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

    pairs = SMTPTLSREPORTING_TAG_VALUE_REGEX.findall(record)
    tags = OrderedDict()

    for pair in pairs:
        tag = pair[0].lower().strip()
        tag_value = str(pair[1].strip())
        if tag not in smtp_rpt_tags:
            raise InvalidSMTPTLSReportingTag(
                f"{tag} is not a valid SMTP TLS Reporting record tag"
            )
        tags[tag] = OrderedDict(value=tag_value)
        if include_tag_descriptions:
            tags[tag]["description"] = smtp_rpt_tags[tag]["description"]
    if "rua" not in tags:
        SMTPTLSReportingSyntaxError("The record is missing the required rua tag")
    tags["rua"]["value"] = tags["rua"]["value"].split(",")
    for uri in tags["rua"]["value"]:
        if len(SMTPTLSREPORTING_URI_REGEX.findall(uri)) != 1:
            raise SMTPTLSReportingSyntaxError(
                f"{uri} is not a valid SMTP TLS reporting URI"
            )

    return OrderedDict(tags=tags, warnings=warnings)


def check_smtp_tls_reporting(
    domain: str,
    *,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> OrderedDict:
    """
    Returns a dictionary with a parsed SMTP-TLS Reporting policy or an error.

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:

                       - ``valid`` - True
                         ``tags`` - A dictionary of tags and values
                       - ``warnings`` - A ``list`` of warnings

                    If an error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - Tne error message
                      - ``valid`` - False
    """
    domain = normalize_domain(domain)
    smtp_tls_reporting_results = OrderedDict([("valid", True)])
    try:
        smtp_tls_reporting_record = query_smtp_tls_reporting_record(
            domain, nameservers=nameservers, resolver=resolver, timeout=timeout
        )
        warnings = smtp_tls_reporting_record["warnings"]
        smtp_tls_reporting_record = parse_smtp_tls_reporting_record(
            smtp_tls_reporting_record["record"]
        )
        warnings += smtp_tls_reporting_record["warnings"]
        smtp_tls_reporting_results["tags"] = smtp_tls_reporting_record["tags"]
        smtp_tls_reporting_results["warnings"] = warnings
    except SMTPTLSReportingError as error:
        smtp_tls_reporting_results["valid"] = False
        smtp_tls_reporting_results["error"] = str(error)

    return smtp_tls_reporting_results
