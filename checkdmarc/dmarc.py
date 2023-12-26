# -*- coding: utf-8 -*-
"""DMARC record validation"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict
from typing import Union

import dns
from pyleri import (Grammar,
                    Regex,
                    Sequence,
                    List,
                    )


from checkdmarc.utils import (WSP_REGEX, query_dns, get_base_domain,
                              MAILTO_REGEX, DNSException)
from checkdmarc.utils import get_mx_records
from checkdmarc._constants import SYNTAX_ERROR_MARKER

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

DMARC_VERSION_REGEX_STRING = fr"v{WSP_REGEX}*={WSP_REGEX}*DMARC1{WSP_REGEX}*;"
DMARC_TAG_VALUE_REGEX_STRING = (
    fr"([a-z]{{1,5}}){WSP_REGEX}*={WSP_REGEX}*([\w.:@/+!,_\- ]+)"
)

DMARC_TAG_VALUE_REGEX = re.compile(DMARC_TAG_VALUE_REGEX_STRING,
                                   re.IGNORECASE)


class _DMARCWarning(Exception):
    """Raised when a non-fatal DMARC error occurs"""


class _DMARCBestPracticeWarning(_DMARCWarning):
    """Raised when a DMARC record does not follow a best practice"""


class DMARCError(Exception):
    """Raised when a fatal DMARC error occurs"""

    def __init__(self, msg: str, data: dict = None):
        """
        Args:
            msg (str): The error message
            data (dict): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class DMARCRecordNotFound(DMARCError):
    def __init__(self, error):
        """
        Raised when a DMARC record could not be found
        """
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class DMARCSyntaxError(DMARCError):
    """Raised when a DMARC syntax error is found"""


class InvalidDMARCTag(DMARCSyntaxError):
    """Raised when an invalid DMARC tag is found"""


class InvalidDMARCTagValue(DMARCSyntaxError):
    """Raised when an invalid DMARC tag value is found"""


class DMARCRecordStartsWithWhitespace(DMARCSyntaxError):
    """Raised when DMARC record starts with whitespace"""


class InvalidDMARCReportURI(InvalidDMARCTagValue):
    """Raised when an invalid DMARC reporting URI is found"""


class UnrelatedTXTRecordFoundAtDMARC(DMARCError):
    """Raised when a TXT record unrelated to DMARC is found"""


class SPFRecordFoundWhereDMARCRecordShouldBe(UnrelatedTXTRecordFoundAtDMARC):
    """Raised when an SPF record is found where a DMARC record should be;
       most likely, the ``_dmarc`` subdomain
       record does not actually exist, and the request for ``TXT`` records was
       redirected to the base domain"""


class DMARCRecordInWrongLocation(DMARCError):
    """Raised when a DMARC record is found at the root of a domain"""


class DMARCReportEmailAddressMissingMXRecords(_DMARCWarning):
    """Raised when an email address in a DMARC report URI is missing MX
       records"""


class UnverifiedDMARCURIDestination(_DMARCWarning):
    """Raised when the destination of a DMARC report URI does not indicate
       that it accepts reports for the domain"""


class MultipleDMARCRecords(DMARCError):
    """Raised when multiple DMARC records are found, in violation of
       RFC 7486, section 6.6.3"""


class _DMARCGrammar(Grammar):
    """Defines Pyleri grammar for DMARC records"""
    version_tag = Regex(DMARC_VERSION_REGEX_STRING, re.IGNORECASE)
    tag_value = Regex(DMARC_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = Sequence(
        version_tag,
        List(
            tag_value,
            delimiter=Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"),
            opt=True))


dmarc_tags = OrderedDict(adkim=OrderedDict(name="DKIM Alignment Mode",
                                           required=False,
                                           default="r",
                                           description='In relaxed mode, '
                                                       'the Organizational '
                                                       'Domains of both the '
                                                       'DKIM-authenticated '
                                                       'signing domain (taken '
                                                       'from the value of the '
                                                       '"d=" tag in the '
                                                       'signature) and that '
                                                       'of the RFC 5322 '
                                                       'From domain '
                                                       'must be equal if the '
                                                       'identifiers are to be '
                                                       'considered aligned.'),
                         aspf=OrderedDict(name="SPF alignment mode",
                                          required=False,
                                          default="r",
                                          description='In relaxed mode, '
                                                      'the SPF-authenticated '
                                                      'domain and RFC5322 '
                                                      'From domain must have '
                                                      'the same '
                                                      'Organizational Domain. '
                                                      'In strict mode, only '
                                                      'an exact DNS domain '
                                                      'match is considered to '
                                                      'produce Identifier '
                                                      'Alignment.'),
                         fo=OrderedDict(name="Failure Reporting Options",
                                        required=False,
                                        default="0",
                                        description='Provides requested '
                                                    'options for generation '
                                                    'of failure reports. '
                                                    'Report generators MAY '
                                                    'choose to adhere to the '
                                                    'requested options. '
                                                    'This tag\'s content '
                                                    'MUST be ignored if '
                                                    'a "ruf" tag (below) is '
                                                    'not also specified. '
                                                    'The value of this tag is '
                                                    'a colon-separated list '
                                                    'of characters that '
                                                    'indicate failure '
                                                    'reporting options.',
                                        values={
                                            "0": 'Generate a DMARC failure '
                                                 'report if all underlying '
                                                 'authentication mechanisms '
                                                 'fail to produce an aligned '
                                                 '"pass" result.',
                                            "1": 'Generate a DMARC failure '
                                                 'report if any underlying '
                                                 'authentication mechanism '
                                                 'produced something other '
                                                 'than an aligned '
                                                 '"pass" result.',
                                            "d": 'Generate a DKIM failure '
                                                 'report if the message had '
                                                 'a signature that failed '
                                                 'evaluation, regardless of '
                                                 'its alignment. DKIM-'
                                                 'specific reporting is '
                                                 'described in AFRF-DKIM.',
                                            "s": 'Generate an SPF failure '
                                                 'report if the message '
                                                 'failed SPF evaluation, '
                                                 'regardless of its alignment.'
                                                 ' SPF-specific reporting is '
                                                 'described in AFRF-SPF'
                                        }
                                        ),
                         p=OrderedDict(name="Requested Mail Receiver Policy",
                                       reqired=True,
                                       description='Specifies the policy to '
                                                   'be enacted by the '
                                                   'Receiver at the '
                                                   'request of the '
                                                   'Domain Owner. The '
                                                   'policy applies to '
                                                   'the domain and to its '
                                                   'subdomains, unless '
                                                   'subdomain policy '
                                                   'is explicitly described '
                                                   'using the "sp" tag.',
                                       values={
                                           "none": 'The Domain Owner requests '
                                                   'no specific action be '
                                                   'taken regarding delivery '
                                                   'of messages.',
                                           "quarantine": 'The Domain Owner '
                                                         'wishes to have '
                                                         'email that fails '
                                                         'the DMARC mechanism '
                                                         'check be treated by '
                                                         'Mail Receivers as '
                                                         'suspicious. '
                                                         'Depending on the '
                                                         'capabilities of the '
                                                         'MailReceiver, '
                                                         'this can mean '
                                                         '"place into spam '
                                                         'folder", '
                                                         '"scrutinize '
                                                         'with additional '
                                                         'intensity", and/or '
                                                         '"flag as '
                                                         'suspicious".',
                                           "reject": 'The Domain Owner wishes '
                                                     'for Mail Receivers to '
                                                     'reject '
                                                     'email that fails the '
                                                     'DMARC mechanism check. '
                                                     'Rejection SHOULD '
                                                     'occur during the SMTP '
                                                     'transaction.'
                                       }
                                       ),
                         pct=OrderedDict(name="Percentage",
                                         required=False,
                                         default=100,
                                         description='Integer percentage of '
                                                     'messages from the '
                                                     'Domain Owner\'s '
                                                     'mail stream to which '
                                                     'the DMARC policy is to '
                                                     'be applied. '
                                                     'However, this '
                                                     'MUST NOT be applied to '
                                                     'the DMARC-generated '
                                                     'reports, all of which '
                                                     'must be sent and '
                                                     'received unhindered. '
                                                     'The purpose of the '
                                                     '"pct" tag is to allow '
                                                     'Domain Owners to enact '
                                                     'a slow rollout of '
                                                     'enforcement of the '
                                                     'DMARC mechanism.'
                                         ),
                         rf=OrderedDict(name="Report Format",
                                        required=False,
                                        default="afrf",
                                        description='A list separated by '
                                                    'colons of one or more '
                                                    'report formats as '
                                                    'requested by the '
                                                    'Domain Owner to be '
                                                    'used when a message '
                                                    'fails both SPF and DKIM '
                                                    'tests to report details '
                                                    'of the individual '
                                                    'failure. Only "afrf" '
                                                    '(the auth-failure report '
                                                    'type) is currently '
                                                    'supported in the '
                                                    'DMARC standard.',
                                        values={
                                            "afrf": ' "Authentication Failure '
                                                    'Reporting Using the '
                                                    'Abuse Reporting Format", '
                                                    'RFC 6591, April 2012,'
                                                    '<https://www.rfc-'
                                                    'editor.org/info/rfc6591>'
                                        }
                                        ),
                         ri=OrderedDict(name="Report Interval",
                                        required=False,
                                        default=86400,
                                        description='Indicates a request to '
                                                    'Receivers to generate '
                                                    'aggregate reports '
                                                    'separated by no more '
                                                    'than the requested '
                                                    'number of seconds. '
                                                    'DMARC implementations '
                                                    'MUST be able to provide '
                                                    'daily reports and '
                                                    'SHOULD be able to '
                                                    'provide hourly reports '
                                                    'when requested. '
                                                    'However, anything other '
                                                    'than a daily report is '
                                                    'understood to '
                                                    'be accommodated on a '
                                                    'best-effort basis.'
                                        ),
                         rua=OrderedDict(name="Aggregate Feedback Addresses",
                                         required=False,
                                         description=' A comma-separated list '
                                                     'of DMARC URIs to which '
                                                     'aggregate feedback '
                                                     'is to be sent.'
                                         ),
                         ruf=OrderedDict(name="Forensic Feedback Addresses",
                                         required=False,
                                         description=' A comma-separated list '
                                                     'of DMARC URIs to which '
                                                     'forensic feedback '
                                                     'is to be sent.'
                                         ),
                         sp=OrderedDict(name="Subdomain Policy",
                                        required=False,
                                        description='Indicates the policy to '
                                                    'be enacted by the '
                                                    'Receiver at the request '
                                                    'of the Domain Owner. '
                                                    'It applies only to '
                                                    'subdomains of the '
                                                    'domain queried, and not '
                                                    'to the domain itself. '
                                                    'Its syntax is identical '
                                                    'to that of the "p" tag '
                                                    'defined above. If '
                                                    'absent, the policy '
                                                    'specified by the "p" '
                                                    'tag MUST be applied '
                                                    'for subdomains.'
                                        ),
                         v=OrderedDict(name="Version",
                                       reqired=True,
                                       description='Identifies the record '
                                                   'retrieved as a DMARC '
                                                   'record. It MUST have the '
                                                   'value of "DMARC1". The '
                                                   'value of this tag MUST '
                                                   'match precisely; if it '
                                                   'does not or it is absent, '
                                                   'the entire retrieved '
                                                   'record MUST be ignored. '
                                                   'It MUST be the first '
                                                   'tag in the list.')
                         )


def _query_dmarc_record(domain: str, nameservers: list[str] = None,
                        resolver: dns.resolver.Resolver = None,
                        timeout: float = 2.0,
                        ignore_unrelated_records: bool = False
                        ) -> Union[str, None]:
    """
    Queries DNS for a DMARC record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS

    Returns:
        str: A record string or None
    """
    domain = domain.lower()
    target = f"_dmarc.{domain}"
    txt_prefix = "v=DMARC1"
    dmarc_record = None
    dmarc_record_count = 0
    unrelated_records = []

    try:
        records = query_dns(target, "TXT", nameservers=nameservers,
                            resolver=resolver, timeout=timeout)
        for record in records:
            if record.startswith(txt_prefix):
                dmarc_record_count += 1
            elif record.strip().startswith(txt_prefix):
                raise DMARCRecordStartsWithWhitespace(
                    "Found a DMARC record that starts with whitespace. "
                    "Please remove the whitespace, as some implementations "
                    "may not process it correctly."
                )
            else:
                unrelated_records.append(record)

        if dmarc_record_count > 1:
            raise MultipleDMARCRecords(
                "Multiple DMARC policy records are not permitted - "
                "https://tools.ietf.org/html/rfc7489#section-6.6.3")
        if len(unrelated_records) > 0:
            if not ignore_unrelated_records:
                ur_str = "\n\n".join(unrelated_records)
                raise UnrelatedTXTRecordFoundAtDMARC(
                    "Unrelated TXT records were discovered. These should be "
                    "removed, as some receivers may not expect to find "
                    f"unrelated TXT records at {target}\n\n{ur_str}")
        dmarc_record = [record for record in records if record.startswith(
            txt_prefix)][0]

    except dns.resolver.NoAnswer:
        try:
            records = query_dns(domain, "TXT",
                                nameservers=nameservers, resolver=resolver,
                                timeout=timeout)
            for record in records:
                if record.startswith(txt_prefix):
                    raise DMARCRecordInWrongLocation(
                        "The DMARC record must be located at "
                        f"{target}, not {domain}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise DMARCRecordNotFound(
                f"The domain {0} does not exist".format(domain))
        except Exception as error:
            raise DMARCRecordNotFound(error)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except DMARCRecordStartsWithWhitespace as error:
        raise error
    except MultipleDMARCRecords as error:
        raise error
    except Exception as error:
        raise DMARCRecordNotFound(error)

    return dmarc_record


def query_dmarc_record(domain: str, nameservers: list[str] = None,
                       resolver: dns.resolver.Resolver = None,
                       timeout: float = 2.0,
                       ignore_unrelated_records: bool = False) -> OrderedDict:
    """
    Queries DNS for a DMARC record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
        ignore_unrelated_records (bool): Ignore unrelated TXT records

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``record`` - the unparsed DMARC record string
                     - ``location`` - the domain where the record was found
                     - ``warnings`` - warning conditions found

     Raises:
        :exc:`checkdmarc.dmarc.DMARCRecordNotFound`
        :exc:`checkdmarc.dmarc.DMARCRecordInWrongLocation`
        :exc:`checkdmarc.dmarc.MultipleDMARCRecords`
        :exc:`checkdmarc.dmarc.SPFRecordFoundWhereDMARCRecordShouldBe`

    """
    logging.debug(f"Checking for a DMARC record on {domain}")
    warnings = []
    base_domain = get_base_domain(domain)
    location = domain.lower()
    record = _query_dmarc_record(
        domain, nameservers=nameservers,
        resolver=resolver, timeout=timeout,
        ignore_unrelated_records=ignore_unrelated_records)
    try:
        root_records = query_dns(domain, "TXT",
                                 nameservers=nameservers, resolver=resolver,
                                 timeout=timeout)
        for root_record in root_records:
            if root_record.startswith("v=DMARC1"):
                warnings.append(f"DMARC record at root of {domain} "
                                "has no effect")
    except dns.resolver.NXDOMAIN:
        raise DMARCRecordNotFound(
            f"The domain {domain} does not exist")
    except dns.exception.DNSException:
        pass

    if record is None and domain != base_domain:
        record = _query_dmarc_record(base_domain, nameservers=nameservers,
                                     resolver=resolver, timeout=timeout)
        location = base_domain
    if record is None:
        raise DMARCRecordNotFound(
            "A DMARC record does not exist for this domain or its base domain")

    return OrderedDict([("record", record), ("location", location),
                        ("warnings", warnings)])


def get_dmarc_tag_description(
        tag: str,
        value: Union[str, list[str]] = None) -> OrderedDict:
    """
    Get the name, default value, and description for a DMARC tag, amd/or a
    description for a tag value

    Args:
        tag (str): A DMARC tag
        value: An optional value

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``name`` - the tag name
                     - ``default``- the tag's default value
                     - ``description`` - A description of the tag or value
    """
    name = dmarc_tags[tag]["name"]
    description = dmarc_tags[tag]["description"]
    default = None
    allowed_values = {}
    if "default" in dmarc_tags[tag]:
        default = dmarc_tags[tag]["default"]
    if type(value) is str and value in allowed_values:
        description = allowed_values[value]
    elif type(value) is list and len(allowed_values):
        new_description = ""
        for sub_value in value:
            if sub_value in allowed_values:
                value_description = allowed_values[sub_value]
                new_description += f"{sub_value}: {value_description}\n\n"
        new_description = new_description.strip()
        if new_description != "":
            description = new_description

    return OrderedDict(
        [("name", name), ("default", default), ("description", description)])


def parse_dmarc_report_uri(uri: str) -> OrderedDict:
    """
    Parses a DMARC Reporting (i.e. ``rua``/``ruf``) URI

    .. note::
        ``mailto`` is the only reporting URI scheme supported in DMARC1

    Args:
        uri: A DMARC URI

    Returns:
        OrderedDict: An ``OrderedDict`` of the URI's components:
                    - ``scheme``
                    - ``address``
                    - ``size_limit``
    Raises:
        :exc:`checkdmarc.dmarc.InvalidDMARCReportURI`

    """
    uri = uri.strip()
    mailto_matches = MAILTO_REGEX.findall(uri)
    if len(mailto_matches) != 1:
        raise InvalidDMARCReportURI(
            (
                f"{uri} is not a valid DMARC report URI" + (
                    ""
                    if uri.startswith("mailto:")
                    else (
                        " - please make sure that the URI begins with "
                        "a schema such as mailto:"
                    )
                )
            )
        )
    match = mailto_matches[0]
    scheme = match[0].lower()
    email_address = match[1]
    size_limit = match[2].lstrip("!")
    if size_limit == "":
        size_limit = None

    return OrderedDict([("scheme", scheme), ("address", email_address),
                        ("size_limit", size_limit)])


def check_wildcard_dmarc_report_authorization(
        domain: str,
        nameservers: list[str] = None,
        resolver: dns.resolver.Resolver = None,
        timeout: float = 2.0) -> bool:
    """
    Checks for a wildcard DMARC report authorization record, e.g.:

    ::

      *._report.example.com IN TXT "v=DMARC1"

    Args:
        domain (str): The domain to check
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        bool: An indicator of the existence of a valid wildcard DMARC report
        authorization record
    """
    wildcard_target = f"*._report._dmarc.{domain}"
    dmarc_record_count = 0
    unrelated_records = []
    try:
        records = query_dns(wildcard_target, "TXT",
                            nameservers=nameservers, resolver=resolver,
                            timeout=timeout)

        for record in records:
            if record.startswith("v=DMARC1"):
                dmarc_record_count += 1
            else:
                unrelated_records.append(record)

        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            raise UnrelatedTXTRecordFoundAtDMARC(
                "Unrelated TXT records were discovered. "
                "These should be removed, as some "
                "receivers may not expect to find unrelated TXT records "
                f"at {wildcard_target}\n\n{ur_str}")

        if dmarc_record_count < 1:
            return False
    except dns.exception.DNSException:
        return False

    return True


def verify_dmarc_report_destination(source_domain: str,
                                    destination_domain: str,
                                    nameservers: list[str] = None,
                                    resolver: dns.resolver.Resolver = None,
                                    timeout: float = 2.0) -> bool:
    """
      Checks if the report destination accepts reports for the source domain
      per RFC 7489, section 7.1

      Args:
          source_domain (str): The source domain
          destination_domain (str): The destination domain
          nameservers (list): A list of nameservers to query
          resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

      Returns:
          bool: Indicates if the report domain accepts reports from the given
          domain

      Raises:
          :exc:`checkdmarc.dmarc.UnverifiedDMARCURIDestination`
          :exc:`checkdmarc.dmarc.UnrelatedTXTRecordFound`
      """

    source_domain = source_domain.lower()
    destination_domain = destination_domain.lower()

    if get_base_domain(source_domain) != get_base_domain(destination_domain):
        if check_wildcard_dmarc_report_authorization(destination_domain,
                                                     nameservers=nameservers,
                                                     resolver=resolver):
            return True
        target = f"{source_domain}._report._dmarc.{destination_domain}"
        message = f"{destination_domain} does not indicate that it accepts " \
                  f"DMARC reports about {source_domain} - " \
                  "Authorization record not found: " \
                  f'{source_domain}._report._dmarc.{destination_domain} " \
                    IN TXT "v=DMARC1"'
        dmarc_record_count = 0
        unrelated_records = []
        try:
            records = query_dns(target, "TXT",
                                nameservers=nameservers, resolver=resolver,
                                timeout=timeout)

            for record in records:
                if record.startswith("v=DMARC1"):
                    dmarc_record_count += 1
                else:
                    unrelated_records.append(record)

            if len(unrelated_records) > 0:
                ur_str = "\n\n".join(unrelated_records)
                raise UnrelatedTXTRecordFoundAtDMARC(
                    "Unrelated TXT records were discovered. "
                    "These should be removed, as some "
                    "receivers may not expect to find unrelated TXT records "
                    f"at {target}\n\n{ur_str}")

            if dmarc_record_count < 1:
                return False
        except Exception:
            raise UnverifiedDMARCURIDestination(message)

    return True


def parse_dmarc_record(
        record: str, domain: str, parked: bool = False,
        include_tag_descriptions: bool = False,
        nameservers: list[str] = None,
        resolver: dns.resolver.Resolver = None,
        timeout: float = 2.0,
        syntax_error_marker: str = SYNTAX_ERROR_MARKER) -> OrderedDict:
    """
    Parses a DMARC record

    Args:
        record (str): A DMARC record
        domain (str): The domain where the record is found
        parked (bool): Indicates if a domain is parked
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``tags`` - An ``OrderedDict`` of DMARC tags

           - ``value`` - The DMARC tag value
           - ``explicit`` - ``bool``: A value is explicitly set
           - ``default`` - The tag's default value
           - ``description`` - A description of the tag/value

         - ``warnings`` - A ``list`` of warnings

         .. note::
            ``default`` and ``description`` are only included if
            ``include_tag_descriptions`` is set to ``True``

    Raises:
        :exc:`checkdmarc.dmarc.DMARCSyntaxError`
        :exc:`checkdmarc.dmarc.InvalidDMARCTag`
        :exc:`checkdmarc.dmarc.InvalidDMARCTagValue`
        :exc:`checkdmarc.dmarc.InvalidDMARCReportURI`
        :exc:`checkdmarc.dmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.dmarc.UnrelatedTXTRecordFound`
        :exc:`checkdmarc.dmarc.DMARCReportEmailAddressMissingMXRecords`

    """
    logging.debug(f"Parsing the DMARC record for {domain}")
    spf_in_dmarc_error_msg = "Found a SPF record where a DMARC record " \
                             "should be; most likely, the _dmarc " \
                             "subdomain record does not actually exist, " \
                             "and the request for TXT records was " \
                             "redirected to the base domain"
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereDMARCRecordShouldBe(spf_in_dmarc_error_msg)
    dmarc_syntax_checker = _DMARCGrammar()
    parsed_record = dmarc_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        expecting = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting)))
        marked_record = (record[:parsed_record.pos] + syntax_error_marker +
                         record[parsed_record.pos:])
        expecting = " or ".join(expecting)
        raise DMARCSyntaxError(f"Error: Expected {expecting} at position "
                               f"{parsed_record.pos} "
                               f"(marked with {syntax_error_marker}) in: "
                               f"{marked_record}")

    pairs = DMARC_TAG_VALUE_REGEX.findall(record)
    tags = OrderedDict()

    # Find explicit tags
    for pair in pairs:
        tags[pair[0].lower()] = OrderedDict(
            [("value", str(pair[1].strip())), ("explicit", True)])

    # Include implicit tags and their defaults
    for tag in dmarc_tags.keys():
        if tag not in tags and "default" in dmarc_tags[tag]:
            tags[tag] = OrderedDict(
                [("value", dmarc_tags[tag]["default"]), ("explicit", False)])
    if "p" not in tags:
        raise DMARCSyntaxError(
            'The record is missing the required policy ("p") tag')
    tags["p"]["value"] = tags["p"]["value"].lower()
    if "sp" not in tags:
        tags["sp"] = OrderedDict([("value", tags["p"]["value"]),
                                  ("explicit", False)])
    if list(tags.keys())[1] != "p":
        raise DMARCSyntaxError("the p tag must immediately follow the v tag")
    tags["v"]["value"] = tags["v"]["value"].upper()
    # Validate tag values
    for tag in tags:
        if tag not in dmarc_tags:
            raise InvalidDMARCTag(f"{tag} is not a valid DMARC tag")
        tag_value = tags[tag]["value"]
        allowed_values = None
        if "values" in dmarc_tags[tag]:
            allowed_values = dmarc_tags[tag]["values"]
        if tag == "fo":
            tag_value = tag_value.split(":")
            if "0" in tag_value and "1" in tag_value:
                warnings.append(
                    "When 1 is present in the fo tag, including 0 is "
                    "redundant"
                )
            for value in tag_value:
                if value not in allowed_values:
                    raise InvalidDMARCTagValue(
                        f"{value} is not a valid option for the DMARC fo tag")
        elif tag == "rf":
            tag_value = tag_value.lower().split(":")
            for value in tag_value:
                if value not in allowed_values:
                    raise InvalidDMARCTagValue(
                        f"{value} is not a valid option for the DMARC "
                        "rf tag")

        elif allowed_values and tag_value not in allowed_values:
            allowed_values_str = ",".join(allowed_values)
            raise InvalidDMARCTagValue(
                f"Tag {tag} must have one of the following values: "
                f"{allowed_values_str} - not {tags[tag]['value']}")

    try:
        tags["pct"]["value"] = int(tags["pct"]["value"])
    except ValueError:
        raise InvalidDMARCTagValue(
            "The value of the pct tag must be an integer")

    try:
        tags["ri"]["value"] = int(tags["ri"]["value"])
    except ValueError:
        raise InvalidDMARCTagValue(
            "The value of the ri tag must be an integer")

    if "rua" in tags:
        parsed_uris = []
        uris = tags["rua"]["value"].split(",")
        for uri in uris:
            try:
                uri = parse_dmarc_report_uri(uri)
                parsed_uris.append(uri)
                email_address = uri["address"]
                email_domain = email_address.split("@")[-1]
                if email_domain.lower() != domain:
                    verify_dmarc_report_destination(domain, email_domain,
                                                    nameservers=nameservers,
                                                    resolver=resolver,
                                                    timeout=timeout)
                try:
                    hosts = get_mx_records(email_domain,
                                           nameservers=nameservers,
                                           resolver=resolver,
                                           timeout=timeout)
                    if len(hosts) == 0:
                        raise DMARCReportEmailAddressMissingMXRecords(
                            "The domain for rua email address "
                            f"{email_address} has no MX records"
                        )
                except DNSException as warning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "Failed to retrieve MX records for the domain of "
                        "rua email address "
                        f"{email_address} - {warning}")
            except _DMARCWarning as warning:
                warnings.append(str(warning))

        tags["rua"]["value"] = parsed_uris
        if len(parsed_uris) > 2:
            warnings.append(str(_DMARCBestPracticeWarning(
                "Some DMARC reporters might not send to more than two rua URIs"
            )))
    else:
        warnings.append(str(_DMARCBestPracticeWarning(
            "rua tag (destination for aggregate reports) not found")))

    if "ruf" in tags.keys():
        parsed_uris = []
        uris = tags["ruf"]["value"].split(",")
        for uri in uris:
            try:
                uri = parse_dmarc_report_uri(uri)
                parsed_uris.append(uri)
                email_address = uri["address"]
                email_domain = email_address.split("@")[-1]
                if email_domain.lower() != domain:
                    verify_dmarc_report_destination(domain, email_domain,
                                                    nameservers=nameservers,
                                                    resolver=resolver,
                                                    timeout=timeout)
                try:
                    hosts = get_mx_records(email_domain,
                                           nameservers=nameservers,
                                           resolver=resolver,
                                           timeout=timeout)
                    if len(hosts) == 0:
                        raise DMARCReportEmailAddressMissingMXRecords(
                            "The domain for ruf email address "
                            f"{email_address} has no MX records"
                        )
                except DNSException as warning:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        "Failed to retrieve MX records for the domain of "
                        "ruf email address "
                        f"{email_address} - {warning}"
                    )

            except _DMARCWarning as warning:
                warnings.append(str(warning))

        tags["ruf"]["value"] = parsed_uris
        if len(parsed_uris) > 2:
            warnings.append(str(_DMARCBestPracticeWarning(
                "Some DMARC reporters might not send to more than two ruf URIs"
            )))

    if tags["pct"]["value"] < 0 or tags["pct"]["value"] > 100:
        warnings.append(str(InvalidDMARCTagValue(
            "pct value must be an integer between 0 and 100")))
    elif tags["pct"]["value"] < 100:
        warning_msg = "pct value is less than 100. This leads to " \
                      "inconsistent and unpredictable policy " \
                      "enforcement. Consider using p=none to " \
                      "monitor results instead"
        warnings.append(str(_DMARCBestPracticeWarning(warning_msg)))
    if parked and tags["p"] != "reject":
        warning_msg = "Policy (p=) should be reject for parked domains"
        warnings.append(str(_DMARCBestPracticeWarning(warning_msg)))
    if parked and tags["sp"] != "reject":
        warning_msg = "Subdomain policy (sp=) should be reject for " \
                      "parked domains"
        warnings.append(str(_DMARCBestPracticeWarning(warning_msg)))

    # Add descriptions if requested
    if include_tag_descriptions:
        for tag in tags:
            tag_value = tags[tag]["value"]
            details = get_dmarc_tag_description(tag, tag_value)
            tags[tag]["name"] = details["name"]
            if details["default"]:
                tags[tag]["default"] = details["default"]
            tags[tag]["description"] = details["description"]

    return OrderedDict([("tags", tags), ("warnings", warnings)])


def get_dmarc_record(domain: str,
                     include_tag_descriptions: bool = False,
                     nameservers: list[str] = None,
                     resolver: dns.resolver.Resolver = None,
                     timeout: float = 2.0) -> OrderedDict:
    """
    Retrieves a DMARC record for a domain and parses it

    Args:
        domain (str): A domain name
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``record`` - The DMARC record string
         - ``location`` -  Where the DMARC was found
         - ``parsed`` - See :meth:`checkdmarc.parse_dmarc_record`

     Raises:
        :exc:`checkdmarc.dmarc.DMARCRecordNotFound`
        :exc:`checkdmarc.dmarc.DMARCRecordInWrongLocation`
        :exc:`checkdmarc.dmarc.MultipleDMARCRecords`
        :exc:`checkdmarc.dmarc.SPFRecordFoundWhereDMARCRecordShouldBe`
        :exc:`checkdmarc.dmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.dmarc.DMARCSyntaxError`
        :exc:`checkdmarc.dmarc.InvalidDMARCTag`
        :exc:`checkdmarc.dmarc.InvalidDMARCTagValue`
        :exc:`checkdmarc.dmarc.InvalidDMARCReportURI`
        :exc:`checkdmarc.dmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.dmarc.UnrelatedTXTRecordFound`
        :exc:`checkdmarc.dmarc.DMARCReportEmailAddressMissingMXRecords`
    """
    query = query_dmarc_record(domain, nameservers=nameservers,
                               resolver=resolver, timeout=timeout)

    tag_descriptions = include_tag_descriptions

    tags = parse_dmarc_record(query["record"], query["location"],
                              include_tag_descriptions=tag_descriptions,
                              nameservers=nameservers, resolver=resolver,
                              timeout=timeout)

    return OrderedDict([("record",
                         query["record"]),
                        ("location", query["location"]),
                        ("parsed", tags)])


def check_dmarc(domain: str, parked: bool = False,
                include_dmarc_tag_descriptions: bool = False,
                ignore_unrelated_records: bool = False,
                nameservers: list[str] = None,
                resolver: dns.resolver.Resolver = None,
                timeout: float = 2.0) -> OrderedDict:
    """
        Returns a dictionary with a parsed DMARC record or an error

        Args:
            domain (str): A domain name
            parked (bool): The domain is parked
            include_dmarc_tag_descriptions (bool): Include tag descriptions
            ignore_unrelated_records (bool): Ignore unrelated TXT records
            nameservers (list): A list of nameservers to query
            resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                              requests
            timeout (float): number of seconds to wait for a record from DNS

        Returns:
            OrderedDict: An ``OrderedDict`` with the following keys:

                         - ``record`` - the unparsed DMARC record string
                         - ``location`` - the domain where the record was found
                         - ``warnings`` - warning conditions found

                        If a DNS error occurs, the dictionary will have the
                        following keys:

                      - ``error``  - An error message
                      - ``valid`` - False

        """
    dmarc_results = OrderedDict([("record", None), ("valid", True),
                                 ("location", None)])
    try:
        dmarc_query = query_dmarc_record(
            domain,
            ignore_unrelated_records=ignore_unrelated_records,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout)
        dmarc_results["record"] = dmarc_query["record"]
        dmarc_results["location"] = dmarc_query["location"]
        parsed_dmarc_record = parse_dmarc_record(
            dmarc_query["record"],
            dmarc_query["location"],
            parked=parked,
            include_tag_descriptions=include_dmarc_tag_descriptions,
            nameservers=nameservers, resolver=resolver,
            timeout=timeout)
        dmarc_results["warnings"] = dmarc_query["warnings"]

        dmarc_results["tags"] = parsed_dmarc_record["tags"]
        dmarc_results["warnings"] += parsed_dmarc_record[
            "warnings"]
    except DMARCError as error:
        dmarc_results["error"] = str(error)
        dmarc_results["valid"] = False
        if hasattr(error, "data") and error.data:
            for key in error.data:
                dmarc_results[key] = error.data[key]

    return dmarc_results
