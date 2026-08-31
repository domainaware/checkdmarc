"""DMARC record validation"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Literal, TypedDict, overload

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
    MAILTO_REGEX,
    WSP_REGEX,
    DNSException,
    get_base_domain,
    get_mx_records,
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

# RFC 9989 §4.8: the tag name "v" is case-insensitive, but the value
# "DMARC1" is case sensitive (%s"DMARC1" in the ABNF), and whitespace is
# allowed around the equals sign.
DMARC_VERSION_REGEX_STRING = rf"[vV]{WSP_REGEX}*={WSP_REGEX}*DMARC1"
# RFC 9989 §4.8: a tag name is 1*ALPHA (any length), and a tag value may
# contain any printing character except a semicolon (%x20-3A / %x3C-7E).
DMARC_TAG_VALUE_REGEX_STRING = (
    rf"([a-z]+){WSP_REGEX}*={WSP_REGEX}*([\x20-\x3a\x3c-\x7e]+)"
)
DMARC_SEPARATOR_REGEX_STRING = rf"{WSP_REGEX}*;{WSP_REGEX}*"

DMARC_TAG_VALUE_REGEX = re.compile(DMARC_TAG_VALUE_REGEX_STRING, re.IGNORECASE)

# Used to decide whether a TXT record is a DMARC record before parsing it.
# The version tag must come first and must be followed by a separator or
# the end of the record, matching the ABNF in RFC 9989 §4.8 (which allows
# whitespace around the equals sign and an upper- or lowercase tag name).
_DMARC_RECORD_REGEX = re.compile(rf"^{DMARC_VERSION_REGEX_STRING}{WSP_REGEX}*(?:;|$)")

# RFC 9989 section 4.7 imports the RFC 3986 URI grammar for report URIs.
# This is not the full grammar: it requires a scheme followed by RFC 3986
# unreserved and reserved characters or valid percent-escapes, which is
# enough to reject raw spaces, control characters, and malformed escapes.
_URI_REGEX = re.compile(
    r"[a-z][a-z0-9+.\-]*:(?:[a-z0-9\-._~!$&'()*+,;=:@/?#\[\]]|%[0-9a-f]{2})+",
    re.IGNORECASE,
)

# Extracts the value of the psd tag from a raw record string during the
# RFC 9989 §4.10 tree walk, before the record is fully parsed. The v tag
# must come first, so a psd tag is always preceded by a separator, and a
# valid psd value is a single letter followed by a separator or the end
# of the record.
_PSD_TAG_REGEX = re.compile(
    rf";{WSP_REGEX}*psd{WSP_REGEX}*={WSP_REGEX}*([a-z]){WSP_REGEX}*(?:;|$)",
    re.IGNORECASE,
)


def _is_dmarc_record(record: str) -> bool:
    """Returns True if a TXT record string is a DMARC record, per the
    RFC 9989 §4.8 ABNF for the version tag"""
    return _DMARC_RECORD_REGEX.match(record) is not None


def _get_psd_tag_value(record: str) -> str | None:
    """Returns the lowercase value of the psd tag in a raw DMARC record
    string, or None if the tag is not present"""
    match = _PSD_TAG_REGEX.search(record)
    if match is None:
        return None
    return match.group(1).lower()


class _DMARCWarning(Exception):
    """Raised when a non-fatal DMARC error occurs"""


class _DMARCBestPracticeWarning(_DMARCWarning):
    """Raised when a DMARC record does not follow a best practice"""


class DMARCError(Exception):
    """Raised when a fatal DMARC error occurs"""

    def __init__(self, msg: str, data: DMARCErrorData | None = None):
        """
        Args:
            msg (str): The error message
            data (DMARCErrorData): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class DMARCRecordNotFound(DMARCError):
    """Raised when a DMARC record could not be found"""

    def __init__(self, error):
        # Round the timeout before stringifying, so the message shows the
        # rounded value
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)
        super().__init__(str(error))


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
    """Raised when multiple DMARC records are found. RFC 9989 § 4.10
    (steps 2 and 6) requires receivers to discard all of the records
    when more than one is returned for a name, so publishing multiple
    records disables DMARC (previously RFC 7489 § 6.6.3)"""


class _DMARCGrammar(pyleri.Grammar):
    """Defines Pyleri grammar for DMARC records, following the RFC 9989
    §4.8 ABNF: dmarc-record = dmarc-version *(dmarc-sep dmarc-tag)
    [dmarc-sep]. A bare ``v=DMARC1`` record is valid (p defaults to
    none), and the DMARC1 version value is case sensitive (so no
    re.IGNORECASE on the version tag)."""

    version_tag = pyleri.Regex(DMARC_VERSION_REGEX_STRING)
    tag_value = pyleri.Regex(DMARC_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = pyleri.Sequence(
        version_tag,
        pyleri.Optional(
            pyleri.Sequence(
                pyleri.Regex(DMARC_SEPARATOR_REGEX_STRING),
                pyleri.List(
                    tag_value,
                    delimiter=pyleri.Regex(DMARC_SEPARATOR_REGEX_STRING),
                    opt=True,
                ),
            )
        ),
    )


class DMARCTagMapItem(TypedDict):
    name: str
    required: bool
    description: str


class DMARCTagMapItemWithDefault(DMARCTagMapItem):
    default: str | int


class DMARCTagMapItemWithValues(DMARCTagMapItem):
    values: dict[str, str | int]


class DMARCTagMapItemWithDefaultAndValues(DMARCTagMapItem):
    default: str | int
    values: dict[str, str | int]


class DMARCTagMap(TypedDict):
    adkim: DMARCTagMapItemWithDefault
    aspf: DMARCTagMapItemWithDefault
    fo: DMARCTagMapItemWithDefaultAndValues
    np: DMARCTagMapItemWithValues
    p: DMARCTagMapItemWithValues
    psd: DMARCTagMapItemWithDefaultAndValues
    rua: DMARCTagMapItem
    ruf: DMARCTagMapItem
    sp: DMARCTagMapItemWithValues
    t: DMARCTagMapItemWithDefaultAndValues
    v: DMARCTagMapItem


class DMARCTagDetails(TypedDict):
    name: str
    default: str | int | None
    description: str


class DMARCRecordQueryResults(TypedDict):
    record: str
    location: str
    warnings: list[str]


class ParsedDMARCReportURI(TypedDict):
    """Structure for a parsed DMARC report URI"""

    scheme: str
    address: str
    size_limit: str | None


# TypedDicts for DMARC tag values
class DMARCTagValue(TypedDict):
    """Base structure for a DMARC tag value without descriptions"""

    value: str | int | list[ParsedDMARCReportURI]
    explicit: bool


class _DMARCTagValueOptionalFields(TypedDict, total=False):
    """Optional fields for DMARC tag values with descriptions"""

    default: str | int


class DMARCTagValueWithDescription(DMARCTagValue, _DMARCTagValueOptionalFields):
    """Structure for a DMARC tag value with descriptions"""

    name: str
    description: str


# Type aliases for parsed tags dictionaries
DMARCParsedTags = dict[str, DMARCTagValue]
DMARCParsedTagsWithDescriptions = dict[str, DMARCTagValueWithDescription]


class ParsedDMARCRecord(TypedDict):
    """Return type for parse_dmarc_record without descriptions"""

    tags: DMARCParsedTags
    warnings: list[str]


class ParsedDMARCRecordWithDescriptions(TypedDict):
    """Return type for parse_dmarc_record with descriptions"""

    tags: DMARCParsedTagsWithDescriptions
    warnings: list[str]


class DMARCRecord(TypedDict):
    """Return type for get_dmarc_record without descriptions"""

    record: str
    location: str
    parsed: ParsedDMARCRecord


class DMARCRecordWithDescriptions(TypedDict):
    """Return type for get_dmarc_record with descriptions"""

    record: str
    location: str
    parsed: ParsedDMARCRecordWithDescriptions


class DMARCResults(TypedDict):
    """Success return type for check_dmarc"""

    record: str
    location: str
    valid: Literal[True]
    warnings: list[str]
    tags: DMARCParsedTags | DMARCParsedTagsWithDescriptions


class _DMARCErrorResultsOptionalFields(TypedDict, total=False):
    """Optional fields for DMARCErrorResults"""

    target: str


class DMARCErrorResults(_DMARCErrorResultsOptionalFields):
    """Error return type for check_dmarc"""

    record: str | None
    location: str | None
    valid: Literal[False]
    error: str


class DMARCErrorData(TypedDict, total=False):
    """Optional data structure for DMARCError"""

    target: str


dmarc_tags: DMARCTagMap = {
    "adkim": {
        "name": "DKIM Alignment Mode",
        "required": False,
        "default": "r",
        "description": (
            "In relaxed mode, "
            "the Organizational "
            "Domains of both the "
            "DKIM-authenticated "
            "signing domain (taken "
            "from the value of the "
            '"d=" tag in the '
            "signature) and that "
            "of the RFC 5322 "
            "From domain "
            "must be equal if the "
            "identifiers are to be "
            "considered aligned."
        ),
    },
    "aspf": {
        "name": "SPF alignment mode",
        "required": False,
        "default": "r",
        "description": (
            "In relaxed mode, "
            "the SPF-authenticated "
            "domain and RFC 5322 "
            "From domain must have "
            "the same "
            "Organizational Domain. "
            "In strict mode, only "
            "an exact DNS domain "
            "match is considered to "
            "produce Identifier "
            "Alignment."
        ),
    },
    "fo": {
        "name": "Failure Reporting Options",
        "required": False,
        "default": "0",
        "description": (
            "Provides requested "
            "options for generation "
            "of failure reports. "
            "Report generators MAY "
            "choose to adhere to the "
            "requested options. "
            "This tag's content "
            "MUST be ignored if "
            'a "ruf" tag (below) is '
            "not also specified. "
            "The value of this tag is "
            "a colon-separated list "
            "of characters that "
            "indicate failure "
            "reporting options."
        ),
        "values": {
            "0": (
                "Generate a DMARC failure "
                "report if all underlying "
                "authentication mechanisms "
                "fail to produce an aligned "
                '"pass" result.'
            ),
            "1": (
                "Generate a DMARC failure "
                "report if any underlying "
                "authentication mechanism "
                "produced something other "
                "than an aligned "
                '"pass" result.'
            ),
            "d": (
                "Generate a DKIM failure "
                "report if the message had "
                "a signature that failed "
                "evaluation, regardless of "
                "its alignment. DKIM-"
                "specific reporting is "
                "described in AFRF-DKIM."
            ),
            "s": (
                "Generate an SPF failure "
                "report if the message "
                "failed SPF evaluation, "
                "regardless of its alignment. "
                "SPF-specific reporting is "
                "described in AFRF-SPF."
            ),
        },
    },
    "np": {
        "name": "Non-existent Subdomain Policy",
        "required": False,
        "description": (
            "Indicates the policy to "
            "be enacted by the "
            "Receiver at the request "
            "of the Domain Owner for "
            "non-existent subdomains "
            "of the domain queried. "
            "Its syntax is identical "
            'to that of the "p" tag. '
            "If absent, the policy "
            'specified by the "sp" tag '
            "(if present) or the "
            '"p" tag MUST be applied '
            "for non-existent subdomains."
        ),
        "values": {
            "none": (
                "The Domain Owner requests "
                "no specific action be "
                "taken regarding delivery "
                "of messages."
            ),
            "quarantine": (
                "The Domain Owner "
                "wishes to have "
                "email that fails "
                "the DMARC mechanism "
                "check be treated by "
                "Mail Receivers as "
                "suspicious."
            ),
            "reject": (
                "The Domain Owner wishes "
                "for Mail Receivers to "
                "reject email that fails "
                "the DMARC mechanism check. "
                "Rejection SHOULD occur "
                "during the SMTP "
                "transaction."
            ),
        },
    },
    "p": {
        "name": "Requested Mail Receiver Policy",
        "required": False,
        "description": (
            "Specifies the policy to "
            "be enacted by the "
            "Receiver at the "
            "request of the "
            "Domain Owner. The "
            "policy applies to "
            "the domain and to its "
            "subdomains, unless "
            "subdomain policy "
            "is explicitly described "
            'using the "sp" tag.'
        ),
        "values": {
            "none": (
                "The Domain Owner requests "
                "no specific action be "
                "taken regarding delivery "
                "of messages."
            ),
            "quarantine": (
                "The Domain Owner "
                "wishes to have "
                "email that fails "
                "the DMARC mechanism "
                "check be treated by "
                "Mail Receivers as "
                "suspicious. "
                "Depending on the "
                "capabilities of the "
                "Mail Receiver, "
                'this can mean "place into spam folder", '
                '"scrutinize with additional intensity", '
                'and/or "flag as suspicious".'
            ),
            "reject": (
                "The Domain Owner wishes "
                "for Mail Receivers to "
                "reject email that fails "
                "the DMARC mechanism check. "
                "Rejection SHOULD occur "
                "during the SMTP "
                "transaction."
            ),
        },
    },
    "psd": {
        "name": "PSD Flag",
        "required": False,
        "default": "u",
        "description": (
            "A flag indicating whether the domain is a Public Suffix Domain (PSD)."
        ),
        "values": {
            "y": (
                "The domain is a PSD. "
                "This tag is included "
                "by PSOs to indicate "
                "that the domain is a "
                "Public Suffix Domain."
            ),
            "n": (
                "The DMARC Policy Record "
                "is published for a domain "
                "that is not a PSD, but it "
                "is the Organizational "
                "Domain for itself and "
                "its subdomains."
            ),
            "u": (
                "The default indicates "
                "that the DMARC Policy "
                "Record is published for "
                "a domain that is not a "
                "PSD, and may or may not "
                "be an Organizational "
                "Domain for itself and "
                "its subdomains."
            ),
        },
    },
    "rua": {
        "name": "Aggregate Feedback Addresses",
        "required": False,
        "description": (
            "A comma-separated list "
            "of DMARC URIs to which "
            "aggregate feedback "
            "is to be sent."
        ),
    },
    "ruf": {
        "name": "Forensic Feedback Addresses",
        "required": False,
        "description": (
            "A comma-separated list "
            "of DMARC URIs to which "
            "forensic feedback "
            "is to be sent."
        ),
    },
    "sp": {
        "name": "Subdomain Policy",
        "required": False,
        "description": (
            "Indicates the policy to "
            "be enacted by the "
            "Receiver at the request "
            "of the Domain Owner. "
            "It applies only to "
            "subdomains of the "
            "domain queried, and not "
            "to the domain itself. "
            "Its syntax is identical "
            'to that of the "p" tag '
            "defined above. If "
            "absent, the policy "
            'specified by the "p" '
            "tag MUST be applied "
            "for subdomains."
        ),
        "values": {
            "none": (
                "The Domain Owner requests "
                "no specific action be "
                "taken regarding delivery "
                "of messages."
            ),
            "quarantine": (
                "The Domain Owner "
                "wishes to have "
                "email that fails "
                "the DMARC mechanism "
                "check be treated by "
                "Mail Receivers as "
                "suspicious. "
                "Depending on the "
                "capabilities of the "
                "Mail Receiver, "
                'this can mean "place into spam folder", '
                '"scrutinize with additional intensity", '
                'and/or "flag as suspicious".'
            ),
            "reject": (
                "The Domain Owner wishes "
                "for Mail Receivers to "
                "reject email that fails "
                "the DMARC mechanism check. "
                "Rejection SHOULD occur "
                "during the SMTP "
                "transaction."
            ),
        },
    },
    "t": {
        "name": "DMARC Policy Test Mode",
        "required": False,
        "default": "n",
        "description": (
            "Signals whether or not "
            "the Domain Owner wishes "
            "the Domain Owner Assessment "
            "Policy declared in the "
            '"p", "sp", and/or "np" tags '
            "to actually be applied. "
            "This tag does not affect "
            "the generation of DMARC "
            "reports, and it has no "
            "effect on any policy that "
            'is "none".'
        ),
        "values": {
            "y": (
                "A request that the actor "
                "performing the DMARC "
                "validation check not "
                "apply the policy, but "
                "instead apply any special "
                "handling rules it might "
                "have in place. The Domain "
                "Owner is currently testing "
                "its specified DMARC "
                "assessment policy."
            ),
            "n": (
                "The default is a request "
                "to apply the Domain Owner "
                "Assessment Policy as "
                "specified to any message "
                "that produces a DMARC "
                '"fail" result.'
            ),
        },
    },
    "v": {
        "name": "Version",
        "required": True,
        "description": (
            "Identifies the record "
            "retrieved as a DMARC "
            "record. It MUST have the "
            'value of "DMARC1". The '
            "value of this tag MUST "
            "match precisely; if it "
            "does not or it is absent, "
            "the entire retrieved "
            "record MUST be ignored. "
            "It MUST be the first "
            "tag in the list."
        ),
    },
}


def _query_dmarc_record(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    ignore_unrelated_records: bool = False,
    apex_fallback: bool = True,
) -> str | None:
    """
    Queries DNS for a DMARC record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors
        ignore_unrelated_records (bool): Do not raise an error if unrelated TXT records are found
        apex_fallback (bool): When ``_dmarc.{domain}`` has no answer, also
            query the apex of ``{domain}`` and raise
            ``DMARCRecordInWrongLocation`` if a ``v=DMARC1`` record is found
            there. Disabled during the RFC 9989 tree walk: misplaced apex
            records at parent domains are not the operator's concern when
            looking up the policy for a subdomain.

    Returns:
        str: A record string or None
    """
    domain = normalize_domain(domain)
    target = f"_dmarc.{domain}"
    dmarc_record = None
    dmarc_records = []
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
            # The RFC 9989 §4.8 ABNF allows whitespace around the equals
            # sign and a lowercase or uppercase v, so tolerate the same
            # variations here that parse_dmarc_record accepts.
            if _is_dmarc_record(record):
                dmarc_records.append(record)
            elif _is_dmarc_record(record.strip()):
                raise DMARCRecordStartsWithWhitespace(
                    f"Found a DMARC record at {target} that starts with whitespace. "
                    "Please remove the whitespace, as some implementations "
                    "may not process it correctly."
                )
            else:
                unrelated_records.append(record)

        if len(dmarc_records) > 1:
            raise MultipleDMARCRecords(
                "Multiple DMARC policy records are not permitted - "
                "https://www.rfc-editor.org/rfc/rfc9989.html#section-4.10"
            )
        if len(unrelated_records) > 0 and not ignore_unrelated_records:
            ur_str = "\n\n".join(unrelated_records)
            raise UnrelatedTXTRecordFoundAtDMARC(
                "Unrelated TXT records were discovered. These should be "
                "removed, as some receivers may not expect to find "
                f"unrelated TXT records at {target}\n\n{ur_str}",
                data={"target": target},
            )
        if len(dmarc_records) == 1:
            dmarc_record = dmarc_records[0]

    except dns.resolver.NoAnswer:
        if not apex_fallback:
            return None
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
                if _is_dmarc_record(record):
                    raise DMARCRecordInWrongLocation(
                        f"The DMARC record must be located at {target}, not {domain}."
                    )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise DMARCRecordNotFound(f"The domain {domain} does not exist.")
        except DMARCError:
            # DMARCRecordInWrongLocation is a DMARCError raised on purpose
            # above — propagate it instead of letting the broad ``except``
            # below convert it to DMARCRecordNotFound.
            raise
        except dns.exception.DNSException as error:
            raise DMARCRecordNotFound(error)

    except dns.resolver.NXDOMAIN:
        pass
    except DMARCRecordStartsWithWhitespace:
        raise
    except UnrelatedTXTRecordFoundAtDMARC:
        raise
    except MultipleDMARCRecords:
        raise
    except dns.exception.DNSException as error:
        raise DMARCError(str(error))

    return dmarc_record


def query_dmarc_record(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    ignore_unrelated_records: bool = False,
) -> DMARCRecordQueryResults:
    """
    Queries DNS for a DMARC record

    Args:
        domain (str): A domain name
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors
        ignore_unrelated_records (bool): Ignore unrelated TXT records

    Returns:
        dict: a ``dict`` with the following keys:
                     - ``record`` - the unparsed DMARC record string
                     - ``location`` - the domain where the record was found
                     - ``warnings`` - warning conditions found

     Raises:
        :exc:`checkdmarc.dmarc.DMARCRecordNotFound`
        :exc:`checkdmarc.dmarc.DMARCRecordInWrongLocation`
        :exc:`checkdmarc.dmarc.MultipleDMARCRecords`
        :exc:`checkdmarc.dmarc.SPFRecordFoundWhereDMARCRecordShouldBe`

    """
    domain = normalize_domain(domain).rstrip(".")
    logger.debug(f"Checking for a DMARC record on {domain}")
    warnings = []
    location = domain

    try:
        record = _query_dmarc_record(
            domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
            ignore_unrelated_records=ignore_unrelated_records,
        )
    except DMARCRecordNotFound:
        # Skip this exception as we want to perform a tree walk. If we fail
        # at that, at the end of this function we will raise another
        # DMARCRecordNotFound.
        record = None

    try:
        root_records = query_dns(
            domain,
            "TXT",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        for root_record in root_records:
            if _is_dmarc_record(root_record):
                warnings.append(
                    f"A DMARC record at the root of {domain} has no effect."
                )
    except dns.resolver.NXDOMAIN:
        # Some DNS servers mishandle names that only exist as parents of
        # other names, and return NXDOMAIN for the apex even though
        # _dmarc.{domain} answered above. A record that was already found
        # must not be discarded because of this courtesy query.
        if record is None:
            raise DMARCRecordNotFound("The domain does not exist.")
    except dns.exception.DNSException:
        pass

    # RFC 9989 §4.10 DNS tree walk for DMARC policy discovery
    if record is None:
        labels = domain.split(".")
        num_labels = len(labels)
        if num_labels > 1:
            # Determine starting point for tree walk
            if num_labels <= 8:
                # Start from the parent domain (remove leftmost label)
                start = 1
            else:
                # Skip to 7 labels remaining so that initial query + walk
                # stays within the RFC 9989 8-query budget.
                start = num_labels - 7
            # Walk up the tree collecting records as we go, including
            # single-label parents: a PSO may publish ``_dmarc.<tld>``
            # with ``psd=y`` (RFC 9989 §4.10). Per §4.10 steps 6-7 the
            # walk continues after finding a record, and stops early only
            # when a record carries psd=n or psd=y.
            walked: list[tuple[int, str, str]] = []
            for i in range(start, num_labels):
                parent = ".".join(labels[i:])
                try:
                    parent_record = _query_dmarc_record(
                        parent,
                        nameservers=nameservers,
                        resolver=resolver,
                        timeout=timeout,
                        retries=retries,
                        ignore_unrelated_records=ignore_unrelated_records,
                        apex_fallback=False,
                    )
                except DMARCRecordNotFound:
                    # No DMARC record at this parent; continue walking up the tree
                    continue
                except DMARCError:
                    # A DMARC record exists but is invalid or otherwise problematic;
                    # re-raise so the caller can surface the actual configuration error.
                    raise
                if parent_record is None:
                    continue
                walked.append((i, parent, parent_record))
                if _get_psd_tag_value(parent_record) in ("n", "y"):
                    break
            if walked:
                # RFC 9989 §4.10.2 Organizational Domain selection. Because
                # the walk goes from the longest name to the shortest and
                # stops at the first psd=n or psd=y record, only the last
                # collected record can carry a psd tag, so:
                # 1. psd=n: that record's domain is the Organizational
                #    Domain (last collected).
                # 2. psd=y: the Organizational Domain is one label below
                #    the psd=y domain; the record found there (if any)
                #    applies, otherwise the PSD record itself does.
                # 3. Otherwise: the record at the name with the fewest
                #    labels applies (also the last collected).
                index, location, record = walked[-1]
                if _get_psd_tag_value(record) == "y":
                    org_domain = ".".join(labels[index - 1 :])
                    if len(walked) > 1 and walked[-2][0] == index - 1:
                        index, location, record = walked[-2]
                    else:
                        warnings.append(
                            f"The Organizational Domain of {domain} is "
                            f"{org_domain} (the domain one label below the "
                            f"psd=y record at {location}), but no DMARC "
                            "record was found there, so the Public Suffix "
                            f"Domain record at {location} applies."
                        )

    if record is None:
        error_str = "A DMARC record does not exist"
        labels = domain.split(".")
        if len(labels) <= 2:
            error_str += "."
        else:
            error_str += " for this domain or its parent domains."
        raise DMARCRecordNotFound(error_str)

    return {"record": record, "location": location, "warnings": warnings}


def get_dmarc_tag_description(
    tag: str, value: str | list[str] | None = None
) -> DMARCTagDetails:
    """
    Get the name, default value, and description for a DMARC tag, and/or a
    description for a tag value

    Args:
        tag (str): A DMARC tag
        value: An optional value

    Returns:
        dict: a ``dict`` with the following keys:
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
    if "values" in dmarc_tags[tag]:
        allowed_values = dmarc_tags[tag]["values"]
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

    return {"name": name, "default": default, "description": description}


def parse_dmarc_report_uri(uri: str) -> ParsedDMARCReportURI:
    """
    Parses a DMARC Reporting (i.e. ``rua``/``ruf``) URI

    .. note::
        RFC 9989 § 4.7 allows any valid URI, but ``mailto`` is the only
        scheme mail receivers are required to support. For a non-mailto
        URI, ``address`` contains the full URI and ``size_limit`` is
        ``None``.

    Args:
        uri: A DMARC URI

    Returns:
        dict: a ``dict`` of the URI's components:
                    - ``scheme``
                    - ``address``
                    - ``size_limit``
    Raises:
        :exc:`checkdmarc.dmarc.InvalidDMARCReportURI`

    """
    uri = uri.strip()
    mailto_matches = MAILTO_REGEX.findall(uri)
    if len(mailto_matches) != 1:
        # RFC 9989 §4.7: any valid URI can be specified, and receivers
        # ignore URIs with schemes they do not support. Keep a URI with a
        # recognizable non-mailto scheme in the parsed output; only a URI
        # with no scheme at all (or a malformed mailto URI) is an error.
        scheme_match = re.match(r"([a-z][a-z0-9+.\-]*):", uri, re.IGNORECASE)
        if (
            scheme_match is not None
            and scheme_match.group(1).lower() != "mailto"
            and _URI_REGEX.fullmatch(uri) is not None
        ):
            return {
                "scheme": scheme_match.group(1).lower(),
                "address": uri,
                "size_limit": None,
            }
        raise InvalidDMARCReportURI(
            f"{uri} is not a valid DMARC report URI"
            + (
                ""
                if uri.startswith("mailto:")
                else (
                    " - please make sure that the URI begins with "
                    "a scheme such as mailto:"
                )
            )
        )
    match = mailto_matches[0]
    scheme = match[0].lower()
    email_address = match[1]
    size_limit = match[2].lstrip("!")
    if size_limit == "":
        size_limit = None

    return {"scheme": scheme, "address": email_address, "size_limit": size_limit}


def check_wildcard_dmarc_report_authorization(
    domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    ignore_unrelated_records: bool = False,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> bool:
    """
    Checks for a wildcard DMARC report authorization record, e.g.:

    ::

      *._report.example.com IN TXT "v=DMARC1"

    Args:
        domain (str): The domain to check
        nameservers (list): A list of nameservers to query
        ignore_unrelated_records (bool): Ignore unrelated TXT records
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors


    Returns:
        bool: An indicator of the existence of a valid wildcard DMARC report
        authorization record
    """
    wildcard_target = f"*._report._dmarc.{domain}"
    dmarc_record_count = 0
    unrelated_records = []
    try:
        records = query_dns(
            wildcard_target,
            "TXT",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )

        for record in records:
            if _is_dmarc_record(record):
                dmarc_record_count += 1
            else:
                unrelated_records.append(record)

        if len(unrelated_records) > 0 and not ignore_unrelated_records:
            ur_str = "\n\n".join(unrelated_records)
            raise UnrelatedTXTRecordFoundAtDMARC(
                "Unrelated TXT records were discovered. "
                "These should be removed, as some "
                "receivers may not expect to find unrelated TXT records "
                f"at {wildcard_target}\n\n{ur_str}",
                data={"target": wildcard_target},
            )

        if dmarc_record_count < 1:
            return False
    except dns.exception.DNSException:
        return False

    return True


def verify_dmarc_report_destination(
    source_domain: str,
    destination_domain: str,
    *,
    nameservers: Sequence[str | Nameserver] | None = None,
    ignore_unrelated_records: bool = False,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> None:
    """
    Checks if the report destination accepts reports for the source domain
    per RFC 9990, § 4 (the authorization-record check, previously in
    RFC 7489 § 7.1). Raises
    `checkdmarc.dmarc.UnverifiedDMARCURIDestination` if it doesn't accept.

    Args:
        source_domain (str): The source domain
        destination_domain (str): The destination domain
        nameservers (list): A list of nameservers to query
        ignore_unrelated_records (bool): Ignore unrelated TXT records
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                        requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors


    Raises:
        :exc:`checkdmarc.dmarc.UnverifiedDMARCURIDestination`
        :exc:`checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC`
    """

    source_domain = source_domain.lower()
    destination_domain = destination_domain.lower()

    # RFC 9990 §4 defines "external" by comparing the tree-walk
    # Organizational Domains of the policy domain and the report
    # destination. Determining those exactly would cost up to eight extra
    # DNS queries per domain for every report URI, so the Public Suffix
    # List is used as an approximation here. The two can disagree for
    # domains whose published psd tags draw the organizational boundary
    # somewhere other than where the PSL does.
    if get_base_domain(source_domain) != get_base_domain(destination_domain):
        if check_wildcard_dmarc_report_authorization(
            destination_domain,
            nameservers=nameservers,
            ignore_unrelated_records=ignore_unrelated_records,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        ):
            return
        target = f"{source_domain}._report._dmarc.{destination_domain}"
        message = (
            f"{destination_domain} does not indicate that it accepts "
            f"DMARC reports about {source_domain} - "
            "Authorization record not found: "
            f'{source_domain}._report._dmarc.{destination_domain} IN TXT "v=DMARC1"'
        )
        try:
            records = query_dns(
                target,
                "TXT",
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
                retries=retries,
            )
        except dns.exception.DNSException:
            # A DNS failure means the destination can't be confirmed.
            raise UnverifiedDMARCURIDestination(message)

        # RFC 9990 §4 steps 6-8: discard TXT records that are not DMARC
        # authorization records; if at least one record remains, the
        # external reporting arrangement is authorized. Unrelated records
        # coexisting with a valid authorization record do not undo it.
        for record in records:
            if _is_dmarc_record(record):
                return

        raise UnverifiedDMARCURIDestination(message)


def _parse_report_uris(
    tag_name: str,
    value: str,
    domain: str,
    warnings: list[str],
    *,
    nameservers: Sequence[str | Nameserver] | None,
    ignore_unrelated_records: bool,
    resolver: dns.resolver.Resolver | None,
    timeout: float,
    retries: int,
) -> list[ParsedDMARCReportURI]:
    """
    Parses and checks the comma-separated URI list of a ``rua`` or ``ruf``
    tag, appending any warning messages found to ``warnings``

    Args:
        tag_name (str): ``rua`` or ``ruf``, used in warning messages
        value (str): The raw tag value
        domain (str): The domain where the DMARC record was found
        warnings (list): The warnings list to append to
        nameservers (list): A list of nameservers to query
        ignore_unrelated_records (bool): Ignore unrelated TXT records
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        list: The parsed report URIs

    Raises:
        :exc:`checkdmarc.dmarc.InvalidDMARCReportURI`
    """
    parsed_uris: list[ParsedDMARCReportURI] = []
    for uri in value.split(","):
        try:
            parsed_uri = parse_dmarc_report_uri(uri)
            parsed_uris.append(parsed_uri)
            if parsed_uri["scheme"] != "mailto":
                # RFC 9989 §4.7: any valid URI is allowed, but mail
                # receivers are only required to support mailto, and they
                # ignore URIs with schemes they do not support.
                warnings.append(
                    f"The {tag_name} URI {parsed_uri['address']} uses the "
                    f"{parsed_uri['scheme']} scheme. That is valid per "
                    "RFC 9989 § 4.7, but mail receivers are only required "
                    "to support mailto URIs, so most will ignore it."
                )
                continue
            email_address = parsed_uri["address"]
            if parsed_uri["size_limit"]:
                warnings.append(
                    f"The size limit (`!size`) on {tag_name} URI for "
                    f"{email_address} is obsolete in RFC 9989 "
                    "(reporters MUST ignore it); pre-9989 readers may "
                    "still honor it and produce incomplete reports."
                )
            email_domain = email_address.split("@")[-1]
            if email_domain.lower() != domain:
                verify_dmarc_report_destination(
                    domain,
                    email_domain,
                    nameservers=nameservers,
                    ignore_unrelated_records=ignore_unrelated_records,
                    resolver=resolver,
                    timeout=timeout,
                    retries=retries,
                )
            try:
                hosts = get_mx_records(
                    email_domain,
                    nameservers=nameservers,
                    resolver=resolver,
                    timeout=timeout,
                    retries=retries,
                )
                if len(hosts) == 0:
                    raise DMARCReportEmailAddressMissingMXRecords(
                        f"The domain for {tag_name} email address "
                        f"{email_address} has no MX records."
                    )
            except DNSException as warning:
                raise DMARCReportEmailAddressMissingMXRecords(
                    "Failed to retrieve MX records for the domain of "
                    f"{tag_name} email address "
                    f"{email_address} - {warning}"
                )
        except _DMARCWarning as warning:
            warnings.append(str(warning))

    if len(parsed_uris) > 2:
        warnings.append(
            str(
                _DMARCBestPracticeWarning(
                    "Some DMARC reporters might not send to more than "
                    f"two {tag_name} URIs."
                )
            )
        )
    return parsed_uris


@overload
def parse_dmarc_record(
    record: str,
    domain: str,
    *,
    parked: bool = False,
    include_tag_descriptions: Literal[False] = False,
    nameservers: Sequence[str | Nameserver] | None = None,
    ignore_unrelated_records: bool = False,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> ParsedDMARCRecord: ...


@overload
def parse_dmarc_record(
    record: str,
    domain: str,
    *,
    parked: bool = False,
    include_tag_descriptions: Literal[True],
    nameservers: Sequence[str | Nameserver] | None = None,
    ignore_unrelated_records: bool = False,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> ParsedDMARCRecordWithDescriptions: ...


def parse_dmarc_record(
    record: str,
    domain: str,
    *,
    parked: bool = False,
    include_tag_descriptions: bool = False,
    nameservers: Sequence[str | Nameserver] | None = None,
    ignore_unrelated_records: bool = False,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> ParsedDMARCRecord | ParsedDMARCRecordWithDescriptions:
    """
    Parses a DMARC record

    Args:
        record (str): A DMARC record
        domain (str): The domain where the record is found
        parked (bool): Indicates if a domain is parked
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        ignore_unrelated_records (bool): Ignore unrelated TXT records
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors
        syntax_error_marker (str): The marker for pointing out syntax errors

    Returns:
        dict: a ``dict`` with the following keys:
         - ``tags`` - a ``dict`` of DMARC tags

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
        :exc:`checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC`
        :exc:`checkdmarc.dmarc.DMARCReportEmailAddressMissingMXRecords`

    """
    logger.debug(f"Parsing the DMARC record for {domain}")
    spf_in_dmarc_error_msg = (
        "Found an SPF record where a DMARC record "
        "should be; most likely, the _dmarc "
        "subdomain record does not actually exist, "
        "and the request for TXT records was "
        "redirected to the base domain."
    )
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereDMARCRecordShouldBe(spf_in_dmarc_error_msg)
    dmarc_syntax_checker = _DMARCGrammar()
    grammar_result = dmarc_syntax_checker.parse(record)
    if not grammar_result.is_valid:
        expecting = [str(x).strip('"') for x in list(grammar_result.expecting)]
        marked_record = (
            record[: grammar_result.pos]
            + syntax_error_marker
            + record[grammar_result.pos :]
        )
        expecting_str = " or ".join(expecting)
        raise DMARCSyntaxError(
            f"Error: Expected {expecting_str} at position "
            f"{grammar_result.pos} "
            f"(marked with {syntax_error_marker}) in: "
            f"{marked_record}"
        )

    # Find explicit tags
    pairs: list[tuple[str, str]] = DMARC_TAG_VALUE_REGEX.findall(record)
    tags = {}

    # Tags defined in RFC 7489 but removed in RFC 9989. We still recognize
    # them for backward compatibility (pre-9989 readers may parse them) but
    # warn on use and skip strict value validation.
    removed_tags = ("pct", "rf", "ri")

    seen_tags: list[str] = []
    duplicate_tags: list[str] = []
    for pair in pairs:
        tag = pair[0].lower()
        # RFC 9989: Unknown tags MUST be ignored. Removed-in-9989 tags
        # (pct/rf/ri) get their own warning below.
        if tag not in dmarc_tags and tag not in removed_tags:
            warnings.append(
                f"Unknown DMARC tag '{tag}' was ignored "
                "(RFC 9989 requires unknown tags to be ignored)."
            )
            continue
        # Check for duplicate tags
        if tag in seen_tags:
            if tag not in duplicate_tags:
                duplicate_tags.append(tag)
        else:
            seen_tags.append(tag)
        if len(duplicate_tags):
            duplicate_tags_str = ",".join(duplicate_tags)
            raise InvalidDMARCTag(
                f"Duplicate {duplicate_tags_str} tags are not permitted"
            )
        if tag in removed_tags:
            warnings.append(f"Support for the {tag} tag was removed in RFC 9989")
            continue
        value = pair[1].lower().strip()
        tags[tag] = {"value": value, "explicit": True}

    # Include implicit tags and their defaults
    for tag in dmarc_tags:
        if tag not in tags and "default" in dmarc_tags[tag]:
            tags[tag] = {"value": dmarc_tags[tag]["default"], "explicit": False}
    if "p" not in tags:
        tags["p"] = {"value": "none", "explicit": False}
        warnings.append(
            "A missing p tag is equivalent to p=none in RFC 9989, "
            "but a p tag is required in older versions of DMARC."
        )
    tags["p"]["value"] = tags["p"]["value"].lower()
    if "sp" not in tags:
        tags["sp"] = {"value": tags["p"]["value"], "explicit": False}
    # Normalize sp value for validation consistency (mirrors p behavior)
    tags["sp"]["value"] = tags["sp"]["value"].lower()
    if "np" not in tags:
        if tags["sp"]["explicit"]:
            tags["np"] = {"value": tags["sp"]["value"], "explicit": False}
        else:
            tags["np"] = {"value": tags["p"]["value"], "explicit": False}
    tags["np"]["value"] = tags["np"]["value"].lower()
    # RFC 9989 only requires that the v tag come first; the p tag may appear
    # in any position. Older readers (pre-9989 implementations of RFC 7489)
    # may still expect p immediately after v, so warn when it isn't there.
    if tags["p"]["explicit"] and list(tags.keys())[1] != "p":
        warnings.append(
            "The p tag does not immediately follow the v tag. "
            "RFC 9989 permits any ordering, but some older DMARC "
            "implementations may require p to be the second tag."
        )
    tags["v"]["value"] = tags["v"]["value"].upper()

    # Validate tag values
    for tag in tags:
        tag_value = tags[tag]["value"]
        allowed_values = []
        explicit = tags[tag]["explicit"]
        if "values" in dmarc_tags[tag]:
            allowed_values = dmarc_tags[tag]["values"]
        if tag == "p" and tag_value == "none":
            warnings.append(
                f"A p tag value of none makes DMARC unenforced on email sent as {domain}."
            )
        if tag == "sp" and tag_value == "none" and explicit:
            warnings.append(
                f"An sp tag value of none makes DMARC unenforced on email sent as a subdomain of {domain}."
            )
        if tag in ("adkim", "aspf") and tag_value not in ("r", "s"):
            # RFC 9989 §4.8: syntax errors in a tag value are discarded in
            # favor of the default value, so an invalid alignment mode
            # falls back to relaxed (r) rather than failing the record.
            warnings.append(
                f"{tag_value} is not a valid {tag} tag value (must be r "
                "or s); the default value r was used instead, because "
                "RFC 9989 § 4.8 requires discarding an invalid value in "
                "favor of the default."
            )
            tags[tag] = {"value": "r", "explicit": False}
        elif tag == "fo":
            fo_options = tag_value.split(":")
            for value in fo_options:
                if value not in allowed_values:
                    raise InvalidDMARCTagValue(
                        f"{value} is not a valid option for the DMARC fo tag."
                    )
            # RFC 9989 §4.7: "0" and "1" are mutually exclusive, and the
            # §4.8 ABNF allows each value to appear at most once, so a
            # list that breaks either rule is a syntax error. Per §4.8 the
            # invalid value is discarded in favor of the default ("0").
            invalid_fo_reason = None
            if "0" in fo_options and "1" in fo_options:
                invalid_fo_reason = "the 0 and 1 values are mutually exclusive"
            elif len(fo_options) != len(set(fo_options)):
                invalid_fo_reason = "each value may appear at most once"
            if invalid_fo_reason is not None:
                warnings.append(
                    f"fo={tag_value} is invalid ({invalid_fo_reason} per "
                    "RFC 9989 § 4.7); the default value fo=0 was used "
                    "instead."
                )
                tags["fo"] = {"value": "0", "explicit": False}
        elif allowed_values and tag_value not in allowed_values:
            allowed_values_str = ",".join(allowed_values)
            raise InvalidDMARCTagValue(
                f"Tag {tag} must have one of the following values: "
                f"{allowed_values_str} - not {tags[tag]['value']}"
            )

    if "rua" in tags:
        tags["rua"]["value"] = _parse_report_uris(
            "rua",
            tags["rua"]["value"],
            domain,
            warnings,
            nameservers=nameservers,
            ignore_unrelated_records=ignore_unrelated_records,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
    else:
        warnings.append(
            str(
                _DMARCBestPracticeWarning(
                    "rua tag (destination for aggregate reports) not found."
                )
            )
        )

    if "ruf" in tags:
        tags["ruf"]["value"] = _parse_report_uris(
            "ruf",
            tags["ruf"]["value"],
            domain,
            warnings,
            nameservers=nameservers,
            ignore_unrelated_records=ignore_unrelated_records,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )

    if parked and tags["p"]["value"] != "reject":
        warning_msg = "Policy (p=) should be reject for parked domains."
        warnings.append(str(_DMARCBestPracticeWarning(warning_msg)))
    if parked and tags["sp"]["value"] != "reject":
        warning_msg = "Subdomain policy (sp=) should be reject for parked domains."
        warnings.append(str(_DMARCBestPracticeWarning(warning_msg)))

    # Add descriptions if requested
    if include_tag_descriptions:
        for tag, tag_details in tags.items():
            details = get_dmarc_tag_description(tag, tag_details["value"])
            tag_details["name"] = details["name"]
            if details["default"]:
                tag_details["default"] = details["default"]
            tag_details["description"] = details["description"]

    return {"tags": tags, "warnings": warnings}


@overload
def get_dmarc_record(
    domain: str,
    *,
    include_tag_descriptions: Literal[False] = False,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> DMARCRecord: ...


@overload
def get_dmarc_record(
    domain: str,
    *,
    include_tag_descriptions: Literal[True],
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> DMARCRecordWithDescriptions: ...


def get_dmarc_record(
    domain: str,
    *,
    include_tag_descriptions: bool = False,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> DMARCRecord | DMARCRecordWithDescriptions:
    """
    Retrieves a DMARC record for a domain and parses it

    Args:
        domain (str): A domain name
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: a ``dict`` with the following keys:
         - ``record`` - The DMARC record string
         - ``location`` - The domain where the DMARC record was found
         - ``parsed`` - See :func:`checkdmarc.dmarc.parse_dmarc_record`

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
        :exc:`checkdmarc.dmarc.UnrelatedTXTRecordFoundAtDMARC`
        :exc:`checkdmarc.dmarc.DMARCReportEmailAddressMissingMXRecords`
    """
    query = query_dmarc_record(
        domain, nameservers=nameservers, resolver=resolver, timeout=timeout
    )

    if include_tag_descriptions:
        parsed = parse_dmarc_record(
            query["record"],
            query["location"],
            include_tag_descriptions=True,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        result: DMARCRecordWithDescriptions = {
            "record": query["record"],
            "location": query["location"],
            "parsed": parsed,
        }
        return result
    else:
        parsed = parse_dmarc_record(
            query["record"],
            query["location"],
            include_tag_descriptions=False,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        result_no_desc: DMARCRecord = {
            "record": query["record"],
            "location": query["location"],
            "parsed": parsed,
        }
        return result_no_desc


def check_dmarc(
    domain: str,
    *,
    parked: bool = False,
    include_dmarc_tag_descriptions: bool = False,
    ignore_unrelated_records: bool = False,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> DMARCResults | DMARCErrorResults:
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
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors


    Returns:
        dict: a ``dict`` with the following keys:

                     - ``record`` - the unparsed DMARC record string
                     - ``location`` - the domain where the record was found
                     - ``valid`` - True
                     - ``tags`` - a ``dict`` of parsed DMARC tags
                     - ``warnings`` - warning conditions found

                    If a DNS error occurs, the dictionary will have the
                    following keys:

                  - ``error``  - An error message
                  - ``valid`` - False

    """
    try:
        dmarc_query = query_dmarc_record(
            domain,
            ignore_unrelated_records=ignore_unrelated_records,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
    except DMARCError as error:
        error_results: DMARCErrorResults = {
            "record": None,
            "location": None,
            "valid": False,
            "error": str(error),
        }
        return error_results
    try:
        parsed_dmarc_record = parse_dmarc_record(
            dmarc_query["record"],
            dmarc_query["location"],
            parked=parked,
            include_tag_descriptions=include_dmarc_tag_descriptions,
            ignore_unrelated_records=ignore_unrelated_records,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        combined_warnings = dmarc_query["warnings"] + parsed_dmarc_record["warnings"]
        dmarc_results: DMARCResults = {
            "record": dmarc_query["record"],
            "location": dmarc_query["location"],
            "valid": True,
            "warnings": combined_warnings,
            "tags": parsed_dmarc_record["tags"],
        }
        return dmarc_results
    except DMARCError as error:
        error_results: DMARCErrorResults = {
            "record": dmarc_query["record"],
            "location": dmarc_query["location"],
            "valid": False,
            "error": str(error),
        }
        # error.data only contains a "target" key based on codebase analysis
        if hasattr(error, "data") and error.data and "target" in error.data:
            error_results["target"] = error.data["target"]
        return error_results
