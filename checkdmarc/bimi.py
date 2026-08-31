"""Brand Indicators for Message Identification (BIMI) record validation"""

from __future__ import annotations

import base64
import gzip
import hashlib
import logging
import re
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, TypedDict
from xml.parsers.expat import ExpatError

try:
    from importlib.resources import files
except ImportError:
    # Fall back to the `importlib_resources` backport on older Python versions
    from importlib_resources import files


import dns.exception
import dns.resolver
import pyleri
import requests
import xmltodict
from cryptography import x509
from cryptography.x509 import (
    ExtensionNotFound,
    ExtensionOID,  # pyright: ignore[reportPrivateImportUsage]
    NameOID,
    ObjectIdentifier,
    load_pem_x509_certificates,
)
from cryptography.x509.verification import (
    Criticality,
    ExtensionPolicy,
    PolicyBuilder,
    Store,
    VerificationError,
)
from dns.nameserver import Nameserver

import checkdmarc.resources
from checkdmarc._constants import (
    DEFAULT_DNS_MAX_RETRIES,
    DEFAULT_DNS_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
    SYNTAX_ERROR_MARKER,
    USER_AGENT,
)
from checkdmarc.dmarc import DMARCErrorResults, DMARCResults
from checkdmarc.utils import (
    WSP_REGEX,
    get_base_domain,
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


# TypedDict definitions for BIMI record structures


class SVGMetadata(TypedDict):
    """Metadata extracted from SVG image"""

    svg_version: str
    base_profile: str
    x: str
    y: str
    title: str
    description: str
    overflow: str
    width: float
    height: float
    filesize: str
    sha256: str


class CertificateMetadata(TypedDict):
    """Metadata about a Verified Mark Certificate (VMC)"""

    issuer: dict[str, str]
    subject: dict[str, str]
    serial_number: int
    not_valid_before: str
    not_valid_after: str
    expired: bool
    valid: bool
    domains: list[str] | None
    logotype_sha256: str | None
    warnings: list[str]
    validation_errors: list[str]


class BIMIQueryResult(TypedDict):
    """Result from querying a BIMI record"""

    record: str
    location: str
    warnings: list[str]


class BIMITagValue(TypedDict, total=False):
    """BIMI tag value structure

    ``value`` is a list only for the ``lps`` tag, whose value is a
    comma-separated list of local-part prefixes.
    """

    value: str | list[str]
    name: str
    description: str


class BIMIParseResult(TypedDict):
    """Result from parsing a BIMI record"""

    tags: dict[str, BIMITagValue]
    image: SVGMetadata | dict[str, str]
    certificate: CertificateMetadata | dict[str, str]
    warnings: list[str]


class BIMICheckResult(TypedDict, total=False):
    """Result from checking BIMI for a domain"""

    record: str | None
    valid: bool
    selector: str
    location: str
    tags: dict[str, BIMITagValue]
    image: SVGMetadata | dict[str, str]
    certificate: CertificateMetadata | dict[str, str]
    warnings: list[str]
    error: str


BIMI_VERSION_REGEX_STRING = rf"v{WSP_REGEX}*={WSP_REGEX}*BIMI1{WSP_REGEX}*;"
# lps= tag value, per draft-brand-indicators-for-message-identification-14
# section 4.3.14:
#     local-part-prefix-list = local-part-prefix *[ *WSP "," *WSP local-part-prefix ]
#     local-part-prefix      = 1*63local-part-text
#     local-part-text        = ALPHA / DIGIT / "-"
BIMI_LPS_LOCAL_PART_REGEX = r"[A-Za-z0-9\-]{1,63}"
BIMI_LPS_VALUE_REGEX = (
    rf"{BIMI_LPS_LOCAL_PART_REGEX}"
    rf"(?:{WSP_REGEX}*,{WSP_REGEX}*{BIMI_LPS_LOCAL_PART_REGEX})*"
)
# A tag is a name, "=", and a value. The name and value are kept loose on
# purpose: unknown tags must be ignored rather than rejected (see the
# BIMI draft, section 4.3), so any tag name of any length must lex, and
# each known tag's value is checked individually in parse_bimi_record.
BIMI_TAG_VALUE_REGEX_STRING = rf"([a-z][a-z0-9_\-.]*){WSP_REGEX}*={WSP_REGEX}*([^;]*)"
BIMI_TAG_VALUE_REGEX = re.compile(BIMI_TAG_VALUE_REGEX_STRING, re.IGNORECASE)

# Matches a record that starts with a v= tag identifying the current BIMI
# version, used when deciding whether a TXT record is a BIMI record at all
# (BIMI draft, section 7.2, steps 4 and 7). The record grammar allows
# spaces or tabs around the "=", so the same tolerance applies here.
_BIMI_VERSION_PREFIX_REGEX = re.compile(
    rf"v{WSP_REGEX}*={WSP_REGEX}*BIMI1{WSP_REGEX}*(?:;|$)"
)

# Anchored check for the l= and a= tag values. Per the bimi-uri definition
# in the BIMI draft, section 4.3, the value must be a single HTTPS URI
# whose host is a fully qualified domain name, and any comma inside the
# URI must be percent-encoded. Raw spaces are not legal in a URI, so the
# character set below excludes both spaces and commas.
_BIMI_URI_REGEX = re.compile(
    r"https://"
    r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"  # host labels before the last dot
    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"  # final host label
    r"(?::\d{1,5})?"  # optional port
    r"(?:[/?#][a-z0-9\-._~:/?#\[\]@!$&'()*+=%]*)?",  # path/query/fragment
    re.IGNORECASE,
)

# Anchored (via fullmatch) check for a non-empty lps= tag value.
_BIMI_LPS_VALUE_REGEX = re.compile(BIMI_LPS_VALUE_REGEX)

# Heuristic for SVG <title> elements that look like generator/template
# placeholders rather than a brand-descriptive title (e.g. the SVG Tiny PS
# profile name leaked into the title, or a literal "untitled").
GENERIC_SVG_TITLE_REGEX = re.compile(
    r"^\s*(bimi[\s\-_]*svg[\s\-_]*tiny[\w\s\-_]*|untitled|title|no\s+title|svg)\s*$",
    re.IGNORECASE,
)

# VMC OIDs
OID_LOGOTYPE = ObjectIdentifier("1.3.6.1.5.5.7.1.12")
OID_MARK_TYPE = ObjectIdentifier("1.3.6.1.4.1.53087.1.13")
OID_STATUTE_LOCALITY_NAME = ObjectIdentifier("1.3.6.1.4.1.53087.3.4")
OID_STATUTE_STATE_OR_PROVINCE_NAME = ObjectIdentifier("1.3.6.1.4.1.53087.3.3")
OID_STATUTE_COUNTRY_NAME = ObjectIdentifier("1.3.6.1.4.1.53087.3.2")
OID_STATUTE_CITATION = ObjectIdentifier("1.3.6.1.4.1.53087.3.5")
OID_STATUTE_URL = ObjectIdentifier("1.3.6.1.4.1.53087.3.6")
OID_PRIOR_USE_MARK_URL = ObjectIdentifier("1.3.6.1.4.1.53087.5.1")
OID_LEGAL_ENTITY_IDENTIFIER = ObjectIdentifier("1.3.6.1.4.1.53087.1.5")
OID_TRADEMARK_COUNTRY_OR_REGION_NAME = ObjectIdentifier("1.3.6.1.4.1.53087.1.3")
OID_TRADEMARK_OFFICE_NAME = ObjectIdentifier("1.3.6.1.4.1.53087.1.2")
OID_TRADEMARK_IDENTIFIER = ObjectIdentifier("1.3.6.1.4.1.53087.1.4")
OID_WORD_MARK = ObjectIdentifier("1.3.6.1.4.1.53087.1.6")
OID_ORGANIZATION_IDENTIFIER = ObjectIdentifier("2.5.4.97")
OID_PRIOR_USE_MARK_SOURCE_URL = ObjectIdentifier("1.3.6.1.4.1.53087.5.1")
OID_SIGNED_CERTIFICATE_TIMESTAMP_LIST = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")
OID_CERTIFICATE_GENERAL_POLICY_IDENTIFIER = ObjectIdentifier("1.3.6.1.4.1.53087.1.1")
OID_KP_BIMI = ObjectIdentifier("1.3.6.1.5.5.7.3.31")
OID_PILOT_IDENTIFIER_EXTENSION = ObjectIdentifier("1.3.6.1.4.1.53087.4.1")

OID_LABELS = {
    # Common OIDs
    NameOID.COMMON_NAME: "commonName",
    NameOID.ORGANIZATION_NAME: "organizationName",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
    NameOID.STREET_ADDRESS: "streetAddress",
    NameOID.LOCALITY_NAME: "localityName",
    NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
    NameOID.POSTAL_CODE: "postalCode",
    NameOID.COUNTRY_NAME: "countryName",
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "subjectAlternativeName",
    ExtensionOID.NAME_CONSTRAINTS: "nameConstraints",
    # EVC OIDs
    NameOID.JURISDICTION_LOCALITY_NAME: "jurisdictionOfIncorporationLocalityName",
    NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME: "jurisdictionOfIncorporationStateOrProvinceName",
    NameOID.JURISDICTION_COUNTRY_NAME: "jurisdictionOfIncorporationCountryName",
    NameOID.BUSINESS_CATEGORY: "businessCategory",
    NameOID.SERIAL_NUMBER: "serialNumber",
    # VMC OIDs
    OID_LOGOTYPE: "logotype",  # Extension
    OID_MARK_TYPE: "markType",
    OID_STATUTE_LOCALITY_NAME: "statuteLocalityName",
    OID_STATUTE_STATE_OR_PROVINCE_NAME: "statuteStateOrProvinceName",
    OID_STATUTE_COUNTRY_NAME: "statuteCountryName",
    OID_STATUTE_CITATION: "statuteCitation",
    OID_STATUTE_URL: "statuteURL",
    OID_PRIOR_USE_MARK_URL: "priorUseMarkURL",
    OID_LEGAL_ENTITY_IDENTIFIER: "legalEntityIdentifier",
    OID_TRADEMARK_COUNTRY_OR_REGION_NAME: "trademarkCountryOrRegionName",
    OID_TRADEMARK_OFFICE_NAME: "trademarkOfficeName",
    OID_TRADEMARK_IDENTIFIER: "trademarkIdentifier",
    OID_WORD_MARK: "wordMark",
    OID_ORGANIZATION_IDENTIFIER: "organizationIdentifier",
    OID_PRIOR_USE_MARK_SOURCE_URL: "priorUseMarkSourceURL",
    OID_SIGNED_CERTIFICATE_TIMESTAMP_LIST: "signedCertificateTimestampList",
    OID_KP_BIMI: "id-kp-BrandIndicatorforMessageIdentification",
    OID_PILOT_IDENTIFIER_EXTENSION: "Pilot extension",
}


BUSINESS_CATEGORIES = [
    "Private Organization",
    "Government Entity",
    "Business Entity",
    "Non-Commercial Entity",
]

MARK_TYPES = [
    "Registered Mark",
    "Government Mark",
    "Prior Use Mark",
    "Modified Registered Mark",
]

REQUIRED_EXTENSIONS = [
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    OID_LOGOTYPE,
]
FORBIDDEN_EXTENSIONS = [ExtensionOID.NAME_CONSTRAINTS]

REQUIRED_SUBJECT_FIELDS_BY_MARK_TYPE = {
    "All": [
        "markType",
        "organizationName",
        "streetAddress",
        "countryName",
        "businessCategory",
        "serialNumber",
        "jurisdictionOfIncorporationCountryName",
    ],
    "Registered Mark": ["trademarkCountryOrRegionName", "trademarkIdentifier"],
    "Government Mark": ["statuteCountryName", "statuteCitation"],
    "Prior Use Mark": [],
    "Modified Registered Mark": ["trademarkCountryOrRegionName", "trademarkIdentifier"],
}

OPTIONAL_SUBJECT_FIELDS_BY_MARK_TYPE = {
    "All": [
        "commonName",
        "localityName",
        "stateOrProvinceName",
        "postalCode",
        "organizationalUnitName",
        "legalEntityIdentifier",
        "jurisdictionOfIncorporationStateOrProvinceName",
        "jurisdictionOfIncorporationLocalityName",
    ],
    "Registered Mark": ["trademarkOfficeName"],
    "Government Mark": [
        "statuteURL",
        "statuteStateOrProvinceName",
        "statuteLocalityName",
    ],
    "Prior Use Mark": [
        "priorUseMarkSourceURL",
    ],
    "Modified Registered Mark": [
        "trademarkOfficeName",
    ],
}


# Pairs where at least one of the two subject fields must be present.
# Per VMC Requirements §7.1.4.2.2(d, e): localityName is required if
# stateOrProvinceName is absent (and vice versa).
EITHER_OR_SUBJECT_FIELDS_BY_MARK_TYPE: dict[str, list[tuple[str, str]]] = {
    "All": [
        ("localityName", "stateOrProvinceName"),
    ],
}

# If the trigger field is present, the required field must also be present.
# Per VMC Requirements §7.1.4.2.2(j, s): jurisdiction (and statute) fields
# describe the level of the Incorporating/Registration Agency (or the
# Government Entity that established a Government Mark). A locality-level
# value implies a state/province-level value must also be present; a
# country-level entity legitimately has neither locality nor state/province.
FIELD_REQUIRED_IF_FIELD_IS_PRESENT_BY_MARK_TYPE: dict[str, dict[str, str]] = {
    "All": {
        "jurisdictionOfIncorporationLocalityName": "jurisdictionOfIncorporationStateOrProvinceName",
    },
    "Government Mark": {
        "statuteLocalityName": "statuteStateOrProvinceName",
    },
}

KNOWN_SUBJECT_FIELDS = frozenset(
    field
    for fields_by_mark_type in (
        REQUIRED_SUBJECT_FIELDS_BY_MARK_TYPE,
        OPTIONAL_SUBJECT_FIELDS_BY_MARK_TYPE,
    )
    for fields in fields_by_mark_type.values()
    if isinstance(fields, list)
    for field in fields
)


BIMI_TAGS = {
    "v": {
        "name": "Version",
        "required": True,
        "description": "Identifies the record "
        "retrieved as a BIMI "
        "record. It MUST have the "
        'value of "BIMI1". The '
        "value of this tag MUST "
        "match precisely; if it "
        "does not or it is absent, "
        "the entire retrieved "
        "record MUST be ignored. "
        "It MUST be the first "
        "tag in the list.",
    },
    "a": {
        "name": "Authority Evidence Location",
        "required": False,
        "default": "",
        "description": "If present, this tag MUST have an empty value "
        "or its value MUST be a single URI. An empty "
        "value for the tag is interpreted to mean the "
        "Domain Owner does not wish to publish or does "
        "not have authority evidence to disclose. The "
        "URI, if present, MUST contain a fully "
        "qualified domain name (FQDN) and MUST specify "
        'HTTPS as the URI scheme ("https"). The URI '
        "SHOULD specify the location of a publicly "
        "retrievable BIMI Evidence Document.",
    },
    "l": {
        "name": "Location",
        "required": False,
        "default": "",
        "description": "The value of this tag is either empty "
        "indicating declination to publish, or a single "
        "URI representing the location of a Brand "
        "Indicator file. The only supported transport "
        "is HTTPS.",
    },
    "lps": {
        "name": "Local-Part Selectors",
        "default": "",
        "description": "A comma separated list of allowed Local-Part Selectors",
    },
    "avp": {
        "name": "Avatar Preference",
        "required": False,
        "default": "brand",
        "description": "For mail sent to those mailbox providers that both participate in BIMI and "
        "support the display of personal avatars, this flag is a way for the Domain "
        "Owner to express its preference as to whether to show the BIMI logo or the "
        "personal avatar. Options are personal or brand",
    },
}

_mvaca_path = str(files(checkdmarc.resources).joinpath("MVACAs.pem"))

# Load the certificates included in MVACAs.pem into a certificate store
with open(_mvaca_path, "rb") as pems:
    _store = Store(load_pem_x509_certificates(pems.read()))

# Do not consider certificate invalid if a certificate extension marked critical
# by the issuer cannot be processed by OpenSSL.
# https://github.com/domainaware/checkdmarc/issues/161
_ee_policy = (
    ExtensionPolicy.permit_all()
    .require_present(x509.SubjectAlternativeName, Criticality.AGNOSTIC, None)
    .may_be_present(x509.ExtendedKeyUsage, Criticality.AGNOSTIC, None)
)
_ca_policy = (
    ExtensionPolicy.permit_all()
    .require_present(x509.BasicConstraints, Criticality.AGNOSTIC, None)
    .may_be_present(x509.ExtendedKeyUsage, Criticality.AGNOSTIC, None)
)

_builder = (
    PolicyBuilder()
    .store(_store)
    .extension_policies(ee_policy=_ee_policy, ca_policy=_ca_policy)
    .max_chain_depth(5)
)
_verifier = _builder.build_client_verifier()


class BIMIError(Exception):
    """Raised when a fatal BIMI error occurs"""

    def __init__(self, msg: str, data: dict | None = None):
        """
        Args:
            msg (str): The error message
            data (dict): A dictionary of data to include in the results
        """
        self.data = data
        Exception.__init__(self, msg)


class BIMIRecordNotFound(BIMIError):
    """Raised when a BIMI record could not be found"""

    def __init__(self, error):
        if isinstance(error, dns.exception.Timeout):
            error.kwargs["timeout"] = round(error.kwargs["timeout"], 1)


class BIMISyntaxError(BIMIError):
    """Raised when a BIMI syntax error is found"""


class InvalidBIMITag(BIMISyntaxError):
    """Raised when an invalid BIMI tag is found"""


class InvalidBIMITagValue(BIMISyntaxError):
    """Raised when an invalid BIMI tag value is found"""


class InvalidBIMIIndicatorURI(InvalidBIMITagValue):
    """Raised when an invalid BIMI indicator URI is found"""


class UnrelatedTXTRecordFoundAtBIMI(BIMIError):
    """Raised when a TXT record unrelated to BIMI is found"""


class SPFRecordFoundWhereBIMIRecordShouldBe(UnrelatedTXTRecordFoundAtBIMI):
    """Raised when an SPF record is found where a BIMI record should be;
    most likely, the ``selector_bimi`` subdomain
    record does not actually exist, and the request for ``TXT`` records was
    redirected to the base domain"""


class BIMIRecordInWrongLocation(BIMIError):
    """Raised when a BIMI record is found at the root of a domain"""


class MultipleBIMIRecords(BIMIError):
    """Raised when multiple BIMI records are found"""


class _BIMIGrammar(pyleri.Grammar):
    """Defines Pyleri grammar for BIMI records"""

    version_tag = pyleri.Regex(BIMI_VERSION_REGEX_STRING)
    tag_value = pyleri.Regex(BIMI_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = pyleri.Sequence(
        version_tag,
        pyleri.List(
            tag_value, delimiter=pyleri.Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"), opt=True
        ),
    )


def get_svg_metadata(raw_xml: str | bytes) -> dict[str, Any]:
    metadata = {}
    # Keep the original bytes for the size and hash below. The decoded text
    # is only used for XML parsing; decoding can drop bytes, so measuring or
    # hashing it would not describe the file actually served.
    if isinstance(raw_xml, bytes):
        raw_bytes = raw_xml
        raw_xml = raw_xml.decode(errors="ignore")
    else:
        raw_bytes = raw_xml.encode("utf-8")
    try:
        xml = xmltodict.parse(raw_xml)
        svg = xml["svg"]
        metadata["svg_version"] = svg["@version"]
        if "@baseProfile" in svg:
            metadata["base_profile"] = svg["@baseProfile"]
        view_box = svg["@viewBox"]
        view_box = view_box.split(" ")
        width = float(view_box[-2])
        height = float(view_box[-1])
        if "@x" in svg:
            metadata["x"] = svg["@x"]
        if "@y" in svg:
            metadata["y"] = svg["@y"]
        if "title" in svg:
            metadata["title"] = svg["title"]
        description = None
        if "description" in svg:
            description = svg["description"]
        if "overflow" in svg:
            metadata["overflow"] = svg["overflow"]
        if description is not None:
            metadata["description"] = description
        metadata["width"] = width
        metadata["height"] = height
        # The size that counts against the 32 KB cap is the size of the
        # file as served, i.e. the length of the raw bytes.
        metadata["filesize"] = f"{len(raw_bytes) / 1000} KB"
        # Hash the raw bytes so the value can be compared against the
        # certificate's embedded logotype hash byte for byte.
        metadata["sha256"] = hashlib.sha256(raw_bytes).hexdigest()
        return metadata
    except (ExpatError, KeyError, ValueError, IndexError, TypeError) as e:
        raise ValueError(f"Not an SVG file: {e!s}")


def check_svg_requirements(svg_metadata: dict) -> list[str]:
    _errors = []
    if svg_metadata["svg_version"] != "1.2":
        _errors.append(
            f"The SVG version must be 1.2, not {svg_metadata['svg_version']}"
        )
    if "base_profile" not in svg_metadata:
        _errors.append(
            "The SVG is missing a base profile. It must have the "
            "base profile tiny-ps and conform to its standards. "
            "https://bimigroup.org/solving-svg-issues/"
        )
    else:
        base_profile = svg_metadata["base_profile"]
        if base_profile != "tiny-ps":
            _errors.append(f"The SVG base profile must be tiny-ps, not {base_profile}")
    if "title" not in svg_metadata:
        _errors.append("The SVG must have a title element")
    invalid_attributes = ["x", "y"]
    for attribute in invalid_attributes:
        if attribute in svg_metadata:
            _errors.append(f"The SVG cannot include {attribute} in the svg element")
    if float(svg_metadata["filesize"].strip(" KB")) > 32:
        _errors.append("The SVG file exceeds the maximum size of 32 KB")
    return _errors


def extract_logo_from_certificate(
    cert: x509.Certificate | bytes,
) -> bytes | None:
    try:
        if not isinstance(cert, x509.Certificate):
            # PEM bundles list the leaf (end-entity) certificate first,
            # followed by intermediates, so the leaf is the first one.
            cert = load_pem_x509_certificates(cert)[0]

        ext = cert.extensions.get_extension_for_oid(OID_LOGOTYPE)

        # This is DER (binary ASN.1)
        ext_bytes: bytes = ext.value.value  # pyright: ignore[reportAttributeAccessIssue]

        marker = b"data:"
        idx = ext_bytes.find(marker)
        if idx == -1:
            return None

        # Take bytes from the first "data:" onward.
        tail = ext_bytes[idx:]

        # Decode tail as ASCII/UTF-8 since data: URIs are plain text.
        tail_str = tail.decode("utf-8", errors="strict")

        # Example: data:image/svg+xml;base64,AAAA....
        if ";base64," not in tail_str:
            return None

        b64_part = tail_str.split(";base64,", 1)[1]

        # Some certs may embed trailing ASN.1 bytes after the base64;
        # strip anything that isn't base64 alphabet.
        b64_clean = "".join(ch for ch in b64_part if ch.isalnum() or ch in "+/=\n\r")

        compressed = base64.b64decode(b64_clean, validate=False)

        # If it’s gzipped SVG (common), decompress. Otherwise return raw.
        try:
            return gzip.decompress(compressed)
        except OSError:
            return compressed

    except ExtensionNotFound:
        return None


def get_certificate_metadata(pem_crt: bytes, *, domain=None) -> dict[str, Any]:
    """Get metadata about a Verified Mark Certificate (VMC)"""

    def get_cert_name_components(cert_field: x509.Name):
        mapping = []
        for rdn in cert_field.rdns:
            for attr in rdn:
                label = OID_LABELS.get(attr.oid) or attr.oid.dotted_string
                mapping.append((label, attr.value))
        return {k: v for k, v in mapping}

    def get_certificate_domains(cert: x509.Certificate):
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
        except ExtensionNotFound:
            return None
        return ext.value.get_values_for_type(  # pyright: ignore[reportAttributeAccessIssue]
            x509.DNSName
        )  # pyright: ignore[reportAttributeAccessIssue]

    metadata = {}
    valid = True
    validation_errors: list[str] = []
    warnings: list[str] = []
    certs = load_pem_x509_certificates(pem_crt)
    vmc = certs[0]
    for ext in REQUIRED_EXTENSIONS:
        try:
            vmc.extensions.get_extension_for_oid(ext)
        except ExtensionNotFound:
            ext_label = OID_LABELS[ext]
            validation_errors.append(
                f"The certificate does not contain the required extension: {ext_label}."
            )
    for extension in FORBIDDEN_EXTENSIONS:
        try:
            vmc.extensions.get_extension_for_oid(extension)
            ext_label = OID_LABELS[extension]
            valid = False
            validation_errors.append(
                f"The certificate contains a forbidden extension: {ext_label}."
            )
        except ExtensionNotFound:
            pass
    if vmc.not_valid_before_utc >= datetime(
        year=2025, month=3, day=15, tzinfo=timezone.utc
    ):
        try:
            vmc.extensions.get_extension_for_oid(OID_PILOT_IDENTIFIER_EXTENSION)
            validation_errors.append(
                "Certificates issued on or after 2025-03-15 must not contain the Pilot identifier extension."
            )
            valid = False
        except ExtensionNotFound:
            pass
    cert_domains = get_certificate_domains(vmc)
    intermediates = certs[1:] if len(certs) > 0 else []
    try:
        _verifier.verify(vmc, intermediates)
    except VerificationError as e:
        e_str = str(e)
        metadata["valid"] = False
        logger.debug(f"Certificate ValidationError exception: {e_str}")
        if "all candidates exhausted with no interior errors" in e_str:
            e_str = "The certificate was not issued by a recognized Mark Verifying Authority (MVA)."
            validation_errors.append(e_str)
            valid = False
    not_valid_before_timestamp = vmc.not_valid_before_utc.strftime("%Y-%m-%d %H:%M:%SZ")
    not_valid_after_timestamp = vmc.not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%SZ")
    not_yet_valid = datetime.now(timezone.utc) < vmc.not_valid_before_utc
    if not_yet_valid:
        valid = False
        validation_errors.append(
            f"The certificate is not valid until {not_valid_before_timestamp}"
        )
    expired = datetime.now(timezone.utc) > vmc.not_valid_after_utc
    if expired:
        valid = False
        validation_errors.append(
            f"The certificate expired on {not_valid_after_timestamp}"
        )
    time_until_expired = vmc.not_valid_after_utc - datetime.now(timezone.utc)
    if time_until_expired < timedelta(days=1) and not expired:
        warnings.append("The certificate will expire in less than a day")
    elif time_until_expired == timedelta(days=1):
        warnings.append("The certificate will expire in 1 day")
    elif time_until_expired <= timedelta(days=14) and not expired:
        warnings.append(
            f"The certificate will expire in {time_until_expired.days} days"
        )
    if domain is not None:
        base_domain = get_base_domain(domain).encode("utf-8").decode("unicode_escape")
        if (
            cert_domains is not None
            and domain not in cert_domains
            and base_domain not in cert_domains
        ):
            plural = "domain" if len(cert_domains) == 1 else "domains"
            cert_domains_str = ", ".join(cert_domains)
            validation_errors.append(
                f"{base_domain} does not match the certificate {plural}: "
                f"{cert_domains_str}"
            )
            valid = False
    try:
        cert_issuer = get_cert_name_components(vmc.issuer)
        cert_subject = get_cert_name_components(vmc.subject)
        for field in cert_subject:
            if field not in KNOWN_SUBJECT_FIELDS:
                warnings.append(f"{field} is not a known VMC subject field.")
        mark_type = None
        if "markType" in cert_subject:
            if cert_subject["markType"] in MARK_TYPES:
                mark_type = cert_subject["markType"]
                if (
                    mark_type == "Prior Use Mark"
                    and vmc.not_valid_before_utc
                    >= datetime(year=2025, month=4, day=15, tzinfo=timezone.utc)
                    and "priorUseMarkSourceURL" not in cert_subject
                ):
                    validation_errors.append(
                        "Certificates with a subject markType of Prior Use Mark issued on or after 2025-04-15 must have a priorUseMarkSourceURL subject field."
                    )
                required_fields = (
                    REQUIRED_SUBJECT_FIELDS_BY_MARK_TYPE["All"]
                    + REQUIRED_SUBJECT_FIELDS_BY_MARK_TYPE[mark_type]
                )
                for required_field in required_fields:
                    if required_field not in cert_subject:
                        valid = False
                        validation_errors.append(
                            f"The certificate's subject is missing the required field {required_field}."
                        )
                either_or_pairs = list(
                    EITHER_OR_SUBJECT_FIELDS_BY_MARK_TYPE.get("All", [])
                ) + list(EITHER_OR_SUBJECT_FIELDS_BY_MARK_TYPE.get(mark_type, []))
                for field_a, field_b in either_or_pairs:
                    if field_a not in cert_subject and field_b not in cert_subject:
                        validation_errors.append(
                            f"At least one of {field_a} or {field_b} is required in the certificate subject."
                        )
                        valid = False
                implies_rules: dict[str, str] = {}
                implies_rules.update(
                    FIELD_REQUIRED_IF_FIELD_IS_PRESENT_BY_MARK_TYPE.get("All", {})
                )
                implies_rules.update(
                    FIELD_REQUIRED_IF_FIELD_IS_PRESENT_BY_MARK_TYPE.get(mark_type, {})
                )
                for trigger_field, required_field in implies_rules.items():
                    if (
                        trigger_field in cert_subject
                        and required_field not in cert_subject
                    ):
                        validation_errors.append(
                            f"{required_field} is required in the certificate subject when {trigger_field} is present."
                        )
                        valid = False
                mark_type_fields = (
                    REQUIRED_SUBJECT_FIELDS_BY_MARK_TYPE[mark_type]
                    + OPTIONAL_SUBJECT_FIELDS_BY_MARK_TYPE[mark_type]
                )
                other_mark_types = MARK_TYPES.copy()
                other_mark_types.remove(mark_type)
                for other_mark_type in other_mark_types:
                    other_mark_type_fields = (
                        REQUIRED_SUBJECT_FIELDS_BY_MARK_TYPE[other_mark_type]
                        + OPTIONAL_SUBJECT_FIELDS_BY_MARK_TYPE[other_mark_type]
                    )
                    other_mark_type_fields = set(other_mark_type_fields) - set(
                        mark_type_fields
                    )
                    for field in other_mark_type_fields:
                        if field in cert_subject:
                            validation_errors.append(
                                f"The subject {field} is used by {other_mark_type} certificates, not {mark_type} certificates."
                            )
                            valid = False
            else:
                valid = False
                validation_errors.append(
                    f"{cert_subject['markType']} is not a valid subject markType."
                )
        else:
            valid = False
            validation_errors.append("markType is missing from the subject.")

        metadata["issuer"] = cert_issuer
        metadata["subject"] = cert_subject
        metadata["serial_number"] = vmc.serial_number
        metadata["not_valid_before"] = not_valid_before_timestamp
        metadata["not_valid_after"] = not_valid_after_timestamp
        metadata["expired"] = expired
        metadata["valid"] = valid
        metadata["domains"] = cert_domains
        metadata["logotype_sha256"] = None
        logotype = extract_logo_from_certificate(vmc)
        if logotype is not None:
            metadata["logotype_sha256"] = hashlib.sha256(logotype).hexdigest()
        metadata["warnings"] = warnings
        metadata["validation_errors"] = validation_errors
    except (KeyError, ValueError, IndexError, AttributeError) as e:
        validation_errors.append(str(e))
        metadata["valid"] = False
        metadata["validation_errors"] = validation_errors
    return metadata


def _query_bimi_record(
    domain: str,
    *,
    selector: str | None = "default",
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
    warnings: list[str] | None = None,
):
    """
    Queries DNS for a BIMI record

    Args:
        domain (str): A domain name
        selector: the BIMI selector
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors
        warnings (list): A list that warning messages are appended to

    Returns:
        str: A record string or None
    """
    domain = normalize_domain(domain)
    target = f"{selector}._bimi.{domain}"
    bimi_record = None
    if warnings is None:
        warnings = []

    try:
        records = query_dns(
            target,
            "TXT",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        bimi_records = []
        unrelated_records = []
        for record in records:
            if _BIMI_VERSION_PREFIX_REGEX.match(record):
                bimi_records.append(record)
            else:
                unrelated_records.append(record)

        if len(bimi_records) > 1:
            raise MultipleBIMIRecords("Multiple BIMI records are not permitted.")
        if len(unrelated_records) > 0:
            # TXT records that are not BIMI records are ignored, not fatal:
            # section 7.2 step 4 of the BIMI draft says records that do not
            # start with the BIMI version tag must be discarded. Warn so the
            # domain owner can clean them up.
            ur_str = "\n\n".join(unrelated_records)
            warnings.append(
                f"Unrelated TXT records were found at {target} and ignored. "
                "These should be removed, as some receivers may not expect "
                f"to find unrelated TXT records there:\n\n{ur_str}"
            )
        if len(bimi_records) == 1:
            bimi_record = bimi_records[0]

    except dns.resolver.NoAnswer:
        try:
            records = query_dns(
                domain,
                "TXT",
                nameservers=nameservers,
                resolver=resolver,
                timeout=timeout,
            )
            for record in records:
                if _BIMI_VERSION_PREFIX_REGEX.match(record):
                    raise BIMIRecordInWrongLocation(
                        f"The BIMI record must be located at {target}, not {domain}."
                    )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise BIMIRecordNotFound("The domain does not exist.")
        except BIMIError:
            # Let BIMI-specific exceptions (BIMIRecordInWrongLocation) propagate
            # — they were being silently swallowed because `raise` was missing.
            raise
        except dns.exception.DNSException as error:
            raise BIMIRecordNotFound(error)

    except dns.resolver.NXDOMAIN:
        pass
    except BIMIError:
        # MultipleBIMIRecords is raised in the try-body above; propagate it
        # so callers can act on the specific type instead of catching the
        # broad BIMIRecordNotFound this clause used to convert everything to.
        raise
    except dns.exception.DNSException as error:
        raise BIMIRecordNotFound(error)

    return bimi_record


def query_bimi_record(
    domain: str,
    *,
    selector: str | None = "default",
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> BIMIQueryResult:
    """
    Queries DNS for a BIMI record

    Args:
        domain (str): A domain name
        selector (str): The BIMI selector
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: a ``dict`` with the following keys:
                     - ``record`` - the unparsed BIMI record string
                     - ``location`` - the domain where the record was found
                     - ``warnings`` - warning conditions found

    Raises:
        :exc:`checkdmarc.bimi.BIMIRecordNotFound`
        :exc:`checkdmarc.bimi.BIMIRecordInWrongLocation`
        :exc:`checkdmarc.bimi.MultipleBIMIRecords`

    """
    domain = normalize_domain(domain)
    logger.debug(f"Checking for a BIMI record at {selector}._bimi.{domain}")
    warnings = []
    base_domain = get_base_domain(domain)
    location = domain
    record = _query_bimi_record(
        domain,
        selector=selector,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        retries=retries,
        warnings=warnings,
    )
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
            if _BIMI_VERSION_PREFIX_REGEX.match(root_record):
                warnings.append(f"A BIMI record at the root of {domain} has no effect.")
    except dns.resolver.NXDOMAIN:
        raise BIMIRecordNotFound("The domain does not exist.")
    except dns.exception.DNSException:
        pass

    if record is None and domain != base_domain:
        # Fall back to the organizational domain while keeping the caller's
        # selector: per section 7.2 step 6 of the BIMI draft, a custom
        # selector that does not exist falls back to
        # <selector>._bimi.<organizational domain>.
        record = _query_bimi_record(
            base_domain,
            selector=selector,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
            warnings=warnings,
        )
        location = base_domain
    if record is None:
        if domain == base_domain:
            raise BIMIRecordNotFound(
                f"A BIMI record does not exist at the {selector} selector."
            )
        else:
            raise BIMIRecordNotFound(
                f"A BIMI record does not exist at the {selector} selector for "
                "this subdomain or its base domain."
            )

    return {"record": record, "location": location, "warnings": warnings}


def parse_bimi_record(
    record: str,
    *,
    domain: str | None = None,
    parsed_dmarc_record: DMARCResults | DMARCErrorResults | None = None,
    include_tag_descriptions: bool = False,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
    http_timeout: float = DEFAULT_HTTP_TIMEOUT,
) -> dict[str, Any]:
    """
    Parses a BIMI record

    Args:
        record (str): A BIMI record
        domain (str): The domain where the BIMI record was located
        parsed_dmarc_record (dict): A parsed DMARC record
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The marker for pointing out syntax errors
        http_timeout (float): HTTP timeout in seconds

    Returns:
        dict: a ``dict`` with the following keys:
         - ``tags`` - a ``dict`` of BIMI tags

           - ``value`` - The BIMI tag value
           - ``description`` - A description of the tag/value
         - ``image`` - SVG image metadata, if any
         - ``certificate`` - Verified Mark Certificate (VMC) metadata, if any
         - ``warnings`` - A ``list`` of warnings

        .. note::
            This will attempt to download and validate the SVG image and mark
            certificate at the URLs provided in the BIMI record; a download or
            processing failure is reported as an ``error`` entry under
            ``image`` or ``certificate``.

         .. note::
            ``description`` is only included if
            ``include_tag_descriptions`` is set to ``True``

    Raises:
        :exc:`checkdmarc.bimi.BIMISyntaxError`
        :exc:`checkdmarc.bimi.InvalidBIMITag`
        :exc:`checkdmarc.bimi.InvalidBIMITagValue`
        :exc:`checkdmarc.bimi.SPFRecordFoundWhereBIMIRecordShouldBe`
    """
    results = {}
    svg_metadata = None
    cert_metadata = None
    valid_cert = False
    logger.debug("Parsing the BIMI record")
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    spf_in_bimi_error_msg = (
        "Found an SPF record where a BIMI record "
        "should be; most likely, the _bimi "
        "subdomain record does not actually exist, "
        "and the request for TXT records was "
        "redirected to the base domain."
    )
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereBIMIRecordShouldBe(spf_in_bimi_error_msg)
    bimi_syntax_checker = _BIMIGrammar()
    grammar_result = bimi_syntax_checker.parse(record)
    if not grammar_result.is_valid:
        expecting = [str(x).strip('"') for x in list(grammar_result.expecting)]
        marked_record = (
            record[: grammar_result.pos]
            + syntax_error_marker
            + record[grammar_result.pos :]
        )
        expecting_str = " or ".join(expecting)
        raise BIMISyntaxError(
            f"Error: Expected {expecting_str} at position "
            f"{grammar_result.pos} "
            f"(marked with {syntax_error_marker}) in: "
            f"{marked_record}"
        )

    pairs: list[tuple[str, str]] = BIMI_TAG_VALUE_REGEX.findall(record)
    tags = {}
    hash_match = False

    seen_tags: list[str] = []
    duplicate_tags: list[str] = []
    for pair in pairs:
        tag = pair[0].lower().strip()
        tag_value = str(pair[1].strip())
        if tag not in BIMI_TAGS:
            # Unknown tags must be ignored, not treated as errors, per
            # section 4.3 of the BIMI draft. Warn so typos are still visible.
            warnings.append(
                f"Unknown BIMI record tag {tag} was ignored. Unknown tags "
                "are ignored per section 4.3 of the BIMI draft."
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
            raise InvalidBIMITag(
                f"Duplicate {duplicate_tags_str} tags are not permitted."
            )
        tags[tag] = {"value": tag_value}
        if include_tag_descriptions:
            tags[tag]["name"] = BIMI_TAGS[tag]["name"]
            tags[tag]["description"] = BIMI_TAGS[tag]["description"]
        if tag in ("l", "a") and tag_value != "":
            if not _BIMI_URI_REGEX.fullmatch(tag_value):
                message = (
                    f"The {tag} tag value must be empty or a single HTTPS "
                    "URI containing a fully qualified domain name, with any "
                    "commas percent-encoded, per section 4.3 of the BIMI "
                    f"draft: {tag_value}"
                )
                if tag == "l":
                    raise InvalidBIMIIndicatorURI(message)
                raise InvalidBIMITagValue(message)
        elif tag == "avp":
            if tag_value not in ["brand", "personal"]:
                raise BIMISyntaxError(
                    f"Acceptable avp tag values are personal or brand, not {tag_value}"
                )
        elif tag == "lps":
            if tag_value == "":
                # An empty list is allowed: "The value of this tag is zero,
                # one or more local-part string prefixes" (section 4.3 of
                # the BIMI draft). With no prefixes, the local-part always
                # matches.
                tags[tag]["value"] = []
            elif not _BIMI_LPS_VALUE_REGEX.fullmatch(tag_value):
                raise InvalidBIMITagValue(
                    "The lps tag value must be a comma-separated list of "
                    "prefixes containing only letters, digits, and hyphens, "
                    f"per section 4.3 of the BIMI draft: {tag_value}"
                )
            else:
                # Comma-separated local-parts; strip whitespace and lowercase
                # for case-insensitive matching at delivery time.
                local_part_prefixes = [s.strip().lower() for s in tag_value.split(",")]
                tags[tag]["value"] = local_part_prefixes

    if "l" not in tags:
        # The l= tag is required by section 4.3 of the BIMI draft. Declining
        # to participate is expressed with an empty value (section 4.3.1),
        # not by leaving the tag out.
        raise BIMISyntaxError(
            "The BIMI record is missing the required l tag. To decline "
            "BIMI participation, publish the l tag with an empty value (l=;)."
        )

    l_tag_value = tags["l"]["value"]
    if l_tag_value != "":
        raw_xml = None
        try:
            response = session.get(l_tag_value, timeout=http_timeout)
            response.raise_for_status()
            raw_xml = response.content
        except requests.RequestException as e:
            results["image"] = {
                "error": f"Failed to download BIMI image at {l_tag_value} - {e!s}"
            }
        if raw_xml is not None:
            try:
                svg_metadata = get_svg_metadata(raw_xml)
                if svg_metadata["width"] != svg_metadata["height"]:
                    warnings.append(
                        f"It is recommended that the BIMI SVG image be square (equal width and height), not {svg_metadata['width']}x{svg_metadata['height']}."
                    )
                title = svg_metadata.get("title")
                if isinstance(title, dict):
                    title_text = str(title.get("#text", "") or "")
                else:
                    title_text = str(title or "")
                if title_text and GENERIC_SVG_TITLE_REGEX.match(title_text):
                    warnings.append(
                        f"The SVG title '{title_text}' looks like a generator/template placeholder. The <title> should be a short, human-readable name for the brand or mark — typically the organization name (e.g. the value of the certificate subject's organizationName field)."
                    )
                svg_validation_errors = check_svg_requirements(svg_metadata)
                if len(svg_validation_errors) > 0:
                    svg_metadata["validation_errors"] = svg_validation_errors
            except (ValueError, KeyError) as e:
                results["image"] = {
                    "error": f"Failed to process BIMI image at {l_tag_value} - {e!s}"
                }

    a_tag_value = tags.get("a", {}).get("value", "")
    if a_tag_value != "":
        try:
            response = session.get(a_tag_value, timeout=http_timeout)
            response.raise_for_status()
            pem_bytes = response.content
            cert_metadata = get_certificate_metadata(pem_bytes, domain=domain)
        except (requests.RequestException, ValueError, KeyError) as e:
            results["certificate"] = {
                "error": f"Failed to download the mark certificate at {a_tag_value} - {e!s}"
            }

    # Compare the downloaded image against the logo embedded in the
    # certificate only after all tags have been processed, so the outcome
    # is the same whether a= appears before or after l= in the record
    # (tags other than v= may appear in any order per section 4.3 of the
    # BIMI draft).
    if svg_metadata is not None and cert_metadata is not None:
        # get_certificate_metadata's error path returns metadata without a
        # logotype_sha256 key, so read it with .get(): with no hash to
        # compare against, the certificate's own error or validation
        # messages already describe the problem.
        cert_logo_hash = cert_metadata.get("logotype_sha256")
        if cert_logo_hash is not None and svg_metadata["sha256"] == cert_logo_hash:
            hash_match = True
        elif cert_logo_hash is not None:
            warnings.append(
                "The image at the l= tag URL does not match the image embedded in the certificate."
            )

    if parsed_dmarc_record and tags.get("l", {}).get("value", "") != "":
        if parsed_dmarc_record["valid"] is False:
            warnings.append(
                "The domain does not have a valid DMARC record. A DMARC policy of quarantine or reject must be in place."
            )
        else:
            if parsed_dmarc_record["tags"]["p"]["value"] not in [
                "quarantine",
                "reject",
            ]:
                warnings.append(
                    "The DMARC policy (p tag) must be set to quarantine or reject."
                )
            if parsed_dmarc_record["tags"]["sp"]["value"] not in [
                "quarantine",
                "reject",
            ]:
                warnings.append(
                    "The DMARC subdomain policy (sp tag) must be set to quarantine or reject if it is used."
                )
            # BIMI only constrains pct when the policy is quarantine:
            # section 7.1 step 9 of the BIMI draft requires pct=100 when
            # p=quarantine and a pct tag is present. p=reject with any pct
            # satisfies BIMI. (The pct tag itself was removed in RFC 9989.)
            pct_tag = parsed_dmarc_record["tags"].get("pct")
            if (
                pct_tag is not None
                and pct_tag["value"] != 100
                and parsed_dmarc_record["tags"]["p"]["value"] == "quarantine"
            ):
                warnings.append(
                    "When the DMARC policy is p=quarantine, the pct tag "
                    "must be 100 (or absent) for BIMI to be displayed. "
                    "The pct tag was removed in RFC 9989."
                )
    if cert_metadata:
        valid_cert = hash_match and cert_metadata["valid"]
    if l_tag_value != "" and not valid_cert:
        warnings.append(
            "Most email providers will not display a BIMI image without a valid mark certificate."
        )
    results["tags"] = tags
    if svg_metadata is not None:
        results["image"] = svg_metadata
    if cert_metadata is not None:
        results["certificate"] = cert_metadata
    results["warnings"] = warnings

    return results


def check_bimi(
    domain: str,
    *,
    selector: str = "default",
    parsed_dmarc_record: DMARCResults | DMARCErrorResults | None = None,
    include_tag_descriptions: bool = False,
    nameservers: Sequence[str | Nameserver] | None = None,
    resolver: dns.resolver.Resolver | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    retries: int = DEFAULT_DNS_MAX_RETRIES,
) -> BIMICheckResult:
    """
    Returns a dictionary with a parsed BIMI record or an error.

    .. note::
            This will attempt to download and validate the SVG image and mark
            certificate at the URLs provided in the BIMI record; a download or
            processing failure is reported as an ``error`` entry under
            ``image`` or ``certificate``.

    Args:
        domain (str): A domain name
        selector (str): The BIMI selector
        parsed_dmarc_record (dict): A parsed DMARC record

        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        retries (int): The number of times to retry on timeout or other transient errors

    Returns:
        dict: a ``dict`` with the following keys:

                       - ``record`` - The BIMI record string
                       - ``valid`` - True
                       - ``selector`` - The BIMI selector
                       - ``location`` - The domain where the record was found
                       - ``tags`` - The parsed BIMI record tags
                       - ``image`` - SVG image metadata, if any
                       - ``certificate`` - Mark certificate metadata, if any
                       - ``warnings`` - A ``list`` of warnings

                    If a DNS error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - The error message
                      - ``valid`` - False
    """
    bimi_results: BIMICheckResult = {"record": None, "valid": True}
    selector = selector.lower()
    try:
        bimi_query = query_bimi_record(
            domain,
            selector=selector,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            retries=retries,
        )
        bimi_results["selector"] = selector
        bimi_results["location"] = bimi_query["location"]
        bimi_results["record"] = bimi_query["record"]
        parsed_bimi = parse_bimi_record(
            bimi_results["record"],
            include_tag_descriptions=include_tag_descriptions,
            domain=domain,
            parsed_dmarc_record=parsed_dmarc_record,
            http_timeout=DEFAULT_HTTP_TIMEOUT,
        )
        bimi_results["tags"] = parsed_bimi["tags"]
        if "image" in parsed_bimi:
            bimi_results["image"] = parsed_bimi["image"]
        if "certificate" in parsed_bimi:
            bimi_results["certificate"] = parsed_bimi["certificate"]
        bimi_results["warnings"] = parsed_bimi["warnings"]
    except BIMIError as error:
        bimi_results["selector"] = selector
        bimi_results["valid"] = False
        bimi_results["error"] = str(error)

    return bimi_results
