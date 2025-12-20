# -*- coding: utf-8 -*-
"""Brand Indicators for Message Identification (BIMI) record validation"""

from __future__ import annotations

import base64
import gzip
import hashlib
import logging
import re
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from sys import getsizeof
from typing import Optional, Union, TypedDict, Any

try:
    from importlib.resources import files
except ImportError:
    # Try backported to PY<3 `importlib_resources`
    from importlib_resources import files


import dns.exception
import dns.resolver
from dns.nameserver import Nameserver
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
import pyleri

import checkdmarc.resources
from checkdmarc._constants import DEFAULT_HTTP_TIMEOUT, SYNTAX_ERROR_MARKER, USER_AGENT
from checkdmarc.utils import (
    HTTPS_REGEX,
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


# TypedDict definitions for BIMI record structures


# These typedicts can't be used in Python 3.9-3.10 because there is no way to set a field as optional, but keeping them for later
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
    domains: Optional[list[str]]
    logotype_sha256: Optional[str]
    warnings: list[str]
    validation_errors: list[str]


class BIMIQueryResult(TypedDict):
    """Result from querying a BIMI record"""

    record: str
    location: str
    warnings: list[str]


class BIMITagValue(TypedDict, total=False):
    """BIMI tag value structure"""

    value: str
    name: str
    description: str


class BIMIParseResult(TypedDict):
    """Result from parsing a BIMI record"""

    tags: dict[str, BIMITagValue]
    image: Union[SVGMetadata, dict[str, str]]
    certificate: Union[CertificateMetadata, dict[str, str]]
    warnings: list[str]


class BIMICheckResult(TypedDict, total=False):
    """Result from checking BIMI for a domain"""

    record: Optional[str]
    valid: bool
    selector: str
    location: str
    tags: dict[str, BIMITagValue]
    image: Union[SVGMetadata, dict[str, str]]
    certificate: Union[CertificateMetadata, dict[str, str]]
    warnings: list[str]
    error: str


BIMI_VERSION_REGEX_STRING = rf"v{WSP_REGEX}*={WSP_REGEX}*BIMI1{WSP_REGEX}*;"
BIMI_TAG_VALUE_REGEX_STRING = (
    rf"([a-z]{{1,3}}){WSP_REGEX}*={WSP_REGEX}*(bimi1|{HTTPS_REGEX}|personal|brand)?"
)
BIMI_TAG_VALUE_REGEX = re.compile(BIMI_TAG_VALUE_REGEX_STRING, re.IGNORECASE)

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
OID_WORD_MARK = (ObjectIdentifier("1.3.6.1.4.1.53087.1.6"),)
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
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME: "serviceAlternativeName",
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


FIELD_REQUIRED_IF_FIELD_IS_MISSING = {
    "All": {
        "localityName": "stateOrProvinceName",
        "jurisdictionOfIncorporationLocalityName": "jurisdictionOfIncorporationStateOrProvinceName",
        "stateOrProvinceName": "localityName",
        "jurisdictionOfIncorporationStateOrProvinceName": "jurisdictionOfIncorporationLocalityName",
    },
    "Government Mark": {
        "statuteLocalityName": "statuteStateOrProvinceName",
        "statuteStateOrProvinceName": "statuteLocalityName",
    },
}

_ksf_dicts = [
    REQUIRED_SUBJECT_FIELDS_BY_MARK_TYPE,
    OPTIONAL_SUBJECT_FIELDS_BY_MARK_TYPE,
]
KNOWN_SUBJECT_FIELDS = []
for ksf_dict in _ksf_dicts:
    for key in ksf_dict:
        if isinstance(ksf_dict[key], list):
            for i in range(len(ksf_dict[key])):
                KNOWN_SUBJECT_FIELDS.append(ksf_dict[key][i])
KNOWN_SUBJECT_FIELDS = set(KNOWN_SUBJECT_FIELDS)


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

    def __init__(self, msg: str, data: Optional[dict] = None):
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


def get_svg_metadata(raw_xml: Union[str, bytes]) -> dict[str, Any]:
    metadata = {}
    if isinstance(raw_xml, bytes):
        raw_xml = raw_xml.decode(errors="ignore")
    try:
        xml = xmltodict.parse(raw_xml)
        svg = xml["svg"]
        metadata["svg_version"] = svg["@version"]
        if "@baseProfile" in svg.keys():
            metadata["base_profile"] = svg["@baseProfile"]
        view_box = svg["@viewBox"]
        view_box = view_box.split(" ")
        width = float(view_box[-2])
        height = float(view_box[-1])
        if "x" in svg.keys():
            metadata["x"] = svg["x"]
        if "y" in svg.keys():
            metadata["x"] = svg["y"]
        if "title" in svg.keys():
            metadata["title"] = svg["title"]
        description = None
        if "description" in svg.keys():
            description = svg["description"]
        if "overflow" in svg.keys():
            metadata["overflow"] = svg["overflow"]
        if description is not None:
            metadata["description"] = description
        metadata["width"] = width
        metadata["height"] = height
        metadata["filesize"] = f"{getsizeof(raw_xml) / 1000} KB"
        metadata["sha256"] = hashlib.sha256(
            raw_xml.encode("utf-8")  # pyright: ignore[reportAttributeAccessIssue]
        ).hexdigest()  # pyright: ignore[reportAttributeAccessIssue]
        return metadata
    except Exception as e:
        raise ValueError(f"Not a SVG file: {str(e)}")


def check_svg_requirements(svg_metadata: dict) -> list[str]:
    _errors = []
    if svg_metadata["svg_version"] != "1.2":
        _errors.append(
            f"The SVG version must be 1.2, not {svg_metadata['svg_version']}"
        )
    if "base_profile" not in svg_metadata.keys():
        _errors.append(
            "The SVG is missing a base profile. It must have the "
            "base profile tiny-ps and conform to its standards. "
            "https://bimigroup.org/solving-svg-issues/"
        )
    else:
        base_profile = svg_metadata["base_profile"]
        if base_profile != "tiny-ps":
            _errors.append(f"The SVG base profile must be tiny-ps, not {base_profile}")
    if "title" not in svg_metadata.keys():
        _errors.append("The SVG must have a title element")
    invalid_attributes = ["x", "y"]
    for attribute in invalid_attributes:
        if attribute in svg_metadata.keys():
            _errors.append(f"The SVG cannot include {attribute} in the svg element")
    if float(svg_metadata["filesize"].strip(" KB")) > 32:
        _errors.append("The SVG file exceeds the maximum size of 32 KB")
    return _errors


def extract_logo_from_certificate(
    cert: Union[x509.Certificate, bytes],
) -> Union[None, bytes]:
    try:
        if not isinstance(cert, x509.Certificate):
            cert = load_pem_x509_certificates(cert)[1]
        ext = cert.extensions.get_extension_for_oid(OID_LOGOTYPE)
        ext_bytes = ext.value.value  # pyright: ignore[reportAttributeAccessIssue]
        ext_str = ext_bytes.decode("utf-8", errors="ignore")
        logo_base64 = base64.b64decode(ext_str.split(",")[1])
        logo = gzip.decompress(logo_base64)
        return logo
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
                "Certificate issued on or after 2025-03-15 must not contain the Pilot identifier extension."
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
        logging.debug(f"Certificate ValidationError exception: {e_str}")
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
        if cert_domains is not None:
            if domain not in cert_domains and base_domain not in cert_domains:
                plural = "domain" if len(cert_domains) == 1 else "domains"
                cert_domains = ". ".join(cert_domains)
                validation_errors.append(
                    f"{base_domain} does not match the certificate {plural}: {cert_domains}"
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
                ):
                    if "priorUseMarkSourceURL" not in cert_subject:
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
                            f"The the certificate's subject is missing the required field {required_field}."
                        )
                for key in FIELD_REQUIRED_IF_FIELD_IS_MISSING:
                    if key in ["All", mark_type]:
                        if key in FIELD_REQUIRED_IF_FIELD_IS_MISSING:
                            for required_field in FIELD_REQUIRED_IF_FIELD_IS_MISSING[
                                key
                            ]:
                                if required_field not in cert_subject:
                                    alt_field = FIELD_REQUIRED_IF_FIELD_IS_MISSING[key][
                                        required_field
                                    ]
                                    if alt_field not in cert_subject:
                                        validation_errors.append(
                                            f"{alt_field} is required in the certificate subject if {required_field} is not used in the certificate subject."
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
    except Exception as e:
        validation_errors.append(str(e))
        metadata["valid"] = False
        metadata["validation_errors"] = validation_errors
    return metadata


def _query_bimi_record(
    domain: str,
    *,
    selector: Optional[str] = "default",
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
):
    """
    Queries DNS for a BIMI record

    Args:
        domain (str): A domain name
        selector: the BIMI selector
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout

    Returns:
        str: A record string or None
    """
    domain = normalize_domain(domain)
    target = f"{selector}._bimi.{domain}"
    txt_prefix = "v=BIMI1"
    bimi_record = None
    bimi_record_count = 0
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
                bimi_record_count += 1
            else:
                unrelated_records.append(record)

        if bimi_record_count > 1:
            raise MultipleBIMIRecords("Multiple BMI records are not permitted.")
        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            raise UnrelatedTXTRecordFoundAtBIMI(
                "Unrelated TXT records were discovered. These should be "
                "removed, as some receivers may not expect to find "
                "unrelated TXT records "
                f"at {target}\n\n{ur_str}"
            )
        bimi_record = records[0]

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
                if record.startswith(txt_prefix):
                    raise BIMIRecordInWrongLocation(
                        f"The BIMI record must be located at {target}, not {domain}."
                    )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise BIMIRecordNotFound("The domain does not exist.")
        except Exception as error:
            BIMIRecordNotFound(error)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as error:
        raise BIMIRecordNotFound(error)

    return bimi_record


def query_bimi_record(
    domain: str,
    *,
    selector: Optional[str] = "default",
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> BIMIQueryResult:
    """
    Queries DNS for a BIMI record

    Args:
        domain (str): A domain name
        selector (str): The BMI selector
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout

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
    logging.debug(f"Checking for a BIMI record at {selector}._bimi.{domain}")
    warnings = []
    base_domain = get_base_domain(domain)
    location = domain
    record = _query_bimi_record(
        domain,
        selector=selector,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
        timeout_retries=timeout_retries,
    )
    try:
        root_records = query_dns(
            domain,
            "TXT",
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
        )
        for root_record in root_records:
            if root_record.startswith("v=BIMI1"):
                warnings.append(f"BIMI record at root of {domain} has no effect.")
    except dns.resolver.NXDOMAIN:
        raise BIMIRecordNotFound("The domain does not exist.")
    except dns.exception.DNSException:
        pass

    if record is None and domain != base_domain:
        record = _query_bimi_record(
            base_domain,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
            timeout_retries=timeout_retries,
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
    domain: Optional[str] = None,
    parsed_dmarc_record: Optional[dict] = None,
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
        syntax_error_marker (str): The maker for pointing out syntax errors
        http_timeout (float): HTTP timeout in seconds

    Returns:
        dict: a ``dict`` with the following keys:
         - ``tags`` - a ``dict`` of BIMI tags

           - ``value`` - The BIMI tag value
           - ``description`` - A description of the tag/value
         - ``image`` - SVG image metadata, if any
         - ``certificate`` - Verified Mark Certificate (VMC metadata), if any
         - ``warnings`` - A ``list`` of warnings

        .. note::
            This will attempt to download the files at the URLs provided in
            the BIMI record and will include a warning if the downloads fail,
            but the file content is not currently analyzed.

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
    logging.debug("Parsing the BIMI record")
    session = requests.Session()
    session.headers = {"User-Agent": USER_AGENT}
    spf_in_dmarc_error_msg = (
        "Found a SPF record where a BIMI record "
        "should be; most likely, the _bimi "
        "subdomain record does not actually exist, "
        "and the request for TXT records was "
        "redirected to the base domain."
    )
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereBIMIRecordShouldBe(spf_in_dmarc_error_msg)
    bimi_syntax_checker = _BIMIGrammar()
    parsed_record = bimi_syntax_checker.parse(record)
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
        raise BIMISyntaxError(
            f"Error: Expected {expecting} at position "
            f"{parsed_record.pos} "
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
            raise InvalidBIMITag(f"{tag} is not a valid BIMI record tag.")
        # Check for duplicate tags
        if tag in seen_tags:
            if tag not in duplicate_tags:
                duplicate_tags.append(tag)
        else:
            seen_tags.append(tag)
        if len(duplicate_tags):
            duplicate_tags_str = ",".join(duplicate_tags)
            raise InvalidBIMITag(
                f"Duplicate {duplicate_tags_str} tags are not permitted"
            )
        tags[tag] = {"value": tag_value}
        if include_tag_descriptions:
            tags[tag]["name"] = BIMI_TAGS[tag]["name"]
            tags[tag]["description"] = BIMI_TAGS[tag]["description"]
        if tag == "l" and tag_value != "":
            raw_xml = None
            try:
                response = session.get(tag_value, timeout=http_timeout)
                response.raise_for_status()
                raw_xml = response.content
            except Exception as e:
                results["image"] = {
                    "error": f"Failed to download BIMI image at {tag_value} - {str(e)}"
                }
            if raw_xml is not None:
                try:
                    svg_metadata = get_svg_metadata(raw_xml)
                    if svg_metadata["width"] != svg_metadata["height"]:
                        warnings.append(
                            f"It is recommended for BIMI SVG dimensions to be square, not {svg_metadata['width']}x{svg_metadata['height']}."
                        )
                    svg_validation_errors = check_svg_requirements(svg_metadata)
                    if len(svg_validation_errors) > 0:
                        svg_metadata["validation_errors"] = svg_validation_errors
                except Exception as e:
                    results["image"] = {
                        "error": f"Failed to process BIMI image at {tag_value} - {str(e)}"
                    }
        elif tag == "a" and tag_value != "":
            cert_metadata = None
            try:
                response = session.get(tag_value, timeout=http_timeout)
                response.raise_for_status()
                pem_bytes = response.content
                cert_metadata = get_certificate_metadata(pem_bytes, domain=domain)
                if svg_metadata is not None:
                    if svg_metadata["sha256"] == cert_metadata["logotype_sha256"]:
                        hash_match = True
                    else:
                        warnings.append(
                            "The image at the l= tag URL does not match the image embedded in the certificate."
                        )
            except Exception as e:
                results["certificate"] = {
                    "error": f"Failed to download the mark certificate at {tag_value} - {str(e)}"
                }
        elif tag == "avp":
            if tag_value not in ["brand", "personal"]:
                raise BIMISyntaxError(
                    f"Acceptable avp tag values are personal or brand, not {tag_value}"
                )
        elif tag == "lps":
            tag_value = tag_value.split(",")
            for i in range(len(tag_value)):
                tag_value[i] = tag_value[i].lower()

    if parsed_dmarc_record and not tags["l"] == "":
        if not parsed_dmarc_record["valid"]:
            warnings.append(
                "The domain does not have a valid DMARC record. A DMARC policy of quarantine or reject must be in place."
            )
        else:
            if parsed_dmarc_record["tags"]["p"]["value"] not in [
                "quarantine",
                "reject",
            ]:
                warnings.append(
                    "The DMARC policy (p tag) must not be set to quarantine or reject."
                )
            if parsed_dmarc_record["tags"]["sp"]["value"] not in [
                "quarantine",
                "reject",
            ]:
                warnings.append(
                    "The DMARC subdomain policy (sp tag) must be set to quarantine or reject if it is used."
                )
            if parsed_dmarc_record["tags"]["pct"]["value"] != 100:
                warnings.append(
                    "The DMARC pct tag must be set to 100 (the implicit default) if it is used."
                )
    if cert_metadata:
        matching_certificate_provided = hash_match and cert_metadata["valid"]
        l_tag_value = tags.get("l", {}).get("value", "")
        if l_tag_value != "" and not matching_certificate_provided:
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
    parsed_dmarc_record: Optional[dict] = None,
    include_tag_descriptions: bool = False,
    nameservers: Optional[Sequence[str | Nameserver]] = None,
    resolver: Optional[dns.resolver.Resolver] = None,
    timeout: float = 2.0,
    timeout_retries: int = 2,
) -> BIMICheckResult:
    """
    Returns a dictionary with a parsed BIMI record or an error.

    .. note::
            This will attempt to download the files at the URLs provided in
            the BIMI record and will include a warning if the downloads fail,
            but the file content is not currently analyzed.

    Args:
        domain (str): A domain name
        selector (str): The BIMI selector
        parsed_dmarc_record (dict): A parsed DMARC record

        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS
        timeout_retries (int): The number of times to reattempt a query after a timeout

    Returns:
        dict: a ``dict`` with the following keys:

                       - ``record`` - The BIMI record string
                       - ``parsed`` - The parsed BIMI record
                       - ``valid`` - True
                       - ``warnings`` - A ``list`` of warnings

                    If a DNS error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - Tne error message
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
            timeout_retries=timeout_retries,
        )
        bimi_results["selector"] = selector
        bimi_results["location"] = bimi_query["location"]
        bimi_results["record"] = bimi_query["record"]
        parsed_bimi = parse_bimi_record(
            bimi_results["record"],
            include_tag_descriptions=include_tag_descriptions,
            domain=domain,
            parsed_dmarc_record=parsed_dmarc_record,
            http_timeout=timeout,
        )
        bimi_results["tags"] = parsed_bimi["tags"]
        if "image" in parsed_bimi.keys():
            bimi_results["image"] = parsed_bimi["image"]
        if "certificate" in parsed_bimi.keys():
            bimi_results["certificate"] = parsed_bimi["certificate"]
        bimi_results["warnings"] = parsed_bimi["warnings"]
    except BIMIError as error:
        bimi_results["selector"] = selector
        bimi_results["valid"] = False
        bimi_results["error"] = str(error)

    return bimi_results
