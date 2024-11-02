# -*- coding: utf-8 -*-
"""Brand Indicators for Message Identification (BIMI) record validation"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Union
import re
from collections import OrderedDict
from sys import getsizeof
import base64
import gzip
import hashlib

try:
    import importlib.resources as pkg_resources
except ImportError:
    # Try backported to PY<37 `importlib_resources`
    import importlib_resources as pkg_resources

import dns
import requests
import xmltodict
import pem
from pyleri import Grammar, Regex, Sequence, List
from OpenSSL.crypto import (
    load_certificate,
    FILETYPE_PEM,
    X509Store,
    X509StoreContext,
    X509,
    X509StoreContextError,
)

import checkdmarc.resources
from checkdmarc._constants import SYNTAX_ERROR_MARKER, USER_AGENT
from checkdmarc.utils import WSP_REGEX, HTTPS_REGEX, query_dns, get_base_domain

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

BIMI_VERSION_REGEX_STRING = rf"v{WSP_REGEX}*={WSP_REGEX}*BIMI1{WSP_REGEX}*;"
BIMI_TAG_VALUE_REGEX_STRING = (
    rf"([a-z]{{1,2}}){WSP_REGEX}*={WSP_REGEX}*(bimi1|{HTTPS_REGEX})?"
)
BIMI_TAG_VALUE_REGEX = re.compile(BIMI_TAG_VALUE_REGEX_STRING, re.IGNORECASE)


# Load the certificates included in MVACAs.pem into a certificate store
X509STORE = X509Store()
with pkg_resources.path(checkdmarc.resources, "MVACAs.pem") as path:

    CA_PEMS = pem.parse_file(path)
for CA_PEM in CA_PEMS:
    CA = load_certificate(FILETYPE_PEM, CA_PEM.as_bytes())
    X509STORE.add_cert(CA)

BIMI_TAGS = OrderedDict(
    v=OrderedDict(
        name="Version",
        required=True,
        description="Identifies the record "
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
    ),
    a=OrderedDict(
        name="Authority Evidence Location",
        required=False,
        default="",
        description="If present, this tag MUST have an empty value "
        "or its value MUST be a single URI. An empty "
        "value for the tag is interpreted to mean the "
        "Domain Owner does not wish to publish or does "
        "not have authority evidence to disclose. The "
        "URI, if present, MUST contain a fully "
        "qualified domain name (FQDN) and MUST specify "
        'HTTPS as the URI scheme ("https"). The URI '
        "SHOULD specify the location of a publicly "
        "retrievable BIMI Evidence Document.",
    ),
    l=OrderedDict(
        name="Location",
        required=False,
        default="",
        description="The value of this tag is either empty "
        "indicating declination to publish, or a single "
        "URI representing the location of a Brand "
        "Indicator file. The only supported transport "
        "is HTTPS.",
    ),
)


class _BIMIWarning(Exception):
    """Raised when a non-fatal BIMI error occurs"""


class BIMIError(Exception):
    """Raised when a fatal BIMI error occurs"""

    def __init__(self, msg: str, data: dict = None):
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


class _BIMIGrammar(Grammar):
    """Defines Pyleri grammar for BIMI records"""

    version_tag = Regex(BIMI_VERSION_REGEX_STRING)
    tag_value = Regex(BIMI_TAG_VALUE_REGEX_STRING, re.IGNORECASE)
    START = Sequence(
        version_tag,
        List(tag_value, delimiter=Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"), opt=True),
    )


def get_svg_metadata(raw_xml: Union[str, bytes]) -> OrderedDict:
    metadata = OrderedDict()
    if isinstance(raw_xml, bytes):
        raw_xml = raw_xml.decode(errors="ignore")
    try:
        xml = xmltodict.parse(raw_xml)
        base_profile = None
        svg = xml["svg"]
        version = svg["@version"]
        if "@baseProfile" in svg.keys():
            base_profile = svg["@baseProfile"]
        view_box = svg["@viewBox"]
        view_box = view_box.split(" ")
        width = float(view_box[-2])
        height = float(view_box[-1])
        title = None
        if "x" in svg.keys():
            metadata["x"] = svg["x"]
        if "y" in svg.keys():
            metadata["x"] = svg["y"]
        if "title" in svg.keys():
            title = svg["title"]
        description = None
        if "description" in svg.keys():
            description = svg["description"]
        metadata["svg_version"] = version
        metadata["base_profile"] = base_profile
        metadata["title"] = title
        if description is not None:
            metadata["description"] = description
        metadata["width"] = width
        metadata["height"] = height
        metadata["filesize"] = f"{getsizeof(raw_xml)/1000} KB"
        metadata["sha256"] = hashlib.sha256(raw_xml.encode("utf-8")).hexdigest()
        return metadata
    except Exception as e:
        raise ValueError(f"Not a SVG file: {str(e)}")


def check_svg_requirements(svg_metadata: OrderedDict) -> list[str]:
    _warnings = []
    if svg_metadata["svg_version"] != "1.2":
        _warnings.append(
            f"The SVG version must be 1.2, not {svg_metadata['svg_version']}"
        )
    if svg_metadata["base_profile"] != "tiny-ps":
        _warnings.append(f"The SVG base profile must be tiny-ps")
    if svg_metadata["width"] != svg_metadata["height"]:
        _warnings.append("The SVG dimensions must be square, not {width}x{height}")
    if "title" not in svg_metadata.keys():
        _warnings.append("The SVG must have a title element")
    if "x" in svg_metadata.keys() or "y" in svg_metadata.keys():
        _warnings.append("The SVG cannot include x or y in the svg element")
    if float(svg_metadata["filesize"].strip(" KB")) > 32:
        _warnings.append("The SVG file exceeds the maximum size of 32 kB")
    return _warnings


def _get_certificate_san(cert: Union[X509, bytes]) -> list[str]:
    """Get the subjectaltname from a PEM certificate"""
    if type(cert) is bytes:
        cert = load_certificate(FILETYPE_PEM, cert)
    for cert_ext_id in range(cert.get_extension_count()):
        cert_ext = cert.get_extension(cert_ext_id)
        if cert_ext.get_short_name() == b"subjectAltName":
            san = cert_ext.__str__()
            san = san.replace("DNS:", "")
            san = san.split(", ")
            return san


def extract_logo_from_certificate(cert: Union[bytes, X509]) -> bytes:
    """Extracts the logo from a mark certificate"""
    if type(cert) is bytes:
        cert = load_certificate(FILETYPE_PEM, cert)
    for cert_ext_id in range(cert.get_extension_count()):
        cert_ext = cert.get_extension(cert_ext_id)
        if cert_ext.get_short_name() == b"UNDEF":
            logotype_data = cert_ext.get_data().decode("utf-8", errors="ignore")
            logo_base64 = base64.b64decode(logotype_data.split(",")[1])
            logo = gzip.decompress(logo_base64)
            return logo


def get_certificate_metadata(pem_crt: Union[str, bytes], domain=None) -> OrderedDict:
    """Get metadata about a Verified Mark Certificate"""
    metadata = OrderedDict()
    valid = False
    validation_errors = []
    san = []

    def _decode_components(components: list[tuple[bytes, bytes]]):
        new_dict = OrderedDict()
        for component in components:
            new_key = component[0].decode("utf-8", errors="ignore")
            new_value = component[1].decode("utf-8", errors="ignore")
            new_dict[new_key] = new_value
        return new_dict

    try:
        if type(pem_crt) is bytes:
            pem_crt = pem_crt.decode(errors="ignore")
        loaded_certs = []
        for cert in pem.parse(pem_crt):
            cert = load_certificate(FILETYPE_PEM, cert.as_bytes())
            loaded_certs.append(cert)
        vmc = loaded_certs[0]
        metadata["issuer"] = _decode_components(vmc.get_issuer().get_components())
        metadata["subject"] = _decode_components(vmc.get_subject().get_components())
        metadata["serial_number"] = vmc.get_serial_number().__str__()
        metadata["expires"] = vmc.get_notAfter().decode("utf-8", errors="ignore")
        metadata["expires"] = datetime.strptime(metadata["expires"], "%Y%m%d%H%M%SZ")
        metadata["expires"] = metadata["expires"].strftime("%Y-%m-%d %H:%M:%SZ")
        metadata["valid"] = valid and not vmc.has_expired()
        san = _get_certificate_san(vmc)
        metadata["domains"] = san
        metadata["logotype_sha256"] = None
        logotype = extract_logo_from_certificate(vmc)
        if logotype is not None:
            metadata["logotype_sha256"] = hashlib.sha256(logotype).hexdigest()
        store_context = X509StoreContext(X509STORE, vmc, chain=loaded_certs)
        try:
            store_context.verify_certificate()
            valid = True
            metadata["valid"] = valid
        except X509StoreContextError as e:
            validation_errors.append(str(e))
            metadata["validation_errors"] = validation_errors
            metadata["valid"] = valid
    except Exception as e:
        validation_errors.append(str(e))
    if domain is not None:
        if domain.lower() not in san:
            validation_errors.append(
                f"{domain} does not match the certificate domains, {san}"
            )
            metadata["validation_errors"] = validation_errors
            metadata["valid"] = False
    return metadata


def _query_bimi_record(
    domain: str,
    selector: str = "default",
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
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

    Returns:
        str: A record string or None
    """
    domain = domain.lower()
    target = f"{selector}._bimi.{domain}"
    txt_prefix = "v=BIMI1"
    bimi_record = None
    bimi_record_count = 0
    unrelated_records = []

    try:
        records = query_dns(
            target, "TXT", nameservers=nameservers, resolver=resolver, timeout=timeout
        )
        for record in records:
            if record.startswith(txt_prefix):
                bimi_record_count += 1
            else:
                unrelated_records.append(record)

        if bimi_record_count > 1:
            raise MultipleBIMIRecords("Multiple BMI records are not permitted")
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
                        "The BIMI record must be located at " f"{target}, not {domain}"
                    )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise BIMIRecordNotFound(f"The domain {domain} does not exist")
        except Exception as error:
            BIMIRecordNotFound(error)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as error:
        raise BIMIRecordNotFound(error)

    return bimi_record


def query_bimi_record(
    domain: str,
    selector: str = "default",
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> OrderedDict:
    """
    Queries DNS for a BIMI record

    Args:
        domain (str): A domain name
        selector (str): The BMI selector
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for a record from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
                     - ``record`` - the unparsed BIMI record string
                     - ``location`` - the domain where the record was found
                     - ``warnings`` - warning conditions found

     Raises:
        :exc:`checkdmarc.bimi.BIMIRecordNotFound`
        :exc:`checkdmarc.bimi.BIMIRecordInWrongLocation`
        :exc:`checkdmarc.bimi.MultipleBIMIRecords`

    """
    logging.debug(f"Checking for a BIMI record at {selector}._bimi.{domain}")
    warnings = []
    base_domain = get_base_domain(domain)
    location = domain.lower()
    record = _query_bimi_record(
        domain,
        selector=selector,
        nameservers=nameservers,
        resolver=resolver,
        timeout=timeout,
    )
    try:
        root_records = query_dns(
            domain, "TXT", nameservers=nameservers, resolver=resolver, timeout=timeout
        )
        for root_record in root_records:
            if root_record.startswith("v=BIMI1"):
                warnings.append(f"BIMI record at root of {domain} " "has no effect")
    except dns.resolver.NXDOMAIN:
        raise BIMIRecordNotFound(f"The domain {domain} does not exist")
    except dns.exception.DNSException:
        pass

    if record is None and domain != base_domain:
        record = _query_bimi_record(
            base_domain, nameservers=nameservers, resolver=resolver, timeout=timeout
        )
        location = base_domain
    if record is None:
        raise BIMIRecordNotFound(
            f"A BIMI record does not exist at the {selector} selector for "
            f"this domain or its base domain"
        )

    return OrderedDict(
        [("record", record), ("location", location), ("warnings", warnings)]
    )


def parse_bimi_record(
    record: str,
    domain: str = None,
    include_tag_descriptions: bool = False,
    syntax_error_marker: str = SYNTAX_ERROR_MARKER,
) -> OrderedDict:
    """
    Parses a BIMI record

    Args:
        record (str): A BIMI record
        domain (str): The domain where the BIMI record was located
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``tags`` - An ``OrderedDict`` of BIMI tags

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
    results = OrderedDict()
    image_metadata = None
    cert_metadata = None
    logging.debug("Parsing the BIMI record")
    session = requests.Session()
    session.headers = {"User-Agent": USER_AGENT}
    spf_in_dmarc_error_msg = (
        "Found a SPF record where a BIMI record "
        "should be; most likely, the _bimi "
        "subdomain record does not actually exist, "
        "and the request for TXT records was "
        "redirected to the base domain"
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

    pairs = BIMI_TAG_VALUE_REGEX.findall(record)
    tags = OrderedDict()
    hash_match = False

    for pair in pairs:
        tag = pair[0].lower().strip()
        tag_value = str(pair[1].strip())
        if tag not in BIMI_TAGS:
            raise InvalidBIMITag(f"{tag} is not a valid BIMI record tag")
        tags[tag] = OrderedDict(value=tag_value)
        if include_tag_descriptions:
            tags[tag]["name"] = BIMI_TAGS[tag]["name"]
            tags[tag]["description"] = BIMI_TAGS[tag]["description"]
        if tag == "l" and tag_value != "":
            raw_xml = None
            try:
                response = session.get(tag_value)
                response.raise_for_status()
                raw_xml = response.content
            except Exception as e:
                results["certificate"] = dict(
                    error=f"Failed to download BIMI image at {tag_value} - {str(e)}"
                )
            if raw_xml is not None:
                try:
                    image_metadata = get_svg_metadata(raw_xml)
                    svg_validation_errors = check_svg_requirements(image_metadata)
                    if len(svg_validation_errors) > 0:
                        image_metadata["validation_errors"] = svg_validation_errors
                except Exception as e:
                    results["image"] = dict(
                        error=f"Failed to process BIMI image at {tag_value} - {str(e)}"
                    )
        elif tag == "a" and tag_value != "":
            cert_metadata = None
            try:
                response = session.get(tag_value)
                response.raise_for_status()
                pem_bytes = response.content
                cert_metadata = get_certificate_metadata(pem_bytes, domain=domain)
                if image_metadata is not None:
                    if image_metadata["sha256"] == cert_metadata["logotype_sha256"]:
                        hash_match = True
                    else:
                        warnings.append(
                            "The image at the l= tag URL does not match the image embedded in the certificate"
                        )
            except Exception as e:
                results["certificate"] = dict(
                    error=f"Failed to download the mark certificate at {tag_value} - {str(e)}"
                )
    certificate_provided = hash_match and cert_metadata["valid"]
    if not certificate_provided:
        warnings.append(
            "Most providers will not display a BIMI image without a valid mark certificate"
        )
    results["tags"] = tags
    if image_metadata is not None:
        results["image"] = image_metadata
    if cert_metadata is not None:
        results["certificate"] = cert_metadata
    results["warnings"] = warnings

    return results


def check_bimi(
    domain: str,
    selector: str = "default",
    include_tag_descriptions: bool = False,
    nameservers: list[str] = None,
    resolver: dns.resolver.Resolver = None,
    timeout: float = 2.0,
) -> OrderedDict:
    """
    Returns a dictionary with a parsed BIMI record or an error.

    .. note::
            This will attempt to download the files at the URLs provided in
            the BIMI record and will include a warning if the downloads fail,
            but the file content is not currently analyzed.

    Args:
        domain (str): A domain name
        selector (str): The BIMI selector
        include_tag_descriptions (bool): Include descriptions in parsed results
        nameservers (list): A list of nameservers to query
        resolver (dns.resolver.Resolver): A resolver object to use for DNS
                                          requests
        timeout (float): number of seconds to wait for an answer from DNS

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:

                       - ``record`` - The BIMI record string
                       - ``parsed`` - The parsed BIMI record
                       - ``valid`` - True
                       - ``warnings`` - A ``list`` of warnings

                    If a DNS error occurs, the dictionary will have the
                    following keys:

                      - ``error`` - Tne error message
                      - ``valid`` - False
    """
    bimi_results = OrderedDict([("record", None), ("valid", True)])
    selector = selector.lower()
    try:
        bimi_query = query_bimi_record(
            domain,
            selector=selector,
            nameservers=nameservers,
            resolver=resolver,
            timeout=timeout,
        )
        bimi_results["selector"] = selector
        bimi_results["record"] = bimi_query["record"]
        parsed_bimi = parse_bimi_record(
            bimi_results["record"],
            include_tag_descriptions=include_tag_descriptions,
            domain=domain,
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
