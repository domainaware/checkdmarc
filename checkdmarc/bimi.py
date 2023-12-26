# -*- coding: utf-8 -*-
"""Brand Indicators for Message Identification (BIMI) record validation"""

from __future__ import annotations

import logging
import re
from collections import OrderedDict

import dns
import requests
from pyleri import (Grammar,
                    Regex,
                    Sequence,
                    List
                    )

from checkdmarc._constants import SYNTAX_ERROR_MARKER, USER_AGENT
from checkdmarc.utils import (WSP_REGEX, HTTPS_REGEX, query_dns,
                              get_base_domain)

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

BIMI_VERSION_REGEX_STRING = fr"v{WSP_REGEX}*={WSP_REGEX}*BIMI1{WSP_REGEX}*;"
BIMI_TAG_VALUE_REGEX_STRING = (
    fr"([a-z]{{1,2}}){WSP_REGEX}*={WSP_REGEX}*(bimi1|{HTTPS_REGEX})?"
)
BIMI_TAG_VALUE_REGEX = re.compile(BIMI_TAG_VALUE_REGEX_STRING, re.IGNORECASE)


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
        version_tag, List(tag_value,
                          delimiter=Regex(f"{WSP_REGEX}*;{WSP_REGEX}*"),
                          opt=True))


bimi_tags = OrderedDict(
    v=OrderedDict(name="Version",
                  required=True,
                  description='Identifies the record '
                              'retrieved as a BIMI '
                              'record. It MUST have the '
                              'value of "BIMI1". The '
                              'value of this tag MUST '
                              'match precisely; if it '
                              'does not or it is absent, '
                              'the entire retrieved '
                              'record MUST be ignored. '
                              'It MUST be the first '
                              'tag in the list.'),
    a=OrderedDict(name="Authority Evidence Location",
                  required=False,
                  default="",
                  description='If present, this tag MUST have an empty value '
                              'or its value MUST be a single URI. An empty '
                              'value for the tag is interpreted to mean the '
                              'Domain Owner does not wish to publish or does '
                              'not have authority evidence to disclose. The '
                              'URI, if present, MUST contain a fully '
                              'qualified domain name (FQDN) and MUST specify '
                              'HTTPS as the URI scheme ("https"). The URI '
                              'SHOULD specify the location of a publicly '
                              'retrievable BIMI Evidence Document.'
                  ),
    l=OrderedDict(name="Location",
                  required=False,
                  default="",
                  description='The value of this tag is either empty '
                              'indicating declination to publish, or a single '
                              'URI representing the location of a Brand '
                              'Indicator file. The only supported transport '
                              'is HTTPS.'
                  )
)


def _query_bimi_record(domain: str, selector: str = "default",
                       nameservers: list[str] = None,
                       resolver: dns.resolver.Resolver = None,
                       timeout: float = 2.0):
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
        records = query_dns(target, "TXT", nameservers=nameservers,
                            resolver=resolver, timeout=timeout)
        for record in records:
            if record.startswith(txt_prefix):
                bimi_record_count += 1
            else:
                unrelated_records.append(record)

        if bimi_record_count > 1:
            raise MultipleBIMIRecords(
                "Multiple BMI records are not permitted")
        if len(unrelated_records) > 0:
            ur_str = "\n\n".join(unrelated_records)
            raise UnrelatedTXTRecordFoundAtBIMI(
                "Unrelated TXT records were discovered. These should be "
                "removed, as some receivers may not expect to find "
                "unrelated TXT records "
                f"at {target}\n\n{ur_str}")
        bimi_record = records[0]

    except dns.resolver.NoAnswer:
        try:
            records = query_dns(domain, "TXT",
                                nameservers=nameservers, resolver=resolver,
                                timeout=timeout)
            for record in records:
                if record.startswith(txt_prefix):
                    raise BIMIRecordInWrongLocation(
                        "The BIMI record must be located at "
                        f"{target}, not {domain}")
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            raise BIMIRecordNotFound(
                f"The domain {domain} does not exist")
        except Exception as error:
            BIMIRecordNotFound(error)

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception as error:
        raise BIMIRecordNotFound(error)

    return bimi_record


def query_bimi_record(domain: str, selector: str = "default",
                      nameservers: list[str] = None,
                      resolver: dns.resolver.Resolver = None,
                      timeout: float = 2.0) -> OrderedDict:
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
    record = _query_bimi_record(domain, selector=selector,
                                nameservers=nameservers, resolver=resolver,
                                timeout=timeout)
    try:
        root_records = query_dns(domain, "TXT",
                                 nameservers=nameservers, resolver=resolver,
                                 timeout=timeout)
        for root_record in root_records:
            if root_record.startswith("v=BIMI1"):
                warnings.append(f"BIMI record at root of {domain} "
                                "has no effect")
    except dns.resolver.NXDOMAIN:
        raise BIMIRecordNotFound(
            f"The domain {domain} does not exist")
    except dns.exception.DNSException:
        pass

    if record is None and domain != base_domain and selector != "default":
        record = _query_bimi_record(base_domain,
                                    nameservers=nameservers, resolver=resolver,
                                    timeout=timeout)
        location = base_domain
    if record is None:
        raise BIMIRecordNotFound(
            f"A BIMI record does not exist at the {selector} selector for "
            f"this domain or its base domain")

    return OrderedDict([("record", record), ("location", location),
                        ("warnings", warnings)])


def parse_bimi_record(
        record: str,
        include_tag_descriptions: bool = False,
        syntax_error_marker: str = SYNTAX_ERROR_MARKER) -> OrderedDict:
    """
    Parses a BIMI record

    Args:
        record (str): A BIMI record
        include_tag_descriptions (bool): Include descriptions in parsed results
        syntax_error_marker (str): The maker for pointing out syntax errors

    Returns:
        OrderedDict: An ``OrderedDict`` with the following keys:
         - ``tags`` - An ``OrderedDict`` of BIMI tags

           - ``value`` - The BIMI tag value
           - ``description`` - A description of the tag/value

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
    logging.debug("Parsing the BIMI record")
    session = requests.Session()
    session.headers = {"User-Agent": USER_AGENT}
    spf_in_dmarc_error_msg = "Found a SPF record where a BIMI record " \
                             "should be; most likely, the _bimi " \
                             "subdomain record does not actually exist, " \
                             "and the request for TXT records was " \
                             "redirected to the base domain"
    warnings = []
    record = record.strip('"')
    if record.lower().startswith("v=spf1"):
        raise SPFRecordFoundWhereBIMIRecordShouldBe(spf_in_dmarc_error_msg)
    bimi_syntax_checker = _BIMIGrammar()
    parsed_record = bimi_syntax_checker.parse(record)
    if not parsed_record.is_valid:
        expecting = list(
            map(lambda x: str(x).strip('"'), list(parsed_record.expecting)))
        marked_record = (record[:parsed_record.pos] + syntax_error_marker +
                         record[parsed_record.pos:])
        expecting = " or ".join(expecting)
        raise BIMISyntaxError(f"Error: Expected {expecting} at position "
                              f"{parsed_record.pos} "
                              f"(marked with {syntax_error_marker}) in: "
                              f"{marked_record}")

    pairs = BIMI_TAG_VALUE_REGEX.findall(record)
    tags = OrderedDict()

    for pair in pairs:
        tag = pair[0].lower().strip()
        tag_value = str(pair[1].strip())
        if tag not in bimi_tags:
            raise InvalidBIMITag(f"{tag} is not a valid BIMI record tag")
        tags[tag] = OrderedDict(value=tag_value)
        if include_tag_descriptions:
            tags[tag]["name"] = bimi_tags[tag]["name"]
            tags[tag]["description"] = bimi_tags[tag]["description"]
        if tag == "a" and tag_value != "":
            try:
                response = session.get(tag_value)
                response.raise_for_status()
            except Exception as e:
                warnings.append(f"Unable to download Authority Evidence at "
                                f"{tag_value} - {str(e)}")
        elif tag == "e" and tag_value != "":
            try:
                response = session.get(tag_value)
                response.raise_for_status()
            except Exception as e:
                warnings.append(f"Unable to download  "
                                f"{tag_value} - {str(e)}")

    return OrderedDict(tags=tags, warnings=warnings)


def check_bimi(domain: str, selector: str = "default",
               include_tag_descriptions: bool = False,
               nameservers: list[str] = None,
               resolver: dns.resolver.Resolver = None,
               timeout: float = 2.0) -> OrderedDict:
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
            nameservers=nameservers, resolver=resolver,
            timeout=timeout)
        bimi_results["selector"] = selector
        bimi_results["record"] = bimi_query["record"]
        parsed_bimi = parse_bimi_record(
            bimi_results["record"],
            include_tag_descriptions=include_tag_descriptions)
        bimi_results["tags"] = parsed_bimi["tags"]
        bimi_results["warnings"] = parsed_bimi["warnings"]
    except BIMIError as error:
        bimi_results["selector"] = selector
        bimi_results["valid"] = False
        bimi_results["error"] = str(error)

    return bimi_results
