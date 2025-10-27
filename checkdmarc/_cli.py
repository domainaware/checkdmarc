#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validates and parses email-related DNS records"""

from __future__ import annotations

import os
from argparse import ArgumentParser

import logging

from checkdmarc import (
    __version__,
    check_domains,
    results_to_json,
    results_to_csv,
    output_to_file,
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


def _main():
    """Called when the module in executed"""
    arg_parser = ArgumentParser(description=__doc__)
    arg_parser.add_argument(
        "domain",
        nargs="+",
        help="one or more domains, or a single path to a "
        "file containing a list of domains",
    )
    arg_parser.add_argument(
        "-p",
        "--parked",
        help="indicate that the domains are parked",
        action="store_true",
        default=False,
    )
    arg_parser.add_argument("--ns", nargs="+", help="approved nameserver substrings")
    arg_parser.add_argument("--mx", nargs="+", help="approved MX hostname substrings")
    arg_parser.add_argument(
        "-d",
        "--descriptions",
        action="store_true",
        help="include descriptions of tags in the JSON output",
    )
    arg_parser.add_argument(
        "-f",
        "--format",
        default="json",
        help="specify JSON or CSV screen output format",
    )
    arg_parser.add_argument(
        "-o",
        "--output",
        nargs="+",
        help="one or more file paths to output to "
        "(must end in .json or .csv) "
        "(silences screen output)",
    )
    arg_parser.add_argument(
        "-n", "--nameserver", nargs="+", help="nameservers to query"
    )
    arg_parser.add_argument(
        "-t",
        "--timeout",
        help="number of seconds to wait for an answer from DNS (default 2.0)",
        type=float,
        default=2.0,
    )
    arg_parser.add_argument(
        "--timeout-retries",
        help="number of times to reattempt a query after a timeout (default 2)",
        type=int,
        default=2,
    )

    arg_parser.add_argument(
        "-b", "--bimi-selector", default="default", help="the BIMI selector to use"
    )
    arg_parser.add_argument("-v", "--version", action="version", version=__version__)
    (
        arg_parser.add_argument(
            "-w",
            "--wait",
            type=float,
            help="number of seconds to wait between checking domains (default 0.0)",
            default=0.0,
        ),
    )
    arg_parser.add_argument(
        "--skip-tls", action="store_true", help="skip TLS/SSL testing"
    )
    arg_parser.add_argument(
        "--debug", action="store_true", help="enable debugging output"
    )

    args = arg_parser.parse_args()

    logging_format = "%(asctime)s - %(levelname)s: %(message)s"
    logging.basicConfig(level=logging.WARNING, format=logging_format)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug output enabled")
    domains = args.domain
    if len(domains) == 1 and os.path.exists(domains[0]):
        with open(domains[0]) as domains_file:
            domains = sorted(
                list(
                    set(
                        map(
                            lambda d: d.rstrip(".\r\n").strip().lower().split(",")[0],
                            domains_file.readlines(),
                        )
                    )
                )
            )
            not_domains = []
            for domain in domains:
                if "." not in domain:
                    not_domains.append(domain)
            for domain in not_domains:
                domains.remove(domain)

    results = check_domains(
        domains,
        skip_tls=args.skip_tls,
        parked=args.parked,
        approved_nameservers=args.ns,
        approved_mx_hostnames=args.mx,
        include_tag_descriptions=args.descriptions,
        nameservers=args.nameserver,
        timeout=args.timeout,
        timeout_retries=args.timeout_retries,
        bimi_selector=args.bimi_selector,
        wait=args.wait,
    )

    if args.output is None:
        if args.format.lower() == "json":
            results = results_to_json(results)
        elif args.format.lower() == "csv":
            results = results_to_csv(results)
        print(results)
    else:
        for path in args.output:
            json_path = path.lower().endswith(".json")
            csv_path = path.lower().endswith(".csv")

            if not json_path and not csv_path:
                logging.error(f"Output path {path} must end in .json or .csv")
            else:
                if path.lower().endswith(".json"):
                    output_to_file(path, results_to_json(results))
                elif path.lower().endswith(".csv"):
                    output_to_file(path, results_to_csv(results))


if __name__ == "__main__":
    _main()
