Changelog
=========

4.1.7
-----

- Better DNS exception handling

4.1.6
------

- Fix TLS/STARTTLS failure output


4.1.5
-----

- Add warning if MX hosts are missing A or AAAA records


4.1.4
-----

- Timeout SMTP TLS check after 5 seconds

4.1.3
-----

- Debug output fixes

4.1.2
-----

- Fix `--skip-tls` option
- Replace `publicsuffix` with `publicsuffix2`

4.1.1
-----

- Fix `tls` and `starttls` CSV fields

4.1.0
-----

- Test for SSL/TLS over port 465 if `STARTTLS` is not supported
- Fix display of SSL/TLS errors

4.0.2
-----

- Improve `STARTTLS` test

4.0.1
-----

- Add option to CLI and API to skip STARTTLS testing
- Fix CSV output
- Fix debug logging
- Documentation fixes

4.0.0
-----

- Refactor API and CLI


3.1.2
-----

- Save `public_suffix_list.dat` to a temporary folder instead of the current 
working directory (CWD)
- Emulate a brouser HTTP `User-Agent` sting when downloading 
`public_suffix_list.dat`
- Add requirement `requests`
- Change list seperator within CSV fields from `,` to `|`

3.1.1
-----

- Fix returning `STARTTLS` results upon exception

3.1.0
-----

- Fix debug output
- Fix crash when checking domains with more than 10 MX records
- Cache `STARTTLS` failures
- Add warning for duplicate hostnames in MX records
- Increase cache sizes
- Disable check for SPF records on MX hostnames - too noisy

3.0.3
-----

- Catch `BlockingIOError` exception when testing `STARTTLS`
- Add warning if PTR records for MX do not match the hostname's A/AAAA records

3.0.2
-----

- Use output path file extension to set output format

3.0.1
-----

- Use substrings for matching approved 'MX' and 'NS' records, rather than the 
full string

3.0.0
-----

- Add `get_nameservers()` to the API
- Add `NS` record lookup to output as `ns`
- Add `--ns` option to CLI for listing approved nameservers

2.9.2
-----

- Fix `--mx` CLI option

2.9.1
-----

- Bugfix: STARTTLS caching
- Add MX warnings for parked domains
- Increase default DNS timeout from 2.0 seconds to 6.0 seconds

2.9.0
-----

- Bugfix: CSV format `-f csv` for starttls header
- Bugfix: Always properly close a SMTP connection
- Cache DNS and STARTTLS results in memory
- Use python3 in docs Makefile for Sphinx build
- Add `--debug` option
- Make warning about proper SPF records for MX hosts a only show with `--debug`
 (Very noisy - Many hosts use DKIM without SPF to DMARC align bouncebacks)


2.8.0
-----

- Bugfix: Always raise warning when SPF type DNS records are found
- Add check for proper SPF records for MX hosts
- Add check for STARTTLS
- Add option `-p/--parked` to check for best practices for parked domains
- Add option `--mx` to provide a list of approved MX hostnames
- Add `query_bimi_record()` to the API

2.7.3
-----

- Fix parsing of TXT records over multiple lines (PR #36)

2.7.2
-----
- Fix false-negative SPF validation of `ipv4` mechanisms with a single digit
  CIDR notation (PR #35)

2.7.1
-----

- Fix false-negative SPF and DMARC validations

2.7.0
------

- Fix report destination verification

2.6.3
-----

- Reduce default DNS timeout to 2.0 seconds
- Always use `\n` as the newline when generating output

2.6.2
-----

- Properly concatenate multi-line TXT records

2.6.1
-----

- Fix exception generation

2.6.0
-----

- Refactored  `DMARCError` and `SPFError` exceptions to support adding data to the results (seanthegeek)
- Close #18 - include `dns_lookups` in `spf`  results when number of SPF lookups are exceeded (seanthegeek)
- Added timeout rounding to the Exception classes (malvidin)


2.6.0
-----

- Refactored  `DMARCError` and `SPFError` exceptions to support adding data to the results (seanthegeek)
- Close #18 - include `dns_lookups` in `spf`  results when number of SPF lookups are exceeded (seanthegeek)
- Added timeout rounding to the Exception classes (malvidin)

2.5.1
-----

- PEP 8 fixes

2.5.0
-----

- Close #32 - Raise `SPFSyntaxError` when an invalid value is encountered for an `ip4`SPF mechanism
- Close #33 - Add `python3 setup.py sdist` to `build.sh`, and publish source distribution to PyPI

2.4.0
-----
- Close #31 - Public Suffix List checked before list is available (malvidin)
- Decrease precision of DNS timeout (malvidin)
- Close #15 - Add sorting of A/AAAA records (malvidin)
- Add basic logging of runtime warnings (seanthegeek)

2.3.0
-----
- Use Cloudflare's DNS resolvers by default

2.2.0
-----
- Fix DMARC record location when subdomain is missing record
- Fix typos

2.1.15
------
- prefix `.` to `public_suffix_list.dat`

2.1.14
-------
- Fix typo in help


2.1.13
------
- Treat `pct` < 1 as invalid
- Issue warning if there are more that two URIs for `rua` or `ruf` (separate count)

2.1.12
------
- Allow whitespace in DMARC values

2.1.11
------
- Actually fix DMARC `rua` and `ruf` CSV output

2.1.10
------
- Fix DMARC `rua` and `ruf` CSV output

2.1.9
-----
- More exception handling fixes

2.1.8
-----
- Fix DNS report destination verification error message

2.1.7
-----
- Yet more DNS error handling

2.1.6
-----
- More DNS `SERVFAIL` handling
- More descriptive warning if DMARC `pct` < 100

2.1.5
-----
- Handle DNS failures better

2.1.4
-----
- Properly handle a useless DMARC record at the root of a domain

2.1.3
-----
- Use correct example output in documentation
  - Replace `accenture.com` output from debugging with `fbi.gov` output
   - That's what I get for copy/pasting without reading :(

2.1.2
-----
- Raise an error when multiple `spf1` `TXT` records are found

2.1.1
-----
- Fix external DMARC report destination validation
- Update sample output in documentation

2.1.0
-----
- Improve DMARC regex for edge cases
- Use Organisational Domain when checking DMARC URI destination
- Simplify exceptions
- Refactor dome method return values
- Add more unit tests
- Many documentation improvements and fixes
- PEP 8 compliant

2.0.0
-----
- Check for misplaced DMARC records
- Update documentation
- Write unit tests and deploy CI (#12)

1.8.1
-----
- Fix a bug that causes all DMARC lookups to fail
- First unit tests

1.8.0
-----

- Fix SPF loop false-positives (#20)
- Use the base/organisational domain name when validating DMARC report destinations (#21)
- Add more granular exception classes in preparation for unit tests in 2.0.0

1.7.10
------
- Fix SPF regex regression

1.7.9
-----
- Make DMARC `p` required, as specified in the RFC
- Improve SPF regex and syntax error details

1.7.8
-----
- Update `mailto` regex to accept single char mailbox names
- Clarify DMARC tag and value descriptions
- Pass in nameservers and timeout when querying for `MX` records

1.7.7
-----
- Fix sample command in documentation

1.7.6
-----
- Raise an error instead of a warning when DMARC reporting URIs cannot receive reports about a domain

1.7.5
-----
- Fix JSON output structure or included/redirected SPF records

1.7.4
-----
- Fix typo in error message

1.7.3
-----
- Detect Requests for `_dmarc` records that actually return SPF records
- Correct documentation for `get_mx_hosts(domain, nameservers=None, timeout=6.0)`

1.7.2
-----
- Update output sample in documentation

1.7.1
-----
- Change in JSON structure - Separate DMARC URI scheme and address to better support potential future URI schemes

1.7.0
-----
- Change in JSON structure - Parse `mailto:` DMARC URIs, including size limits (if any)
- More granular Exception classes
- Updated documentation

1.6.1
-----

- Refactor and simplify DNS queries

1.6.0
-----

- Properly look for DMARC records in base/organisational domains
- Properly count DNS lookups for SPF
- Update sample output in the documentation

1.5.4
-----
- Remove faulty `ruf` tag warning

1.5.3
-----
- Fix another show-stopping bug :(

1.5.1
-----
- Fix show-stopping bug

1.5.0
-----

- Turn `rua` and `ruf` tag values in to lists
- Fix conversion of lists to strings in CSVs
- Raise `DMARCWarning` if the value of the `pct` tag is  less than 100
- Raise `DMARCError` if the value of the `pct` tag is less than 0 or greater than 100

1.4.0
-----
- Proper parsing of DMARC tags `fo` and `rf`

1.3.8
-----

- Improve regex for the DMARC `mailto:` URI
- `__version__` only needs to be updated in one place now
- Fix docstring formatting

1.3.7
----
- Properly handle DMARC records that are made up of multiple strings

1.3.6
-----

- Allow input file to be a CSV where the domain is the first field; all other fields are ignored
- Better handling of invalid DMARC values

1.3.5
-----
- Rearrange the order of the CSV fields to that the longest entries are to the right
- Documentation improvements
- Fix external DMARC report destination validation
- Count each MX resource record once

1.3.3 and 1.3.4
---------------
- Clarify warning messages

1.3.2
-----
- Pass timeout in for SPF queries when outputting in CSV format
- Raise default timeout to 6 seconds

1.3.1
-----
- Only include hostname in mx SPF mechanism results

1.3.0
-----
- Show MX preference in output
- Sort MX records by preference
- Mark package as supporting Python 3 only (Python 2 was never actually supported because Pyleri does not support it)
- Removed all previous versions from PyPI so someone dosen't think Python 2 was supported when it never was

1.2.1
-----

- Change default timeout to 4 seconds
- Use ; to delimit warnings and MX records in CSV format

1.2.0
-----
- Add MX warnings to output

1.1.1
------

- Fix DMARC warning CSV output

1.1.0
------

- Separate SPF MX record limit from SPF DNS mechanism limit
- Fix DMARC CSV output

1.0.12
------

- Fix more SPF exceptions

1.0.11
------

- Fix SPF exceptions

1.0.10
------
- Fix DMARC record discovery
- Rename mx domain key to hostname
- Add example output to README

1.0.9
-----
- Fix PyPI readme display

1.0.8
-----
- Fix typos
- Add MX records to output

1.0.7
-----
- Fix `--timeout/-t` option
- Add `--wait/-w` oprion

1.0.6
-----
- Make SPF loops errors instead of warnings
- Check SPF records for `redirect` loops

1.0.5
------
- Ignore blank lines/domains in input

1.0.4
-----
- Include the DMARC organisational domain in JSON and CSV output
- Change CSV field order for readability
- Make JSON output order consistent
- Resolve SPF `redirect`
- Put include results in a JSON list
- Count `exists` SPF mechanisms in the overall SPF query limit
- Make `a` SPF mechanisms count as one lookup instead of two
  - `checkdmarc` actually makes two queries per `a` mechanism, one for `A` records, and one for `AAAA` records.
  However, [RFC 7208, Section 1.6.4][1] only mentions counting the mechanisms that use lookups
  (i.e. `mx`, `a`, `exists`, `include`, and `redirect`), and including each `MX` record returned in the overall count,
    (since those in turn will need to be resolved). This aligns `checkdmarc` with 3rd party SPF validators at
    [MxToolbox][2] and [DMARC Analyzer][3]

1.0.3
------
- Removed from PyPI due to bugs
- Subdomains inherit the DMARC record of the organisational domain

1.0.2
-----
- Removed from PyPI due to bugs
- Validate existence of MX amd A/AAAA records
- Add a `--timeout/-t` option
- Improve DMARC record syntax validation
- Check for SPF include loops
- Validate `rua` and `ruf` URIs
- Fail SPF validation if query limit reached [RFC 7208, Section 1.6.4][1]

1.0.1
-----
- First release on PyPi (since removed due to bugs)

1.0.0
-----
- Initial commit to GitHub

[1]: https://tools.ietf.org/html/rfc7208#section-1.6.4
[2]: https://mxtoolbox.com/spf.aspx
[3]: https://app.dmarcanalyzer.com/dns/spf
