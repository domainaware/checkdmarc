Changelog
=========

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
