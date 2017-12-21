Changelog
=========

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
  However, [RFC 7208, Section 4.6.4][1] only mentions counting the mechanisms that use lookups 
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
- Fail SPF validation if query limit reached [RFC 7208, Section 4.6.4][1]

1.0.1
-----
- First release on PyPi (since removed due to bugs)

1.0.0
-----
- Initial commit to GitHub

[1]: https://tools.ietf.org/html/rfc7208#section-4.6.4
[2]: https://mxtoolbox.com/spf.aspx
[3]: https://app.dmarcanalyzer.com/dns/spf
