Changelog
=========

1.0.7
-----
- Fix timeout option

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