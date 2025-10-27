# Changelog

## 5.2.18

- Fix void `a` SPF mechanism lookup output

## 5.12.17

- Fix crash on DNS retry

## 5.12.16

- Fix crash on DNS retry

## 5.12.15

- Fix bug in MX TLSA detection introduced in `5.12.13`

## 5.12.14

- Fix bug in MX DNSSEC detection introduced in `5.12.13`

## 5.12.13

- Add timeout retry options to the CLI and API (Closes #90 and #180)
- Rename caught exception value in SPF parsing parsing (PR #192 closes #191)

## 5.12.12

- Do not attempt to include an SMTP error code when none is provided (Close #189)

## 5.12.11

- Remove unneeded `finally` blocks in `smtp.py` that were causing warnings in Python 3.14 (Close #178)

## 5.12.10

- Always use the base domain when querying for the SOA record

## 5.12.9

- Fix bug in counting SPF DNS lookups involving the `a` mechanism

## 5.12.8

- Add support for the `lps` (Local-Part Selectors) BIMI assertion record tag

## 5.12.7

- Fix parsing of SPF exp mechanism

## 5.12.6

- More improvements to the SPF warning messages

## 5.12.5

- Update another SPF TXT length warning language to match the RFC

## 5.12.4

- Update the SPF TXT length warning language to match the RFC

## 5.12.3

- Standardize SPF error and warning messages

## 5.12.2

- Fix DNS lookup counts for redirects

## 5.12.1

- Fix crash when parsing SPF redirect

## 5.12.0

### ⚠️ Breaking Changes

#### 1. SPF Record Parsing Structure

- **Before**: The `parse_spf_record()` function returned a `parsed` dictionary with top-level keys like `"pass"`, `"neutral"`, `"softfail"`, `"fail"`, along with `"include"`, `"redirect"`, `"exp"`, and `"all"`.
- **After**: The `parsed` structure now contains a list of dictionaries under the `"mechanisms"` key. Each entry describes a mechanism (e.g., `mx`, `a`, `include`), and includes additional data such as DNS lookup counts and associated addresses. `"redirect"`, `"exp"`, and `"all"` remain unchanged.

   **Example:**

- Before:

     ```json
     "pass": [...]
     ```

- After:

     ```json
     "mechanisms": [
       {
         "mechanism": "mx",
         "value": "example.com",
         "dns_lookups": 3,
         "void_dns_lookups": 0,
         "action": "pass",
         "hosts": {
           "mx1.example.com": ["203.0.113.10"]
         }
       },
       {
         "mechanism": "a",
         "value": "example.com",
         "dns_lookups": 1,
         "void_dns_lookups": 0,
         "action", "pass",
         "addresses": [
          "23.192.228.80",
          "2600:1406:5e00:6::17ce:bc12"
        ]
       }
     ]
     ```

#### 2. DNS Lookup Counting Changes

- DNS lookup counts are now tracked per mechanism and globally. The total number of DNS lookups is counted and limited (including `mx` lookups).
- An exception is raised for DNS lookups if more than **9 MX records** are found (reduced from **10** in `5.11.0`), ensuring that the overall limit of 10 DNS queries per SPF evaluation is respected.

#### 3. DNS void fields

- The field for void DNS lookups in exceptions is now `void_dns_lookups`, as opposed to `dns_void_lookups` in the master branch. Code reading exception data should be updated to reflect this change.

   **Example:**

- Before:

     ```python
     e.data["dns_void_lookups"]
     ```

- After:

     ```python
     e.data["void_dns_lookups"]
     ```

#### 4. Redirect Handling

- The `redirect` mechanism now propagates the terminal policy (i.e., `all`) from the redirected SPF record. The effective `all` policy is now available directly under `parsed["all"]` after resolving redirects.

---

### 🛠️ Improvements

#### Enhanced Output Data for Mechanisms

- Each mechanism entry that uses DNS lookups now includes detailed information such as DNS lookup counts (`dns_lookups`), void DNS lookups (`void_dns_lookups`), and resolved addresses (`hosts` for `mx` mechanisms).

---

### 🧰 Migration Notes

#### 1. Handling SPF Parsing Results

- Update how you iterate over SPF record results. Previously, you could directly access the `"pass"`, `"neutral"`, etc., keys. In the new structure, you must filter the `"mechanisms"` list based on the `action` key.

**Before**:

 ```python
 for item in parsed["pass"]:
     ...
 ```

**After**:

 ```python
 for m in parsed["mechanisms"]:
     if m["action"] == "pass":
         ...
 ```

#### 2. Error Payload Field Updates

- Code that references `e.data["dns_void_lookups"]` must update to `e.data["void_dns_lookups"]`.

---

### 🚨 Potential Compatibility Breaks for Consumers

- If you are consuming SPF evaluation results in JSON format (via `--json` flag or other means), note that the structure of the output has changed. The old format with top-level `pass`, `fail`, and other categories has been replaced with a list of mechanisms.
- Consumers should update to handle the new format, which organizes data by individual mechanisms and includes detailed DNS lookup statistics.
  
---

### 🧑‍💻 For CLI Users

- **SPF Record Parsing**: The output format has changed. You will now see a list of mechanisms under `mechanisms`, each containing information like DNS lookups, void lookups, and resolved addresses.
- **Lookup Limits**: If your SPF record exceeds the DNS lookup limit (especially with MX records), you'll see an error message when more than **9 MX records** are found.
- **Warnings**: Expect warnings for oversized TXT records or overly large SPF records (exceeding RFC limits).

---

### ✨ Summary of Changes

- The **SPF parsing structure** has been overhauled for more detailed reporting.
- **DNS lookup counting** has been improved with more granular tracking of DNS queries per mechanism.
- **Exceptions** and error data formats have been streamlined.
- **Redirect handling** has been enhanced, making the terminal policy easier to trace after redirects.
  
This release introduces significant changes that improve the clarity, flexibility, and robustness of SPF record evaluation. Please ensure your codebase is compatible with these new structures and exception formats.

## 5.11.6

- Remove inaccurate warning about SMTP-STS policy line endings
- Clarify DMARC `none` policy warnings

## 5.11.5

- Allow for matching subdomain or base domain when validating VMCs

## 5.11.4

Fix bug where including a domain that did not would act as if the whole domain didn't exist

**Scope:** `checkdmarc/spf.py`

**Example:**: `npr.org` includes `c9eb27a2d7.berenice.eoidentity.com`

## 5.11.3

- Fix reading environment variables

## 5.11.2

- Add warnings if an SPF record is too long or too large (Close #70)

## 5.11.1

### 🧩 SPF Parser Fixes and Improvements

#### Fixed

- **SPF modifier parsing (`exp=`)** — corrected grammar and regex to accept the valid `exp=` syntax (previously `exp:` caused false-positive syntax errors for valid records such as `service.govdelivery.com`).
- **Incorrect `all:` allowance** — disallowed `all:` (colon form), which is invalid per RFC 7208.
- **Macro value parsing** — added `}` to the allowed character class so macros like `%{d2}` parse correctly.
- **Anchor handling after `all`** — fixed `AFTER_ALL_REGEX` to properly detect and trim trailing mechanisms after `all` (previously `^` inside a character class was treated as a literal).
- **Resolver handling for `exp`** — now threads `nameservers`, `resolver`, and `timeout` into `get_txt_records()` when resolving the `exp` modifier, ensuring consistent behavior with other lookups.
- **Error message typo** — corrected “ra tag value” → “rp tag value” in syntax-error messages.
- **Quoted TXT concatenation** — replaced overly aggressive quote/space stripping with a safer RFC-style join of split TXT strings (`re.sub(r'"\s+"', ' ', record)`).
- The `mx` mechanism properly counts the total DNS queries performed for A/AAAA resolution per RFC 7208 §4.6.4

#### Improved

- **Parsing robustness** — unified `SPF_MECHANISM_REGEX_STRING` and `_SPFGrammar` so both recognize the corrected `exp=` and reject invalid forms.
- **Void-lookup accounting** — improved consistency when counting void DNS lookups (e.g., `exp` now included).
- **Documentation and comments** — added inline explanations for grammar decisions and spec references for maintainability.

---

**Scope:** `checkdmarc/spf.py`
**Impact:** Fixes false positives in valid SPF records (e.g., `ssa.gov` / `service.govdelivery.com`) and improves spec compliance and resolver consistency.

## 5.11.0

Allow cache sizes amd timeouts to be controlled via environment variables.

All caches have the default length of `200000` and the the default max age of `1800` seconds. These defaults can be overridden using the environment variables `CACHE_MAX_LEN` and `CACHE_MAX_AGE_SECONDS` respectively.

Values for specific caches can be set using:

- `DNS_CACHE_MAX_LEN`
- `DNS_CACHE_MAX_AGE_SECONDS`
- `DNSSEC_CACHE_MAX_LEN`
- `DNSSEC_CACHE_MAX_AGE_SECONDS`
- `SMTP_CACHE_MAX_LEN`
- `SMTP_CACHE_MAX_AGE_SECONDS`

## 5.10.16

- Ensure `valid` is set to `False` if a mark validation certificate was not issues by a recognized Mark Verifying Authority (MVA)

## 5.10.15

- Rename `Validation_errors` key to `validation_errors` in BIMI results

## 5.10.14

- Include lookup counts under `include` SPF mechanisms that use SPF macros

## 5.10.13

- Fix macOS multiprocessing compatibility with timeout decorators (PR #186 closes #185)
- Updated dependencies to allow cryptography 46 to be used (PR #187)
- Make error messages consistent

## 5.10.12

- Proper checking for the start of an SPF record (PR #184)
- Improve error messages and fix typos (Close issue #182)
- Remove warning when no MX records are found

## 5.10.11

- Make BIMI error messages clearer

## 5.10.10

- Add missing periods at the end of BIMI error messages and warnings

## 5.10.9

- Add periods at the end of error messages to make them nicer for web apps

## 5.10.8

- Return the proper error message when checking an SOA record for a domain that exist

## 5.10.7

- Set `use_signals=False` when using timeout decorator to allow it to be used in multithreaded applications such as web applications

## 5.10.6

- Fix BIMI certificate validation error generation, close #177
- Add support for the avp bimi tag, closes  #179

## 5.10.5

- Switch from DNS over UDP to DNS over TCP for DNSSEC and TLSA queries (Close #176)

## 5.10.4

- Provide a clearer description of SPF void lookup warnings #173

## 5.10.3

- Fix: SPF includes are not displayed beyond the 10 lookup limit (#172)
- Add a warning when a size limit is added to a DMARC report destination

## 5.10.2

- Fix BIMI cert expiration time display

## 5.10.1

- Update the `cryptography` requirement to work with the BIMI module rewrite

## 5.10.0

- Migrate BIMI certificate checks from pyOpenSSL to pyca/cryptography (PR #175 closes issues #171 and #174
- Add SOA record parsing

## 5.9.5

- Better error message formatting for BIMI certificate domain mismatch errors

## 5.9.4

- Only parse the PSL once

## 5.9.3

- Clarify warnings for DMARC `p=none` and `sp=none`
- Use a different warning if DMARC `pct` is set to `0`
- Add `location` to the JSON output for BIMI

## 5.9.2

- Treat square aspect ratio as a recommendation rather than a requirement for BIMI SVG files (Close [#168](https://github.com/domainaware/checkdmarc/issues/168))

## 5.9.1

- Fix BIMI record parsing error introduced in `5.9.0`

## 5.9.0

Bug fixes:

- Remove zero-width characters from domain inputs (Close #157)
- Add a warning when the DMARC record `p` or `sp` value is `none` (Close #163)
- Evaluate DMARC when checking BIMI
- Do lot show a BIMI certificate warning when the `l` tag is set to `""`
- Include warnings if a domain is using BIMI, but does not have an enforced DMARC policy

New features:

Parsed SPF record details are now provided even if it uses too many DNS lookups

Having all of the details of a SPF record that is over the DNS lookup limit can help administrators see what portions of the SPF record are using the most lookups. The parsed record data can be found in the `parsed` key. In the event that a domain is over the lookup limit, `valid` will still be set to `false` and a helpful message describing the problem can be found in the `error` key. (Close #129)

API changes:

- Require keyword arguments to be passed as `keyword=value` pairs instead of positional arguments
- Add the option `ignore_too_many_lookups` to `checkdmarc.spf.parse_spf_record()`
  - This option will stop `checkdmarc.spf.parse_spf_record()` from rasing exceptions related to too many DNS lookups, in support of the new feature
  - `False` by default to maintain backwards compatibility
  - `checkdmarc.spf.check_spf()` uses this functionality to support the new feature

## 5.8.9

- Fix error message grammar

## 5.8.8

- Provide an easier to understand error message when a mark certificate is not is not issued by a recognized Mark Verifying Authority (MVA)
- Bug fix: failure to download a BIMI image is noted in the `certificate` section instead of the `image` section

## 5.8.7

- Fix downloading of mta-sts policies (PR #166 closes #165)
- Fix DMARC policy checks for parked domains/subdomains (PR #167)

## 5.8.6

- Ignore unhandled critical extensions for mark certificates (PR #162 closes issue #161)

## 5.8.5

- Remove Entrust VMC root
- Add GlobalSign VMC root

## 5.8.4

- Update JSON output for BIMI
  - Rename the `expires` field to `not_valid_after`
  - Add `not_valid_before` field
  - Add `expired` boolean field

## 5.8.3

- Use timeout values for HTTP client timeouts

## 5.8.2

- Add SSL.com root VMC CA certificates to `MVCCAs.pem`
- Replace deprecated `importlib.resources.path` call with `importlib.resources.file`
  - Use `importlib-resources` to support older versions of Python

## 5.8.1

- Fix incomplete fix for issue [#159](https://github.com/domainaware/checkdmarc/issues/159)

## 5.8.0

- Support `ra=`, `rp=` and `rr=` tags from [RFC 6652](https://www.rfc-editor.org/rfc/rfc6652) (PR [#158](https://github.com/domainaware/checkdmarc/pull/158))
- Do not use static answer positions when checking DNSSEC and TLSA (Fixes [#159](https://github.com/domainaware/checkdmarc/issues/159))

## 5.7.11

- Do not replace subdomains with base domains in SPF `a` mechanisms (Close [#151](https://github.com/domainaware/checkdmarc/issues/155))

## 5.7.10

- Raise a warning instead of a `UnicodeDecodeError` when encountering a `TXT` record that is not decodable (Close issue [#124](https://github.com/domainaware/checkdmarc/issues/124))
- Alow CIDR notation on SPF `a` mechanisms (Close [#128](https://github.com/domainaware/checkdmarc/issues/128))
- Fix documentation for `check_smtp_tls_reporting` (Close [#133](https://github.com/domainaware/checkdmarc/issues/133))
- Fix SVG verification checks for BIMI SVG files (Close [#150](https://github.com/domainaware/checkdmarc/issues/150))
- Allow BIMI Mark Verification Certificates to be used for subdomains (Close [#151](https://github.com/domainaware/checkdmarc/issues/151))
- Fix crash on CSV output for a domain with BIMI errors (Close issue [#153](https://github.com/domainaware/checkdmarc/issues/153))
- Fix generation of API documentation

## 5.7.9

- Add an error message to `["bimi"]["image]["error"]` instead of `["bimi"]["warnings"]` when a BIMI image download fails
- Add an error message to `["bimi"]["certificate]["error"]` instead of `["bimi"]["warnings"]` when a BIMI certificate download fails

## 5.7.8

- Move SVG validation errors from `["bimi"]["warnings"]` to `["bimi"]["image"]["validation_errors"]` (#150)

## 5.7.7

- Fix VMC validation errors not appearing (close #149)

## 5.7.6

- Fix crash when trying to output to CSV format

## 5.7.5

- Fix BIMI lookup for subdomains that do not have a BIMI record (fixes #148)

## 5.7.4

- Add additional checks for `tiny-ps` SVG requirements

## 5.7.3

- BIMI images and mark certificates
  - Better error handling
  - Simplified warning messages
  - `sha256_hash` output fields renamed to `sha256`

## 5.7.2

- Account for float SVG sizes

## 5.7.1

- Properly parse a certificate SAN
- Certificate warnings fire properly
- Make the `expires` timestamp more readable

## 5.7.0

`checkdmarc` will now validate Verified Mark Certificates (VMCs) and Common Mark Certificates (CMC),
snd will verify that SHA256 hash of the logo embedded in the certificate matches the SHA256 hash
logo at the URL at the BIMI `l` tag.

Additionally, SVG and certificate metadata is now included in the `checkdmarc.bimi.parse_bimi_record()` API and
JSON CLI output.

## 5.6.2

- Add a warning when BIMI records do not provide a mark certificate
- Ude the correct dependency (`xmltodict`, not `xml2dict`)

## 5.6.1

- Fix SVG base profile detection

## 5.6.0

- Automatically check for a BIMI DNS record at the `default` selector when using the CLI
- Fix parsing of BIMI record tags when they are separated by a `;` without a space
- Validate the file at the URL in the BIMI `l` tag value
  - Must be an SVG file
  - The SVG version must be `1.2`
  - The SVG base profile must be `tiny-ps`
  - The SVG dimensions must be square
  - The file size must not exceed 32 KB

**Note**: This does not currently include certificate validation.

## 5.5.1

- SPF record validation fixes (PR #147)
  - Accept mechanisms with domains that start with `all` (Fixes #145)
  - Ignore multiple trailing mechanisms and random text with spaces

## 5.5.0

- Support `redirect` in SPF (PR #144)

## 5.4.0

- Fix TLS/STARTTLS check (Fixes issue #138)
- Consider `tls: true` if `starttls: true`
- Handle records not existing if ignoring unrelated records (PR #131 fixes #130)
- Query the base domain if a DMARC record is not found at the subdomain (PR #132)
- Do not accept `include=` in the SPF record (PR #134 fixes issue #134)
- Fix DNSSEC cache (PR #136 Fixes issue #137)
- Fixed checking whether there is some text after `all` SPF directive (PR #139)

## 5.3.1

- Ignore `UnicodeDecodeError` exceptions when querying for `TXT` records (close #124)

## 5.3.0

- Check DNSSEC on MX hostnames
- USE DNSSEC when requesting `DNSKEY` records

## 5.2.7

- Do not require an `RRSIG` answer when querying for `DNSKEY` records
  - On Windows and macOS, querying for a `DNSKEY` record on `proton.ch` will return a `RRSET` and `RRSIG`. However,
    running the same query on Debian-based Linux will only return a `RRSET`
- Pass in `nameservers` and `timeout` when running `get_dnskey` recursively

## 5.2.6

- Revert change introduced in 5.2.4 that caused the DNSSEC test to always return `True`
- Test for multiple RDATA types when testing DNSSEC
- Properly cache DNSSEC test results

## 5.2.5

- Properly cache DNSKEY answers

## 5.2.4

- Workaround DNSSEC testing bug in Debian for some domains
  - On Windows, querying for a `DNSKEY` record on `proton.ch` will return a `RRSET` and `RRSIG`. However, running the same query on
    Linux will only return a `RRSET`, but will return a `RRSET` and `RRSIG` if another record type is requested, such
    as `A`

## 5.2.3

- Fix exception handling for `query_mta_sts_record`
- Fix exception handling for `query_smtp_tls_reporting_record`

## 5.2.2

- Better exception handling for `query_mta_sts_record`
- More verbose debug logging

## 5.2.1

- Fix bug where TLSA records would not be checked in some cases
- Improved debug logging

## 5.2.0

- Check for TLSA records

## 5.1.0

- Add support for parsing SMTP TLS Reporting ([RFC8460](https://www.rfc-editor.org/rfc/rfc8460.html)) DNS records

## 5.0.2

- Fix DNSSEC test
  - Add missing `import dns.dnssec`
  - Always use the actual subdomain or domain provided (close #114)

## 5.0.1

- Include MTA-STS and BIMI results in CSV output
- Renamed `include_dmarc_tag_descriptions` parameter in `checkdmarc.check_domains()` to `include_tag_descriptions`
- Added the `include_tag_descriptions` parameter to `checkdmarc.bimi.check_bimi()`
- Ignore encoding value when checking the `Content-Type` header during the MTA-STS policy download
- Added the exception class `MTASTSPolicyDownloadError`
- Update documentation

## 5.0.0

- Major refactoring: Change from a single module to a package of modules, with each checked standard as its own package
- Add support for MTA-STS [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461)
- Add support for [BIMI](https://www.ietf.org/archive/id/draft-brand-indicators-for-message-identification-04.html)
  - Specify a BIMI selector using the `--bimi-selector`/`-b` option
- Various bug fixes

## 4.8.5

- Fix SPF query error and warning messages
- More clear `fo` tag warning (PR #106)
- Do not raise a `DMARCRecordNotFound` exception when the `MultipleDMARCRecordsException` is raised (PR #108)
- Add support for null MX records - [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505.html) (PR #109)

## 4.8.4

- Make DMARC retorting URI error messages more clear (PR #104)

## 4.8.3

- Fix compatibility with Python 3.8

## 4.8.2

- `SPFRecordNotFound` exception now includes a `domain` argument (PR #103)
- The DMARC missing authorization error message now includes the full expected DNS record
- Lots of code cleanup
- Added missing docstrings

## 4.8.1

- `get_base_domain()` will return the input string instead of `None` if it can't parse a domain
- Always use the base domain when testing DNSSEC

## 4.8.0

- Fix DNSSEC test
- Do not treat `include` mechanisms with macros as domains (Close issue #81)
- Add `DMARCRecordStartsWithWhitespace` exception (PR #97)
- Properly parse DMARC and BIMI records for domains that do not have an identified base domain (PR #98)
- Add `ignore_unrelated_records` argument to `query_dmarc_record()` (Slight modification of PR #99 - Close issue #91)
- Mark syntax error positions (Slight modification of PR #100)

## 4.7.0

- Break up code into smaller methods (PR #93)

## 4.6.0

- Replace publicsuffix2 with publicsuffixlist (PR #92)

## 4.5.2

- Maintain the original character case of the DMARC record
- Always treat tag names as lowercase
- Always treat the DMARC `v` tag value as if it was uppercase
- Always treat the DMARC `p`, and `fo` tag values as if they were lowercase
- Always treat URI schemes as lowercase, but maintain the case of the address
- Remove inaccurate `testInvalidDMARCfo` test

## 4.5.1

- Ignore case and whitespace when parsing DMARC and BIMI key=value pairs (Closes [#75](https://github.com/domainaware/checkdmarc/issues/75))
- Handle missing `PTR` records more gracefully (Closes [#64](https://github.com/domainaware/checkdmarc/issues/64))
- Redundant DMARC `fo` tag values now result in a warning instead of a syntax error (Closes [#71](https://github.com/domainaware/checkdmarc/issues/71))

## 4.5.0

- Detect non-trivial loops (PR [#88](https://github.com/domainaware/checkdmarc/pull/88))
- Raise a `SPFSyntaxError` exception when an IP address and IP version do not match (PR [#87](https://github.com/domainaware/checkdmarc/pull/87))
- Fix raising the `DMARCRecordNotFound` exception when a DMARC record does not exist (PR [#86](https://github.com/domainaware/checkdmarc/pull/86) closes issue [#72](https://github.com/domainaware/checkdmarc/issues/72))
- Add void lookup limit (PR [#85](https://github.com/domainaware/checkdmarc/pull/85))
- Add Support for User Defined DNS Resolver Object (PR [#83](https://github.com/domainaware/checkdmarc/pull/83))

## 4.4.4

- Fix DNS caching (issue [#79](https://github.com/domainaware/checkdmarc/issues/79) PR [#80](https://github.com/domainaware/checkdmarc/pull/80))

## 4.4.3

- Fix tarball build (#78)

## 4.4.2

- Fix CSV output
- Always parse RUA and RUF fields, even if other parts of the record are invalid (PR #74)
- Convert documentation to markdown
- Migrate build from setuptools to hatch
- Migrate automated testing from Travis CI to GitHub Actions

## 4.4.1

- Pass in `nameserver` and `timeout` parameters when calling `get_reverse_dns()` (Actually close issue #59)

## 4.4.0

- Use the system's DNS resolvers by default
- Make DMARC report destination errors warnings instead of fatal errors (Closes issue #54)
- Honor nameserver and DNS timeout settings when querying for PTR records (Closes issue #59)
- Separate `TLS` and `STARTTLS` checks (Closes issue #56)
- Fix false positive SPF redirect loop error (Closes issue #55)
- Require the p tag to immediately follow the v tag (Closes issue #57)

## 4.3.1

- Loosen IP address checks (PR # 53)

## 4.3.0

- Include `nameservers` in call to `check_wildcard_dmarc_report_authorization` (PR #51)
- Fix `ipv4` validation and add `ipv6` validation (PR #52)
- Fix `User-Agent` string

## 4.2.4

- Fix `publicsuffix2` minimum version

## 4.2.3

- Fix Python 3.4 support

## 4.2.2

- Fix warning introduced in newer versions of `publicsuffix2` (closes issue #46)
- Set minimum dependency requirements (closes issue #47)

## 4.2.1

- Fix typo in Office 365 MX record verification warning

## 4.2.0

- Add test for DNSSEC (closes issue #44)
- Ignore SPF record content after the `all` mechanism (closes issue #45)
- Use UDP instead of TCP for DNS queries
- Reduce default DNS timeout from `6.0` seconds to `2.0` seconds
- Require `dnspython>=1.16.0`

## 4.1.10

- Make SPF mechanisms and modifiers case-insensitive, in compliance with
  RFC 7208, sections 4.6.1 and 12 (#42)
- Raise a warning instead of an error when an MX hostname does not exist
- Raise a specific warning when an Office 365 MX domain validation record is
  detected

## 4.1.9

- Fix typo in DMARC authorization record warning (#38)
- Add support for validating wildcard DMARC report authorization records
- Support reserved TLDs in `get_base_domain()` (#39)

## 4.1.8

- Still check STARTTLS when reverse DNS lookup fails
- Disable STARTTLS/TLS checks when running on Windows to avoid `timeout_decorator` [Windows incompatibility](https://github.com/pnpnpn/timeout-decorator/issues/1)

## 4.1.7

- Better DNS exception handling
- Show errors instead of warnings when checking NS and MX records for
  non-existent domains

## 4.1.6

- Fix TLS/STARTTLS failure output

## 4.1.5

- Add warning if MX hosts are missing A or AAAA records

## 4.1.4

- Timeout SMTP TLS check after 5 seconds

## 4.1.3

- Debug output fixes

## 4.1.2

- Fix `--skip-tls` option
- Replace `publicsuffix` with `publicsuffix2`

## 4.1.1

- Fix `tls` and `starttls` CSV fields

## 4.1.0

- Test for SSL/TLS over port 465 if `STARTTLS` is not supported
- Fix display of SSL/TLS errors

## 4.0.2

- Improve `STARTTLS` test

## 4.0.1

- Add option to CLI and API to skip STARTTLS testing
- Fix CSV output
- Fix debug logging
- Documentation fixes

## 4.0.0

- Refactor API and CLI

## 3.1.2

- Save `public_suffix_list.dat` to a temporary folder instead of the current
  working directory (CWD)
- Emulate a browser HTTP `User-Agent` string when downloading
`public_suffix_list.dat`
- Add requirement `requests`
- Change list separator within CSV fields from `,` to `|`

## 3.1.1

- Fix returning `STARTTLS` results upon exception

## 3.1.0

- Fix debug output
- Fix crash when checking domains with more than 10 MX records
- Cache `STARTTLS` failures
- Add warning for duplicate hostnames in MX records
- Increase cache sizes
- Disable check for SPF records on MX hostnames - too noisy

## 3.0.3

- Catch `BlockingIOError` exception when testing `STARTTLS`
- Add warning if PTR records for MX do not match the hostname's A/AAAA records

## 3.0.2

- Use output path file extension to set output format

## 3.0.1

- Use substrings for matching approved 'MX' and 'NS' records, rather than the
full string

## 3.0.0

- Add `get_nameservers()` to the API
- Add `NS` record lookup to output as `ns`
- Add `--ns` option to CLI for listing approved nameservers

## 2.9.2

- Fix `--mx` CLI option

## 2.9.1

- Bugfix: STARTTLS caching
- Add MX warnings for parked domains
- Increase default DNS timeout from 2.0 seconds to 6.0 seconds

## 2.9.0

- Bugfix: CSV format `-f csv` for starttls header
- Bugfix: Always properly close an SMTP connection
- Cache DNS and STARTTLS results in memory
- Use python3 in docs Makefile for Sphinx build
- Add `--debug` option
- Make warning about proper SPF records for MX hosts an only show with `--debug`
 (Very noisy - Many hosts use DKIM without SPF to DMARC align bouncebacks)

## 2.8.0

- Bugfix: Always raise warning when SPF type DNS records are found
- Add check for proper SPF records for MX hosts
- Add check for STARTTLS
- Add option `-p/--parked` to check for best practices for parked domains
- Add option `--mx` to provide a list of approved MX hostnames
- Add `query_bimi_record()` to the API

## 2.7.3

- Fix parsing of TXT records over multiple lines (PR #36)

## 2.7.2

- Fix false-negative SPF validation of `ipv4` mechanisms with a single digit
  CIDR notation (PR #35)

## 2.7.1

- Fix false-negative SPF and DMARC validations

## 2.7.0

- Fix report destination verification

## 2.6.3

- Reduce default DNS timeout to 2.0 seconds
- Always use `\n` as the newline when generating output

## 2.6.2

- Properly concatenate multi-line TXT records

## 2.6.1

- Fix exception generation

## 2.6.0

- Refactored  `DMARCError` and `SPFError` exceptions to support adding data to the results (seanthegeek)
- Close #18 - include `dns_lookups` in `spf`  results when number of SPF lookups are exceeded (seanthegeek)
- Added timeout rounding to the Exception classes (malvidin)
- Refactored  `DMARCError` and `SPFError` exceptions to support adding data to the results (seanthegeek)
- Close #18 - include `dns_lookups` in `spf`  results when number of SPF lookups are exceeded (seanthegeek)
- Added timeout rounding to the Exception classes (malvidin)

## 2.5.1

- PEP 8 fixes

## 2.5.0

- Close #32 - Raise `SPFSyntaxError` when an invalid value is encountered for an `ip4`SPF mechanism
- Close #33 - Add `python3 setup.py sdist` to `build.sh`, and publish source distribution to PyPI

## 2.4.0

- Close #31 - Public Suffix List checked before list is available (malvidin)
- Decrease precision of DNS timeout (malvidin)
- Close #15 - Add sorting of A/AAAA records (malvidin)
- Add basic logging of runtime warnings (seanthegeek)

## 2.3.0

- Use Cloudflare's DNS resolvers by default

## 2.2.0

- Fix DMARC record location when subdomain is missing record
- Fix typos

## 2.1.15

- prefix `.` to `public_suffix_list.dat`

## 2.1.14

- Fix typo in help

## 2.1.13

- Treat `pct` < 1 as invalid
- Issue warning if there are more than two URIs for `rua` or `ruf` (separate count)

## 2.1.12

- Allow whitespace in DMARC values

## 2.1.11

- Actually fix DMARC `rua` and `ruf` CSV output

## 2.1.10

- Fix DMARC `rua` and `ruf` CSV output

## 2.1.9

- More exception handling fixes

## 2.1.8

- Fix DNS report destination verification error message

## 2.1.7

- Yet more DNS error handling

## 2.1.6

- More DNS `SERVFAIL` handling
- More descriptive warning if DMARC `pct` < 100

## 2.1.5

- Handle DNS failures better

## 2.1.4

- Properly handle a useless DMARC record at the root of a domain

## 2.1.3

- Use correct example output in documentation
  - Replace `accenture.com` output from debugging with `fbi.gov` output
  - That's what I get for copy/pasting without reading :(

## 2.1.2

- Raise an error when multiple `spf1` `TXT` records are found

## 2.1.1

- Fix external DMARC report destination validation
- Update sample output in documentation

## 2.1.0

- Improve DMARC regex for edge cases
- Use Organizational Domain when checking DMARC URI destination
- Simplify exceptions
- Refactor dome method return values
- Add more unit tests
- Many documentation improvements and fixes
- PEP 8 compliant

## 2.0.0

- Check for misplaced DMARC records
- Update documentation
- Write unit tests and deploy CI (#12)

## 1.8.1

- Fix a bug that causes all DMARC lookups to fail
- First unit tests

## 1.8.0

- Fix SPF loop false-positives (#20)
- Use the base/organizational domain name when validating DMARC report destinations (#21)
- Add more granular exception classes in preparation for unit tests in 2.0.0

## 1.7.10

- Fix SPF regex regression

## 1.7.9

- Make DMARC `p` required, as specified in the RFC
- Improve SPF regex and syntax error details

## 1.7.8

- Update `mailto` regex to accept single char mailbox names
- Clarify DMARC tag and value descriptions
- Pass in nameservers and timeout when querying for `MX` records

## 1.7.7

- Fix sample command in documentation

## 1.7.6

- Raise an error instead of a warning when DMARC reporting URIs cannot receive reports about a domain

## 1.7.5

- Fix JSON output structure or included/redirected SPF records

## 1.7.4

- Fix typo in error message

## 1.7.3

- Detect Requests for `_dmarc` records that actually return SPF records
- Correct documentation for `get_mx_hosts(domain, nameservers=None, timeout=6.0)`

## 1.7.2

- Update output sample in documentation

## 1.7.1

- Change in JSON structure - Separate DMARC URI scheme and address to better support potential future URI schemes

## 1.7.0

- Change in JSON structure - Parse `mailto:` DMARC URIs, including size limits (if any)
- More granular Exception classes
- Updated documentation

## 1.6.1

- Refactor and simplify DNS queries

## 1.6.0

- Properly look for DMARC records in base/organizational domains
- Properly count DNS lookups for SPF
- Update sample output in the documentation

## 1.5.4

- Remove faulty `ruf` tag warning

## 1.5.3

- Fix another show-stopping bug :(

## 1.5.1

- Fix show-stopping bug

## 1.5.0

- Turn `rua` and `ruf` tag values in to lists
- Fix conversion of lists to strings in CSVs
- Raise `DMARCWarning` if the value of the `pct` tag is  less than 100
- Raise `DMARCError` if the value of the `pct` tag is less than 0 or greater than 100

## 1.4.0

- Proper parsing of DMARC tags `fo` and `rf`

## 1.3.8

- Improve regex for the DMARC `mailto:` URI
- `__version__` only needs to be updated in one place now
- Fix docstring formatting

## 1.3.7

- Properly handle DMARC records that are made up of multiple strings

## 1.3.6

- Allow input file to be a CSV where the domain is the first field; all other fields are ignored
- Better handling of invalid DMARC values

## 1.3.5

- Rearrange the order of the CSV fields to that the longest entries are to the right
- Documentation improvements
- Fix external DMARC report destination validation
- Count each MX resource record once

## 1.3.3 and 1.3.4

- Clarify warning messages

## 1.3.2

- Pass timeout in for SPF queries when outputting in CSV format
- Raise default timeout to 6 seconds

## 1.3.1

- Only include hostname in mx SPF mechanism results

## 1.3.0

- Show MX preference in output
- Sort MX records by preference
- Mark package as supporting Python 3 only (Python 2 was never actually supported because Pyleri does not support it)
- Removed all previous versions from PyPI so someone doesn't think Python 2 was supported when it never was

## 1.2.1

- Change default timeout to 4 seconds
- Use ; to delimit warnings and MX records in CSV format

## 1.2.0

- Add MX warnings to output

## 1.1.1

- Fix DMARC warning CSV output

## 1.1.0

- Separate SPF MX record limit from SPF DNS mechanism limit
- Fix DMARC CSV output

## 1.0.12

- Fix more SPF exceptions

## 1.0.11

- Fix SPF exceptions

## 1.0.10

- Fix DMARC record discovery
- Rename mx domain key to hostname
- Add example output to README

## 1.0.9

- Fix PyPI readme display

## 1.0.8

- Fix typos
- Add MX records to output

## 1.0.7

- Fix `--timeout/-t` option
- Add `--wait/-w` option

## 1.0.6

- Make SPF loops errors instead of warnings
- Check SPF records for `redirect` loops

## 1.0.5

- Ignore blank lines/domains in input

## 1.0.4

- Include the DMARC organizational domain in JSON and CSV output
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

## 1.0.3

- Removed from PyPI due to bugs
- Subdomains inherit the DMARC record of the organizational domain

## 1.0.2

- Removed from PyPI due to bugs
- Validate existence of MX amd A/AAAA records
- Add a `--timeout/-t` option
- Improve DMARC record syntax validation
- Check for SPF include loops
- Validate `rua` and `ruf` URIs
- Fail SPF validation if query limit reached [RFC 7208, Section 1.6.4][1]

## 1.0.1

- First release on PyPi (since removed due to bugs)

## 1.0.0

- Initial commit to GitHub

[1]: https://tools.ietf.org/html/rfc7208#section-1.6.4
[2]: https://mxtoolbox.com/spf.aspx
[3]: https://app.dmarcanalyzer.com/dns/spf
