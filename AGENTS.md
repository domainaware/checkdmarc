# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## Project Overview

checkdmarc is a Python library and CLI tool for validating email security DNS records (SPF, DMARC, BIMI, MTA-STS, SMTP TLS Reporting, MX/STARTTLS, DNSSEC, SOA). Published on PyPI as `checkdmarc`.

## Common Commands

```bash
# Run tests with coverage
coverage run -m pytest tests/

# Lint and format
ruff check --show-fixes
ruff format .

# Build package
hatch build

# Build docs
cd docs && make html

# Full build (format + docs + package)
./build.sh
```

Tests use `unittest.TestCase` and are organized under `tests/` with one file per
module (e.g. `tests/test_spf.py`, `tests/test_dmarc.py`). Run a single test with:

```bash
python -m pytest tests/ -k "test_name"
```

Run tests for one module with e.g. `python -m pytest tests/test_spf.py`.

Some tests require network access and are skipped when `GITHUB_ACTIONS` env var is set.

## Architecture

**Entry point:** `checkdmarc/__init__.py` — `check_domains()` orchestrates all checks, returning `DomainCheckResult` TypedDict(s).

**Modules** (each has a primary `check_*()` function):

- `spf.py` — SPF record parsing, DNS lookup counting
- `dmarc.py` — DMARC/RFC 9989 record parsing with DNS tree walk algorithm
- `bimi.py` — BIMI record and certificate validation
- `mta_sts.py` — MTA-STS policy fetching and validation
- `smtp_tls_reporting.py` — TLSRPT record validation
- `smtp.py` — MX record lookup and STARTTLS testing
- `dnssec.py` — DNSSEC validation
- `soa.py` — SOA record parsing
- `utils.py` — DNS helpers, exception classes, domain normalization

**CLI:** `_cli.py` (entry point: `checkdmarc._cli:_main`)

**Constants/version:** `_constants.py`

**Output:** `results_to_json()`, `results_to_csv()`, `output_to_file()` in `__init__.py`.

## Key Dependencies

- `dnspython` for DNS queries
- `pyleri` for grammar parsing
- `publicsuffixlist` for base domain extraction
- `cryptography`/`pyopenssl`/`pem` for certificate handling
- `expiringdict` for DNS result caching

## Code Style

- Formatter/linter: **Ruff**
  - All code must be linted and formatted
- Type annotations use `TypedDict` for structured results
- Supports all currently supported Python versions
- Modern type annotations across the entire project
  - Always use the the latest version of pywright for static type checking
- Testing framework: **pytest**
- Every bit of code should have a test
- Build backend: **hatchling**

## Conventions

These rules apply to anyone — human or agent — making changes to this repo. They are intentionally checked in (rather than living in any one agent's private scratch memory) so that every collaborator picks them up the same way.

- **Wait for explicit commit AND push permission on the default branch — these are separate grants.** Finish the implementation, run the tests, summarize the diff, then **stop and ask**. The author decides when a change is ready to land; auto-committing makes review noisier and harder to reverse. "Commit this" mid-session counts as permission for that one commit, not a standing grant — and crucially, permission to commit is NOT permission to push. Pushing publishes the change to the remote where collaborators / CI / production deploys can pick it up, and is much harder to walk back than a local commit. Wait for an explicit "push it" before `git push`. If the prior commit was itself unauthorized, do NOT push it to "tidy up" — surface the situation and let the author decide whether to keep, amend, or reset.
- **Self-test before every `git commit`:** has the author typed "commit" (or an unambiguous equivalent — "ok to commit", "commit this", "commit and push") in a present-tense imperative since your last commit? If no, **ask**. Conditional phrasings like "if everything works we can push" or "we could commit this" or "if it looks good ..." are NOT authorizations — they are plans you must confirm before acting on. Treat the literal text of the user's last message as the source of truth, not your own interpretation of where the conversation is going.
  - **Self-test before every `git push`:** has the author typed "push" since your last push? Same rule. Permission to commit is NEVER permission to push.
  - **Exception — branches you created in-session** When you have explicitly created a feature branch yourself (e.g. `git checkout -b feat/something`) in that session, commit and push to THAT branch freely without per-step permission. The entire branch is reviewed at PR-open, so the per-commit gate adds review noise without adding safety. The exception is scoped to branches Claude created in the current session; it does NOT extend to `main`, to other long-lived branches, or to branches the author created.
- **Check for and resolve open security alerts and Dependabot PRs before creating a PR branch.** Before branching for a release or a substantive change, look at the repository's open Dependabot / security alerts (`gh api repos/domainaware/checkdmarc/dependabot/alerts`) AND any open Dependabot pull requests (`gh pr list --repo domainaware/checkdmarc --author 'app/dependabot'`), and fold the fixes into the same branch rather than leaving them to pile up against `main`. A Dependabot PR that's already green can simply be merged into the release branch instead of hand-applied; the point is that nothing security-relevant ships a release with the fix still sitting unmerged. Pin the minimum dependency version *above* the first patched version named in the advisory, and verify the new floor actually co-installs with its peers (e.g. `cryptography` and `pyopenssl` constrain each other release-to-release) by doing a clean resolve and running the full test suite against the resolved versions. This is a library, so update the version ranges in `pyproject.toml` and `requirements.txt` — do not add a lock file. Record the fix as a "Security" CHANGELOG entry citing the advisory (e.g. its GHSA id).
- **Back up the any database before any schema or migration change.** Before running any schema-changing SQL (ALTER TABLE, CREATE/DROP, hand-rolled column rewrites, anything that mutates table shape) against a database, back it up.
- **Project-specific rules belong in AGENTS.md, not in any agent's private memory store.** If you (Claude Code, Cursor, Codex, Aider, anything that has a "save this preference for next time" surface) catch yourself about to write down a rule that's actually about the codebase rather than about working with this particular user, write it here instead. Memory is fine for user-profile facts and tool-use preferences; project rules should be portable across agents.
- **Plain language over jargon.** Comments, docstrings, AGENTS.md, commit messages, PR descriptions, and user-facing docs should describe what the code does in words a non-specialist would understand. Avoid terminology imported from neighboring fields that only loosely applies — e.g., "projection" from relational algebra to describe "the subset of recap_document fields we keep in the local store", or "compaction" / "denormalization" / similar when a plain description works. When a domain term IS the right word (because the code really is implementing that concept, or the reader needs to look it up to understand a library), use it AND a brief in-place gloss the first time it appears. When a term is borrowed loosely, replace it with the literal description. The test is whether a contributor coming into the codebase from a different background would have to stop and search to understand what a term refers to here; when in doubt, prefer the plainer rewrite even if it's a few extra words.
- **Concise changelog entries that still carry accurate detail.** A `CHANGELOG.md` line should be skimmable: state what changed in one sentence and cite the single most relevant source directly (e.g. "valid per RFC 7208 section 7.3") rather than chaining several cross-references that read like a footnote. Don't drop the precision either — vague entries are as unhelpful as padded ones. Push fuller justification and nuance into the code comment, where someone editing that code will see it.
- **Fix underlying bugs, never just patch the data.** A manual SQL update or shell command that corrects ONE row of bad state a database doesn't help other users running the same code, doesn't help future data hitting the same bug, and doesn't survive a fresh checkout. Every observed bug must result in a code change that prevents the bad state from recurring, even when an immediate manual patch is also applied to unblock the operator. The manual patch is the bridge; the code fix is the destination — both happen, never just the bridge.
- **Verify library signatures against the installed version, not memory.** Before calling an unfamiliar function from a third-party library, read the source of the version that is actually installed in the project (the file in `site-packages` or equivalent). Training data and prior conversations are not authoritative — the installed code is.
- **Read official documentation in full before implementing against an unfamiliar API.** Fetch the relevant pages and read them end-to-end, not just the headings. When the docs offer both a quick-reference and a detail page on the same topic, read the detail page — quick-references omit aliases, edge cases, and secondary functions you will need.
- **SDK research order: installed source, then vendor docs, then GitHub issues.** When figuring out how a vendor SDK behaves, the installed SDK's source is the source of truth, vendor documentation is second, GitHub issues are third (for known bugs and undocumented behavior). Third-party blogs, Stack Overflow answers, and AI-generated explainers are not primary evidence — at best they are pointers to one of the three primary sources.
- **Don't catch `Exception` broadly.** Catch only the specific exception types you have a recovery path for. A bare `except Exception:` (or `except:`) hides programming errors that should be loud, makes debugging harder, and disguises broken assumptions as transient failures. Let unexpected exceptions propagate.
- **Honest test coverage.** The number on the badge is a means, not the goal — every test must earn its place by exercising real behavior. Concretely:
  - Tests must assert on observable behavior, not on whether a mock was called. A test that mocks every dependency and only asserts the mocks were invoked is testing the test, not the code. The mock is allowed to provide the *trigger* (a synthetic network failure, a forced exception type) as long as the assertion is on the function's contract — its return value, the warning it surfaces, the state it leaves behind.
  - No `# pragma: no cover` to dodge ugly branches. If a branch is unreachable, delete it. If it's reachable but hard to test, write the test.
  - No expanding the coverage `omit` list to chase a number. Legitimate reasons (e.g. maintainer scripts that ship outside the wheel) are fine; "hard to test" is not.
  - No trivial passthrough tests. Calling a getter and asserting it returns the value just set isn't a test.
  - If hitting a coverage target requires faking it, ship the honest lower number and flag the modules where the effort stopped. 85% honest beats 90% performative.
