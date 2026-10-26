# PHP2Shell Check: full reference

[![Tests](https://github.com/CompleteTech-LLC/php2shell-check/actions/workflows/tests.yml/badge.svg)](https://github.com/CompleteTech-LLC/php2shell-check/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: AGPL-3.0 or commercial](https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-blue.svg)](../LICENSING.md)

A **single-file, dependency-free Python CLI** for passive PHP2Shell exposure
triage: **CVE-2026-109618 and CVE-2026-109619**. It compares publicly advertised
PHP versions with the official upstream fix thresholds and preserves the
existing WordPress detection and server-header diagnostics.

**Potential exposure is not confirmed exploitability.** The checker sends no
exploit payloads and cannot establish a server's SAPI, exact package build,
vendor backports, or actual patch status from headers alone.

## PHP2Shell results

Every website result includes `php2shell_status`:

| Value | Meaning |
| --- | --- |
| `potentially_affected` | A complete, unqualified PHP version is advertised below its branch's upstream fix. Administrator review is needed. |
| `fixed_version_reported` | The advertised version meets its branch's upstream fix threshold. This is not verified runtime or package state. |
| `unknown` | Version hidden, partial, conflicting, pre-release, vendor-qualified, or outside the covered branches. |

The version table was checked on **2026-10-21** against the two PHP project
advisories: [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp).

| Upstream branch | Fix for both CVEs |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

A bare `8.3.35` yields `potentially_affected`; `8.3.36` yields
`fixed_version_reported`. A package such as `8.3.6-0ubuntu0.24.04.13` yields
`unknown`: distributions can backport the fixes without adopting the new
upstream base version. See [Ubuntu's advisory](https://ubuntu.com/security/notices/USN-8948-1).

Older and future branches require vendor review. The rule snapshot is embedded
in the script; it is not updated from the internet automatically. See the
[assessment methodology](PHP2SHELL.md) for the complete interpretation.

## Features

- Check one website or a text file containing multiple domains/URLs.
- Assess both PHP2Shell CVEs using a dated, source-linked upstream version table.
- Detect WordPress generator metadata, REST API discovery links, and familiar
  WordPress asset paths.
- Record WordPress versions only when explicitly disclosed in generator metadata.
- Record PHP versions explicitly disclosed in `X-Powered-By` or `Server`,
  retaining qualifiers and detecting conflicting versions.
- Include the page title, final URL, HTTP status, `Server`, `X-Powered-By`,
  timestamp, evidence, and explanatory notes.
- Export CSV, JSON, or a branded HTML report; report progress separately on stderr.
- Respect supported robots.txt rules and pacing hints before requesting pages.
- Use verified TLS, a descriptive User-Agent, bounded redirects, and bounded
  response sizes. Stop on access restrictions instead of retrying them.

## Requirements and installation

Python **3.10 or newer**, on Windows, macOS, or Linux. No `pip install`, API key,
browser, database, or third-party Python package is required.

```sh
git clone https://github.com/CompleteTech-LLC/php2shell-check.git
cd php2shell-check
python wordpress_check.py --help
```

On systems where Python is named `python3`, substitute `python3` in these
commands. You can also copy just `wordpress_check.py` to another directory.
The script filename and default User-Agent are retained for compatibility.

## Quick start

Check a single website and print CSV to the terminal:

```sh
python wordpress_check.py https://example.com
```

Check multiple websites and save JSON:

```sh
python wordpress_check.py example.com https://example.org --format json --output results.json
```

Check a list and save CSV:

```sh
python wordpress_check.py --input websites.txt --output results.csv
```

Use a descriptive contact URL and a slower minimum request interval:

```sh
python wordpress_check.py --input websites.txt --output results.csv --delay 2 --timeout 15 --contact https://your-domain.example/contact
```

The included [websites.example.txt](../websites.example.txt) uses reserved example
domains. Replace them with websites you are permitted to check.

## Input format

Input files are UTF-8 text, with one domain or URL per line:

```text
# Company websites
example.com
https://example.org/

# You can check a specific page too
https://example.net/about/
```

Blank lines and lines beginning with `#` are ignored. UTF-8 BOMs are accepted.
Exact duplicate inputs are skipped. Positional URLs and `--input` can be combined.

Bare domains default to HTTPS. Explicit paths are checked as supplied. There is
no automatic fallback to HTTP after an HTTPS failure. URLs containing credentials
are rejected. Input is a text list, **not a CSV or an Excel workbook**.

## CLI options

| Argument | Default | Description |
| --- | --- | --- |
| `urls` | None | Zero or more HTTP(S) URLs or bare domains. |
| `--input PATH` | None | UTF-8 text file containing one website per line. |
| `--output PATH` | stdout | Atomically publish the final report; refuse an existing path by default. Keep a durable `PATH.partial.json` checkpoint. |
| `--force` | off | Explicitly replace an existing final output after successful rendering; never replace an existing checkpoint. |
| `--recover PATH` | none | Render a persisted checkpoint without targets, requests, or automatic retries. |
| `--format csv\|json\|html` | `csv` | Output format. `html` writes a self-contained, branded report. |
| `--logo PATH` | `assets/logo.png` | Logo inlined into the HTML report. A missing file is omitted. |
| `--brand NAME` | `CompleteTech LLC` | Organization name shown on the HTML report. |
| `--delay SECONDS` | `1` | Positive minimum time between requests to an origin. Robots rules may increase it. |
| `--timeout SECONDS` | `15` | Positive per-socket timeout, not a total deadline for a website. |
| `--target-timeout SECONDS` | `120` | Positive monotonic budget shared by all work for each target. |
| `--authorized-origin ORIGIN` | None | Additional authorized redirect origin; repeat for each approved scheme/host/port. No paths, queries or fragments. |
| `--contact VALUE` | Empty | Public contact URL/email included in the User-Agent. |
| `--help` | — | Show command help. |

The default User-Agent is `WordPressPublicChecker/1.0`. Requests are sequential.
The CLI does not offer an option to ignore robots.txt or disable TLS validation.

## Interpreting results

### Detection status

| `status` | Meaning |
| --- | --- |
| `wordpress` | The page advertises a WordPress generator or WordPress REST API discovery relation. |
| `likely_wordpress` | WordPress-style asset paths were found, without a stronger marker. |
| `no_evidence` | HTML was inspected successfully, but no supported markers were found. This does not prove WordPress is absent. |
| `uncertain` | The response could not be fully interpreted, for example because of content type, encoding, or truncation without a marker. |
| `blocked` | A robots rule, inaccessible robots policy, access restriction, excessive crawl delay, or disallowed redirect prevented inspection. |
| `error` | Invalid input, a network/TLS error, or another unsuccessful HTTP response. |

The checker deliberately does not produce a definitive "not WordPress" result.
Sites can remove identifying headers and markup. Conversely, static exports,
embedded assets, or stale/spoofed metadata can resemble WordPress.

### Fetch status

`fetch_status` is a coarse field for downstream processing:

- `ok`: the final page returned HTTP 2xx, even if its content was inconclusive.
- `timeout`: a recognized socket timeout occurred.
- `deadline_exceeded`: the target's total budget was exhausted; assessment remains unknown and the next input can proceed.
- `dns_error`: a recognized DNS-resolution error occurred.
- `out_of_scope`: a page or robots redirect was stopped before requesting an unauthorized origin; assessment remains unknown.
- `blocked`: other cases preventing a successful fetch, including robots rules,
  HTTP errors, invalid input, and TLS errors.

Read `status`, `http_status`, and `notes` for the precise reason. Do not interpret
the coarse `blocked` value as proof that the owner deliberately blocked you.

### Output fields

| Field | Meaning |
| --- | --- |
| `input_url` | The supplied domain or URL. |
| `final_url` | The final or last attempted page URL. |
| `status` | Detection outcome described above. |
| `fetch_status` | Coarse fetch outcome described above. |
| `http_status` | Last page HTTP status, or null/blank if unavailable. |
| `wordpress_version` | Explicit WordPress generator version, or an empty string. Conflicting versions are left blank and noted. |
| `php_version` | Explicit `PHP/version` from `X-Powered-By` or `Server`; blank if missing or conflicting. |
| `server` | Public `Server` header. |
| `powered_by` | Public `X-Powered-By` header. |
| `title` | HTML page title, limited to 500 characters. |
| `evidence` | The WordPress markers actually observed. |
| `asset_version_hints` | Asset `?ver=` values; these are **not confirmed WordPress versions**. |
| `notes` | Restrictions, uncertainty, truncation, or error details. |
| `checked_at` | Check start time in UTC ISO 8601 format. |
| `php_version_candidates` | All distinct PHP versions found in the inspected headers. |
| `php_evidence` | The public headers providing PHP-related indicators. |
| `php2shell_status` | `potentially_affected`, `fixed_version_reported`, or `unknown`. |
| `php2shell_version_status` | Specific version interpretation; see the methodology. |
| `php2shell_fixed_version` | Upstream fix threshold for the reported branch, if covered. |
| `php2shell_exploitability` | Always `not_tested`; no remote-code-execution confirmation is attempted. |
| `php2shell_cves` | The two CVE identifiers covered by this assessment. |
| `php2shell_rules_as_of` | Date the embedded rule snapshot was checked. |
| `php2shell_sources` | Official PHP advisories and the vendor-backport reference. |
| `php2shell_notes` | Evidence limits and the reason for this interpretation. |
| `php2shell_recommendation` | Administrator review or patch-verification guidance. |

CLI JSON is now a run envelope: `complete`, `completed_targets`, `pending_targets`, `total_targets`, and `results`. Consumers of the previous top-level array must read `results`. The result dictionaries and their evidence arrays are unchanged. CSV appends `record_type` and these four run fields to the existing result columns; an empty report has a summary row. HTML labels run completeness and counts separately from assessment status.

JSON preserves arrays in the evidence, version-candidate, CVE, source, and note fields. CSV joins array values
with ` | ` and prefixes potentially dangerous spreadsheet-formula strings with
an apostrophe. Empty version strings mean "not disclosed", not version zero.

Version strings and headers are server/page disclosures, not independently
verified runtime versions. In particular, an asset's `ver` parameter can refer
to a theme, plugin, or cache key. A `Server` header naming a platform does not
prove which programming language runs behind it.

## What gets requested

1. Normalize and validate the supplied HTTP(S) URL.
2. Fetch the origin's `/robots.txt` and evaluate applicable rules.
3. If permitted, GET the supplied page, checking robots policy at redirect destinations.
4. Inspect response headers and HTML already returned. Linked scripts, images,
   stylesheets, and API endpoints are **not fetched**.

Robots rules support user-agent groups, `Allow`/`Disallow`, wildcards, end anchors,
and common `Crawl-delay`/`Request-rate` hints. A longer matching path wins, with
`Allow` breaking equal-length ties. Policies are cached per origin during a run.
This is a practical, conservative parser, not a claim of full RFC certification.

- A missing policy with HTTP 404/410 permits a page check. Other unsuccessful
  policy responses stop it. HTML masquerading as robots.txt also stops it.
- Each target authorizes its own scheme, hostname and effective port, with
  case-insensitive hostname and default-port normalization. The sole implicit
  cross-origin allowance is HTTP port 80 to HTTPS port 443 on the same hostname.
  A `www` hostname, different hostname, or other port needs explicit approval
  with repeatable `--authorized-origin https://approved.example:8443`.
  Other target entries and earlier checks do not grant redirect authorization.
- Page and robots redirect destinations are checked against this scope before
  any destination request, including its robots fetch. Same-origin robots
  redirects may change path; approved cross-origin robots redirects must retain
  `/robots.txt`. Robots permission never grants assessment authorization.
- Page redirects are limited to five hops. HTTPS-to-HTTP downgrades stop even
  when the HTTP origin was explicitly authorized. Destination robots rules,
  verified TLS and pacing remain enforced.
- HTTP 401/403/407/429/451 page responses stop without an automatic retry.
- Policies requiring more than 60 seconds between requests are recorded as
  blocked; the page is skipped rather than ignoring the delay.
- Each page read is limited to 2 MiB; robots.txt is limited to 512 KiB.
- Gzip/Brotli decoding is not implemented. The checker requests identity encoding
  and reports unsupported encodings as inconclusive or blocked.

## Limitations and responsible use

Use the checker only where the site's terms and your authorization permit
these public requests. Robots.txt expresses crawling preferences; a missing or
permissive file is not independent authorization.

This tool does not execute JavaScript, log in, send exploit probes, enumerate
plugins, probe PHP-info/readme/admin endpoints, or bypass access controls. Hidden
markers and bot challenges returning HTTP 200 can produce inconclusive results.

The program permits arbitrary HTTP(S) hosts, including local addresses. It is
intended as a local CLI/library. Do not expose it as an unauthenticated web
service accepting arbitrary URLs without adding appropriate network controls.

Requests can reach the named websites and configured system proxies. Results may
contain public URLs, titles, and headers. There is no built-in telemetry or
upload destination; avoid committing real target lists or scan results.

## Python use

### Total target deadline

The CLI defaults to `--target-timeout 120`. One monotonic budget covers robots,
redirects, required pacing, DNS, connection/TLS, response headers/body and local
assessment. The socket inactivity timeout is an additional bound, never a substitute
for the total budget. Each HTTP acquisition uses one disposable child process;
the parent keeps robots caches and request spacing. Expired acquisition is killed
and reaped before continuing. Windows, macOS and Linux use the same process boundary,
including for resolver calls that Python cannot cancel in a thread. No child is
left running intentionally. Process creation/OS scheduling and cancellation have
small overhead; reaping allows at most two further seconds, then aborts the batch
rather than launching another request if the OS cannot reap the worker.

Deadline exhaustion produces an error row with `fetch_status=deadline_exceeded`
and `php2shell_status=unknown`. Other targets get fresh budgets. A completed batch
can therefore contain incomplete assessments. There are no retries or authorization
exceptions. Required pacing that cannot fit in the remaining budget fails immediately.

Python callers opt into this same boundary with `Checker(target_timeout=120, ...)`.
The low-level `Checker` default remains `target_timeout=None` for integrations with
their own process supervisors; a direct unbounded `request()` is not a total-work
guarantee. Custom in-process opener changes are not transferred to bounded child
requests. The CLI's `--recover` stays offline and launches no HTTP worker.

```python
from dataclasses import asdict
from wordpress_check import Checker

checker = Checker(timeout=15, target_timeout=120, delay=1, contact="https://your-domain.example/contact")
result = checker.check("https://example.com/")
print(asdict(result))
```

Reuse a `Checker` instance to preserve policy caches and pacing across requests.
The instance is not designed for concurrent use. Python callers can change
`max_crawl_delay` (default 60 seconds); increasing it can mean long waits.
Pass `authorized_origins=["https://approved.example:8443"]` to explicitly allow
additional redirect origins. This applies to all checks on that instance; each
check otherwise starts with only its supplied origin and the narrow upgrade rule.
Do not use `request()` directly to bypass the policy checks in `check()`.

## File handling and exit codes

With `--output report.html`, the CLI first creates `report.html.partial.json` exclusively. Each completed result is committed to a private temporary file, flushed and fsynced, and atomically replaces that checkpoint before progress is printed. Checkpoints contain completed result dictionaries and explicit conservative incomplete/completed/pending counts, not pending target URLs. They contain assessment evidence and must be protected like the report. Never commit real checkpoints.

The final JSON, CSV or HTML is rendered completely and fsynced before publication in the destination directory. Default publication uses an atomic hard link and fails closed if hard links are unavailable or another writer creates the destination first. `--force` explicitly allows atomic replacement of the final file; failures before publication preserve its prior contents. Existing checkpoint names are always refused, even with `--force`; choose a fresh output name. Directories and symbolic-link output paths are refused.

A handled Ctrl-C returns `130`, retains the incomplete checkpoint, and does not publish a final file or replace a previous report. A forced process termination cannot execute cleanup, but previously checkpointed results remain reconstructable. Recovery performs no requests and never reruns completed targets:

```sh
python wordpress_check.py --recover report.html.partial.json --format html --output recovered.html
python wordpress_check.py --recover report.html.partial.json --format json --output recovered.json
```

Recovery returns `130` for an incomplete checkpoint, even if all targets were checkpointed before final publication. The conservative checkpoint is intentionally retained after success and is not final-output attestation. Keep the final report as the completion receipt. Runs accept at most 100,000 targets; split larger lists explicitly. Checkpoint publication refuses content beyond the 64 MiB recovery bound and preserves the previous checkpoint, with an error rather than an unrecoverable larger artifact. Recovery requires a regular non-symlink checkpoint, validates its structure/counts/result types and reads at most 64 MiB (100,000 result rows). Recovery retains integer HTTP statuses 100–999 (or null), matching the fetcher, including nonstandard responses; this does not turn a failed fetch into a successful assessment. Boolean, string, fractional and out-of-domain statuses remain invalid, and exploitability must remain `not_tested`. Keep both the original checkpoint and any reconstructed artifact; continuation requires a separately authorized new run of pending targets only. The tool never resumes automatically.

Without `--output`, results accumulate in memory and stdout receives one well-formed report on completion or a handled interrupt. Stdout/pipes do not provide durable recovery after forced termination; use `--output` when preserving evidence matters. Final output/partial names and report/input paths must differ.

Exit code `0` means the run completed, not that every website was reachable or patched. `130` means interruption or incomplete recovery; `2` means argument/input/recovery/publication error. Inspect operational and assessment status separately. Disk exhaustion or abrupt termination during a new checkpoint leaves the previous atomic checkpoint intact; the in-progress result may not have been committed. No file mechanism guarantees recovery from storage hardware failure.

## Tests and contributing

```sh
python -m unittest -v
```

Tests use fixtures, mocks, and an ephemeral local HTTP server. They do not scan
external websites. GitHub Actions tests Python 3.10 and 3.14 on Linux and Windows.
The PHP2Shell tests include every supported branch's release boundary, vendor
backports, pre-releases, hidden/conflicting versions, and proof that the
assessment does not add network requests.
See [CONTRIBUTING.md](../CONTRIBUTING.md) for the contribution workflow and
[SECURITY.md](../SECURITY.md) for reporting a security issue in this checker.

The WordPress REST marker follows WordPress's documented
[discovery mechanism](https://developer.wordpress.org/rest-api/using-the-rest-api/discovery/).

## License

Dual licensed under [AGPL-3.0](../LICENSE) or a commercial license; see [LICENSING.md](../LICENSING.md).
