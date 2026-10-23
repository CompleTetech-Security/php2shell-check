<p align="center">
  <img src="docs/images/banner.png" alt="php2shell-check by CompleteTech LLC" width="100%">
</p>

<p align="center">
  <a href="https://github.com/CompleteTech-LLC/php2shell-check/actions/workflows/tests.yml"><img src="https://github.com/CompleteTech-LLC/php2shell-check/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <a href="https://github.com/CompleteTech-LLC/php2shell-check/releases"><img src="https://img.shields.io/github/v/release/CompleteTech-LLC/php2shell-check?color=1E3A8A" alt="Release"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-1E3A8A" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-none-067647" alt="No dependencies">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B" alt="AGPL-3.0 or commercial license"></a>
</p>

<p align="center">
  <b>Find websites that advertise a PHP version affected by PHP2Shell</b><br>
  CVE-2026-109618 · CVE-2026-109619 · passive, single-file, dependency-free
</p>

---

`php2shell-check` reads the PHP version a website already advertises in its public headers and compares it with the official upstream fix for each PHP branch. It sends **no exploit payloads**, respects `robots.txt`, and reports uncertainty honestly: a hidden or vendor-patched version is `unknown`, never "safe".

## Quick start

```sh
git clone https://github.com/CompleteTech-LLC/php2shell-check.git
cd php2shell-check

python wordpress_check.py example.com                                   # CSV to the terminal
python wordpress_check.py --input websites.txt --format html --output report.html
```

Python 3.10+ on Windows, macOS, or Linux. Nothing to install.

## The report

`--format html` produces a single offline file with your logo, summary tiles, and every result sorted by risk. It follows the reader's light or dark theme and prints cleanly.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png">
    <img src="docs/images/report-light.png" alt="Example PHP2Shell exposure report with the CompleteTech LLC logo" width="900">
  </picture>
</p>

<p align="center"><sub>Synthetic example built from reserved <code>example.*</code> domains. <a href="docs/example-report.html">View the HTML</a>.</sub></p>

Use `--logo path/to/logo.png` and `--brand "Your Company"` to brand it for your own organization. CSV and JSON remain available for spreadsheets and pipelines.

## What the results mean

| Status | Meaning |
| --- | --- |
| 🔴 `potentially_affected` | A plain PHP version below its branch's fix is advertised. Ask the administrator to verify. |
| 🟢 `fixed_version_reported` | The advertised version meets the fix. Not a verified clean bill of health. |
| ⚪ `unknown` | Version hidden, conflicting, pre-release, vendor-built, or outside 8.2–8.5. |

| PHP branch | 8.2 | 8.3 | 8.4 | 8.5 |
| --- | --- | --- | --- | --- |
| **Fixed in** | 8.2.35 | 8.3.36 | 8.4.27 | 8.5.12 |

Thresholds come from the PHP project's advisories for [CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp), checked on 2026-10-21. Distributions such as [Ubuntu](https://ubuntu.com/security/notices/USN-8948-1) backport fixes without changing the version number, so packaged builds are always `unknown`.

> [!IMPORTANT]
> **Potential exposure is not confirmed exploitability.** Headers cannot reveal the PHP SAPI, vendor backports, or real patch status. Treat every result as a prompt for an administrator to check.

## How it works

1. Reads `robots.txt` and stops if the page is disallowed.
2. Makes one ordinary `GET` request to the page, with verified TLS and an honest User-Agent.
3. Inspects the `X-Powered-By` and `Server` headers, plus WordPress markers in the HTML.
4. Fetches nothing else: no scripts, admin pages, uploads, or crafted requests.

Check only websites you are authorized to assess, and keep real target lists and results out of version control.

## Agent skill

The [php2shell-check skill](skills/php2shell-check/SKILL.md) guides an agent
through authorized passive checks, report creation, interpretation of uncertain
results, and preservation of interrupted runs. It uses the existing CLI and
contains no separate scanner or runtime dependencies.

Copy the entire `skills/php2shell-check/` directory into your agent's skill
directory, keeping `SKILL.md` and `agents/openai.yaml` together. For Codex, use
`$CODEX_HOME/skills/php2shell-check/` (normally
`~/.codex/skills/php2shell-check/`) for a personal installation, or
`.agents/skills/php2shell-check/` in the project where you want to use it.
Check for an existing installation before copying so local edits are preserved.
Reload the agent session if needed to discover the skill.

The skill can be installed independently, but running checks still requires
Python 3.10+ and a checkout of this repository or its `wordpress_check.py` file.
It explains how to locate or obtain the checker; do not assume it lives beside
the installed skill. Then ask, for example:

```text
Use $php2shell-check with my local checker checkout to assess the authorized
websites in /path/to/authorized-sites.txt. Save JSON to a new file outside the
repository, summarize the evidence and unknown results, and report the rule date.
```

For agents contributing to this repository, [AGENTS.md](AGENTS.md) contains the
shared development instructions; [CLAUDE.md](CLAUDE.md) points Claude to them.

## Documentation

- [Full reference](docs/REFERENCE.md): every CLI option, output field, and request rule
- [Assessment methodology](docs/PHP2SHELL.md): how each version is classified
- [WordPress free-scan integration](docs/WORDPRESS.md): signed requests, confirmation,
  private job queue, restricted worker, deployment and recovery. **Activation
  requires enforced network egress** (`egress_enforced`); the repository's
  Compose file does not provide it. It also requires an explicit `terms_policy`
  entry for the served terms version; without one the integration stays
  disabled (503) and in-flight jobs stall.
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md)

```sh
python -m unittest -v      # local-only tests; no external websites are contacted
```

## License

Dual licensed. It's free under [AGPL-3.0](LICENSE) for research, education, and open-source use. A [commercial license](LICENSING.md#commercial-license) is available for closed-source products and hosted services that don't publish their source. See [LICENSING.md](LICENSING.md) for details. Releases up to v1.0.0 remain MIT. The CompleteTech LLC name and logo are covered by neither license; see [BRAND_ASSETS.md](BRAND_ASSETS.md).

<p align="center">
  <a href="https://complete.tech"><img src="assets/logo.png" alt="CompleteTech LLC" width="160"></a><br>
  <sub>Built by <a href="https://complete.tech">CompleteTech LLC</a> · Innovation at Every Integration</sub>
</p>
