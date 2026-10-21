# Contributing

Open an issue for bugs or focused improvements, then submit a pull request.
For a security issue in the checker, use the process in [SECURITY.md](SECURITY.md).

## Local development

Python 3.10+ is sufficient; there are no runtime or test dependencies.

```sh
python -m unittest -v
python wordpress_check.py --help
```

Keep the checker usable as one Python file. Changes must preserve its public-page
scope, TLS verification, robots checks, descriptive User-Agent, request limits,
and explicit uncertainty. Do not turn an absent marker or a version disclosure
into an unsupported vulnerability claim.

Add focused regression tests for behavior changes. Prefer local HTTP fixtures
and mocks; automated tests must not contact external websites. If a case depends
on a real response, reduce it to a small, synthetic fixture without personal
data, tokens, cookies, or private URLs.

Document changes to command arguments and output fields. Run the tests before
submitting a pull request. Never include real outreach lists, workbooks, scan
results, or credentials in a contribution.
