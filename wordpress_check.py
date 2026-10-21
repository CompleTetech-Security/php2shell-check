#!/usr/bin/env python3
"""Conservative, public-page WordPress detection. Python 3.10+."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import socket
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urljoin, urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


BOT = "WordPressPublicChecker"
REDIRECTS = {301, 302, 303, 307, 308}
MAX_BODY = 2 * 1024 * 1024
MAX_ROBOTS = 512 * 1024


class CheckStopped(Exception):
    """The checker cannot safely or usefully continue."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def robots_path(value: str) -> str:
    """Compare encoded reserved characters literally, decoding unreserved bytes."""
    value = quote(value, safe="/%!$&'()*+,-.:;=?@_~")
    def decode(match):
        char = chr(int(match.group(1), 16))
        return char if char.isascii() and (char.isalnum() or char in "-._~") else match.group(0).upper()
    return re.sub(r"%([0-9a-fA-F]{2})", decode, value)


class RobotsPolicy:
    """Parse user-agent groups, wildcard/anchor rules and common pacing hints."""

    def __init__(self, body: str, minimum_delay: float):
        groups = []
        agents, directives = [], []
        for line in body.lstrip("\ufeff").splitlines():
            line = line.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, value = (part.strip() for part in line.split(":", 1))
            key = key.lower()
            if key == "user-agent":
                if directives:
                    groups.append((agents, directives))
                    agents, directives = [], []
                agents.append(value.lower())
            elif agents:
                directives.append((key, value))
        if agents:
            groups.append((agents, directives))
        selected = []
        best = -1
        for agents, directives in groups:
            specificity = max((0 if a == "*" else len(a) for a in agents if a and (a == "*" or a in BOT.lower())), default=-1)
            if specificity < 0:
                continue
            if specificity > best:
                selected, best = [], specificity
            if specificity == best:
                selected.extend(directives)
        self.rules = []
        self.delay = minimum_delay
        for key, value in selected:
            if key in {"allow", "disallow"} and value:
                path = robots_path(value)
                anchored = path.endswith("$")
                if anchored:
                    path = path[:-1]
                pattern = "^" + ".*".join(re.escape(part) for part in path.split("*")) + ("$" if anchored else "")
                self.rules.append((re.compile(pattern), len(path.replace("*", "").encode("utf-8")), key == "allow"))
            elif key in {"crawl-delay", "request-rate"}:
                try:
                    if key == "crawl-delay":
                        delay = float(value)
                    else:
                        count, seconds = map(float, value.split("/"))
                        delay = seconds / count
                    if math.isfinite(delay) and delay >= 0:
                        self.delay = max(self.delay, delay)
                except (ValueError, ZeroDivisionError):
                    pass

    def can_fetch(self, url: str) -> bool:
        parts = urlsplit(url)
        path = robots_path(parts.path or "/")
        if parts.query:
            path += "?" + robots_path(parts.query)
        matches = [(size, allow) for regex, size, allow in self.rules if regex.search(path)]
        return max(matches)[1] if matches else True


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError("URL must not be empty or contain whitespace")
    if "://" not in value:
        value = "https://" + value
    parts = urlsplit(value)
    if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
        raise ValueError("Only HTTP(S) website URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise ValueError("URLs containing credentials are not supported")
    _ = parts.port  # Validate port before making a request.
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def origin(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: str
    truncated: bool


@dataclass
class Result:
    input_url: str
    final_url: str = ""
    status: str = "error"
    fetch_status: str = "blocked"
    http_status: int | None = None
    wordpress_version: str = ""
    php_version: str = ""
    server: str = ""
    powered_by: str = ""
    title: str = ""
    evidence: list[str] = field(default_factory=list)
    asset_version_hints: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.generators: list[str] = []
        self.assets: list[str] = []
        self.api_links: list[str] = []
        self.title_parts: list[str] = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "meta" and (a.get("name") or "").lower() == "generator":
            self.generators.append(a.get("content") or "")
        if tag == "link" and "https://api.w.org/" in (a.get("rel") or "").split():
            self.api_links.append(a.get("href") or "")
        if tag in {"script", "img", "source", "link"}:
            for key in ("src", "href"):
                if a.get(key):
                    self.assets.append(a[key])
        if tag == "title":
            self.in_title = True

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def inspect_page(response: Response, result: Result) -> None:
    result.http_status = response.status
    result.fetch_status = "ok" if 200 <= response.status < 300 else "blocked"
    result.server = response.headers.get("server", "")
    result.powered_by = response.headers.get("x-powered-by", "")
    php = re.search(r"\bPHP/([0-9]+(?:\.[0-9]+)*(?:[-+._a-zA-Z0-9]*)?)", result.powered_by, re.I)
    if php:
        result.php_version = php.group(1)
    if response.status in {401, 403, 407, 429, 451}:
        result.status = "blocked"
        result.notes.append(f"HTTP {response.status}; access restriction or rate limit. No retry.")
        return
    if not 200 <= response.status < 300:
        result.status = "error"
        result.notes.append(f"HTTP {response.status}; detection skipped.")
        return
    if response.headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
        result.status = "uncertain"
        result.notes.append("Server sent an unsupported content encoding despite requesting identity.")
        return
    content_type = response.headers.get("content-type", "").lower()
    if content_type and not any(t in content_type for t in ("text/html", "application/xhtml+xml")):
        result.status = "uncertain"
        result.notes.append(f"Expected HTML; received {content_type}.")
        return
    page = PageParser()
    page.feed(response.body)
    result.title = " ".join("".join(page.title_parts).split())[:500]
    versions = set()
    for generator in page.generators:
        match = re.match(r"^WordPress(?:\s+([0-9]+(?:\.[0-9]+)*(?:[-+._a-zA-Z0-9]*)?))?(?:\s|$)", generator, re.I)
        if match:
            result.evidence.append(f"HTML generator: {generator[:200]}")
            if match.group(1):
                versions.add(match.group(1))
    if len(versions) == 1:
        result.wordpress_version = next(iter(versions))
    elif versions:
        result.notes.append("Conflicting WordPress generator versions: " + ", ".join(sorted(versions)))
    if page.api_links or re.search(r'\brel\s*=\s*["\']?https://api\.w\.org/', response.headers.get("link", ""), re.I):
        result.evidence.append("WordPress REST API discovery relation (https://api.w.org/)")
    strong = bool(result.evidence)
    for asset in sorted(set(page.assets)):
        p = urlsplit(urljoin(result.final_url, asset))
        if re.search(r"/(?:wp-content|wp-includes)/", p.path, re.I):
            result.evidence.append(f"WordPress-style asset: {asset[:300]}")
            # An asset's ver parameter can be a plugin/theme version or cache key.
            for version in parse_qs(p.query).get("ver", []):
                result.asset_version_hints.append(f"{version[:80]} ({p.path[:200]})")
    result.status = "wordpress" if strong else "likely_wordpress" if result.evidence else "no_evidence"
    if response.truncated:
        result.notes.append("HTML inspection limited to the first 2 MiB.")
        if result.status == "no_evidence":
            result.status = "uncertain"
    if result.status == "no_evidence":
        result.notes.append("No public WordPress markers found; this does not establish that WordPress is absent.")
    if result.php_version or result.wordpress_version:
        result.notes.append("Versions are server/page disclosures, not independently verified runtime versions.")


class Checker:
    def __init__(self, *, timeout=15.0, delay=1.0, contact="", max_crawl_delay=60.0):
        self.timeout = timeout
        self.delay = delay
        self.max_crawl_delay = max_crawl_delay
        self.user_agent = f"{BOT}/1.0" + (f" (+{contact})" if contact else "")
        self.opener = build_opener(NoRedirect())
        self.last_request: dict[str, float] = {}
        self.robots: dict[str, tuple[RobotsPolicy | None, float, str]] = {}

    def request(self, url: str, limit: int, delay: float | None = None) -> Response:
        site = origin(url)
        wait = max(self.delay, delay or 0) - (time.monotonic() - self.last_request.get(site, -math.inf))
        if wait > 0:
            time.sleep(wait)
        self.last_request[site] = time.monotonic()
        req = Request(url, headers={"User-Agent": self.user_agent, "Accept": "text/html,text/plain;q=0.9,*/*;q=0.1", "Accept-Encoding": "identity"})
        try:
            stream = self.opener.open(req, timeout=self.timeout)
        except HTTPError as exc:
            stream = exc  # Preserve status/headers; never automatically retry.
        with stream:
            raw = stream.read(limit + 1)
            charset = stream.headers.get_content_charset() or "utf-8"
            try:
                body = raw[:limit].decode(charset, errors="replace")
            except LookupError:
                body = raw[:limit].decode("utf-8", errors="replace")
            headers = {k.lower(): ", ".join(stream.headers.get_all(k)) for k in stream.headers.keys()}
            return Response(stream.code, headers, body, len(raw) > limit)

    def policy(self, url: str) -> float:
        site = origin(url)
        if site not in self.robots:
            robot_url = site + "/robots.txt"
            response = None
            seen = set()
            for _ in range(6):
                if robot_url in seen:
                    raise CheckStopped("robots.txt redirect loop; skipping site.")
                seen.add(robot_url)
                response = self.request(robot_url, MAX_ROBOTS)
                if response.status not in REDIRECTS:
                    break
                location = response.headers.get("location")
                if not location:
                    raise CheckStopped("robots.txt redirect without Location; skipping site.")
                target = normalize_url(urljoin(robot_url, location))
                if origin(target) != site:
                    initial = urlsplit(site)
                    redirected = urlsplit(target)
                    same_host = (initial.hostname or '').removeprefix('www.') == (redirected.hostname or '').removeprefix('www.')
                    same_port = initial.port == redirected.port
                    canonical = same_host and same_port and redirected.path == '/robots.txt'
                    no_downgrade = not (initial.scheme == 'https' and redirected.scheme == 'http')
                    if not (canonical and no_downgrade):
                        raise CheckStopped("robots.txt redirects to another origin; policy cannot be verified, skipping site.")
                robot_url = target
            assert response is not None
            if response.status in {404, 410}:
                self.robots[site] = (None, self.delay, "robots.txt not published")
            elif response.status == 200 and not response.truncated:
                if response.headers.get("content-encoding", "identity").lower() not in {"identity", ""}:
                    raise CheckStopped("Cannot decode robots.txt; skipping site.")
                if re.search(r"<(?:!doctype\s+html|html|head|body)\b", response.body, re.I):
                    raise CheckStopped("robots.txt returned HTML; policy cannot be verified, skipping site.")
                parser = RobotsPolicy(response.body, self.delay)
                self.robots[site] = (parser, parser.delay, "robots.txt checked")
            else:
                raise CheckStopped(f"Cannot verify robots.txt (HTTP {response.status}, truncated={response.truncated}); skipping site.")
        parser, delay, _ = self.robots[site]
        if parser is not None and not parser.can_fetch(url):
            raise CheckStopped("robots.txt disallows this URL for this checker.")
        if delay > self.max_crawl_delay:
            raise CheckStopped(f"robots.txt requires {delay:g}-second request spacing; exceeds the {self.max_crawl_delay:g}-second batch limit. Page not fetched.")
        return delay

    def check(self, value: str) -> Result:
        result = Result(input_url=value)
        try:
            url = normalize_url(value)
            seen = set()
            for _ in range(6):
                result.final_url = url
                if url in seen:
                    raise CheckStopped("Page redirect loop; stopped.")
                seen.add(url)
                delay = self.policy(url)
                response = self.request(url, MAX_BODY, delay)
                result.http_status = response.status
                if response.status not in REDIRECTS:
                    result.notes.append(self.robots[origin(url)][2])
                    inspect_page(response, result)
                    return result
                location = response.headers.get("location")
                if not location:
                    raise CheckStopped("Page redirect without Location; stopped.")
                target = normalize_url(urljoin(url, location))
                if urlsplit(url).scheme == "https" and urlsplit(target).scheme == "http":
                    raise CheckStopped("HTTPS-to-HTTP redirect; stopped.")
                url = target
            raise CheckStopped("Too many page redirects; stopped.")
        except CheckStopped as exc:
            result.status = "blocked"
            result.notes.append(str(exc))
        except (ValueError, URLError, OSError, HTTPException, UnicodeError) as exc:
            result.status = "error"
            cause = exc.reason if isinstance(exc, URLError) else exc
            if isinstance(cause, (TimeoutError, socket.timeout)):
                result.fetch_status = "timeout"
            elif isinstance(cause, socket.gaierror):
                result.fetch_status = "dns_error"
            result.notes.append(str(exc))
        return result


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return number


def csv_safe(value):
    if isinstance(value, list):
        value = " | ".join(value)
    # Prevent spreadsheet formulas from untrusted page titles / response fields.
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("urls", nargs="*", help="Website URLs or bare domains (defaults to HTTPS)")
    parser.add_argument("--input", type=Path, help="UTF-8 text file: one URL per line; # comments allowed")
    parser.add_argument("--output", type=Path, help="Save results here; otherwise write to stdout")
    parser.add_argument("--format", choices=("csv", "json"), default="csv")
    parser.add_argument("--delay", type=positive_float, default=1.0, help="Minimum seconds between requests to an origin (default: 1)")
    parser.add_argument("--timeout", type=positive_float, default=15.0, help="Socket timeout per request (default: 15 seconds)")
    parser.add_argument("--contact", default="", help="Public contact URL/email to include in the honest User-Agent")
    args = parser.parse_args(argv)
    if any(ord(c) < 32 or ord(c) == 127 for c in args.contact):
        parser.error("--contact must not contain control characters")
    urls = list(args.urls)
    if args.input:
        try:
            urls.extend(line.strip() for line in args.input.read_text(encoding="utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#"))
        except OSError as exc:
            parser.error(str(exc))
    urls = list(dict.fromkeys(urls))
    if not urls:
        parser.error("provide website URLs or --input websites.txt")
    if args.input and args.output and args.input.resolve() == args.output.resolve():
        parser.error("--output must differ from --input")
    checker = Checker(timeout=args.timeout, delay=args.delay, contact=args.contact)
    output = args.output.open("w", encoding="utf-8", newline="") if args.output else sys.stdout
    writer = csv.DictWriter(output, fieldnames=list(Result.__dataclass_fields__)) if args.format == "csv" else None
    try:
        if writer:
            writer.writeheader()
        else:
            output.write("[\n")
        for index, url in enumerate(urls):
            result = checker.check(url)
            print(f"[{index + 1}/{len(urls)}] {url}: {result.status}", file=sys.stderr)
            row = asdict(result)
            if writer:
                writer.writerow({key: csv_safe(value) for key, value in row.items()})
            else:
                if index:
                    output.write(",\n")
                output.write(json.dumps(row, ensure_ascii=False, indent=2))
            output.flush()
        if not writer:
            output.write("\n]\n")
    finally:
        if args.output:
            output.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
