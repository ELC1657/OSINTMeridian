from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator
from urllib.parse import urlparse

import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize

# JS files from these domains are third-party libraries — skip them
_CDN_SKIP = {
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "ajax.googleapis.com",
    "code.jquery.com", "maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com",
    "unpkg.com", "fonts.googleapis.com", "www.googletagmanager.com",
    "connect.facebook.net", "platform.twitter.com", "d3js.org",
    "static.cloudflareinsights.com", "cdn.optimizely.com",
}

_MAX_FILES  = 20
_MAX_BYTES  = 400_000  # 400 KB per file

# (label, pattern)  — ordered most specific first
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Private Key",       re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    ("AWS Access Key",    re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub Token",      re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("Google API Key",    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe Live Key",   re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    ("Slack Token",       re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("SendGrid Key",      re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("JWT",               re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Internal URL",      re.compile(r"https?://(?:10\.\d+|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d+")),
    ("API Key",           re.compile(r'(?i)(?:api[_\-]?key|x-api-key)\s*[=:]\s*["\'][0-9A-Za-z_\-]{20,}["\']')),
    ("Hardcoded Secret",  re.compile(r'(?i)(?:client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*["\'][0-9A-Za-z_\-/+=]{16,}["\']')),
    ("Password",          re.compile(r'(?i)\bpassword\s*[=:]\s*["\'][^"\'\\]{8,}["\']')),
]

# Skip matches that look like placeholders
_FP_FRAGMENTS = ("placeholder", "your_", "change_me", "example", "xxxxxxx",
                 "todo", "test_key", "sample", "insert_", "enter_")


class JSScanModule(ReconModule):
    name = "JS Secrets"
    panel_id = "jsscan"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        js_urls = await self._fetch_js_urls(domain)
        if not js_urls:
            yield Finding("jsscan", "[dim]No archived JS files found[/dim]")
            return

        yield Finding("jsscan", f"[dim]Found {len(js_urls)} unique JS URLs — scanning {min(len(js_urls), _MAX_FILES)}[/dim]")

        sem = asyncio.Semaphore(5)
        seen_secrets: set[str] = set()

        async def scan_one(url: str) -> list[Finding]:
            async with sem:
                return await self._scan_file(url, seen_secrets)

        results = await asyncio.gather(*[scan_one(u) for u in js_urls[:_MAX_FILES]])

        hit_count = 0
        for findings in results:
            for f in findings:
                yield f
                if "FOUND" in f.line:
                    hit_count += 1

        yield Finding("jsscan", "")
        if hit_count:
            yield Finding("jsscan", f"[bold red]{hit_count} secret(s) found across JS files[/bold red]")
        else:
            yield Finding("jsscan", "[green]No secrets found in scanned JS files[/green]")

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _fetch_js_urls(self, domain: str) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(
                    "http://web.archive.org/cdx/search/cdx",
                    params={
                        "url":      f"*.{domain}/*.js",
                        "output":   "json",
                        "fl":       "original",
                        "collapse": "urlkey",
                        "limit":    "200",
                        "filter":   "statuscode:200",
                    },
                )
                if r.status_code != 200:
                    return []
                rows = r.json()
        except Exception:
            return []

        seen: set[str] = set()
        urls: list[str] = []
        for row in rows[1:]:  # skip header
            url = row[0]
            host = urlparse(url).netloc.lower()
            if any(cdn in host for cdn in _CDN_SKIP):
                continue
            # Only keep target's own JS
            if domain not in host:
                continue
            # Deduplicate by filename
            fname = urlparse(url).path.split("/")[-1]
            if fname not in seen:
                seen.add(fname)
                urls.append(url)

        return urls

    async def _scan_file(self, url: str, seen_secrets: set[str]) -> list[Finding]:
        try:
            async with httpx.AsyncClient(timeout=8) as client:
                r = await client.get(
                    f"https://web.archive.org/web/2024/{url}",
                    follow_redirects=True,
                    headers={"User-Agent": "Meridian"},
                )
                if r.status_code != 200:
                    return []
                content = r.text[:_MAX_BYTES]
        except Exception:
            return []

        findings: list[Finding] = []
        fname = escape(urlparse(url).path.split("/")[-1] or url[:60])
        file_hits: list[str] = []

        for label, pattern in _PATTERNS:
            for match in pattern.finditer(content):
                val = match.group(0)
                # Skip obvious placeholders
                if any(fp in val.lower() for fp in _FP_FRAGMENTS):
                    continue
                key = f"{label}:{val[:40]}"
                if key in seen_secrets:
                    continue
                seen_secrets.add(key)
                preview = escape(val[:60] + ("..." if len(val) > 60 else ""))
                file_hits.append(f"  [bold red]FOUND[/bold red] [yellow]{label}[/yellow]  [dim]{preview}[/dim]")

        if file_hits:
            size_kb = len(content) // 1024
            findings.append(Finding("jsscan", f"[cyan]{fname}[/cyan]  [dim]{size_kb}KB[/dim]"))
            for line in file_hits:
                findings.append(Finding("jsscan", line))

        return findings
