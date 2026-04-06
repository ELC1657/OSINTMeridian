from __future__ import annotations

from collections import Counter
from typing import AsyncIterator
from urllib.parse import parse_qs, urlparse

import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize

# Parameter names associated with SSRF / open-redirect
_SSRF_PARAMS = {
    "url", "uri", "host", "redirect", "return", "next", "to", "from",
    "target", "path", "src", "dest", "destination", "file", "load",
    "fetch", "open", "callback", "goto", "window", "ref", "data",
    "continue", "forward", "location", "return_url", "returnurl",
    "returnto", "redirecturl", "redirect_uri", "redirect_url",
}

# Parameter names associated with injection (SQLi / XSS / LFI)
_INJECT_PARAMS = {
    "id", "uid", "user", "username", "item", "order", "orderby", "sort",
    "search", "q", "query", "page", "cat", "category", "pid", "product",
    "view", "type", "name", "value", "action", "cmd", "exec", "dir",
    "path", "file", "template", "theme", "lang", "language", "module",
}

# Path fragments worth flagging
_INTERESTING_PATHS: dict[str, list[str]] = {
    "Admin":    ["/admin", "/administrator", "/wp-admin", "/phpmyadmin", "/cpanel", "/panel"],
    "Debug":    ["/debug", "/_debug", "/actuator", "/trace", "/test", "/status", "/info"],
    "API":      ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc"],
    "Sensitive":[  "/.git/", "/.env", "/.aws/", "/backup", "/db/", "/.htaccess",
                   "/.htpasswd", "/config", "/credentials", "/passwd", "/.ssh/"],
    "Console":  ["/console", "/shell", "/terminal", "/jenkins/", "/jira/", "/confluence/"],
    "Upload":   ["/upload", "/uploads/", "/files/", "/static/", "/media/"],
}


class ParamsModule(ReconModule):
    name = "URL Params"
    panel_id = "params"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)
        urls = await self._fetch_urls(domain)

        if not urls:
            yield Finding("params", "[dim]No archived URLs found[/dim]")
            return

        yield Finding("params", f"[bold]{len(urls):,}[/bold] [dim]unique archived URLs analyzed[/dim]")

        param_counter: Counter[str] = Counter()
        ssrf_hits:   Counter[str] = Counter()
        inject_hits: Counter[str] = Counter()
        path_hits:   dict[str, set[str]] = {cat: set() for cat in _INTERESTING_PATHS}

        for url in urls:
            parsed = urlparse(url)
            path   = parsed.path.lower()
            params = parse_qs(parsed.query)

            # Count all params
            for p in params:
                p_lower = p.lower()
                param_counter[p_lower] += 1
                if p_lower in _SSRF_PARAMS:
                    ssrf_hits[p_lower] += 1
                if p_lower in _INJECT_PARAMS:
                    inject_hits[p_lower] += 1

            # Check interesting paths
            for cat, fragments in _INTERESTING_PATHS.items():
                for frag in fragments:
                    if frag in path:
                        path_hits[cat].add(parsed.path)

        # ── SSRF / Redirect ───────────────────────────────────────────────────
        if ssrf_hits:
            yield Finding("params", "")
            yield Finding("params", "[bold yellow]SSRF / Redirect candidates[/bold yellow]")
            for param, count in ssrf_hits.most_common():
                yield Finding("params", f"  [yellow]{escape(param)}=[/yellow]  [dim]{count} URL(s)[/dim]")

        # ── Injection candidates ──────────────────────────────────────────────
        if inject_hits:
            yield Finding("params", "")
            yield Finding("params", "[bold cyan]Injection candidates[/bold cyan]")
            for param, count in inject_hits.most_common(15):
                yield Finding("params", f"  [cyan]{escape(param)}=[/cyan]  [dim]{count} URL(s)[/dim]")

        # ── Interesting paths ─────────────────────────────────────────────────
        has_paths = any(v for v in path_hits.values())
        if has_paths:
            yield Finding("params", "")
            yield Finding("params", "[bold]Interesting paths[/bold]")
            for cat, paths in path_hits.items():
                if not paths:
                    continue
                color = "red" if cat == "Sensitive" else "yellow" if cat in ("Admin", "Console") else "cyan"
                yield Finding("params", f"  [{color}]{cat}[/{color}]  [dim]({len(paths)} unique)[/dim]")
                for p in sorted(paths)[:5]:
                    marker = " [red][!][/red]" if cat == "Sensitive" else ""
                    yield Finding("params", f"    [dim]{escape(p)}[/dim]{marker}")
                if len(paths) > 5:
                    yield Finding("params", f"    [dim]... {len(paths) - 5} more[/dim]")

        # ── All unique params ─────────────────────────────────────────────────
        if param_counter:
            yield Finding("params", "")
            yield Finding("params", f"[bold]All params[/bold]  [dim]({len(param_counter)} unique)[/dim]")
            for param, count in param_counter.most_common(20):
                yield Finding("params", f"  [dim]{escape(param)}= ({count})[/dim]")
            if len(param_counter) > 20:
                yield Finding("params", f"  [dim]... {len(param_counter) - 20} more[/dim]")

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _fetch_urls(self, domain: str) -> list[str]:
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                r = await client.get(
                    "http://web.archive.org/cdx/search/cdx",
                    params={
                        "url":      f"*.{domain}/*",
                        "output":   "json",
                        "fl":       "original",
                        "collapse": "urlkey",
                        "limit":    "8000",
                        "filter":   "statuscode:200",
                    },
                )
                if r.status_code != 200:
                    return []
                rows = r.json()
        except Exception:
            return []

        return [row[0] for row in rows[1:] if row]
