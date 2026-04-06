from __future__ import annotations

import asyncio
import re
from typing import AsyncIterator

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize

# service_name -> (cname_regex, [body_strings that confirm the slot is unclaimed])
_FINGERPRINTS: dict[str, tuple[str, list[str]]] = {
    "GitHub Pages":  (
        r"github\.io$",
        ["there isn't a github pages site here", "for root urls"],
    ),
    "Heroku":  (
        r"herokuapp\.com$|herokussl\.com$",
        ["no such app", "herokucdn.com/error-pages/no-such-app"],
    ),
    "AWS S3":  (
        r"s3\.amazonaws\.com$|s3-website[^.]*\.amazonaws\.com$",
        ["nosuchbucket", "the specified bucket does not exist"],
    ),
    "Netlify":  (
        r"netlify\.(app|com)$",
        ["not found - request id", "page not found | netlify"],
    ),
    "Azure":  (
        r"azurewebsites\.net$|cloudapp\.net$|azureedge\.net$|trafficmanager\.net$",
        ["404 web site not found", "no web app was found for the hostname"],
    ),
    "Fastly":  (
        r"fastly\.net$",
        ["fastly error: unknown domain", "please check that this domain has been added"],
    ),
    "Shopify":  (
        r"myshopify\.com$",
        ["sorry, this shop is currently unavailable", "only available to the shop owner"],
    ),
    "Squarespace":  (
        r"squarespace\.com$",
        ["no such account", "squarespace.com/no-such-account"],
    ),
    "Ghost":  (
        r"ghost\.io$",
        ["the thing you were looking for is no longer here"],
    ),
    "Tumblr":  (
        r"tumblr\.com$",
        ["there's nothing here", "whatever you were looking for doesn't currently exist"],
    ),
    "Surge.sh":  (
        r"surge\.sh$",
        ["project not found"],
    ),
    "Freshdesk":  (
        r"freshdesk\.com$",
        ["there is no helpdesk here"],
    ),
    "Zendesk":  (
        r"zendesk\.com$",
        ["help center closed"],
    ),
    "Readme.io":  (
        r"readme\.io$|readmessl\.com$",
        ["project doesnt exist", "readme.io 404"],
    ),
    "UserVoice":  (
        r"uservoice\.com$",
        ["this uservoice subdomain is currently available"],
    ),
    "Strikingly":  (
        r"strikingly\.com$|strikinglydns\.com$",
        ["page not found"],
    ),
    "Cargo":  (
        r"cargocollective\.com$",
        ["if you're moving your domain away from cargo"],
    ),
    "Webflow":  (
        r"webflow\.io$|proxy\.webflow\.com$",
        ["the page you are looking for doesn't exist or has been moved"],
    ),
    "Pantheon":  (
        r"pantheonsite\.io$",
        ["the hostname is not configured on pantheon"],
    ),
    "WP Engine":  (
        r"wpengine\.com$",
        ["the site you were looking for couldn't be found"],
    ),
}

_CNAME_PATTERNS: dict[str, re.Pattern[str]] = {
    svc: re.compile(pat, re.IGNORECASE)
    for svc, (pat, _) in _FINGERPRINTS.items()
}

_CONCURRENCY = 15


class TakeoverModule(ReconModule):
    name = "Takeover"
    panel_id = "takeover"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)
        subdomains = await self._fetch_subdomains(domain)

        if not subdomains:
            yield Finding("takeover", "[dim]No subdomains found to check[/dim]")
            return

        yield Finding(
            "takeover",
            f"[dim]Checking [bold]{len(subdomains)}[/bold] subdomains...[/dim]",
        )

        sem = asyncio.Semaphore(_CONCURRENCY)

        async def check_one(sub: str) -> Finding | None:
            async with sem:
                return await self._check(sub)

        results = await asyncio.gather(*[check_one(s) for s in sorted(subdomains)])

        hits = [r for r in results if r is not None and "VULN" in r.line]
        infos = [r for r in results if r is not None and "VULN" not in r.line]

        for f in hits:
            yield f
        for f in infos:
            yield f

        if hits:
            yield Finding(
                "takeover",
                f"[bold red]{len(hits)} potential takeover(s) detected[/bold red]",
            )
        else:
            yield Finding(
                "takeover",
                "[green]No dangling CNAMEs found[/green]",
            )

    # -------------------------------------------------------------------------

    async def _fetch_subdomains(self, domain: str) -> set[str]:
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                r = await client.get(
                    "https://crt.sh/",
                    params={"q": f"%.{domain}", "output": "json"},
                    headers={"User-Agent": "Meridian"},
                    follow_redirects=True,
                )
                if r.status_code != 200:
                    return set()
                data = r.json()
        except Exception:
            return set()

        subs: set[str] = set()
        for entry in data:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name and name != domain and name.endswith(f".{domain}"):
                    subs.add(name)
        return subs

    async def _check(self, subdomain: str) -> Finding | None:
        cname = await self._resolve_cname(subdomain)
        if not cname:
            return None

        service = self._match_service(cname)
        if not service:
            return None

        _, fingerprints = _FINGERPRINTS[service]
        safe_sub = escape(subdomain)
        safe_cname = escape(cname)

        # First: does the CNAME target itself resolve?
        target_resolves = await self._resolves(cname)
        if not target_resolves:
            return Finding(
                "takeover",
                f"[bold red]VULN[/bold red] [yellow]{safe_sub}[/yellow]"
                f" -> [dim]{safe_cname}[/dim] [red][{service} - NXDOMAIN][/red]",
            )

        # Second: check HTTP body for "unclaimed slot" fingerprint
        vulnerable = await self._body_matches(subdomain, fingerprints)
        if vulnerable:
            return Finding(
                "takeover",
                f"[bold red]VULN[/bold red] [yellow]{safe_sub}[/yellow]"
                f" -> [dim]{safe_cname}[/dim] [red][{service}][/red]",
            )

        # CNAME exists and looks live - report for awareness
        return Finding(
            "takeover",
            f"[dim]CNAME [cyan]{safe_sub}[/cyan] -> {safe_cname} [{service}][/dim]",
        )

    async def _resolve_cname(self, subdomain: str) -> str | None:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            answers = await resolver.resolve(subdomain, "CNAME")
            return str(answers[0]).rstrip(".")
        except Exception:
            return None

    async def _resolves(self, hostname: str) -> bool:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            await resolver.resolve(hostname, "A")
            return True
        except dns.resolver.NXDOMAIN:
            return False
        except Exception:
            return True  # unknown - assume live, avoid false positives

    def _match_service(self, cname: str) -> str | None:
        for svc, pattern in _CNAME_PATTERNS.items():
            if pattern.search(cname):
                return svc
        return None

    async def _body_matches(self, subdomain: str, fingerprints: list[str]) -> bool:
        try:
            async with httpx.AsyncClient(timeout=7, follow_redirects=True) as client:
                r = await client.get(f"http://{subdomain}")
                body = r.text.lower()
                return any(fp.lower() in body for fp in fingerprints)
        except Exception:
            return False
