from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from typing import AsyncIterator

import httpx
from rich.markup import escape

from .base import Finding, ReconModule

_UA = {"User-Agent": "Mozilla/5.0 (compatible; Meridian OSINT)"}

_PROVIDERS = ["gmail.com", "outlook.com", "yahoo.com", "protonmail.com", "icloud.com"]


# ── Username variant generator ────────────────────────────────────────────────

def _username_variants(first: str, last: str) -> list[str]:
    f, l = first.lower(), last.lower()
    fi = f[0] if f else ""
    li = l[0] if l else ""
    variants: list[str] = []
    seen: set[str] = set()

    candidates = [
        f"{f}{l}",
        f"{f}.{l}",
        f"{f}_{l}",
        f"{fi}{l}",
        f"{fi}.{l}",
        f"{fi}_{l}",
        f"{f}{li}",
        f"{l}{f}",
        f"{l}.{f}",
        f"{f}",
        f"{l}",
        f"{f}{l[:3]}",
    ]
    for c in candidates:
        if c and c not in seen:
            seen.add(c)
            variants.append(c)
    return variants


# ── Platform checkers (no API key needed) ────────────────────────────────────

@dataclass
class _Hit:
    platform: str
    username: str
    url: str
    detail: str = ""


async def _check_reddit(username: str, client: httpx.AsyncClient) -> _Hit | None:
    try:
        r = await client.get(
            f"https://www.reddit.com/user/{username}/about.json",
            headers=_UA,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            karma = data.get("total_karma", 0)
            return _Hit("Reddit", username, f"https://reddit.com/u/{username}", f"karma {karma:,}")
    except Exception:
        pass
    return None


async def _check_keybase(username: str, client: httpx.AsyncClient) -> _Hit | None:
    try:
        r = await client.get(
            f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={username}",
        )
        if r.status_code == 200:
            them = (r.json().get("them") or [None])[0]
            if them:
                full = them.get("profile", {}).get("full_name", "")
                detail = escape(full) if full else ""
                return _Hit("Keybase", username, f"https://keybase.io/{username}", detail)
    except Exception:
        pass
    return None


async def _check_hackernews(username: str, client: httpx.AsyncClient) -> _Hit | None:
    try:
        r = await client.get(
            f"https://hacker-news.firebaseio.com/v0/user/{username}.json",
        )
        if r.status_code == 200 and r.text.strip() not in ("null", ""):
            data = r.json() or {}
            karma = data.get("karma", 0)
            return _Hit("HackerNews", username, f"https://news.ycombinator.com/user?id={username}", f"karma {karma:,}")
    except Exception:
        pass
    return None


async def _check_devto(username: str, client: httpx.AsyncClient) -> _Hit | None:
    try:
        r = await client.get(
            f"https://dev.to/api/users/by_username?url={username}",
            headers=_UA,
        )
        if r.status_code == 200:
            data = r.json()
            name = escape(data.get("name", ""))
            detail = name if name else ""
            return _Hit("DEV.to", username, f"https://dev.to/{username}", detail)
    except Exception:
        pass
    return None


async def _check_dockerhub(username: str, client: httpx.AsyncClient) -> _Hit | None:
    try:
        r = await client.get(
            f"https://hub.docker.com/v2/users/{username}/",
            headers=_UA,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("username"):
                full = escape(data.get("full_name", ""))
                return _Hit("Docker Hub", username, f"https://hub.docker.com/u/{username}", full)
    except Exception:
        pass
    return None


async def _check_npm(username: str, client: httpx.AsyncClient) -> _Hit | None:
    try:
        r = await client.get(
            f"https://registry.npmjs.org/-/user/org.couchdb.user:{username}",
            headers=_UA,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("name") or data.get("_id"):
                return _Hit("npm", username, f"https://www.npmjs.com/~{username}", "")
    except Exception:
        pass
    return None


async def _check_gravatar(email: str, client: httpx.AsyncClient) -> _Hit | None:
    try:
        md5 = hashlib.md5(email.strip().lower().encode()).hexdigest()
        r = await client.get(
            f"https://www.gravatar.com/avatar/{md5}?d=404",
            headers=_UA,
        )
        if r.status_code == 200:
            return _Hit("Gravatar", email, f"https://gravatar.com/{md5}", "avatar found")
    except Exception:
        pass
    return None


_PLATFORM_CHECKS = [
    _check_reddit,
    _check_keybase,
    _check_hackernews,
    _check_devto,
    _check_dockerhub,
    _check_npm,
]


# ── Module ────────────────────────────────────────────────────────────────────

class PersonModule(ReconModule):
    """OSINT gathering for a named individual. no API keys required for core checks."""

    name = "Person Intel"
    panel_id = "person"

    async def run(self, target: str) -> AsyncIterator[Finding]:  # type: ignore[override]
        parts = target.strip().split()
        first = parts[0] if parts else target
        last  = parts[-1] if len(parts) > 1 else ""
        fl, ll = first.lower(), last.lower()

        yield Finding("person", f"[bold]Person:[/bold] {escape(target)}", progress=True)
        yield Finding("person", "")

        # Platform presence checks
        async for f in self._platform_scan(fl, ll):
            yield f

        # Email permutations with real providers
        if fl and ll:
            async for f in self._email_perms(fl, ll):
                yield f

        # OSINT dorks
        async for f in self._dorks(target):
            yield f

        # GitHub (optional — uses key if available)
        async for f in self._github_users(target):
            yield f

        # Dehashed (optional — uses key if available)
        async for f in self._dehashed(target):
            yield f

        # GitHub code search (optional — uses key if available)
        async for f in self._github_code(target):
            yield f

    # ── Platform presence scan ────────────────────────────────────────────────

    async def _platform_scan(self, first: str, last: str) -> AsyncIterator[Finding]:
        yield Finding("person", "[bold cyan]── Platform Presence ──[/bold cyan]")

        variants = _username_variants(first, last)[:6]

        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            # Run all (username × platform) checks concurrently
            tasks = [
                check(uname, client)
                for uname in variants
                for check in _PLATFORM_CHECKS
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        hits: list[_Hit] = [r for r in results if isinstance(r, _Hit)]

        if hits:
            # Group by platform for clean output
            by_platform: dict[str, list[_Hit]] = {}
            for h in hits:
                by_platform.setdefault(h.platform, []).append(h)

            for _, platform_hits in sorted(by_platform.items()):
                for h in platform_hits:
                    detail = f"  [dim]{h.detail}[/dim]" if h.detail else ""
                    yield Finding(
                        "person",
                        f"  [green]✓[/green] [bold]{escape(h.platform)}[/bold]"
                        f"  [cyan]{escape(h.username)}[/cyan]"
                        f"  [dim]{escape(h.url)}[/dim]{detail}",
                    )
        else:
            yield Finding("person", "  [dim]No matching accounts found[/dim]")

        # Gravatar check on most likely email
        if first and last:
            async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
                for provider in ("gmail.com", "outlook.com"):
                    email = f"{first}.{last}@{provider}"
                    hit = await _check_gravatar(email, client)
                    if hit:
                        yield Finding(
                            "person",
                            f"  [green]✓[/green] [bold]Gravatar[/bold]"
                            f"  [dim]{escape(email)}[/dim]  [dim]{escape(hit.url)}[/dim]",
                        )
                        break

        yield Finding("person", "")

    # ── Email permutations with real providers ────────────────────────────────

    async def _email_perms(self, first: str, last: str) -> AsyncIterator[Finding]:
        yield Finding("person", "[bold cyan]── Email Permutations ──[/bold cyan]")
        patterns = [
            f"{first}.{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{first}_{last}",
            f"{last}.{first}",
            f"{first}",
        ]
        for pattern in patterns:
            row = "  " + "  ".join(
                f"[yellow]{escape(pattern)}@{p}[/yellow]" for p in _PROVIDERS[:3]
            )
            yield Finding("person", row)
        yield Finding("person", "")

    # ── OSINT dork strings ────────────────────────────────────────────────────

    async def _dorks(self, name: str) -> AsyncIterator[Finding]:
        yield Finding("person", "[bold cyan]── OSINT Dorks ──[/bold cyan]")
        yield Finding("person", "[dim]  (copy into Google / Bing)[/dim]")
        dorks = [
            f'"{name}" site:linkedin.com/in',
            f'"{name}" site:twitter.com',
            f'"{name}" site:facebook.com',
            f'"{name}" filetype:pdf resume OR CV',
            f'"{name}" email contact',
            f'"{name}" "@gmail.com" OR "@outlook.com" OR "@yahoo.com"',
            f'"{name}" password OR credentials site:github.com',
            f'"{name}" site:pastebin.com OR site:paste.ee',
        ]
        for d in dorks:
            yield Finding("person", f"  [dim]$[/dim] {escape(d)}")
        yield Finding("person", "")

    # ── GitHub user search (optional key) ────────────────────────────────────

    async def _github_users(self, name: str) -> AsyncIterator[Finding]:
        token = self.get_key("github_token")
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            async with httpx.AsyncClient(timeout=10, headers=headers) as client:
                r = await client.get(
                    "https://api.github.com/search/users",
                    params={"q": name, "per_page": 5},
                )
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    if items:
                        yield Finding("person", "[bold cyan]── GitHub Profiles ──[/bold cyan]")
                        for u in items:
                            login = escape(u.get("login", ""))
                            url   = escape(u.get("html_url", ""))
                            score = u.get("score", 0)
                            yield Finding(
                                "person",
                                f"  [cyan]{login}[/cyan]  [dim]{url}[/dim]  [dim]score={score:.0f}[/dim]",
                            )
                        yield Finding("person", "")
        except Exception:
            pass

    # ── Dehashed by name (optional key) ──────────────────────────────────────

    async def _dehashed(self, name: str) -> AsyncIterator[Finding]:
        email = self.get_key("dehashed_email")
        key   = self.get_key("dehashed_api_key")
        if not (email and key):
            return

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    "https://api.dehashed.com/search",
                    params={"query": f'name:"{name}"', "size": 10},
                    auth=(email, key),
                    headers={"Accept": "application/json"},
                )
                if r.status_code == 200:
                    entries = r.json().get("entries") or []
                    if entries:
                        yield Finding("person", "[bold red]── Dehashed Leaks ──[/bold red]")
                        for e in entries[:8]:
                            em = escape(e.get("email", ""))
                            pw = escape(e.get("password", ""))
                            db = escape(e.get("database_name", ""))
                            row_parts: list[str] = []
                            if em:
                                row_parts.append(f"[yellow]{em}[/yellow]")
                            if pw:
                                row_parts.append(f"pass:[red]{pw}[/red]")
                            if db:
                                row_parts.append(f"[dim]{db}[/dim]")
                            yield Finding("person", "  " + "  ".join(row_parts))
                        yield Finding("person", "")
        except Exception:
            pass

    # ── GitHub code search (optional key) ────────────────────────────────────

    async def _github_code(self, name: str) -> AsyncIterator[Finding]:
        token = self.get_key("github_token")
        if not token:
            return

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
        }
        try:
            async with httpx.AsyncClient(timeout=10, headers=headers) as client:
                r = await client.get(
                    "https://api.github.com/search/code",
                    params={"q": f'"{name}"', "per_page": 5},
                )
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    if items:
                        yield Finding("person", "[bold cyan]── GitHub Code Mentions ──[/bold cyan]")
                        for item in items[:5]:
                            repo = escape(item.get("repository", {}).get("full_name", ""))
                            path = escape(item.get("path", ""))
                            url  = escape(item.get("html_url", ""))
                            yield Finding(
                                "person",
                                f"  [dim]{repo}[/dim]  {path}  [dim]{url}[/dim]",
                            )
                        yield Finding("person", "")
        except Exception:
            pass
