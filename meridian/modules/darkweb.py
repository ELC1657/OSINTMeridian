from __future__ import annotations

import asyncio
from typing import AsyncIterator

import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize

_INTELX_SEARCH  = "https://2.intelx.io/intelligent/search"
_INTELX_RESULT  = "https://2.intelx.io/intelligent/search/result"
_BREACHDIR_URL  = "https://breachdirectory.p.rapidapi.com/"
_DEHASHED_URL   = "https://api.dehashed.com/v2/search"

_INTELX_SYSTEMS: dict[int, str] = {
    0: "Pastes",
    1: "Dark Web",
    2: "Usenet",
    3: "Leaked",
    5: "Documents",
    7: "Social",
    8: "IRC",
    9: "Deep Web",
}


class DarkWebModule(ReconModule):
    name = "Dark Web"
    panel_id = "darkweb"
    requires_key = True
    key_env = "INTELX_API_KEY / RAPIDAPI_KEY / DEHASHED"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        intelx_key     = self.get_key("intelx_api_key")
        rapidapi_key   = self.get_key("rapidapi_key")
        dehashed_email = self.get_key("dehashed_email")
        dehashed_key   = self.get_key("dehashed_api_key")

        if not any([intelx_key, rapidapi_key, (dehashed_email and dehashed_key)]):
            yield Finding("darkweb", "[yellow]No API keys configured[/yellow]")
            yield Finding("darkweb", "")
            yield Finding("darkweb", "[dim]Keys that unlock this panel:[/dim]")
            yield Finding("darkweb", "[dim]  INTELX_API_KEY    — intelx.io  (free tier)[/dim]")
            yield Finding("darkweb", "[dim]  RAPIDAPI_KEY      — breachdirectory.org (free tier)[/dim]")
            yield Finding("darkweb", "[dim]  DEHASHED_EMAIL    — dehashed.com (paid)[/dim]")
            yield Finding("darkweb", "[dim]  DEHASHED_API_KEY  — dehashed.com (paid)[/dim]")
            return

        if intelx_key:
            yield Finding("darkweb", "[bold cyan]━━━ IntelligenceX ━━━[/bold cyan]")
            async for f in _intelx(domain, intelx_key):
                yield f
            yield Finding("darkweb", "")

        if rapidapi_key:
            yield Finding("darkweb", "[bold cyan]━━━ BreachDirectory ━━━[/bold cyan]")
            async for f in _breachdir(domain, rapidapi_key):
                yield f
            yield Finding("darkweb", "")

        if dehashed_email and dehashed_key:
            yield Finding("darkweb", "[bold cyan]━━━ Dehashed ━━━[/bold cyan]")
            async for f in _dehashed(domain, dehashed_key):
                yield f


# ── IntelligenceX ─────────────────────────────────────────────────────────────

async def _intelx(domain: str, api_key: str) -> AsyncIterator[Finding]:
    headers = {"x-key": api_key, "Content-Type": "application/json"}
    body = {
        "term": domain,
        "buckets": [],
        "lookuplevel": 0,
        "maxresults": 30,
        "timeout": 0,
        "datefrom": "",
        "dateto": "",
        "sort": 4,
        "media": 0,
        "terminate": [],
    }

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(_INTELX_SEARCH, json=body, headers=headers)

            if r.status_code == 401:
                yield Finding("darkweb", "  [red]Invalid IntelligenceX API key[/red]")
                return
            if r.status_code == 402:
                yield Finding("darkweb", "  [yellow]IntelligenceX quota exhausted[/yellow]")
                return
            if r.status_code != 200:
                yield Finding("darkweb", f"  [red]HTTP {r.status_code}[/red]")
                return

            search_id = r.json().get("id", "")
            if not search_id:
                yield Finding("darkweb", "  [dim]No results[/dim]")
                return

            # Let the search engine gather results
            await asyncio.sleep(3)

            r2 = await client.get(
                _INTELX_RESULT,
                params={"id": search_id, "limit": 30, "offset": 0},
                headers=headers,
            )
            if r2.status_code != 200:
                yield Finding("darkweb", f"  [red]Fetch error {r2.status_code}[/red]")
                return

            records: list[dict] = r2.json().get("records", []) or []

    except Exception as exc:
        yield Finding("darkweb", f"  [red]Error: {exc}[/red]")
        return

    if not records:
        yield Finding("darkweb", "  [green]No results found[/green]")
        return

    yield Finding("darkweb", f"  [bold]{len(records)} result(s)[/bold]")

    for rec in records:
        sys_id = rec.get("systemid", -1)
        name   = escape((rec.get("name") or "?")[:80])
        date   = (rec.get("date") or "")[:10]
        bucket = escape(rec.get("bucket") or "")
        label  = _INTELX_SYSTEMS.get(sys_id, f"sys{sys_id}")
        color  = "red" if sys_id in (1, 3) else "yellow" if sys_id == 0 else "cyan"

        yield Finding("darkweb", f"  [{color}][{label}][/{color}]  {name}  [dim]{date}[/dim]")
        if bucket:
            yield Finding("darkweb", f"    [dim]Source: {bucket}[/dim]")


# ── BreachDirectory ────────────────────────────────────────────────────────────

async def _breachdir(domain: str, rapidapi_key: str) -> AsyncIterator[Finding]:
    headers = {
        "X-RapidAPI-Key":  rapidapi_key,
        "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com",
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.get(
                _BREACHDIR_URL,
                params={"func": "auto", "term": domain},
                headers=headers,
            )
    except Exception as exc:
        yield Finding("darkweb", f"  [red]Error: {exc}[/red]")
        return

    if r.status_code == 401 or r.status_code == 403:
        yield Finding("darkweb", "  [red]Invalid RapidAPI key[/red]")
        return
    if r.status_code == 429:
        yield Finding("darkweb", "  [yellow]RapidAPI rate limit / quota exhausted[/yellow]")
        return
    if r.status_code != 200:
        yield Finding("darkweb", f"  [red]HTTP {r.status_code}[/red]")
        return

    body    = r.json()
    found   = body.get("found", 0)
    results = body.get("result", []) or []

    if not body.get("success") or found == 0:
        yield Finding("darkweb", "  [green]No credentials found[/green]")
        return

    yield Finding("darkweb", f"  [bold red]{found:,} credential(s) found[/bold red]  [dim](showing up to {len(results)})[/dim]")
    yield Finding("darkweb", "")

    for i, entry in enumerate(results[:50], 1):
        email    = escape(entry.get("email") or "?")
        password = entry.get("password")
        sha1     = entry.get("sha1") or ""
        h        = entry.get("hash") or ""

        yield Finding("darkweb", f"  [dim]#{i:03d}[/dim]  [cyan]{email}[/cyan]")

        if password:
            yield Finding("darkweb", f"         [red]pass:[/red] {escape(password)}")
        elif sha1:
            yield Finding("darkweb", f"         [dim]SHA1:[/dim] [dim]{sha1[:40]}[/dim]")
        elif h:
            yield Finding("darkweb", f"         [dim]hash:[/dim] [dim]{h[:60]}[/dim]")
        else:
            yield Finding("darkweb", "         [dim]hash: (not available on free tier)[/dim]")


def _str(val) -> str:
    """Normalise a Dehashed field that may be a str, list, or None."""
    if val is None:
        return ""
    if isinstance(val, list):
        return ", ".join(str(v) for v in val if v)
    return str(val)


# ── Dehashed ───────────────────────────────────────────────────────────────────

async def _dehashed(domain: str, api_key: str) -> AsyncIterator[Finding]:
    headers = {
        "Dehashed-Api-Key": api_key,
        "Accept":           "application/json",
    }
    payload = {
        "query": f"domain:{domain}",
        "size":  20,
        "page":  1,
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r = await client.post(
                _DEHASHED_URL,
                json=payload,
                headers=headers,
            )
    except Exception as exc:
        yield Finding("darkweb", f"  [red]Error: {exc}[/red]")
        return

    if r.status_code == 401 or r.status_code == 403:
        yield Finding("darkweb", "  [red]Invalid Dehashed API key[/red]")
        return
    if r.status_code == 402:
        yield Finding("darkweb", "  [yellow]Dehashed — no API credits remaining[/yellow]")
        return
    if r.status_code != 200:
        yield Finding("darkweb", f"  [red]HTTP {r.status_code}: {escape(r.text[:120])}[/red]")
        return

    body    = r.json()
    total   = body.get("total", 0)
    entries = body.get("entries", []) or []

    if total == 0 or not entries:
        yield Finding("darkweb", "  [green]No records found[/green]")
        return

    yield Finding(
        "darkweb",
        f"  [bold red]{total:,} record(s) in Dehashed[/bold red]  [dim](showing {len(entries)})[/dim]",
    )
    yield Finding("darkweb", "")

    for i, entry in enumerate(entries, 1):
        em       = escape(_str(entry.get("email")))
        username = escape(_str(entry.get("username")))
        name     = escape(_str(entry.get("name")))
        password = _str(entry.get("password"))
        hashed   = _str(entry.get("hashed_password"))
        db       = escape(_str(entry.get("database_name")) or "unknown db")

        ident = em or username or name or "?"
        yield Finding("darkweb", f"  [dim]#{i:03d}[/dim]  [cyan]{ident}[/cyan]  [dim][{db}][/dim]")

        if name and name not in ident:
            yield Finding("darkweb", f"         [dim]name: {name}[/dim]")
        if password:
            yield Finding("darkweb", f"         [red]pass:[/red] {escape(password)}")
        elif hashed:
            yield Finding("darkweb", f"         [dim]hash:[/dim] [dim]{escape(hashed[:60])}[/dim]")
