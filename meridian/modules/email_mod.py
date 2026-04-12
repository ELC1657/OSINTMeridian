from __future__ import annotations

import hashlib
from typing import AsyncIterator

import httpx
from rich.markup import escape

from .base import Finding, ReconModule

_EMAILREP_URL = "https://emailrep.io/{email}"
_GRAVATAR_JSON = "https://www.gravatar.com/{hash}.json"
_GRAVATAR_AVATAR = "https://www.gravatar.com/avatar/{hash}?d=404"

_RISK_COLOR = {
    "none":     "green",
    "low":      "green",
    "medium":   "yellow",
    "high":     "red",
    "critical": "bold red",
}


class EmailIntelModule(ReconModule):
    """Email-specific intelligence: reputation, breach flags, profile enumeration."""

    name = "Email Intel"
    panel_id = "email_intel"

    async def run(self, target: str) -> AsyncIterator[Finding]:  # type: ignore[override]
        email = target.strip().lower()

        if "@" not in email:
            yield Finding("email_intel", "[dim]No email address to analyse[/dim]", progress=True)
            return

        yield Finding("email_intel", f"[bold]Email:[/bold] {escape(email)}", progress=True)
        yield Finding("email_intel", "")

        # Username extraction
        local = email.split("@")[0]
        yield Finding("email_intel", "[bold cyan]── Username ──[/bold cyan]")
        yield Finding("email_intel", f"  [cyan]{escape(local)}[/cyan]")
        yield Finding("email_intel", "")

        # Run enrichment sources concurrently
        import asyncio
        emailrep_findings: list[Finding] = []
        gravatar_findings: list[Finding] = []

        async def _collect_emailrep() -> None:
            async for f in _emailrep(email):
                emailrep_findings.append(f)

        async def _collect_gravatar() -> None:
            async for f in _gravatar(email):
                gravatar_findings.append(f)

        await asyncio.gather(_collect_emailrep(), _collect_gravatar())

        for f in emailrep_findings:
            yield f
        for f in gravatar_findings:
            yield f


# ── EmailRep.io ───────────────────────────────────────────────────────────────

async def _emailrep(email: str) -> AsyncIterator[Finding]:
    yield Finding("email_intel", "[bold cyan]── EmailRep.io ──[/bold cyan]")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.get(
                _EMAILREP_URL.format(email=email),
                headers={"User-Agent": "Meridian"},
            )
    except Exception as exc:
        yield Finding("email_intel", f"  [red]Error: {escape(str(exc))}[/red]")
        return

    if r.status_code == 429:
        yield Finding("email_intel", "  [yellow]EmailRep.io rate limit hit[/yellow]")
        return
    if r.status_code != 200:
        yield Finding("email_intel", f"  [red]HTTP {r.status_code}[/red]")
        return

    data = r.json()
    details = data.get("details", {})

    reputation = data.get("reputation", "unknown")
    risk_color = _RISK_COLOR.get(reputation, "dim")
    suspicious = data.get("suspicious", False)
    references = data.get("references", 0)

    yield Finding(
        "email_intel",
        f"  Reputation: [{risk_color}]{escape(reputation.upper())}[/{risk_color}]"
        + (f"  [red]⚠ SUSPICIOUS[/red]" if suspicious else ""),
    )
    yield Finding("email_intel", f"  References: [dim]{references:,} public mentions[/dim]")

    # Key boolean flags
    flags: list[tuple[str, str, str]] = [
        ("credentials_leaked",        "Credentials leaked",    "red"),
        ("credentials_leaked_recent", "Leaked (recent)",       "bold red"),
        ("data_breach",               "In data breach",        "red"),
        ("malicious_activity",        "Malicious activity",    "red"),
        ("blacklisted",               "Blacklisted",           "red"),
        ("spam",                      "Spam account",          "yellow"),
        ("disposable",                "Disposable address",    "yellow"),
        ("free_provider",             "Free provider",         "dim"),
        ("deliverable",               "Deliverable",           "green"),
        ("valid_mx",                  "Valid MX",              "green"),
    ]
    for key, label, color in flags:
        val = details.get(key)
        if val is True:
            yield Finding("email_intel", f"  [{color}]✓ {label}[/{color}]")
        elif val is False and key in ("deliverable", "valid_mx"):
            yield Finding("email_intel", f"  [red]✗ {label}[/red]")

    # Dates
    first_seen = details.get("first_seen", "")
    last_seen  = details.get("last_seen", "")
    if first_seen:
        yield Finding("email_intel", f"  First seen: [dim]{escape(first_seen)}[/dim]")
    if last_seen:
        yield Finding("email_intel", f"  Last seen:  [dim]{escape(last_seen)}[/dim]")

    # Spoofability
    spoofable = details.get("spoofable", False)
    spf_strict = details.get("spf_strict", False)
    dmarc = details.get("dmarc_enforced", False)
    if spoofable:
        yield Finding("email_intel", "  [red]⚠ Domain is spoofable[/red]")
    else:
        prot = []
        if spf_strict:
            prot.append("SPF strict")
        if dmarc:
            prot.append("DMARC enforced")
        if prot:
            yield Finding("email_intel", f"  [green]✓ {', '.join(prot)}[/green]")

    # Social profiles
    profiles: list[str] = details.get("profiles", [])
    if profiles:
        yield Finding("email_intel", "")
        yield Finding("email_intel", f"  [bold]Profiles found:[/bold] {escape(', '.join(profiles))}")

    yield Finding("email_intel", "")


# ── Gravatar ──────────────────────────────────────────────────────────────────

async def _gravatar(email: str) -> AsyncIterator[Finding]:
    yield Finding("email_intel", "[bold cyan]── Gravatar ──[/bold cyan]")
    md5 = hashlib.md5(email.encode()).hexdigest()

    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
            # Check if avatar exists first (fast, no 404 on redirect)
            check = await client.get(_GRAVATAR_AVATAR.format(hash=md5))
            if check.status_code == 404:
                yield Finding("email_intel", "  [dim]No Gravatar account found[/dim]")
                return

            # Fetch JSON profile
            r = await client.get(_GRAVATAR_JSON.format(hash=md5))
    except Exception as exc:
        yield Finding("email_intel", f"  [red]Error: {escape(str(exc))}[/red]")
        return

    if r.status_code != 200:
        yield Finding("email_intel", "  [dim]No public Gravatar profile[/dim]")
        return

    profile = (r.json().get("entry") or [{}])[0]

    display = escape(profile.get("displayName") or profile.get("name", {}).get("formatted", ""))
    if display:
        yield Finding("email_intel", f"  [green]✓ Gravatar account found[/green]  [bold]{display}[/bold]")
    else:
        yield Finding("email_intel", "  [green]✓ Gravatar account found[/green]")

    profile_url = escape(profile.get("profileUrl", ""))
    if profile_url:
        yield Finding("email_intel", f"  URL: [dim]{profile_url}[/dim]")

    about_me = (profile.get("aboutMe") or "").strip()
    if about_me:
        yield Finding("email_intel", f"  Bio: [dim]{escape(about_me[:120])}[/dim]")

    location = escape(profile.get("currentLocation") or "")
    if location:
        yield Finding("email_intel", f"  Location: [dim]{location}[/dim]")

    # Linked accounts
    accounts: list[dict] = profile.get("accounts", [])
    if accounts:
        yield Finding("email_intel", "  Linked accounts:")
        for acct in accounts[:8]:
            service = escape(acct.get("shortname") or acct.get("name") or "")
            url = escape(acct.get("url") or "")
            yield Finding("email_intel", f"    [cyan]{service}[/cyan]  [dim]{url}[/dim]")

    yield Finding("email_intel", "")
