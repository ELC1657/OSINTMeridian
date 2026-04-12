from __future__ import annotations

from typing import AsyncIterator

import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize

_HIBP_BREACHES = "https://haveibeenpwned.com/api/v3/breaches"
_HEADERS = {"User-Agent": "Meridian", "Accept": "application/json"}


class BreachModule(ReconModule):
    name = "Breach Intel"
    panel_id = "breach"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        # If an email address was passed, use the domain portion for HIBP
        if "@" in target:
            domain = target.split("@")[-1].strip().lower()
        else:
            domain = _normalize(target)
        base = domain.split(".")[0].lower()  # "twitter" from "twitter.com"

        try:
            async with httpx.AsyncClient(timeout=20, headers=_HEADERS) as client:
                r = await client.get(_HIBP_BREACHES)
                if r.status_code != 200:
                    yield Finding("breach", f"[red]HIBP error {r.status_code}[/red]")
                    return
                all_breaches: list[dict] = r.json()
        except Exception as exc:
            yield Finding("breach", f"[red]Error: {exc}[/red]")
            return

        # Exact domain match first, then loose name match
        exact = [
            b for b in all_breaches
            if b.get("Domain", "").lower() == domain.lower()
        ]
        fuzzy = [
            b for b in all_breaches
            if base in b.get("Name", "").lower()
            and b not in exact
            and not b.get("IsSpamList")
            and not b.get("IsFabricated")
        ]

        total = len(exact) + len(fuzzy)
        if total == 0:
            yield Finding("breach", "[green]No breaches found in HIBP[/green]")
            return

        yield Finding("breach", f"[bold]{total} breach(es) found[/bold]")

        for b in exact + fuzzy:
            for line in _format_breach(b, is_exact=b in exact):
                yield Finding("breach", line)


def _format_breach(b: dict, is_exact: bool) -> list[str]:
    name        = escape(b.get("Title") or b.get("Name", "Unknown"))
    date        = b.get("BreachDate", "?")[:7]           # "2013-10"
    pwn_count   = b.get("PwnCount", 0)
    data_types  = b.get("DataClasses", [])
    is_verified = b.get("IsVerified", False)
    is_sensitive = b.get("IsSensitive", False)

    count_str = _fmt_count(pwn_count)
    tag = "[dim](domain match)[/dim]" if is_exact else "[dim](name match)[/dim]"

    header_color = "red" if is_sensitive else "yellow" if is_exact else "cyan"
    lines = [
        "",
        f"[bold {header_color}]{name}[/bold {header_color}]  {date}  {count_str}  {tag}",
    ]

    if not is_verified:
        lines.append("  [dim]Unverified breach[/dim]")
    if is_sensitive:
        lines.append("  [red]Sensitive data[/red]")

    if data_types:
        types = ", ".join(data_types[:6])
        if len(data_types) > 6:
            types += f" +{len(data_types) - 6} more"
        lines.append(f"  [dim]{escape(types)}[/dim]")

    return lines


def _fmt_count(n: int) -> str:
    if n >= 1_000_000_000:
        return f"[red]{n / 1_000_000_000:.1f}B accounts[/red]"
    if n >= 1_000_000:
        return f"[red]{n // 1_000_000}M accounts[/red]"
    if n >= 1_000:
        return f"[yellow]{n // 1_000}K accounts[/yellow]"
    if n > 0:
        return f"{n} accounts"
    return ""
