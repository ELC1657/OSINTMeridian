from typing import AsyncIterator

import httpx

from .base import Finding, ReconModule, _normalize

_BASE = "https://api.hunter.io/v2"


class HunterModule(ReconModule):
    name = "Hunter.io"
    panel_id = "hunter"
    requires_key = True
    key_env = "HUNTER_API_KEY"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        api_key = self.get_key("hunter_api_key")
        if not api_key:
            yield Finding("hunter", "[yellow]No API key - set HUNTER_API_KEY[/yellow]")
            yield Finding("hunter", "[dim]Free key at https://hunter.io/users/sign_up[/dim]")
            return

        domain = _normalize(target)

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                r = await client.get(
                    f"{_BASE}/domain-search",
                    params={"domain": domain, "api_key": api_key, "limit": 100},
                )
                body = r.json()
            except Exception as e:
                yield Finding("hunter", f"[red]Error: {e}[/red]")
                return

        # Always try to parse the body first — Hunter sends emails even with 4xx
        data = body.get("data", {})

        # Hard failures with no usable data
        if r.status_code == 401:
            yield Finding("hunter", "[red]Invalid API key[/red]")
            return
        if r.status_code == 429:
            yield Finding("hunter", "[red]Rate limit hit - free tier is 25 req/month[/red]")
            return

        # Collect any plan warnings
        warnings = [e.get("details", "") for e in body.get("errors", []) if e.get("details")]
        for w in warnings:
            yield Finding("hunter", f"[yellow]Note: {w}[/yellow]")

        # If there's no data at all, nothing to show
        if not data:
            if warnings:
                yield Finding("hunter", "[dim]Hunter knows this domain but emails are restricted on your plan[/dim]")
            else:
                yield Finding("hunter", "[dim]No data found for this domain[/dim]")
            return

        # Org info
        org = data.get("organization", "")
        if org:
            yield Finding("hunter", f"[bold]Org:[/bold] [cyan]{org}[/cyan]")

        pattern = data.get("pattern", "")
        if pattern:
            yield Finding("hunter", f"[bold]Email pattern:[/bold] [yellow]{pattern}@{domain}[/yellow]")

        total = data.get("emails_count", 0)
        emails = data.get("emails", [])
        yield Finding("hunter", f"[bold]Emails found:[/bold] [green]{total}[/green]")

        for platform in ("twitter", "linkedin", "facebook", "instagram"):
            handle = data.get(platform, "")
            if handle:
                yield Finding("hunter", f"[bold]{platform.capitalize()}:[/bold] [dim]{handle}[/dim]")

        if not emails:
            return

        yield Finding("hunter", "")

        for entry in sorted(emails, key=lambda x: x.get("confidence", 0), reverse=True):
            address    = entry.get("value", "")
            confidence = entry.get("confidence", 0)
            first      = entry.get("first_name", "") or ""
            last       = entry.get("last_name", "") or ""
            position   = entry.get("position", "") or ""
            dept       = entry.get("department", "") or ""

            conf_color = "green" if confidence >= 80 else "yellow" if confidence >= 50 else "dim"
            name_str   = f" ({(first + ' ' + last).strip()})" if (first or last) else ""
            role_str   = f"  [dim]{position}[/dim]" if position else ""
            dept_str   = f"  [dim]{dept}[/dim]" if dept and dept != position else ""

            yield Finding(
                "hunter",
                f"[{conf_color}]{confidence:3d}%[/{conf_color}]  [cyan]{address}[/cyan]{name_str}{role_str}{dept_str}",
            )
