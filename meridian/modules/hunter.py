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

        is_email = "@" in target and not target.startswith("@")
        email    = target.strip() if is_email else ""
        domain   = target.split("@")[-1] if is_email else _normalize(target)

        # ── Email verifier (only when a specific address was passed) ──────────
        if is_email:
            async for f in self._verify_email(email, api_key):
                yield f
            yield Finding("hunter", "")

        # ── Domain search ─────────────────────────────────────────────────────
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

    async def _verify_email(self, email: str, api_key: str) -> AsyncIterator[Finding]:
        from rich.markup import escape as _escape
        yield Finding("hunter", "[bold cyan]── Email Verifier ──[/bold cyan]")
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r = await client.get(
                    f"{_BASE}/email-verifier",
                    params={"email": email, "api_key": api_key},
                )
        except Exception as exc:
            yield Finding("hunter", f"  [red]Error: {_escape(str(exc))}[/red]")
            return

        if r.status_code == 401:
            yield Finding("hunter", "  [red]Invalid API key[/red]")
            return
        if r.status_code == 429:
            yield Finding("hunter", "  [yellow]Rate limit hit[/yellow]")
            return
        if r.status_code not in (200, 202):
            yield Finding("hunter", f"  [red]HTTP {r.status_code}[/red]")
            return

        data = (r.json().get("data") or {})
        status    = data.get("status", "unknown")
        score     = data.get("score", 0)
        result    = data.get("result", "")
        mx_host   = data.get("mx_host", "")
        disposable = data.get("disposable", False)
        webmail    = data.get("webmail", False)
        gibberish  = data.get("gibberish", False)
        regexp     = data.get("regexp", False)

        status_color = {
            "valid":      "green",
            "invalid":    "red",
            "accept_all": "yellow",
            "webmail":    "cyan",
            "disposable": "yellow",
            "unknown":    "dim",
        }.get(status, "dim")

        yield Finding("hunter", f"  Status: [{status_color}]{_escape(status.upper())}[/{status_color}]  Score: [bold]{score}[/bold]")
        if result:
            yield Finding("hunter", f"  Result: [dim]{_escape(result)}[/dim]")
        if mx_host:
            yield Finding("hunter", f"  MX:     [dim]{_escape(mx_host)}[/dim]")
        flags = []
        if disposable:
            flags.append("[yellow]disposable[/yellow]")
        if webmail:
            flags.append("[cyan]webmail[/cyan]")
        if gibberish:
            flags.append("[red]gibberish[/red]")
        if not regexp:
            flags.append("[red]invalid format[/red]")
        if flags:
            yield Finding("hunter", f"  Flags: {' · '.join(flags)}")
