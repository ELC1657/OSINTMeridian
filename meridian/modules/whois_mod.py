import asyncio
from datetime import datetime
from typing import AsyncIterator, Any

from rich.markup import escape

from .base import Finding, ReconModule, _normalize


def _fmt_date(val: Any) -> str:
    if isinstance(val, list):
        val = val[0]
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d")
    return str(val)


def _fmt_list(val: Any, limit: int = 5) -> list[str]:
    if not isinstance(val, list):
        return [str(val)]
    return [str(v) for v in val[:limit]]


class WHOISModule(ReconModule):
    name = "WHOIS"
    panel_id = "whois"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        try:
            import whois as _whois
        except ImportError:
            yield Finding("whois", "[red]python-whois not installed[/red]")
            return

        try:
            data = await asyncio.to_thread(_whois.whois, domain)
        except Exception as e:
            yield Finding("whois", f"[red]Error: {e}[/red]")
            return

        if data is None:
            yield Finding("whois", "[dim]No WHOIS data returned[/dim]")
            return

        fields: list[tuple[str, str, bool]] = [
            ("registrar", "Registrar", False),
            ("registrant_name", "Registrant", False),
            ("org", "Org", False),
            ("registrant_country", "Country", False),
            ("creation_date", "Created", True),
            ("expiration_date", "Expires", True),
            ("updated_date", "Updated", True),
            ("dnssec", "DNSSEC", False),
            ("name_servers", "Nameservers", False),
            ("emails", "Emails", False),
            ("status", "Status", False),
        ]

        found = 0
        for attr, label, is_date in fields:
            val = getattr(data, attr, None)
            if val is None:
                continue
            if is_date:
                yield Finding("whois", f"[cyan]{label}:[/cyan] [white]{_fmt_date(val)}[/white]")
                found += 1
            elif isinstance(val, list):
                items = _fmt_list(val)
                if len(items) == 1:
                    yield Finding("whois", f"[cyan]{label}:[/cyan] [white]{escape(items[0])}[/white]")
                else:
                    yield Finding("whois", f"[cyan]{label}:[/cyan]")
                    for item in items:
                        yield Finding("whois", f"  [white]{escape(item)}[/white]")
                found += 1
            else:
                yield Finding("whois", f"[cyan]{label}:[/cyan] [white]{escape(str(val))}[/white]")
                found += 1

        # Privacy / registrar abuse contact
        abuse = getattr(data, "registrar_abuse_contact_email", None)
        if abuse:
            yield Finding("whois", f"[cyan]Abuse Email:[/cyan] [yellow]{escape(str(abuse))}[/yellow]")
            found += 1

        if found == 0:
            yield Finding("whois", "[dim]WHOIS returned data but all fields are redacted or unparseable[/dim]")
            yield Finding("whois", f"[dim]Try: whois {domain}[/dim]")
