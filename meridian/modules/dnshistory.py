from __future__ import annotations

from typing import AsyncIterator

import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize

_BASE = "https://api.securitytrails.com/v1"


class DNSHistoryModule(ReconModule):
    name = "DNS History"
    panel_id = "dnshistory"
    requires_key = True
    key_env = "SECTRAILS_API_KEY"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        api_key = self.get_key("sectrails_api_key")
        if not api_key:
            yield Finding("dnshistory", "[yellow]No API key - set SECTRAILS_API_KEY[/yellow]")
            yield Finding("dnshistory", "[dim]Free tier: securitytrails.com (50 queries/mo)[/dim]")
            return

        domain = _normalize(target)
        headers = {"APIKEY": api_key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=20) as client:
                r_a    = await client.get(f"{_BASE}/history/{domain}/dns/a",   headers=headers)
                r_mx   = await client.get(f"{_BASE}/history/{domain}/dns/mx",  headers=headers)
                r_ns   = await client.get(f"{_BASE}/history/{domain}/dns/ns",  headers=headers)
        except Exception as exc:
            yield Finding("dnshistory", f"[red]Error: {exc}[/red]")
            return

        if r_a.status_code == 401:
            yield Finding("dnshistory", "[red]Invalid SecurityTrails API key[/red]")
            return
        if r_a.status_code == 403:
            yield Finding("dnshistory", "[yellow]SecurityTrails quota exhausted[/yellow]")
            return
        if r_a.status_code != 200:
            yield Finding("dnshistory", f"[red]HTTP {r_a.status_code}[/red]")
            return

        # ── A record history ──────────────────────────────────────────────────

        a_records = r_a.json().get("records", []) or []
        seen_ips: dict[str, tuple[str, str]] = {}

        for rec in a_records:
            first = rec.get("first_seen", "?")
            last  = rec.get("last_seen",  "?")
            for v in rec.get("values", []) or []:
                ip = v.get("ip", "?")
                if ip not in seen_ips:
                    seen_ips[ip] = (first, last)
                else:
                    # extend the range if wider
                    seen_ips[ip] = (
                        min(seen_ips[ip][0], first),
                        max(seen_ips[ip][1], last),
                    )

        if seen_ips:
            yield Finding("dnshistory", f"[bold]{len(seen_ips)} historical IP(s)[/bold]")
            yield Finding("dnshistory", "")
            for ip, (first, last) in seen_ips.items():
                yield Finding(
                    "dnshistory",
                    f"  [cyan]{escape(ip)}[/cyan]  [dim]{first} → {last}[/dim]",
                )
        else:
            yield Finding("dnshistory", "[dim]No A record history[/dim]")

        # ── MX history ────────────────────────────────────────────────────────

        mx_records = r_mx.json().get("records", []) if r_mx.status_code == 200 else []
        seen_mx: set[str] = set()
        for rec in mx_records or []:
            for v in rec.get("values", []) or []:
                host = v.get("hostname", "")
                if host:
                    seen_mx.add(host)

        if seen_mx:
            yield Finding("dnshistory", "")
            yield Finding("dnshistory", f"[bold]{len(seen_mx)} historical MX host(s)[/bold]")
            for mx in sorted(seen_mx):
                yield Finding("dnshistory", f"  [dim]{escape(mx)}[/dim]")

        # ── NS history ────────────────────────────────────────────────────────

        ns_records = r_ns.json().get("records", []) if r_ns.status_code == 200 else []
        seen_ns: set[str] = set()
        for rec in ns_records or []:
            for v in rec.get("values", []) or []:
                host = v.get("nameserver", "")
                if host:
                    seen_ns.add(host)

        if seen_ns:
            yield Finding("dnshistory", "")
            yield Finding("dnshistory", f"[bold]{len(seen_ns)} historical nameserver(s)[/bold]")
            for ns in sorted(seen_ns):
                yield Finding("dnshistory", f"  [dim]{escape(ns)}[/dim]")

        if not seen_ips and not seen_mx and not seen_ns:
            yield Finding("dnshistory", "[green]No historical DNS records found[/green]")
