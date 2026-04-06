from __future__ import annotations

from typing import AsyncIterator

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize

_BGPVIEW = "https://api.bgpview.io"
_HEADERS = {"User-Agent": "Meridian"}


class ASNModule(ReconModule):
    name = "ASN / IP Ranges"
    panel_id = "asn"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        ip = await self._resolve_ip(domain)
        if not ip:
            yield Finding("asn", "[red]Could not resolve domain to IP[/red]")
            return

        async with httpx.AsyncClient(timeout=15, headers=_HEADERS) as client:
            # Step 1: IP -> ASN
            asn_info = await self._asn_for_ip(client, ip)
            if not asn_info:
                yield Finding("asn", f"[dim]{ip}[/dim]  [red]No BGP data found[/red]")
                return

            asn_num  = asn_info.get("asn", "?")
            asn_name = asn_info.get("name", "")
            asn_desc = asn_info.get("description", "")
            asn_cc   = asn_info.get("country_code", "")

            yield Finding("asn", f"[bold]AS{asn_num}[/bold]  {escape(asn_name)}  [dim]{asn_cc}[/dim]")
            if asn_desc and asn_desc.lower() != asn_name.lower():
                yield Finding("asn", f"[dim]{escape(asn_desc)}[/dim]")
            yield Finding("asn", f"[dim]Source IP: {ip}[/dim]")

            # Step 2: ASN -> all prefixes
            v4, v6 = await self._prefixes_for_asn(client, asn_num)

            yield Finding("asn", "")
            yield Finding("asn", f"[bold]IPv4 Ranges[/bold]  [dim]{len(v4)} prefixes[/dim]")
            for p in v4[:40]:
                name = (p.get("name") or p.get("description") or "").strip()
                label = f"  [dim]{escape(name[:45])}[/dim]" if name else ""
                yield Finding("asn", f"  [cyan]{escape(p['prefix'])}[/cyan]{label}")
            if len(v4) > 40:
                yield Finding("asn", f"  [dim]... {len(v4) - 40} more[/dim]")

            if v6:
                yield Finding("asn", "")
                yield Finding("asn", f"[bold]IPv6 Ranges[/bold]  [dim]{len(v6)} prefixes[/dim]")
                for p in v6[:15]:
                    name = (p.get("name") or p.get("description") or "").strip()
                    label = f"  [dim]{escape(name[:40])}[/dim]" if name else ""
                    yield Finding("asn", f"  [cyan]{escape(p['prefix'])}[/cyan]{label}")
                if len(v6) > 15:
                    yield Finding("asn", f"  [dim]... {len(v6) - 15} more[/dim]")

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _resolve_ip(self, domain: str) -> str | None:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            answers = await resolver.resolve(domain, "A")
            return str(answers[0])
        except Exception:
            return None

    async def _asn_for_ip(self, client: httpx.AsyncClient, ip: str) -> dict | None:
        try:
            r = await client.get(f"{_BGPVIEW}/ip/{ip}")
            if r.status_code != 200:
                return None
            data = r.json()
            if data.get("status") != "ok":
                return None
            prefixes = data.get("data", {}).get("prefixes", [])
            if not prefixes:
                return None
            return prefixes[0].get("asn")
        except Exception:
            return None

    async def _prefixes_for_asn(
        self, client: httpx.AsyncClient, asn: int
    ) -> tuple[list[dict], list[dict]]:
        try:
            r = await client.get(f"{_BGPVIEW}/asn/{asn}/prefixes")
            if r.status_code != 200:
                return [], []
            data = r.json()
            if data.get("status") != "ok":
                return [], []
            d = data.get("data", {})
            return d.get("ipv4_prefixes", []), d.get("ipv6_prefixes", [])
        except Exception:
            return [], []
