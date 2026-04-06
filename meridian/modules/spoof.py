from __future__ import annotations

import asyncio
from typing import AsyncIterator

import dns.asyncresolver
import dns.exception
import dns.resolver
from rich.markup import escape

from .base import Finding, ReconModule, _normalize


class SpoofModule(ReconModule):
    name = "Spoofability"
    panel_id = "spoof"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        spf_raw, dmarc_raw = await asyncio.gather(
            self._get_txt(domain, "v=spf1"),
            self._get_txt(f"_dmarc.{domain}", "v=DMARC1"),
        )

        # ── SPF ──────────────────────────────────────────────────────────────
        yield Finding("spoof", "[bold]SPF[/bold]")
        spf_hard = False
        if spf_raw:
            yield Finding("spoof", f"  [dim]{escape(spf_raw)}[/dim]")
            all_mech = self._spf_all(spf_raw)
            if all_mech == "-all":
                yield Finding("spoof", "  [green]Hardfail (-all)  unauthorized senders rejected[/green]")
                spf_hard = True
            elif all_mech == "~all":
                yield Finding("spoof", "  [yellow]Softfail (~all)  may still deliver to inbox[/yellow]")
            elif all_mech in ("?all", "+all"):
                yield Finding("spoof", f"  [red]Permissive ({all_mech})  anyone can send as this domain[/red]")
            else:
                yield Finding("spoof", "  [yellow]No 'all' mechanism  open relay possible[/yellow]")
        else:
            yield Finding("spoof", "  [red]No SPF record  anyone can send as this domain[/red]")

        # ── DMARC ─────────────────────────────────────────────────────────────
        yield Finding("spoof", "")
        yield Finding("spoof", "[bold]DMARC[/bold]")
        dmarc_enforced = False
        if dmarc_raw:
            yield Finding("spoof", f"  [dim]{escape(dmarc_raw)}[/dim]")
            policy = self._dmarc_tag(dmarc_raw, "p")
            pct    = self._dmarc_pct(dmarc_raw)
            sp     = self._dmarc_tag(dmarc_raw, "sp")

            if policy == "reject":
                if pct >= 100:
                    yield Finding("spoof", "  [green]p=reject (100%)  spoofed mail rejected[/green]")
                    dmarc_enforced = True
                else:
                    yield Finding("spoof", f"  [yellow]p=reject ({pct}%)  partial enforcement[/yellow]")
            elif policy == "quarantine":
                yield Finding("spoof", f"  [yellow]p=quarantine ({pct}%)  spoofed mail goes to spam[/yellow]")
            elif policy == "none":
                yield Finding("spoof", "  [red]p=none  monitoring only, delivery not blocked[/red]")
            else:
                yield Finding("spoof", f"  [red]Unknown policy '{escape(policy)}'[/red]")

            if sp and sp != policy:
                yield Finding("spoof", f"  [dim]Subdomain policy: sp={sp}[/dim]")

            rua = self._dmarc_tag(dmarc_raw, "rua")
            if rua:
                yield Finding("spoof", f"  [dim]Reports: {escape(rua)}[/dim]")
        else:
            yield Finding("spoof", "  [red]No DMARC record  policy not enforced[/red]")

        # ── Verdict ───────────────────────────────────────────────────────────
        yield Finding("spoof", "")
        if not dmarc_enforced:
            yield Finding("spoof", "[bold red]VERDICT  SPOOFABLE[/bold red]")
            if not spf_raw:
                yield Finding("spoof", "[dim]No SPF + no enforced DMARC[/dim]")
            else:
                yield Finding("spoof", "[dim]DMARC policy not enforced - From: header unprotected[/dim]")
        elif not spf_hard:
            yield Finding("spoof", "[bold yellow]VERDICT  PARTIAL[/bold yellow]")
            yield Finding("spoof", "[dim]DMARC enforced but SPF softfail may still deliver[/dim]")
        else:
            yield Finding("spoof", "[bold green]VERDICT  PROTECTED[/bold green]")
            yield Finding("spoof", "[dim]SPF hardfail + DMARC enforced[/dim]")

    # ── Helpers ───────────────────────────────────────────────────────────────

    async def _get_txt(self, name: str, prefix: str) -> str | None:
        try:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 8
            answers = await resolver.resolve(name, "TXT")
            for rdata in answers:
                txt = "".join(s.decode() for s in rdata.strings)
                if txt.startswith(prefix):
                    return txt
        except Exception:
            pass
        return None

    def _spf_all(self, record: str) -> str:
        for part in record.lower().split():
            if part in ("-all", "~all", "?all", "+all"):
                return part
        return ""

    def _dmarc_tag(self, record: str, tag: str) -> str:
        for part in record.split(";"):
            part = part.strip()
            if part.lower().startswith(f"{tag}="):
                return part[len(tag) + 1:].strip().lower()
        return ""

    def _dmarc_pct(self, record: str) -> int:
        val = self._dmarc_tag(record, "pct")
        try:
            return int(val)
        except (ValueError, TypeError):
            return 100
