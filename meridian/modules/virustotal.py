from datetime import datetime
from typing import AsyncIterator

import httpx

from .base import Finding, ReconModule, _normalize

_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalModule(ReconModule):
    name = "VirusTotal"
    panel_id = "virustotal"
    requires_key = True
    key_env = "VT_API_KEY"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        api_key = self.get_key("vt_api_key")
        if not api_key:
            yield Finding("virustotal", "[yellow]No API key - set VT_API_KEY[/yellow]")
            yield Finding("virustotal", "[dim]Free key at https://www.virustotal.com/[/dim]")
            return

        domain = _normalize(target)
        headers = {"x-apikey": api_key}

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            # ── Domain report ───────────────────────────────────────────
            try:
                r = await client.get(f"{_BASE}/domains/{domain}")
                r.raise_for_status()
                attrs = r.json()["data"]["attributes"]
            except httpx.HTTPStatusError as e:
                code = e.response.status_code
                if code == 401:
                    yield Finding("virustotal", "[red]Invalid API key[/red]")
                elif code == 404:
                    yield Finding("virustotal", "[dim]Domain not in VT database[/dim]")
                else:
                    yield Finding("virustotal", f"[red]HTTP {code}[/red]")
                return
            except Exception as e:
                yield Finding("virustotal", f"[red]Error: {e}[/red]")
                return

            # Detection stats
            stats = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())

            if malicious == 0:
                det_color = "green"
            elif malicious < 5:
                det_color = "yellow"
            else:
                det_color = "red"

            yield Finding(
                "virustotal",
                f"[bold]Detections:[/bold] [{det_color}]{malicious}/{total}[/{det_color}]"
                + (f"  [yellow]({suspicious} suspicious)[/yellow]" if suspicious else ""),
            )

            rep = attrs.get("reputation", 0)
            rep_color = "green" if rep >= 0 else "red"
            yield Finding("virustotal", f"[bold]Reputation:[/bold] [{rep_color}]{rep:+d}[/{rep_color}]")

            # Categories
            cats = attrs.get("categories", {})
            if cats:
                unique_cats = sorted(set(cats.values()))[:6]
                yield Finding("virustotal", f"[bold]Categories:[/bold] [dim]{', '.join(unique_cats)}[/dim]")

            # Tags
            tags = attrs.get("tags", [])
            if tags:
                yield Finding("virustotal", f"[bold]Tags:[/bold] [dim]{', '.join(tags[:8])}[/dim]")

            # Last analysis date
            ts = attrs.get("last_analysis_date")
            if ts:
                dt = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                yield Finding("virustotal", f"[bold]Last analyzed:[/bold] [dim]{dt}[/dim]")

            # Engines that flagged it
            engines = attrs.get("last_analysis_results", {})
            flagged = [
                (engine, res.get("result", ""))
                for engine, res in engines.items()
                if res.get("category") in ("malicious", "suspicious")
            ]
            if flagged:
                yield Finding("virustotal", "[bold]Flagged by:[/bold]")
                for engine, result in flagged[:10]:
                    yield Finding("virustotal", f"  [red]{engine}[/red]: {result}")

            # ── Subdomains ───────────────────────────────────────────────
            try:
                r2 = await client.get(f"{_BASE}/domains/{domain}/subdomains", params={"limit": 20})
                if r2.status_code == 200:
                    subs = r2.json().get("data", [])
                    if subs:
                        yield Finding("virustotal", f"[bold]Subdomains ({len(subs)}):[/bold]")
                        for sub in subs[:15]:
                            yield Finding("virustotal", f"  [cyan]{sub['id']}[/cyan]")
            except Exception:
                pass

            # ── Resolutions (historical IPs) ─────────────────────────────
            try:
                r3 = await client.get(f"{_BASE}/domains/{domain}/resolutions", params={"limit": 10})
                if r3.status_code == 200:
                    resolutions = r3.json().get("data", [])
                    if resolutions:
                        yield Finding("virustotal", "[bold]Historical IPs:[/bold]")
                        for res in resolutions[:8]:
                            ip = res["attributes"].get("ip_address", "?")
                            date = res["attributes"].get("date", 0)
                            date_str = datetime.fromtimestamp(date).strftime("%Y-%m") if date else "?"
                            yield Finding("virustotal", f"  [green]{ip}[/green]  [dim]{date_str}[/dim]")
            except Exception:
                pass
