from typing import AsyncIterator

import httpx

from .base import Finding, ReconModule, _normalize

_BASE = "https://api.shodan.io"


class ShodanModule(ReconModule):
    name = "Shodan"
    panel_id = "shodan"
    requires_key = True
    key_env = "SHODAN_API_KEY"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        api_key = self.get_key("shodan_api_key")
        if not api_key:
            yield Finding("shodan", "[yellow]No API key - set SHODAN_API_KEY[/yellow]")
            yield Finding("shodan", "[dim]Free key at https://account.shodan.io/[/dim]")
            return

        domain = _normalize(target)

        async with httpx.AsyncClient(timeout=30.0) as client:
            # ── Host search by hostname ──────────────────────────────────
            try:
                r = await client.get(
                    f"{_BASE}/shodan/host/search",
                    params={"key": api_key, "query": f"hostname:{domain}", "minify": "false"},
                )
                r.raise_for_status()
                data = r.json()
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    yield Finding("shodan", "[red]Invalid API key[/red]")
                    return
                elif e.response.status_code == 403:
                    yield Finding("shodan", "[yellow]Search requires a paid Shodan plan[/yellow]")
                    yield Finding("shodan", "[dim]Free tier only supports direct IP lookups[/dim]")
                    yield Finding("shodan", "[dim]Trying DNS lookup instead...[/dim]")
                    data = {}
                else:
                    yield Finding("shodan", f"[red]HTTP {e.response.status_code}[/red]")
                    return
            except Exception as e:
                yield Finding("shodan", f"[red]Error: {e}[/red]")
                return

            total = data.get("total", 0)
            if total or data:
                yield Finding("shodan", f"[bold]Total hosts:[/bold] [green]{total}[/green]")

            seen_ips: set[str] = set()
            all_vulns: set[str] = set()

            for match in data.get("matches", []):
                ip = match.get("ip_str", "?")
                port = match.get("port", "?")
                transport = match.get("transport", "tcp")
                org = match.get("org", "")
                product = match.get("product", "")
                version = match.get("version", "")
                country = match.get("location", {}).get("country_name", "")
                hostnames = match.get("hostnames", [])
                vulns = match.get("vulns", {})

                service = " ".join(filter(None, [product, version]))
                line = f"[green]{ip}[/green]:[yellow]{port}/{transport}[/yellow]"
                if service:
                    line += f"  [cyan]{service}[/cyan]"
                if org and ip not in seen_ips:
                    line += f"  [dim]{org}[/dim]"
                if country:
                    line += f"  [dim]({country})[/dim]"
                yield Finding("shodan", line)
                seen_ips.add(ip)

                if hostnames:
                    for h in hostnames[:3]:
                        yield Finding("shodan", f"  [dim]↳ {h}[/dim]")

                for cve, vuln_data in list(vulns.items())[:5]:
                    cvss = vuln_data.get("cvss", "?")
                    severity = (
                        "red" if float(cvss) >= 7.0 else "yellow"
                        if float(cvss) >= 4.0 else "dim"
                    ) if cvss != "?" else "dim"
                    yield Finding("shodan", f"  [bold {severity}]⚠ {cve}[/bold {severity}]  CVSS:{cvss}")
                    all_vulns.add(cve)

            # ── DNS info ────────────────────────────────────────────────
            try:
                r2 = await client.get(
                    f"{_BASE}/dns/domain/{domain}",
                    params={"key": api_key},
                )
                if r2.status_code == 200:
                    dns_data = r2.json()
                    subdomains = dns_data.get("subdomains", [])
                    if subdomains:
                        yield Finding("shodan", f"[bold]DNS subdomains ({len(subdomains)}):[/bold]")
                        for sub in subdomains[:20]:
                            yield Finding("shodan", f"  [cyan]{sub}.{domain}[/cyan]")
            except Exception:
                pass

            if all_vulns:
                yield Finding("shodan", f"[bold red]Total CVEs found: {len(all_vulns)}[/bold red]")
