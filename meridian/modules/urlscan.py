from typing import AsyncIterator

import httpx

from .base import Finding, ReconModule, _normalize

_BASE = "https://urlscan.io/api/v1"

_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
)


class URLScanModule(ReconModule):
    name = "URLScan.io"
    panel_id = "urlscan"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        async with httpx.AsyncClient(timeout=30.0) as client:
            # ── Search existing scans ─────────────────────────────────────
            try:
                r = await client.get(
                    f"{_BASE}/search/",
                    params={"q": f"domain:{domain}", "size": 5},
                    headers={"Accept": "application/json"},
                )
                r.raise_for_status()
                results = r.json().get("results", [])
            except Exception as e:
                yield Finding("urlscan", f"[red]Error: {e}[/red]")
                return

            if not results:
                yield Finding("urlscan", "[dim]No scans found for this domain[/dim]")
                return

            total = r.json().get("total", len(results))
            yield Finding("urlscan", f"[bold]Scans on record:[/bold] [green]{total}[/green]")

            # Use the most recent scan for deep details
            latest = results[0]
            scan_id = latest.get("_id", "")
            scan_time = latest.get("task", {}).get("time", "")[:10]
            scan_url = latest.get("task", {}).get("url", "")
            screenshot = latest.get("screenshot", "")

            yield Finding("urlscan", f"[bold]Latest scan:[/bold] [dim]{scan_time}[/dim]  {scan_url}")
            if screenshot:
                yield Finding("urlscan", f"[bold]Screenshot:[/bold] [dim]{screenshot}[/dim]")

            # ── Fetch full result for this scan ───────────────────────────
            if not scan_id:
                return

            try:
                r2 = await client.get(f"{_BASE}/result/{scan_id}/")
                r2.raise_for_status()
                data = r2.json()
            except Exception as e:
                yield Finding("urlscan", f"[red]Could not fetch scan detail: {e}[/red]")
                return

            # ── Page info ─────────────────────────────────────────────────
            page = data.get("page", {})
            ip = page.get("ip", "")
            country = page.get("country", "")
            server = page.get("server", "")
            asn_name = page.get("asnname", "")

            if ip:
                line = f"[bold]IP:[/bold] [green]{ip}[/green]"
                if country:
                    line += f"  [dim]({country})[/dim]"
                if asn_name:
                    line += f"  [dim]{asn_name}[/dim]"
                yield Finding("urlscan", line)

            if server:
                yield Finding("urlscan", f"[bold]Server:[/bold] [cyan]{server}[/cyan]")

            # ── Verdicts / malicious score ────────────────────────────────
            verdicts = data.get("verdicts", {})
            urlscan_v = verdicts.get("urlscan", {})
            overall_v = verdicts.get("overall", {})
            malicious = overall_v.get("malicious", False)
            score = urlscan_v.get("score", 0)
            categories = urlscan_v.get("categories", [])

            score_color = "red" if malicious else "green"
            yield Finding("urlscan", f"[bold]Malicious:[/bold] [{score_color}]{'Yes' if malicious else 'No'}[/{score_color}]  [dim]score: {score}[/dim]")
            if categories:
                yield Finding("urlscan", f"[bold]Categories:[/bold] [dim]{', '.join(categories)}[/dim]")

            # ── Tech stack (Wappalyzer) ───────────────────────────────────
            wappa = data.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", [])
            if wappa:
                yield Finding("urlscan", "[bold]Tech stack:[/bold]")
                for tech in wappa:
                    name = tech.get("app", "")
                    categories_t = [c.get("name", "") for c in tech.get("categories", [])]
                    cat_str = f"  [dim]{', '.join(categories_t)}[/dim]" if categories_t else ""
                    yield Finding("urlscan", f"  [cyan]{name}[/cyan]{cat_str}")

            # ── Security headers ──────────────────────────────────────────
            response_headers: dict = {}
            for req in data.get("data", {}).get("requests", [])[:1]:
                hdrs = req.get("response", {}).get("response", {}).get("headers", {})
                response_headers = {k.lower(): v for k, v in hdrs.items()}

            if response_headers:
                present = [h for h in _SECURITY_HEADERS if h in response_headers]
                missing = [h for h in _SECURITY_HEADERS if h not in response_headers]

                if present:
                    yield Finding("urlscan", "[bold]Security headers present:[/bold]")
                    for h in present:
                        yield Finding("urlscan", f"  [green]{h}[/green]")

                if missing:
                    yield Finding("urlscan", "[bold]Security headers missing:[/bold]")
                    for h in missing:
                        yield Finding("urlscan", f"  [red]{h}[/red]")

            # ── External domains / IPs contacted ─────────────────────────
            lists = data.get("lists", {})
            ext_domains = [d for d in lists.get("domains", []) if domain not in d]
            ips = lists.get("ips", [])

            if ext_domains:
                yield Finding("urlscan", f"[bold]External domains ({len(ext_domains)}):[/bold]")
                for d in ext_domains[:10]:
                    yield Finding("urlscan", f"  [dim]{d}[/dim]")

            if ips:
                yield Finding("urlscan", f"[bold]IPs contacted ({len(ips)}):[/bold]")
                for ip_addr in ips[:8]:
                    yield Finding("urlscan", f"  [green]{ip_addr}[/green]")
