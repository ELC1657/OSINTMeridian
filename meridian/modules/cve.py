from __future__ import annotations

import asyncio
import re
import time
from typing import AsyncIterator, Callable

import httpx
from rich.markup import escape

from .base import Finding, ReconModule
from .brief import _SPINNER

_NVD_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_WAIT_FOR  = {"urlscan", "shodan"}
_WAIT_SECS = 90

# Too generic to produce useful CVE searches
_SKIP = {
    "html", "css", "javascript", "json", "xml", "http/2", "http/1.1",
    "google", "font awesome", "bootstrap", "jquery", "react", "angular",
    "vue", "webpack", "lodash", "moment", "axios", "google analytics",
    "google tag manager", "youtube", "vimeo", "twitter", "facebook",
}


class CVEModule(ReconModule):
    name = "CVE Correlation"
    panel_id = "cve"

    def __init__(
        self,
        config: dict[str, str],
        get_panel_data: Callable[[], dict[str, dict]],
    ) -> None:
        super().__init__(config)
        self._get_panel_data = get_panel_data

    async def run(self, target: str) -> AsyncIterator[Finding]:
        # ── Wait for urlscan + shodan ─────────────────────────────────────────

        deadline  = time.monotonic() + _WAIT_SECS
        spin_idx  = 0

        while time.monotonic() < deadline:
            data         = self._get_panel_data()
            still_running = [
                pid for pid in _WAIT_FOR
                if data.get(pid, {}).get("status", "idle") in ("running", "idle")
            ]
            if not still_running:
                break
            remaining = int(deadline - time.monotonic())
            spin = _SPINNER[spin_idx % len(_SPINNER)]
            yield Finding(
                "cve",
                f"[dim]{spin} Waiting for: {', '.join(still_running)}  ({remaining}s)[/dim]",
                progress=True,
            )
            spin_idx += 1
            await asyncio.sleep(1.5)

        # ── Extract tech stack ────────────────────────────────────────────────

        data  = self._get_panel_data()
        techs = _extract_techs(data)

        if not techs:
            yield Finding("cve", "[dim]No technology stack detected[/dim]")
            return

        yield Finding(
            "cve",
            f"[dim]Querying NVD for {len(techs)} technologies...[/dim]",
            progress=True,
        )

        # ── NVD queries ───────────────────────────────────────────────────────

        nvd_key = self.get_key("nvd_api_key")
        headers = {"apiKey": nvd_key} if nvd_key else {}
        # Without key: 5 req/30s.  With key: 50 req/30s.
        delay   = 0.3 if nvd_key else 6.5

        hits: list[tuple[str, str, str, float, str]] = []

        async with httpx.AsyncClient(timeout=15) as client:
            for tech in techs:
                await asyncio.sleep(delay)
                try:
                    r = await client.get(
                        _NVD_URL,
                        params={
                            "keywordSearch":  tech,
                            "resultsPerPage": 5,
                            "cvssV3Severity": "HIGH",
                        },
                        headers=headers,
                    )
                    if r.status_code != 200:
                        continue

                    for vuln in r.json().get("vulnerabilities", []):
                        cve     = vuln.get("cve", {})
                        cve_id  = cve.get("id", "?")
                        desc    = next(
                            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                            "",
                        )[:120]

                        severity = "?"
                        score    = 0.0
                        metrics  = cve.get("metrics", {})
                        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                            m = metrics.get(key, [])
                            if m:
                                cvss_data = m[0].get("cvssData", {})
                                severity  = cvss_data.get("baseSeverity", "?")
                                score     = float(cvss_data.get("baseScore", 0))
                                break

                        hits.append((tech, cve_id, severity, score, desc))

                except Exception:
                    continue

        # ── Output ────────────────────────────────────────────────────────────

        if not hits:
            yield Finding("cve", "[green]No HIGH/CRITICAL CVEs matched detected stack[/green]")
            return

        hits.sort(key=lambda x: x[3], reverse=True)

        yield Finding(
            "cve",
            f"[bold red]{len(hits)} CVE(s) matched[/bold red]  [dim]against detected tech stack[/dim]",
        )
        yield Finding("cve", "")

        for tech, cve_id, severity, score, desc in hits:
            color = "red" if severity in ("CRITICAL", "HIGH") else "yellow"
            yield Finding(
                "cve",
                f"  [{color}]{escape(cve_id)}[/{color}]  [dim]{escape(tech)}[/dim]"
                f"  [{color}]{severity}  {score}[/{color}]",
            )
            if desc:
                yield Finding("cve", f"  [dim]{escape(desc)}[/dim]")
            yield Finding("cve", "")


def _extract_techs(data: dict) -> list[str]:
    techs: set[str] = set()

    # URLScan lines look like "WordPress  CMS, Blogs" or "Nginx  Web servers"
    for line in data.get("urlscan", {}).get("findings", []):
        parts = re.split(r"\s{2,}", line.strip())
        if parts:
            t = parts[0].strip()
            if t and len(t) > 1 and t.lower() not in _SKIP:
                techs.add(t)

    # Shodan lines may contain "Apache httpd 2.4.49" style strings
    for line in data.get("shodan", {}).get("findings", []):
        m = re.match(r"^([A-Za-z][A-Za-z0-9 \-\.]{2,30}?)\s+\d[\d\.]+", line.strip())
        if m:
            t = m.group(1).strip()
            if t.lower() not in _SKIP:
                techs.add(t)

    # Cap to avoid hammering NVD
    return list(techs)[:12]
