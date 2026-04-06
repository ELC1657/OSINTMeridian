from __future__ import annotations

import time
from typing import AsyncIterator, Callable

import asyncio
from rich.markup import escape

_SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

from .base import Finding, ReconModule, _normalize

# Wait for these panels before generating the brief
_WAIT_FOR = {
    "spoof", "takeover", "breach", "github", "hunter",
    "crtsh", "jsscan", "params", "urlscan", "asn",
}
_WAIT_TIMEOUT = 120  # seconds


class AttackBriefModule(ReconModule):
    name = "Attack Brief"
    panel_id = "brief"

    def __init__(
        self,
        config: dict[str, str],
        get_panel_data: Callable[[], dict[str, dict]],
    ) -> None:
        super().__init__(config)
        self._get_panel_data = get_panel_data

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)
        deadline = time.monotonic() + _WAIT_TIMEOUT
        spin_idx = 0

        while time.monotonic() < deadline:
            data = self._get_panel_data()
            still_running = [
                pid for pid in _WAIT_FOR
                if data.get(pid, {}).get("status", "idle") in ("running", "idle")
            ]
            if not still_running:
                break
            remaining = int(deadline - time.monotonic())
            spin = _SPINNER[spin_idx % len(_SPINNER)]
            yield Finding(
                "brief",
                f"[dim]{spin} Waiting for: {', '.join(still_running)}  ({remaining}s)[/dim]",
                progress=True,
            )
            spin_idx += 1
            await asyncio.sleep(3)

        data = self._get_panel_data()
        for finding in _synthesize(domain, data):
            yield finding


# ── Synthesis ─────────────────────────────────────────────────────────────────

def _synthesize(domain: str, data: dict[str, dict]) -> list[Finding]:
    critical: list[str] = []
    high:     list[str] = []
    medium:   list[str] = []
    info:     list[str] = []

    # ── Spoofability ──────────────────────────────────────────────────────────
    spoof_lines = data.get("spoof", {}).get("findings", [])
    spoofable = any("SPOOFABLE" in l for l in spoof_lines)
    softfail  = any("~all" in l for l in spoof_lines)
    if spoofable:
        hunter_lines = data.get("hunter", {}).get("findings", [])
        email_line = next((l for l in hunter_lines if "Emails found:" in l), None)
        email_count = _parse_int(email_line) if email_line else 0
        if email_count >= 3:
            critical.append(
                f"PHISHING READY: Domain spoofable + {email_count} emails via Hunter.io\n"
                f"  Craft From: exec@{domain} using discovered employee list"
            )
        else:
            high.append("Domain is email-spoofable (DMARC p=none or missing)")
    elif softfail:
        medium.append("SPF softfail (~all): spoofed mail may still reach inboxes")

    # ── Subdomain takeover ────────────────────────────────────────────────────
    takeover_lines = data.get("takeover", {}).get("findings", [])
    vuln_lines = [l for l in takeover_lines if "VULN" in l]
    if vuln_lines:
        critical.append(
            f"SUBDOMAIN TAKEOVER: {len(vuln_lines)} vulnerable subdomain(s) detected"
        )
        for l in vuln_lines[:3]:
            critical.append(f"  {l.strip()}")

    # ── JS secrets ────────────────────────────────────────────────────────────
    js_lines = data.get("jsscan", {}).get("findings", [])
    js_secrets = [l for l in js_lines if "FOUND" in l]
    if js_secrets:
        critical.append(
            f"HARDCODED SECRETS: {len(js_secrets)} secret(s) found in JS files"
        )
        for l in js_secrets[:3]:
            critical.append(f"  {l.strip()}")

    # ── Breach data ───────────────────────────────────────────────────────────
    breach_lines = data.get("breach", {}).get("findings", [])
    breach_header = next((l for l in breach_lines if "breach" in l.lower() and "found" in l.lower()), None)
    if breach_header and "No breaches" not in breach_header:
        # Count names of breaches (non-indented, non-empty lines after header)
        breach_names = [
            l.strip() for l in breach_lines
            if l.strip() and not l.startswith(" ") and l.strip() != breach_header
        ]
        high.append(
            f"BREACH DATA: {breach_header.strip()}\n"
            f"  Credential stuffing viable — check combo lists"
        )

    # ── GitHub exposure ───────────────────────────────────────────────────────
    github_count = data.get("github", {}).get("count", 0)
    if github_count > 8:
        high.append(
            f"GITHUB EXPOSURE: {github_count} results across code dork queries\n"
            f"  Review manually for hardcoded secrets and internal endpoints"
        )
    elif github_count > 0:
        medium.append(f"GitHub: {github_count} code results found — manual review recommended")

    # ── SSRF / interesting params ─────────────────────────────────────────────
    param_lines = data.get("params", {}).get("findings", [])
    ssrf_params = [
        l.strip() for l in param_lines
        if l.strip() and "=" in l
        and any(p in l for p in ("url=", "redirect=", "return=", "host=", "src=", "dest=", "file="))
    ]
    if ssrf_params:
        high.append(
            f"SSRF CANDIDATES: {len(ssrf_params)} redirect/SSRF parameter(s) in archived URLs\n"
            f"  {', '.join(p.split()[0] for p in ssrf_params[:4])}"
        )

    # ── Sensitive paths ───────────────────────────────────────────────────────
    sensitive_paths = [l for l in param_lines if "[!]" in l or ".env" in l or ".git" in l]
    if sensitive_paths:
        medium.append(
            f"SENSITIVE PATHS: {len(sensitive_paths)} sensitive path(s) in archive\n"
            + "\n".join(f"  {p.strip()}" for p in sensitive_paths[:3])
        )

    # ── Missing security headers ──────────────────────────────────────────────
    urlscan_lines = data.get("urlscan", {}).get("findings", [])
    missing_hdrs_idx = next(
        (i for i, l in enumerate(urlscan_lines) if "missing" in l.lower()), None
    )
    if missing_hdrs_idx is not None:
        missing = [
            urlscan_lines[j].strip()
            for j in range(missing_hdrs_idx + 1, min(missing_hdrs_idx + 6, len(urlscan_lines)))
            if urlscan_lines[j].strip()
        ]
        if missing:
            medium.append(f"Missing headers: {', '.join(missing[:4])}")

    # ── Info ──────────────────────────────────────────────────────────────────
    crtsh_lines  = data.get("crtsh", {}).get("findings", [])
    sub_line = next((l for l in crtsh_lines if "Total unique:" in l), None)
    if sub_line:
        info.append(sub_line.strip())

    asn_lines = data.get("asn", {}).get("findings", [])
    asn_line  = next((l for l in asn_lines if l.strip().startswith("AS") or "AS" in l[:6]), None)
    v4_line   = next((l for l in asn_lines if "IPv4" in l), None)
    if asn_line:
        info.append(f"ASN: {asn_line.strip()}")
    if v4_line:
        info.append(v4_line.strip())

    tech_idx = next((i for i, l in enumerate(urlscan_lines) if "Tech stack:" in l), None)
    if tech_idx is not None:
        import re as _re
        techs = []
        for j in range(tech_idx + 1, min(tech_idx + 12, len(urlscan_lines))):
            line = urlscan_lines[j].strip()
            if not line or "Missing" in line or "Security" in line:
                break
            # "WordPress  CMS, Blogs" -> "WordPress"
            name = _re.split(r"\s{2,}", line)[0].strip()
            if name:
                techs.append(name)
        if techs:
            info.append(f"Tech: {', '.join(techs[:6])}")

    # ── Assemble output ───────────────────────────────────────────────────────
    findings: list[Finding] = []

    def _divider(label: str, color: str) -> None:
        findings.append(Finding("brief", f"[bold {color}]{label}[/bold {color}]"))

    score = "CRITICAL" if critical else "HIGH" if high else "MEDIUM" if medium else "LOW"
    score_color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "green"}[score]

    findings.append(Finding("brief", f"[bold]MERIDIAN ATTACK BRIEF[/bold]  [dim]{domain}[/dim]"))
    findings.append(Finding("brief", f"Risk level: [bold {score_color}]{score}[/bold {score_color}]"))
    findings.append(Finding("brief", ""))

    if critical:
        _divider("CRITICAL", "red")
        for i, item in enumerate(critical, 1):
            for j, line in enumerate(item.split("\n")):
                prefix = f"  {i}. " if j == 0 else "     "
                findings.append(Finding("brief", f"[red]{prefix}{escape(line)}[/red]"))
        findings.append(Finding("brief", ""))

    if high:
        _divider("HIGH", "yellow")
        for i, item in enumerate(high, 1):
            for j, line in enumerate(item.split("\n")):
                prefix = f"  {i}. " if j == 0 else "     "
                findings.append(Finding("brief", f"[yellow]{prefix}{escape(line)}[/yellow]"))
        findings.append(Finding("brief", ""))

    if medium:
        _divider("MEDIUM", "cyan")
        for i, item in enumerate(medium, 1):
            for j, line in enumerate(item.split("\n")):
                prefix = f"  {i}. " if j == 0 else "     "
                findings.append(Finding("brief", f"[cyan]{prefix}{escape(line)}[/cyan]"))
        findings.append(Finding("brief", ""))

    if info:
        _divider("INFO", "dim")
        for item in info:
            findings.append(Finding("brief", f"  [dim]{escape(item)}[/dim]"))

    if not any([critical, high, medium]):
        findings.append(Finding("brief", "[green]No significant attack surface detected[/green]"))

    return findings


def _parse_int(text: str) -> int:
    import re
    m = re.search(r"\d+", text)
    return int(m.group(0)) if m else 0
