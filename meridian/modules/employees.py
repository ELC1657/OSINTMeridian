from __future__ import annotations

from typing import AsyncIterator

import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize

_BASE = "https://api.hunter.io/v2"

# Role keyword -> attack value score (0-10)
# High = direct system access or financial authority
_ROLE_SCORES: list[tuple[str, int]] = [
    # Executive — impersonation + social engineering goldmine
    ("chief executive", 10), ("ceo", 10), ("founder", 10), ("co-founder", 10), ("president", 10),
    ("chief financial", 9),  ("cfo", 9),
    ("chief technology", 9), ("chief technical", 9), ("cto", 9),
    ("chief security", 9),   ("chief information security", 9), ("ciso", 9),
    ("chief operating", 9),  ("coo", 9),
    ("vice president", 8),   ("vp ", 8),
    # Finance — wire transfer fraud vector
    ("payroll", 8), ("treasurer", 8), ("finance director", 8),
    ("financial controller", 8), ("accounting", 7), ("accountant", 7),
    # IT / Security — system access
    ("it director", 8), ("it manager", 8), ("head of it", 8),
    ("sysadmin", 8), ("system administrator", 8), ("systems administrator", 8),
    ("security engineer", 8), ("security analyst", 7),
    ("devops", 7), ("infrastructure", 7), ("cloud", 7), ("network", 7),
    # Engineering — code/secrets access
    ("software architect", 7), ("lead engineer", 7), ("principal", 7),
    ("developer", 5), ("engineer", 5), ("software", 5),
    # HR — employee data + onboarding phishing
    ("hr director", 7), ("hr manager", 6),
    ("human resources", 6), ("talent", 5), ("recruitment", 5),
    # Management
    ("director", 6), ("head of", 6), ("manager", 5),
    # Lower value
    ("sales", 4), ("marketing", 4), ("business development", 4),
    ("support", 3), ("customer success", 3), ("intern", 2),
]


def _role_score(position: str) -> int:
    p = position.lower()
    for keyword, score in _ROLE_SCORES:
        if keyword in p:
            return score
    return 3  # default — unknown role


def _score_bar(score: float) -> str:
    filled = round(score)
    return "█" * filled + "░" * (10 - filled)


class EmployeesModule(ReconModule):
    name = "Employee Targets"
    panel_id = "employees"
    requires_key = True
    key_env = "HUNTER_API_KEY"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        api_key = self.get_key("hunter_api_key")
        if not api_key:
            yield Finding("employees", "[yellow]No API key - set HUNTER_API_KEY[/yellow]")
            yield Finding("employees", "[dim]Shares key with Hunter.io panel[/dim]")
            return

        domain = _normalize(target)

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.get(
                    f"{_BASE}/domain-search",
                    params={"domain": domain, "api_key": api_key, "limit": 100},
                )
                body = r.json()
        except Exception as exc:
            yield Finding("employees", f"[red]Error: {exc}[/red]")
            return

        if r.status_code in (401,):
            yield Finding("employees", "[red]Invalid API key[/red]")
            return
        if r.status_code == 429:
            yield Finding("employees", "[red]Rate limit hit[/red]")
            return

        data        = body.get("data", {})
        emails      = data.get("emails", [])
        email_count = data.get("emails_count", 0)

        # Surface any plan/quota warnings from the API response
        for err in body.get("errors", []):
            details = err.get("details", "")
            if details:
                yield Finding("employees", f"[yellow]Note: {escape(details)}[/yellow]")

        if not emails:
            if email_count and email_count > 0:
                yield Finding(
                    "employees",
                    f"[yellow]{email_count} email{'s' if email_count != 1 else ''} known for this domain[/yellow]",
                )
                yield Finding(
                    "employees",
                    "[dim]Individual records restricted — Hunter.io paid plan required[/dim]",
                )
            elif not data:
                yield Finding("employees", "[dim]No data found for this domain[/dim]")
            else:
                yield Finding("employees", "[dim]No employees found for this domain[/dim]")
            return

        # Score each employee
        scored: list[tuple[float, dict]] = []
        for entry in emails:
            position   = entry.get("position", "") or ""
            confidence = entry.get("confidence", 0)
            role_s     = _role_score(position)
            # Confidence adds up to +2 bonus
            conf_bonus = round((confidence / 100) * 2, 1)
            total      = min(10.0, role_s + conf_bonus)
            scored.append((total, entry))

        scored.sort(key=lambda x: x[0], reverse=True)

        yield Finding("employees", f"[bold]{len(scored)} employees scored[/bold]  [dim]ranked by attack value[/dim]")
        yield Finding("employees", "")

        for rank, (score, entry) in enumerate(scored, 1):
            address    = entry.get("value", "")
            confidence = entry.get("confidence", 0)
            first      = (entry.get("first_name", "") or "").strip()
            last       = (entry.get("last_name",  "") or "").strip()
            position   = (entry.get("position",   "") or "").strip()
            name       = f"{first} {last}".strip() or "Unknown"

            if score >= 9:
                color = "red"
                tag   = "[bold red]HIGH VALUE[/bold red]"
            elif score >= 7:
                color = "yellow"
                tag   = "[yellow]MED VALUE[/yellow]"
            else:
                color = "cyan"
                tag   = "[dim]STD[/dim]"

            bar = _score_bar(score)

            yield Finding(
                "employees",
                f"[dim]#{rank:02d}[/dim]  [{color}]{escape(name)}[/{color}]  {tag}",
            )
            if position:
                yield Finding("employees", f"      [dim]{escape(position)}[/dim]")
            yield Finding(
                "employees",
                f"      [cyan]{escape(address)}[/cyan]  [dim]{confidence}% confidence[/dim]",
            )
            yield Finding(
                "employees",
                f"      [dim]{bar}[/dim]  [bold]{score:.1f}[/bold]/10",
            )
            yield Finding("employees", "")
