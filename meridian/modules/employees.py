from __future__ import annotations

import asyncio
from typing import AsyncIterator

import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize

_HUNTER_BASE  = "https://api.hunter.io/v2"
_APOLLO_BASE  = "https://api.apollo.io/v1"
_GITHUB_API   = "https://api.github.com"

# Role keyword -> attack value score (0-10)
_ROLE_SCORES: list[tuple[str, int]] = [
    ("chief executive", 10), ("ceo", 10), ("founder", 10), ("co-founder", 10), ("president", 10),
    ("chief financial", 9),  ("cfo", 9),
    ("chief technology", 9), ("chief technical", 9), ("cto", 9),
    ("chief security", 9),   ("chief information security", 9), ("ciso", 9),
    ("chief operating", 9),  ("coo", 9),
    ("vice president", 8),   ("vp ", 8),
    ("payroll", 8), ("treasurer", 8), ("finance director", 8),
    ("financial controller", 8), ("accounting", 7), ("accountant", 7),
    ("it director", 8), ("it manager", 8), ("head of it", 8),
    ("sysadmin", 8), ("system administrator", 8), ("systems administrator", 8),
    ("security engineer", 8), ("security analyst", 7),
    ("devops", 7), ("infrastructure", 7), ("cloud", 7), ("network", 7),
    ("software architect", 7), ("lead engineer", 7), ("principal", 7),
    ("developer", 5), ("engineer", 5), ("software", 5),
    ("hr director", 7), ("hr manager", 6),
    ("human resources", 6), ("talent", 5), ("recruitment", 5),
    ("director", 6), ("head of", 6), ("manager", 5),
    ("sales", 4), ("marketing", 4), ("business development", 4),
    ("support", 3), ("customer success", 3), ("intern", 2),
]


def _role_score(position: str) -> int:
    p = position.lower()
    for keyword, score in _ROLE_SCORES:
        if keyword in p:
            return score
    return 3


def _score_bar(score: float) -> str:
    filled = round(score)
    return "█" * filled + "░" * (10 - filled)


def _render_employee(
    rank: int,
    name: str,
    position: str,
    address: str,
    score: float,
    source: str,
    extra: str = "",
) -> list[Finding]:
    if score >= 9:
        color = "red";    tag = "[bold red]HIGH VALUE[/bold red]"
    elif score >= 7:
        color = "yellow"; tag = "[yellow]MED VALUE[/yellow]"
    else:
        color = "cyan";   tag = "[dim]STD[/dim]"

    bar = _score_bar(score)
    lines: list[Finding] = [
        Finding("employees", f"[dim]#{rank:02d}[/dim]  [{color}]{escape(name)}[/{color}]  {tag}  [dim]{source}[/dim]"),
    ]
    if position:
        lines.append(Finding("employees", f"      [dim]{escape(position)}[/dim]"))
    if address:
        lines.append(Finding("employees", f"      [cyan]{escape(address)}[/cyan]"))
    if extra:
        lines.append(Finding("employees", f"      [dim]{escape(extra)}[/dim]"))
    lines.append(Finding("employees", f"      [dim]{bar}[/dim]  [bold]{score:.1f}[/bold]/10"))
    lines.append(Finding("employees", ""))
    return lines


class EmployeesModule(ReconModule):
    name = "Employee Targets"
    panel_id = "employees"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        hunter_key  = self.get_key("hunter_api_key")
        apollo_key  = self.get_key("apollo_api_key")
        github_token = self.get_key("github_token")

        if not any([hunter_key, apollo_key, github_token]):
            yield Finding("employees", "[yellow]No API keys configured[/yellow]")
            yield Finding("employees", "[dim]Keys that unlock this panel:[/dim]")
            yield Finding("employees", "[dim]  HUNTER_API_KEY  — hunter.io (free)[/dim]")
            yield Finding("employees", "[dim]  APOLLO_API_KEY  — apollo.io (free, 50 credits/mo)[/dim]")
            yield Finding("employees", "[dim]  GITHUB_TOKEN    — already set if using GitHub Dorks[/dim]")
            return

        scored: list[tuple[float, str, str, str, str, str]] = []
        # (score, name, position, email/url, source, extra)

        # ── Hunter.io ─────────────────────────────────────────────────────────
        if hunter_key:
            async for f in _hunter_employees(domain, hunter_key):
                if isinstance(f, tuple):
                    scored.append(f)
                else:
                    yield f

        # ── Apollo.io ─────────────────────────────────────────────────────────
        if apollo_key:
            async for f in _apollo_employees(domain, apollo_key):
                if isinstance(f, tuple):
                    scored.append(f)
                else:
                    yield f

        # ── GitHub org members ────────────────────────────────────────────────
        if github_token:
            async for f in _github_employees(domain, github_token):
                if isinstance(f, tuple):
                    scored.append(f)
                else:
                    yield f

        if not scored:
            yield Finding("employees", "[dim]No employee data found across all sources[/dim]")
            return

        # Deduplicate by name (case-insensitive)
        seen_names: set[str] = set()
        unique: list[tuple[float, str, str, str, str, str]] = []
        for entry in scored:
            key = entry[1].lower().strip()
            if key and key not in seen_names:
                seen_names.add(key)
                unique.append(entry)

        unique.sort(key=lambda x: x[0], reverse=True)

        yield Finding("employees", f"[bold]{len(unique)} employees found[/bold]  [dim]ranked by attack value[/dim]")
        yield Finding("employees", "")

        for rank, (score, name, position, address, source, extra) in enumerate(unique, 1):
            for f in _render_employee(rank, name, position, address, score, source, extra):
                yield f


# ── Hunter.io source ──────────────────────────────────────────────────────────

async def _hunter_employees(domain: str, api_key: str):
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(
                f"{_HUNTER_BASE}/domain-search",
                params={"domain": domain, "api_key": api_key, "limit": 100},
            )
            body = r.json()
    except Exception as exc:
        yield Finding("employees", f"[red]Hunter.io error: {exc}[/red]")
        return

    if r.status_code == 401:
        yield Finding("employees", "[red]Hunter.io: invalid API key[/red]")
        return
    if r.status_code == 429:
        yield Finding("employees", "[yellow]Hunter.io: rate limit hit[/yellow]")
        return

    data        = body.get("data", {})
    emails      = data.get("emails", [])
    email_count = data.get("emails_count", 0)

    for err in body.get("errors", []):
        details = err.get("details", "")
        if details:
            yield Finding("employees", f"[yellow]Hunter.io: {escape(details)}[/yellow]")

    if not emails:
        if email_count and email_count > 0:
            yield Finding("employees", f"[yellow]Hunter.io: {email_count} emails known — restricted on your plan[/yellow]")
        return

    for entry in emails:
        position   = (entry.get("position", "") or "").strip()
        confidence = entry.get("confidence", 0)
        first      = (entry.get("first_name", "") or "").strip()
        last       = (entry.get("last_name",  "") or "").strip()
        address    = entry.get("value", "")
        name       = f"{first} {last}".strip() or "Unknown"
        role_s     = _role_score(position)
        conf_bonus = round((confidence / 100) * 2, 1)
        score      = min(10.0, role_s + conf_bonus)
        yield (score, name, position, address, "Hunter.io", f"{confidence}% confidence")


# ── Apollo.io source ──────────────────────────────────────────────────────────

async def _apollo_employees(domain: str, api_key: str):
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                f"{_APOLLO_BASE}/mixed_people/search",
                json={
                    "api_key":        api_key,
                    "q_organization_domains": domain,
                    "page":           1,
                    "per_page":       25,
                },
                headers={"Content-Type": "application/json"},
            )
            body = r.json()
    except Exception as exc:
        yield Finding("employees", f"[red]Apollo.io error: {exc}[/red]")
        return

    if r.status_code == 401 or r.status_code == 403:
        yield Finding("employees", "[red]Apollo.io: invalid API key[/red]")
        return
    if r.status_code == 422:
        yield Finding("employees", "[yellow]Apollo.io: no data for this domain[/yellow]")
        return
    if r.status_code != 200:
        yield Finding("employees", f"[yellow]Apollo.io: HTTP {r.status_code}[/yellow]")
        return

    people = body.get("people", []) or []
    if not people:
        return

    for person in people:
        first    = (person.get("first_name") or "").strip()
        last     = (person.get("last_name")  or "").strip()
        name     = f"{first} {last}".strip() or "Unknown"
        title    = (person.get("title") or "").strip()
        email    = person.get("email") or ""
        linkedin = person.get("linkedin_url") or ""
        city     = person.get("city") or ""
        country  = person.get("country") or ""
        location = ", ".join(filter(None, [city, country]))

        score = min(10.0, float(_role_score(title)))
        address = email or linkedin
        yield (score, name, title, address, "Apollo.io", location)


# ── GitHub org members ────────────────────────────────────────────────────────

async def _github_employees(domain: str, token: str):
    base    = domain.split(".")[0]
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Try org names derived from domain
    candidates = [base, domain.replace(".", ""), domain.replace(".", "-")]

    org_name = None
    async with httpx.AsyncClient(timeout=15) as client:
        for candidate in candidates:
            try:
                r = await client.get(f"{_GITHUB_API}/orgs/{candidate}", headers=headers)
                if r.status_code == 200:
                    org_name = candidate
                    break
            except Exception:
                continue

    if not org_name:
        return

    yield Finding("employees", f"[dim]GitHub org found: [cyan]{escape(org_name)}[/cyan][/dim]")

    # Fetch public members (up to 100)
    members: list[dict] = []
    async with httpx.AsyncClient(timeout=20) as client:
        try:
            r = await client.get(
                f"{_GITHUB_API}/orgs/{org_name}/members",
                params={"per_page": 100, "filter": "all"},
                headers=headers,
            )
            if r.status_code == 200:
                members = r.json() or []
        except Exception:
            return

    if not members:
        return

    # Fetch profile details concurrently (cap at 40 to avoid rate limits)
    sem = asyncio.Semaphore(5)

    async def _fetch_user(login: str) -> dict | None:
        async with sem:
            try:
                async with httpx.AsyncClient(timeout=10) as c:
                    r = await c.get(f"{_GITHUB_API}/users/{login}", headers=headers)
                    if r.status_code == 200:
                        return r.json()
            except Exception:
                pass
            return None

    tasks   = [_fetch_user(m["login"]) for m in members[:40]]
    results = await asyncio.gather(*tasks)

    for profile in results:
        if not profile:
            continue
        name     = (profile.get("name")    or profile.get("login") or "").strip()
        bio      = (profile.get("bio")     or "").strip()
        email    = (profile.get("email")   or "").strip()
        company  = (profile.get("company") or "").strip().lstrip("@")
        login    = profile.get("login", "")
        url      = f"github.com/{login}"

        position = bio or company or ""
        address  = email or url
        score    = min(10.0, float(_role_score(position)))

        yield (score, name or login, position, address, "GitHub", url if email else "")
