from __future__ import annotations

from typing import AsyncIterator

import httpx
from rich.markup import escape

from .base import Finding, ReconModule


class PersonModule(ReconModule):
    """OSINT gathering for a named individual."""

    name = "Person Intel"
    panel_id = "person"

    async def run(self, target: str) -> AsyncIterator[Finding]:  # type: ignore[override]
        """target = full person name, e.g. 'John Smith'"""
        parts = target.strip().split()
        first = parts[0].lower() if parts else target.lower()
        last = parts[-1].lower() if len(parts) > 1 else ""

        yield Finding("person", f"[bold]Person:[/bold] {escape(target)}", progress=True)

        async for f in self._github_users(target):
            yield f

        if first and last:
            async for f in self._email_perms(first, last):
                yield f

        async for f in self._dehashed(target):
            yield f

        async for f in self._github_code(target):
            yield f

    # ── GitHub user search ────────────────────────────────────────────────────

    async def _github_users(self, name: str) -> AsyncIterator[Finding]:
        token = self.get_key("github_token")
        headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        try:
            async with httpx.AsyncClient(timeout=10, headers=headers) as client:
                r = await client.get(
                    "https://api.github.com/search/users",
                    params={"q": name, "per_page": 5},
                )
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    if items:
                        yield Finding("person", "[bold cyan]── GitHub Profiles ──[/bold cyan]")
                        for u in items:
                            login = escape(u.get("login", ""))
                            url = escape(u.get("html_url", ""))
                            score = u.get("score", 0)
                            yield Finding(
                                "person",
                                f"  [cyan]{login}[/cyan]  [dim]{url}[/dim]  [dim]score={score:.0f}[/dim]",
                            )
        except Exception:
            pass

    # ── Email permutations ────────────────────────────────────────────────────

    async def _email_perms(self, first: str, last: str) -> AsyncIterator[Finding]:
        perms = [
            f"{first}.{last}",
            f"{first[0]}{last}",
            f"{first}{last[0]}",
            f"{first}_{last}",
            f"{last}.{first}",
            f"{first}",
        ]
        yield Finding("person", "[bold cyan]── Email Permutations ──[/bold cyan]")
        yield Finding("person", "[dim]  (append @company.com to each)[/dim]")
        for p in perms:
            yield Finding("person", f"  {escape(p)}")

    # ── Dehashed by name ──────────────────────────────────────────────────────

    async def _dehashed(self, name: str) -> AsyncIterator[Finding]:
        email = self.get_key("dehashed_email")
        key = self.get_key("dehashed_api_key")
        if not (email and key):
            return

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(
                    "https://api.dehashed.com/search",
                    params={"query": f'name:"{name}"', "size": 10},
                    auth=(email, key),
                    headers={"Accept": "application/json"},
                )
                if r.status_code == 200:
                    entries = r.json().get("entries") or []
                    if entries:
                        yield Finding("person", "[bold red]── Dehashed Leaks ──[/bold red]")
                        for e in entries[:8]:
                            em = escape(e.get("email", ""))
                            pw = escape(e.get("password", ""))
                            db = escape(e.get("database_name", ""))
                            parts_out: list[str] = []
                            if em:
                                parts_out.append(f"[yellow]{em}[/yellow]")
                            if pw:
                                parts_out.append(f"pass:[red]{pw}[/red]")
                            if db:
                                parts_out.append(f"[dim]{db}[/dim]")
                            yield Finding("person", "  " + "  ".join(parts_out))
        except Exception:
            pass

    # ── GitHub code search ────────────────────────────────────────────────────

    async def _github_code(self, name: str) -> AsyncIterator[Finding]:
        token = self.get_key("github_token")
        if not token:
            return

        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
        }

        try:
            async with httpx.AsyncClient(timeout=10, headers=headers) as client:
                r = await client.get(
                    "https://api.github.com/search/code",
                    params={"q": f'"{name}"', "per_page": 5},
                )
                if r.status_code == 200:
                    items = r.json().get("items", [])
                    if items:
                        yield Finding("person", "[bold cyan]── GitHub Code Mentions ──[/bold cyan]")
                        for item in items[:5]:
                            repo = escape(item.get("repository", {}).get("full_name", ""))
                            path = escape(item.get("path", ""))
                            url = escape(item.get("html_url", ""))
                            yield Finding(
                                "person",
                                f"  [dim]{repo}[/dim]  {path}  [dim]{url}[/dim]",
                            )
        except Exception:
            pass
