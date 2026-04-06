from typing import AsyncIterator

import httpx

from .base import Finding, ReconModule, _normalize


class CrtShModule(ReconModule):
    name = "Subdomains"
    panel_id = "crtsh"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)
        url = f"https://crt.sh/?q=%.{domain}&output=json"

        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                r = await client.get(url, follow_redirects=True)
                r.raise_for_status()
                data = r.json()
            except httpx.HTTPError as e:
                yield Finding("crtsh", f"[red]HTTP error: {e}[/red]")
                return
            except Exception as e:
                yield Finding("crtsh", f"[red]Error: {e}[/red]")
                return

        seen: set[str] = set()
        wildcards: list[str] = []
        subs: list[str] = []

        for entry in data:
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip()
                if not name or domain not in name:
                    continue
                is_wildcard = name.startswith("*.")
                clean = name.lstrip("*.")
                if clean in seen:
                    continue
                seen.add(clean)
                if is_wildcard:
                    wildcards.append(clean)
                else:
                    subs.append(clean)

        total = len(seen)
        yield Finding("crtsh", f"[bold]Total unique:[/bold] [green]{total}[/green]")

        if wildcards:
            yield Finding("crtsh", "[bold]Wildcards:[/bold]")
            for w in sorted(wildcards):
                yield Finding("crtsh", f"  [yellow]*.{w}[/yellow]")

        if subs:
            yield Finding("crtsh", "[bold]Subdomains:[/bold]")
            for s in sorted(subs):
                # Highlight interesting subdomains
                keywords = ("admin", "api", "dev", "staging", "test", "internal",
                            "vpn", "mail", "smtp", "ftp", "jenkins", "jira",
                            "confluence", "gitlab", "github", "s3", "beta", "prod")
                color = "yellow" if any(k in s for k in keywords) else "cyan"
                yield Finding("crtsh", f"  [{color}]{s}[/{color}]")
