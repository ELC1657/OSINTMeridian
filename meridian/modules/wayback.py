from typing import AsyncIterator
from urllib.parse import urlparse

import httpx

from .base import Finding, ReconModule, _normalize

_INTERESTING_EXT = {
    ".env", ".bak", ".backup", ".sql", ".log", ".conf", ".config",
    ".xml", ".json", ".yaml", ".yml", ".pem", ".key", ".p12",
    ".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z",
    ".csv", ".xls", ".xlsx", ".doc", ".docx", ".pdf",
    ".sh", ".php", ".asp", ".aspx", ".jsp",
}

_INTERESTING_PATH_PREFIXES = (
    "/admin", "/api/", "/v1/", "/v2/", "/internal",
    "/debug", "/config", "/backup", "/wp-admin", "/wp-login",
    "/.git", "/.env", "/phpinfo", "/server-status", "/server-info",
    "/actuator", "/.well-known", "/graphql", "/swagger",
    "/jenkins", "/jira", "/confluence",
)


class WaybackModule(ReconModule):
    name = "Wayback Machine"
    panel_id = "wayback"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}&output=json"
            f"&fl=original,statuscode,timestamp"
            f"&collapse=urlkey&limit=2000&matchType=domain"
        )

        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                r = await client.get(url, follow_redirects=True)
                r.raise_for_status()
                data = r.json()
            except Exception as e:
                yield Finding("wayback", f"[red]Error: {e}[/red]")
                return

        if not data or len(data) <= 1:
            yield Finding("wayback", "[dim]No archived URLs found[/dim]")
            return

        rows = data[1:]  # skip header row
        yield Finding("wayback", f"[bold]Archived URLs:[/bold] [green]{len(rows)}[/green]")

        interesting: list[tuple[str, str, str]] = []
        path_set: set[str] = set()
        subdomain_set: set[str] = set()

        for row in rows:
            if len(row) < 3:
                continue
            original, status, timestamp = row[0], row[1], row[2]

            try:
                parsed = urlparse(original)
            except Exception:
                continue

            host = parsed.netloc.lower()
            path = parsed.path

            # Track unique subdomains discovered via Wayback
            subdomain_set.add(host)

            # Dedupe by path
            if path in path_set:
                continue
            path_set.add(path)

            path_lower = path.lower()
            ext = ""
            if "." in path_lower.rsplit("/", 1)[-1]:
                ext = "." + path_lower.rsplit(".", 1)[-1].split("?")[0]

            is_interesting_ext = ext in _INTERESTING_EXT
            is_interesting_path = any(path_lower.startswith(p) for p in _INTERESTING_PATH_PREFIXES)

            if is_interesting_ext or is_interesting_path:
                interesting.append((status, path, timestamp[:8]))

        # Unique subdomains from wayback
        if subdomain_set:
            yield Finding("wayback", f"[bold]Unique hosts seen:[/bold] [cyan]{len(subdomain_set)}[/cyan]")
            for h in sorted(subdomain_set)[:15]:
                yield Finding("wayback", f"  [dim]{h}[/dim]")

        # Interesting findings
        if interesting:
            yield Finding("wayback", f"[bold yellow]Interesting URLs ({len(interesting)}):[/bold yellow]")
            for status, path, date in sorted(interesting, key=lambda x: x[1]):
                try:
                    code = int(status)
                    color = "green" if 200 <= code < 300 else "yellow" if 300 <= code < 400 else "dim"
                except ValueError:
                    color = "dim"
                yield Finding("wayback", f"  [{color}]{status}[/{color}]  {path}  [dim]{date}[/dim]")
        else:
            yield Finding("wayback", "[dim]No particularly interesting paths found[/dim]")

        # Sample of all paths (unique, sorted)
        all_paths = sorted(path_set)
        sample = all_paths[:40]
        if sample:
            yield Finding("wayback", f"[bold]Path sample ({len(all_paths)} unique):[/bold]")
            for p in sample:
                yield Finding("wayback", f"  [dim]{p}[/dim]")
