import asyncio
from typing import AsyncIterator

import httpx

from .base import Finding, ReconModule, _normalize

_DORKS = [
    ('"{domain}"', "mentions"),
    ('"{domain}" password', "password"),
    ('"{domain}" secret', "secret"),
    ('"{domain}" api_key OR apikey OR api_secret', "API key"),
    ('"{domain}" token', "token"),
    ('"{domain}" DB_PASSWORD OR database_password', "DB creds"),
    ('{domain} filename:.env', ".env files"),
    ('{domain} filename:config.yml OR filename:config.yaml', "config YAML"),
    ('{domain} filename:.pem OR filename:.key', "private keys"),
    ('{domain} filename:wp-config.php', "WordPress config"),
]


class GitHubModule(ReconModule):
    name = "GitHub Dorks"
    panel_id = "github"
    requires_key = True
    key_env = "GITHUB_TOKEN"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        token = self.get_key("github_token")
        domain = _normalize(target)

        headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            headers["Authorization"] = f"token {token}"
        else:
            yield Finding("github", "[yellow]No GITHUB_TOKEN - heavily rate limited[/yellow]")

        async with httpx.AsyncClient(timeout=30.0, headers=headers) as client:
            seen_repos: set[str] = set()
            total_hits = 0

            for query_template, label in _DORKS:
                query = query_template.format(domain=domain)

                try:
                    r = await client.get(
                        "https://api.github.com/search/code",
                        params={"q": query, "per_page": 5, "sort": "indexed"},
                    )
                except httpx.HTTPError as e:
                    yield Finding("github", f"[red]Request error: {e}[/red]")
                    break

                if r.status_code == 403:
                    remaining = r.headers.get("X-RateLimit-Remaining", "?")
                    yield Finding("github", f"[red]Rate limited (remaining: {remaining})[/red]")
                    yield Finding("github", "[dim]Add GITHUB_TOKEN to increase limits[/dim]")
                    return

                if r.status_code == 422:
                    continue  # Invalid query syntax, skip

                if r.status_code != 200:
                    yield Finding("github", f"[dim]HTTP {r.status_code} for query: {label}[/dim]")
                    continue

                data = r.json()
                count = data.get("total_count", 0)

                if count > 0:
                    total_hits += count
                    yield Finding(
                        "github",
                        f"[bold yellow]{label}[/bold yellow]  [dim]({count} result{'s' if count != 1 else ''})[/dim]",
                    )

                    for item in data.get("items", [])[:4]:
                        repo = item.get("repository", {}).get("full_name", "?")
                        path = item.get("path", "?")
                        url = item.get("html_url", "")

                        marker = "[red bold]NEW[/red bold] " if repo not in seen_repos else ""
                        seen_repos.add(repo)
                        yield Finding("github", f"  {marker}[cyan]{repo}[/cyan]  [dim]{path}[/dim]")

                # GitHub code search rate limit: 10 req/min unauthenticated, 30 req/min authenticated
                await asyncio.sleep(2 if token else 6)

            if total_hits == 0:
                yield Finding("github", "[green]No dork results found[/green]")
            else:
                yield Finding("github", f"[bold]Total matches:[/bold] [red]{total_hits}[/red] across {len(seen_repos)} repo(s)")
