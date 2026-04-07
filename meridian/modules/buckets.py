from __future__ import annotations

import asyncio
from typing import AsyncIterator

import httpx
from rich.markup import escape

from .base import Finding, ReconModule, _normalize


def _permutations(domain: str) -> list[tuple[str, str]]:
    base  = domain.split(".")[0]
    dash  = domain.replace(".", "-")

    names = [
        base, dash, domain,
        f"{base}-backup", f"{base}-backups",
        f"{base}-dev", f"{base}-development",
        f"{base}-staging", f"{base}-stage",
        f"{base}-prod", f"{base}-production",
        f"{base}-assets", f"{base}-static",
        f"{base}-media", f"{base}-uploads",
        f"{base}-data", f"{base}-files",
        f"{base}-logs", f"{base}-public",
        f"{base}-private", f"{base}-internal",
        f"{base}-cdn", f"{base}-images",
        f"{base}-api", f"api-{base}",
        f"www-{base}", f"{base}-test",
    ]

    results: list[tuple[str, str]] = []
    for n in names:
        results.append((f"https://{n}.s3.amazonaws.com",        f"AWS  {n}"))
        results.append((f"https://storage.googleapis.com/{n}",  f"GCP  {n}"))
        results.append((f"https://{n}.blob.core.windows.net",   f"Azure {n}"))
    return results


async def _probe(
    client: httpx.AsyncClient,
    sem: asyncio.Semaphore,
    url: str,
    label: str,
) -> tuple[str, str, int] | None:
    async with sem:
        try:
            r = await client.head(url, timeout=6, follow_redirects=False)
            return (url, label, r.status_code)
        except Exception:
            return None


class BucketsModule(ReconModule):
    name = "Cloud Buckets"
    panel_id = "buckets"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)
        targets = _permutations(domain)

        yield Finding(
            "buckets",
            f"[dim]Checking {len(targets)} bucket permutations (AWS / GCP / Azure)...[/dim]",
            progress=True,
        )

        sem = asyncio.Semaphore(12)
        async with httpx.AsyncClient(timeout=8) as client:
            tasks = [_probe(client, sem, url, label) for url, label in targets]
            results = await asyncio.gather(*tasks)

        # 200 = public read, 403 = bucket exists but private, 400/301 = sometimes exists
        found = [
            (url, label, code)
            for r in results if r is not None
            for url, label, code in [r]
            if code in (200, 403, 400)
        ]

        if not found:
            yield Finding("buckets", "[green]No cloud buckets found[/green]")
            return

        public  = [(u, l, c) for u, l, c in found if c == 200]
        private = [(u, l, c) for u, l, c in found if c != 200]

        yield Finding(
            "buckets",
            f"[bold]{len(found)} bucket(s) found[/bold]"
            + (f"  [bold red]{len(public)} PUBLIC[/bold red]" if public else ""),
        )
        yield Finding("buckets", "")

        for url, label, code in public:
            yield Finding("buckets", f"  [bold red]PUBLIC[/bold red]  [red]{escape(label)}[/red]")
            yield Finding("buckets", f"  [dim]{escape(url)}[/dim]")
            yield Finding("buckets", "")

        for url, label, code in private:
            yield Finding("buckets", f"  [yellow]EXISTS (private)[/yellow]  [cyan]{escape(label)}[/cyan]")
            yield Finding("buckets", f"  [dim]{escape(url)}[/dim]")
            yield Finding("buckets", "")
