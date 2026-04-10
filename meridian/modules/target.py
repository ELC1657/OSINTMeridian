from __future__ import annotations

import asyncio
import re
from enum import Enum


class TargetMode(Enum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    ORG = "org"
    PERSON = "person"


async def resolve_target(
    mode: TargetMode, raw: str
) -> tuple[TargetMode, str, str | None]:
    """Return (mode, canonical, domain_hint).

    canonical   – normalised input used for display and mode-specific modules
    domain_hint – domain for domain-oriented modules; None for PERSON
    """
    raw = raw.strip()

    if mode == TargetMode.DOMAIN:
        canonical = _strip_scheme(raw)
        return mode, canonical, canonical

    if mode == TargetMode.IP:
        domain_hint = await _reverse_dns(raw)
        return mode, raw, domain_hint

    if mode == TargetMode.EMAIL:
        domain = raw.split("@")[-1] if "@" in raw else raw
        return mode, raw, _strip_scheme(domain)

    if mode == TargetMode.ORG:
        domain_hint = await _org_to_domain(raw)
        return mode, raw, domain_hint

    # PERSON
    return mode, raw, None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _strip_scheme(s: str) -> str:
    if "://" in s:
        s = s.split("://", 1)[1]
    return s.split("/")[0].strip()


async def _reverse_dns(ip: str) -> str | None:
    """Best-effort PTR lookup; returns the first hostname or None."""
    try:
        import socket
        loop = asyncio.get_event_loop()
        host, *_ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return host
    except Exception:
        return None


async def _org_to_domain(org: str) -> str | None:
    """Resolve an organisation name to its primary domain.

    Tries Clearbit Autocomplete first (no key required), then falls back to
    DuckDuckGo Instant Answers.
    """
    import httpx

    # Clearbit autocomplete — free, no key needed
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.get(
                "https://autocomplete.clearbit.com/v1/companies/suggest",
                params={"query": org},
            )
            if r.status_code == 200:
                data = r.json()
                if data:
                    domain = data[0].get("domain")
                    if domain:
                        return domain
    except Exception:
        pass

    # DuckDuckGo Instant Answer fallback
    try:
        async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
            r = await client.get(
                "https://api.duckduckgo.com/",
                params={
                    "q": f"{org} official website",
                    "format": "json",
                    "no_redirect": "1",
                },
            )
            if r.status_code == 200:
                data = r.json()
                url = data.get("AbstractURL", "")
                if url:
                    m = re.search(r"https?://(?:www\.)?([^/\s]+)", url)
                    if m:
                        return m.group(1)
    except Exception:
        pass

    return None
