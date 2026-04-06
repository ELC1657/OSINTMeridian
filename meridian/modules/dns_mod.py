import asyncio
from typing import AsyncIterator

import dns.asyncresolver
import dns.exception
import dns.query
import dns.resolver
import dns.zone

from .base import Finding, ReconModule, _normalize

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]

_COLORS = {
    "A": "green",
    "AAAA": "bright_green",
    "MX": "yellow",
    "NS": "cyan",
    "TXT": "magenta",
    "CNAME": "blue",
    "SOA": "white",
    "CAA": "bright_cyan",
}


async def _resolve(resolver: dns.asyncresolver.Resolver, domain: str, rtype: str):
    return rtype, await resolver.resolve(domain, rtype)


class DNSModule(ReconModule):
    name = "DNS Records"
    panel_id = "dns"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        resolver = dns.asyncresolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        tasks = [asyncio.create_task(_resolve(resolver, domain, rt)) for rt in _RECORD_TYPES]

        for task in asyncio.as_completed(tasks):
            try:
                rtype, answers = await task
            except dns.resolver.NXDOMAIN:
                yield Finding("dns", f"[red]NXDOMAIN - domain does not exist[/red]")
                # Cancel remaining tasks and stop
                for t in tasks:
                    t.cancel()
                return
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                continue
            except dns.exception.DNSException:
                continue
            except Exception as e:
                yield Finding("dns", f"[dim]Error for {rtype}: {e}[/dim]")
                continue

            color = _COLORS.get(rtype, "white")
            for rdata in answers:
                text = rdata.to_text()
                yield Finding("dns", f"[{color}]{rtype:<6}[/{color}]  {text}")

        # Zone transfer attempt (AXFR) - passive-safe, just a query
        try:
            zone = dns.asyncresolver.Resolver()
            zone.nameservers = ["8.8.8.8"]
            ns_answers = await zone.resolve(domain, "NS")
            for ns_rdata in ns_answers:
                ns_host = str(ns_rdata.target).rstrip(".")
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=3))
                    names = list(z.nodes.keys())
                    if names:
                        yield Finding("dns", f"[bold red]AXFR SUCCESS on {ns_host}! ({len(names)} records)[/bold red]")
                except Exception:
                    pass
        except Exception:
            pass
