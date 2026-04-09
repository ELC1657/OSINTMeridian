from __future__ import annotations

import asyncio
import re
import shutil
from typing import AsyncIterator

from rich.markup import escape

from .base import Finding, ReconModule, _normalize

# Port → friendly service label for quick-win callouts
_INTERESTING: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPC",
    135:  "MSRPC",
    139:  "NetBIOS",
    143:  "IMAP",
    161:  "SNMP",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    587:  "SMTP Submission",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    4443: "HTTPS-alt",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    8888: "HTTP-alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

_HIGH_RISK = {21, 23, 111, 135, 139, 445, 161, 389, 1433, 1521, 2049, 3306,
              3389, 5900, 5985, 5986, 6379, 9200, 27017}


def _port_color(port: int, state: str) -> str:
    if state != "open":
        return "dim"
    if port in _HIGH_RISK:
        return "bold red"
    if port in _INTERESTING:
        return "yellow"
    return "green"


class NmapModule(ReconModule):
    name = "Port Scan (nmap)"
    panel_id = "nmap"

    async def run(self, target: str) -> AsyncIterator[Finding]:
        domain = _normalize(target)

        if not shutil.which("nmap"):
            yield Finding("nmap", "[red]nmap not found.[/red]")
            yield Finding("nmap", "  [dim]Install: brew install nmap[/dim]")
            return

        # Phase 1: fast TCP SYN scan of top 1000 ports
        yield Finding("nmap", "[dim]Phase 1 — fast scan: top 1000 ports (TCP)…[/dim]", progress=True)

        open_ports: list[int] = []
        port_info:  dict[int, tuple[str, str, str]] = {}  # port -> (state, service, version)

        cmd_fast = [
            "nmap", "-T4", "--top-ports", "1000",
            "-Pn",           # skip ping, treat host as up
            "--open",        # only show open ports
            "-n",            # no reverse DNS (speed)
            domain,
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd_fast,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            assert proc.stdout is not None
            async for raw in proc.stdout:
                line = raw.decode(errors="replace").rstrip()
                m = re.match(r"^(\d+)/tcp\s+(\S+)\s+(\S+)\s*(.*)", line)
                if m:
                    port    = int(m.group(1))
                    state   = m.group(2)
                    service = m.group(3)
                    version = m.group(4).strip()
                    if state == "open":
                        open_ports.append(port)
                        port_info[port] = (state, service, version)
            await proc.wait()
        except Exception as exc:
            yield Finding("nmap", f"[red]Scan error: {escape(str(exc))}[/red]")
            return

        if not open_ports:
            yield Finding("nmap", "[dim]No open ports found in top 1000.[/dim]")
            yield Finding("nmap", "  [dim]The host may be firewalled or offline.[/dim]")
            return

        yield Finding("nmap", f"[bold]{len(open_ports)} open port(s) — top 1000 TCP[/bold]")
        yield Finding("nmap", "")

        for port in sorted(open_ports):
            state, service, version = port_info[port]
            color  = _port_color(port, state)
            label  = _INTERESTING.get(port, service)
            risk   = "  [bold red][HIGH RISK][/bold red]" if port in _HIGH_RISK else ""
            ver    = f"  [dim]{escape(version)}[/dim]" if version else ""
            yield Finding(
                "nmap",
                f"  [{color}]{port}/tcp[/{color}]  [bold]{escape(label)}[/bold]{ver}{risk}",
            )

        yield Finding("nmap", "")

        # Phase 2: version + default scripts on open ports only
        if open_ports:
            ports_arg = ",".join(str(p) for p in sorted(open_ports))
            yield Finding(
                "nmap",
                f"[dim]Phase 2 — service versions + default scripts on {len(open_ports)} port(s)…[/dim]",
                progress=True,
            )

            cmd_detail = [
                "nmap", "-sV", "-sC", "-T4",
                "-Pn", "-n",
                "-p", ports_arg,
                domain,
            ]

            script_buf: list[str] = []
            current_port: int | None = None

            try:
                proc2 = await asyncio.create_subprocess_exec(
                    *cmd_detail,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                assert proc2.stdout is not None
                async for raw in proc2.stdout:
                    line = raw.decode(errors="replace").rstrip()

                    # Updated port/service line with version info
                    m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
                    if m:
                        current_port = int(m.group(1))
                        service      = m.group(2)
                        version      = m.group(3).strip()
                        color        = _port_color(current_port, "open")
                        label        = _INTERESTING.get(current_port, service)
                        ver          = f"  [dim]{escape(version)}[/dim]" if version else ""
                        risk         = "  [bold red][HIGH RISK][/bold red]" if current_port in _HIGH_RISK else ""
                        yield Finding(
                            "nmap",
                            f"  [{color}]{current_port}/tcp[/{color}]  [bold]{escape(label)}[/bold]{ver}{risk}",
                        )
                        continue

                    # Script output lines (indented with |)
                    if line.startswith("|"):
                        clean = line.lstrip("| ").rstrip()
                        if clean and current_port is not None:
                            yield Finding("nmap", f"    [dim]{escape(clean)}[/dim]")

                await proc2.wait()
            except Exception as exc:
                yield Finding("nmap", f"[red]Detail scan error: {escape(str(exc))}[/red]")
