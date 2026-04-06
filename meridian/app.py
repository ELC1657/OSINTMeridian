from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Footer, Header, RichLog, Static

from .modules import (
    CrtShModule,
    DNSModule,
    Finding,
    GitHubModule,
    ReconModule,
    ShodanModule,
    VirusTotalModule,
    WaybackModule,
    WHOISModule,
)


# ─── Panel widget ────────────────────────────────────────────────────────────

class ReconPanel(Vertical):
    """A scrollable panel that streams findings from one recon module."""

    DEFAULT_CSS = """
    ReconPanel {
        height: 1fr;
        border: solid #1e1e2e;
    }
    ReconPanel .panel-header {
        height: 1;
        background: #11111b;
        color: #4a9eff;
        padding: 0 1;
        text-style: bold;
    }
    ReconPanel RichLog {
        height: 1fr;
        background: #0d0d0d;
        padding: 0 1;
        scrollbar-size: 1 1;
    }
    """

    _STATUS_ICONS: ClassVar[dict[str, str]] = {
        "idle":    "[dim]○[/dim]",
        "running": "[yellow]◉[/yellow]",
        "done":    "[green]✓[/green]",
        "error":   "[red]✗[/red]",
    }

    status: reactive[str] = reactive("idle")
    count:  reactive[int] = reactive(0)

    def __init__(self, title: str, panel_id: str, **kwargs) -> None:
        super().__init__(id=f"panel-{panel_id}", **kwargs)
        self._title = title
        self._pid = panel_id
        self._findings: list[str] = []  # plain text, for export

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id=f"hdr-{self._pid}", classes="panel-header")
        yield RichLog(id=f"log-{self._pid}", highlight=True, markup=True, wrap=True)

    # ── Reactive watchers ────────────────────────────────────────────────────

    def _render_header(self) -> str:
        icon = self._STATUS_ICONS.get(self.status, "○")
        count_str = f"  [dim]({self.count})[/dim]" if self.count > 0 else ""
        return f"{icon} {self._title}{count_str}"

    def watch_status(self, _: str) -> None:
        try:
            self.query_one(f"#hdr-{self._pid}", Static).update(self._render_header())
        except Exception:
            pass

    def watch_count(self, _: int) -> None:
        self.watch_status(self.status)

    # ── Public API ───────────────────────────────────────────────────────────

    def write_finding(self, finding: Finding) -> None:
        self.query_one(RichLog).write(finding.format_rich())
        self._findings.append(finding.format_plain())
        self.count += 1

    def write_line(self, text: str) -> None:
        self.query_one(RichLog).write(text)

    def set_running(self) -> None:
        self.status = "running"

    def set_done(self) -> None:
        self.status = "done"

    def set_error(self, msg: str) -> None:
        self.status = "error"
        self.write_line(f"[red]✗ {msg}[/red]")

    def clear(self) -> None:
        self.query_one(RichLog).clear()
        self._findings.clear()
        self.count = 0
        self.status = "idle"

    def export_lines(self) -> list[str]:
        return list(self._findings)


# ─── Main app ────────────────────────────────────────────────────────────────

class MeridianApp(App[None]):
    """Meridian - Offensive Recon Aggregator"""

    TITLE = "MERIDIAN"

    CSS = """
    Screen {
        background: #0d0d0d;
        color: #e0e0e0;
    }

    Header {
        background: #0a0a0a;
        color: #00ff41;
        text-style: bold;
    }

    #status-bar {
        height: 1;
        background: #111111;
        color: #666666;
        padding: 0 2;
        border-bottom: solid #1a1a1a;
        content-align: left middle;
    }

    #main {
        height: 1fr;
    }

    .col {
        width: 1fr;
        height: 100%;
        border-right: solid #1a1a1a;
    }

    .col:last-of-type {
        border-right: none;
    }

    ReconPanel {
        height: 1fr;
        border: none;
        border-bottom: solid #1a1a1a;
    }

    ReconPanel:last-of-type {
        border-bottom: none;
    }

    .panel-header {
        background: #111111;
        color: #4a9eff;
        height: 1;
        padding: 0 1;
    }

    RichLog {
        background: #0d0d0d;
        padding: 0 1;
        scrollbar-color: #2a2a2a;
        scrollbar-background: #0d0d0d;
        scrollbar-size: 1 1;
    }

    Footer {
        background: #0a0a0a;
        color: #444444;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "rerun", "Re-run all"),
        Binding("s", "save", "Save report"),
        Binding("ctrl+c", "quit", "Quit", show=False),
    ]

    def __init__(self, target: str, config: dict[str, str], **kwargs) -> None:
        super().__init__(**kwargs)
        self.target = target
        self.config = config

        self._module_map: list[tuple[ReconModule, str]] = [
            (DNSModule(config),        "dns"),
            (WHOISModule(config),      "whois"),
            (CrtShModule(config),      "crtsh"),
            (WaybackModule(config),    "wayback"),
            (ShodanModule(config),     "shodan"),
            (VirusTotalModule(config), "virustotal"),
            (GitHubModule(config),     "github"),
        ]

    # ── Layout ───────────────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            f"[dim]▸[/dim] [bold green]{self.target}[/bold green]"
            "  [dim]│[/dim]  [dim]passive only - crt.sh · WHOIS · DNS · Shodan · VT · GitHub · Wayback[/dim]",
            id="status-bar",
        )

        with Horizontal(id="main"):
            with Vertical(classes="col"):
                yield ReconPanel("DNS Records",  "dns")
                yield ReconPanel("WHOIS",        "whois")

            with Vertical(classes="col"):
                yield ReconPanel("Subdomains (crt.sh)", "crtsh")
                yield ReconPanel("Wayback Machine",     "wayback")

            with Vertical(classes="col"):
                yield ReconPanel("Shodan",      "shodan")
                yield ReconPanel("VirusTotal",  "virustotal")
                yield ReconPanel("GitHub",      "github")

        yield Footer()

    def on_mount(self) -> None:
        self.title = f"MERIDIAN  ▸  {self.target}"
        for module, panel_id in self._module_map:
            self._run_module(module, panel_id)

    # ── Workers ──────────────────────────────────────────────────────────────

    @work(exclusive=False, thread=False)
    async def _run_module(self, module: ReconModule, panel_id: str) -> None:
        panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
        panel.set_running()
        try:
            async for finding in module.run(self.target):
                panel.write_finding(finding)
        except asyncio.CancelledError:
            panel.set_error("Cancelled")
            raise
        except Exception as exc:
            panel.set_error(str(exc))
            return
        panel.set_done()

    # ── Actions ──────────────────────────────────────────────────────────────

    def action_rerun(self) -> None:
        for _, panel_id in self._module_map:
            panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
            panel.clear()
        for module, panel_id in self._module_map:
            self._run_module(module, panel_id)
        self.notify("Re-running all modules…")

    def action_save(self) -> None:
        safe_target = self.target.replace(".", "_").replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path(f"meridian_{safe_target}_{ts}.txt")

        lines = [
            "=" * 70,
            f"MERIDIAN - Recon Report",
            f"Target : {self.target}",
            f"Date   : {datetime.now().isoformat()}",
            "=" * 70,
            "",
        ]

        for module, panel_id in self._module_map:
            panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
            lines.append(f"\n{'─' * 60}")
            lines.append(f"[{panel._title}]  ({panel.count} findings)")
            lines.append("─" * 60)
            lines.extend(panel.export_lines())

        out.write_text("\n".join(lines))
        self.notify(f"Saved → {out}", severity="information")
