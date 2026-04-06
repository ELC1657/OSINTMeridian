from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.theme import Theme
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


# ── Custom themes ─────────────────────────────────────────────────────────────

MATRIX_THEME = Theme(
    name="matrix",
    primary="#00FF41",
    secondary="#008F11",
    accent="#00FF41",
    warning="#FFD700",
    error="#FF3131",
    success="#00FF41",
    background="#0D0D0D",
    surface="#111111",
    panel="#1A1A1A",
    dark=True,
)

BLOOD_THEME = Theme(
    name="blood",
    primary="#FF3131",
    secondary="#8B0000",
    accent="#FF6B6B",
    warning="#FFD700",
    error="#FF0000",
    success="#00FF41",
    background="#0D0000",
    surface="#1A0000",
    panel="#2A0000",
    dark=True,
)

THEMES: list[tuple[str, str]] = [
    ("matrix",           "Matrix"),
    ("blood",            "Blood"),
    ("nord",             "Nord"),
    ("gruvbox",          "Gruvbox"),
    ("catppuccin-mocha", "Catppuccin"),
    ("dracula",          "Dracula"),
    ("tokyo-night",      "Tokyo Night"),
    ("monokai",          "Monokai"),
    ("rose-pine",        "Rose Pine"),
    ("textual-dark",     "Default Dark"),
]


# ── Panel widget ──────────────────────────────────────────────────────────────

class ReconPanel(Vertical):
    """A scrollable panel that streams findings from one recon module."""

    DEFAULT_CSS = """
    ReconPanel {
        height: 1fr;
        border: solid $surface-lighten-2;
    }
    ReconPanel .panel-header {
        height: 1;
        background: $panel;
        color: $primary;
        padding: 0 1;
        text-style: bold;
    }
    ReconPanel RichLog {
        height: 1fr;
        background: $background;
        padding: 0 1;
        scrollbar-color: $primary-darken-3;
        scrollbar-background: $background;
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
        self._findings: list[str] = []

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id=f"hdr-{self._pid}", classes="panel-header")
        yield RichLog(id=f"log-{self._pid}", highlight=True, markup=True, wrap=True)

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


# ── Main app ──────────────────────────────────────────────────────────────────

class MeridianApp(App[None]):
    """Meridian - Offensive Recon Aggregator"""

    TITLE = "MERIDIAN"

    CSS = """
    Screen {
        background: $background;
        color: $text;
    }

    Header {
        background: $panel;
        color: $primary;
        text-style: bold;
    }

    #status-bar {
        height: 1;
        background: $panel;
        color: $text-muted;
        padding: 0 2;
        border-bottom: solid $surface-lighten-1;
        content-align: left middle;
    }

    #main {
        height: 1fr;
    }

    .col {
        width: 1fr;
        height: 100%;
        border-right: solid $surface-lighten-1;
    }

    .col:last-of-type {
        border-right: none;
    }

    ReconPanel {
        height: 1fr;
        border: none;
        border-bottom: solid $surface-lighten-1;
    }

    ReconPanel:last-of-type {
        border-bottom: none;
    }

    .panel-header {
        background: $panel;
        color: $primary;
        height: 1;
        padding: 0 1;
    }

    RichLog {
        background: $background;
        padding: 0 1;
        scrollbar-color: $primary-darken-3;
        scrollbar-background: $background;
        scrollbar-size: 1 1;
    }

    Footer {
        background: $panel;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "rerun", "Re-run all"),
        Binding("s", "save", "Save report"),
        Binding("t", "next_theme", "Theme"),
        Binding("ctrl+c", "quit", "Quit", show=False),
    ]

    def __init__(self, target: str, config: dict[str, str], **kwargs) -> None:
        super().__init__(**kwargs)
        self.target = target
        self.config = config
        self._theme_idx = 0

        self._module_map: list[tuple[ReconModule, str]] = [
            (DNSModule(config),        "dns"),
            (WHOISModule(config),      "whois"),
            (CrtShModule(config),      "crtsh"),
            (WaybackModule(config),    "wayback"),
            (ShodanModule(config),     "shodan"),
            (VirusTotalModule(config), "virustotal"),
            (GitHubModule(config),     "github"),
        ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            f"[dim]>[/dim] [bold]{self.target}[/bold]"
            "  [dim]|[/dim]  [dim]passive only - crt.sh · WHOIS · DNS · Shodan · VT · GitHub · Wayback[/dim]",
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
        self.register_theme(MATRIX_THEME)
        self.register_theme(BLOOD_THEME)
        self.theme = THEMES[0][0]
        self.title = f"MERIDIAN  >  {self.target}"
        for module, panel_id in self._module_map:
            self._run_module(module, panel_id)

    # ── Workers ───────────────────────────────────────────────────────────────

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

    # ── Actions ───────────────────────────────────────────────────────────────

    def action_next_theme(self) -> None:
        self._theme_idx = (self._theme_idx + 1) % len(THEMES)
        name, label = THEMES[self._theme_idx]
        self.theme = name
        self.notify(f"Theme: {label}", timeout=2)

    def action_rerun(self) -> None:
        for _, panel_id in self._module_map:
            panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
            panel.clear()
        for module, panel_id in self._module_map:
            self._run_module(module, panel_id)
        self.notify("Re-running all modules...")

    def action_save(self) -> None:
        safe_target = self.target.replace(".", "_").replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path(f"meridian_{safe_target}_{ts}.txt")

        lines = [
            "=" * 70,
            "MERIDIAN - Recon Report",
            f"Target : {self.target}",
            f"Date   : {datetime.now().isoformat()}",
            "=" * 70,
            "",
        ]

        for _, panel_id in self._module_map:
            panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
            lines.append(f"\n{'-' * 60}")
            lines.append(f"[{panel._title}]  ({panel.count} findings)")
            lines.append("-" * 60)
            lines.extend(panel.export_lines())

        out.write_text("\n".join(lines))
        self.notify(f"Saved: {out}", severity="information")
