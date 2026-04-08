from __future__ import annotations

import asyncio
import json
import platform
import re

from rich.markup import escape
import subprocess
from datetime import datetime
from pathlib import Path
from typing import ClassVar

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.events import Click, Key
from textual.reactive import reactive
from textual.theme import Theme
from textual.widgets import Footer, Header, Input, RichLog, Static, TabbedContent, TabPane

from .modules import (
    ASNModule,
    AttackBriefModule,
    BreachModule,
    BucketsModule,
    CrtShModule,
    CVEModule,
    DarkWebModule,
    DNSHistoryModule,
    DNSModule,
    EmployeesModule,
    ExploitsModule,
    Finding,
    GitHubModule,
    HunterModule,
    JSScanModule,
    ParamsModule,
    PlaybookModule,
    ReconModule,
    ShodanModule,
    SpoofModule,
    TakeoverModule,
    URLScanModule,
    VirusTotalModule,
    WaybackModule,
    WHOISModule,
)


# ── Clipboard helper ──────────────────────────────────────────────────────────

def _copy_to_clipboard(text: str) -> bool:
    """Copy text to the system clipboard. Returns True on success."""
    try:
        system = platform.system()
        if system == "Darwin":
            subprocess.run(["pbcopy"], input=text.encode(), check=True, capture_output=True)
        elif system == "Linux":
            try:
                subprocess.run(["xclip", "-selection", "clipboard"], input=text.encode(), check=True, capture_output=True)
            except FileNotFoundError:
                subprocess.run(["xsel", "--clipboard", "--input"], input=text.encode(), check=True, capture_output=True)
        elif system == "Windows":
            subprocess.run(["clip"], input=text.encode(), check=True, capture_output=True)
        return True
    except Exception:
        return False


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

# Themes to show first in the cycle (custom ones we registered)
_PINNED_THEMES = ["matrix", "blood"]
# Substrings in a theme name that mean we skip it (light / near-duplicate)
_SKIP_THEMES = {"light", "ansi"}


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
        self._all_lines: list[str] = []  # mirrors every write to RichLog for click-to-copy

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
        plain = finding.format_plain()
        self._findings.append(plain)
        self._all_lines.append(plain)
        self.count += 1

    def write_line(self, text: str) -> None:
        self.query_one(RichLog).write(text)
        self._all_lines.append(re.sub(r"\[/?[^\]]*\]", "", text).strip())

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
        self._all_lines.clear()
        self.count = 0
        self.status = "idle"

    def export_lines(self) -> list[str]:
        return list(self._findings)

    def on_click(self, event: Click) -> None:
        # y=0 is the header bar, y=1+ is the log area
        log = self.query_one(RichLog)
        line_idx = int(log.scroll_y) + max(0, event.y - 1)
        if 0 <= line_idx < len(self._all_lines):
            text = self._all_lines[line_idx].strip()
            # Strip the "$ " command prefix so the raw command is copied
            if text.startswith("$ "):
                text = text[2:]
            if text:
                ok = _copy_to_clipboard(text)
                preview = text[:60] + ("..." if len(text) > 60 else "")
                if ok:
                    self.app.notify(f"Copied: {preview}", timeout=2)
                else:
                    self.app.notify("Clipboard unavailable", severity="warning", timeout=2)


# ── Terminal helpers ──────────────────────────────────────────────────────────

def _install_hint(tool: str) -> str:
    _INSTALLS = {
        "swaks":    "brew install swaks",
        "nuclei":   "brew install nuclei  OR  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "hydra":    "brew install hydra",
        "msfconsole": "brew install metasploit  OR  curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod +x msfinstall && ./msfinstall",
        "nmap":     "brew install nmap",
        "sqlmap":   "brew install sqlmap",
        "ffuf":     "brew install ffuf",
        "aws":      "brew install awscli",
        "curl":     "brew install curl",
        "ruler":    "go install github.com/sensepost/ruler@latest",
        "nikto":    "brew install nikto",
        "gobuster": "brew install gobuster",
        "wfuzz":    "brew install wfuzz",
    }
    return _INSTALLS.get(tool.lower(), "")


def _failure_hints(cmd: str, output: list[str]) -> list[str]:
    """Analyse command output and return contextual fix suggestions."""
    combined = " ".join(output).lower()
    hints: list[str] = []
    tool = cmd.split()[0].lower() if cmd.split() else ""

    # Spamhaus / blocklist rejection
    if "block listed" in combined or "pbl" in combined or "spamhaus" in combined:
        hints += [
            "Your IP is on Spamhaus PBL (residential IPs are blocked by most mail servers).",
            "Fix: run swaks from a clean VPS IP (DigitalOcean, Vultr, Linode).",
            "Check your IP: https://check.spamhaus.org",
        ]

    # Generic SMTP rejection
    if tool == "swaks" and ("550" in combined or "554" in combined or "reject" in combined):
        hints += [
            "SMTP 550/554 = mail rejected by the server.",
            "Try a different FROM address or use --tls flag.",
            "If domain has SPF 'softfail', try --from postmaster@" + (cmd.split("--from")[-1].split()[0].split("@")[-1] if "--from" in cmd else "domain.com"),
        ]

    # Connection refused / timeout
    if "connection refused" in combined or "timed out" in combined or "no route" in combined:
        hints += [
            "Could not reach the target — firewall or wrong port.",
            "Try: nmap -p 25,465,587 <host>  to check open SMTP ports.",
            "Use --port 587 or --port 465 with --tls for submission ports.",
        ]

    # Auth required
    if "auth" in combined and ("required" in combined or "535" in combined or "530" in combined):
        hints += [
            "Server requires authentication — open relay is not available.",
            "Use leaked credentials if available: --auth-user user --auth-password pass",
        ]

    # Command not found (exit 127)
    if "not found" in combined or "no such file" in combined:
        install = _install_hint(tool)
        if install:
            hints.append(f"Install {tool}: {install}")

    # Hydra failures
    if tool == "hydra" and ("error" in combined or "invalid" in combined):
        hints += [
            "Check the login form URL and failure string are correct.",
            "Try --http-get instead of https-post-form if the login uses GET.",
            "Use -V for verbose output to see each attempt.",
        ]

    # Nuclei template missing
    if tool == "nuclei" and ("no template" in combined or "not found" in combined):
        hints += [
            "Template not found — update nuclei templates: nuclei -update-templates",
            "Or browse templates at: https://github.com/projectdiscovery/nuclei-templates",
        ]

    # AWS bucket access denied
    if "aws" in tool and ("access denied" in combined or "403" in combined):
        hints += [
            "Bucket exists but is private — access denied.",
            "Try listing without signing: aws s3 ls s3://<bucket> --no-sign-request",
        ]

    return hints


# ── Terminal input with command history ───────────────────────────────────────

class TermInput(Input):
    """Single-line input widget with shell-style up/down command history."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._history: list[str] = []
        self._hist_idx: int = -1  # -1 = not browsing history

    def push_history(self, cmd: str) -> None:
        if cmd and (not self._history or self._history[-1] != cmd):
            self._history.append(cmd)
        self._hist_idx = -1

    def on_key(self, event: Key) -> None:
        if event.key == "up" and self._history:
            if self._hist_idx == -1:
                self._hist_idx = len(self._history) - 1
            elif self._hist_idx > 0:
                self._hist_idx -= 1
            self.value = self._history[self._hist_idx]
            self.cursor_position = len(self.value)
            event.prevent_default()
            event.stop()
        elif event.key == "down" and self._hist_idx != -1:
            if self._hist_idx < len(self._history) - 1:
                self._hist_idx += 1
                self.value = self._history[self._hist_idx]
            else:
                self._hist_idx = -1
                self.value = ""
            self.cursor_position = len(self.value)
            event.prevent_default()
            event.stop()


# ── Execution terminal ────────────────────────────────────────────────────────

class ExecTerminal(Vertical):
    """Interactive terminal panel — run commands, stream output in real time."""

    DEFAULT_CSS = """
    ExecTerminal {
        height: 1fr;
        border: solid $surface-lighten-2;
    }
    ExecTerminal .term-header {
        height: 1;
        background: $panel;
        color: $primary;
        padding: 0 1;
        text-style: bold;
    }
    ExecTerminal RichLog {
        height: 1fr;
        background: $background;
        padding: 0 1;
    }
    ExecTerminal TermInput {
        height: 3;
        background: $surface;
        border: solid $primary;
        padding: 0 1;
        dock: bottom;
    }
    """

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._term_lines: list[str] = []  # all display lines, mirrors RichLog

    def _write(self, text: str) -> None:
        """Write to the terminal log and track in _term_lines for click-to-copy."""
        self.query_one("#term-log", RichLog).write(text)
        self._term_lines.append(re.sub(r"\[/?[^\]]*\]", "", text).strip())

    def compose(self) -> ComposeResult:
        yield Static(" Terminal  [dim](↑↓ history · type 'clear' to reset)[/dim]", classes="term-header")
        yield RichLog(id="term-log", highlight=True, markup=True, wrap=True)
        yield TermInput(placeholder="Type a command and press Enter…", id="term-input")

    def on_mount(self) -> None:
        self._write("[dim]Type a command and press Enter to execute.[/dim]")
        self._write("[dim]Click any output line to copy it. Use ↑↓ to browse history.[/dim]")
        self._write("[yellow]⚠  Only run commands against targets you have written authorization to test.[/yellow]")
        self._write("")

    def on_click(self, event: Click) -> None:
        """Click-to-copy on terminal output lines."""
        log = self.query_one("#term-log", RichLog)
        log_region = log.region
        if log_region.contains(event.screen_x, event.screen_y):
            rel_y = event.screen_y - log_region.y
            line_idx = int(log.scroll_y) + rel_y
            if 0 <= line_idx < len(self._term_lines):
                text = self._term_lines[line_idx].strip()
                # Strip "$ " command prefix so the bare command is copied
                if text.startswith("$ "):
                    text = text[2:]
                if text:
                    ok = _copy_to_clipboard(text)
                    preview = text[:60] + ("..." if len(text) > 60 else "")
                    self.app.notify(f"Copied: {preview}" if ok else "Clipboard unavailable", timeout=2)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        cmd = event.value.strip()
        if not cmd:
            return
        inp = self.query_one("#term-input", TermInput)
        inp.value = ""

        # Built-in clear command
        if cmd.lower() in ("clear", "cls"):
            log = self.query_one("#term-log", RichLog)
            log.clear()
            self._term_lines.clear()
            self._write("[dim]Cleared.[/dim]")
            self._write("")
            return

        inp.push_history(cmd)
        self._run_command(cmd)

    @work(exclusive=False, thread=False)
    async def _run_command(self, cmd: str) -> None:
        self._write(f"[bold green]$ {escape(cmd)}[/bold green]")
        self._write("")

        raw_output: list[str] = []

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                limit=1024 * 256,
            )

            assert proc.stdout is not None
            async for raw in proc.stdout:
                line = raw.decode(errors="replace").rstrip()
                self._write(escape(line))
                raw_output.append(line)

            await proc.wait()
            rc = proc.returncode
            color = "green" if rc == 0 else "red"
            self._write("")
            self._write(f"[{color}]─── exit {rc} ───[/{color}]")
            self._write("")

            if rc != 0:
                hints = _failure_hints(cmd, raw_output)
                if hints:
                    self._write("[yellow]━━━ Possible fixes ━━━[/yellow]")
                    for h in hints:
                        self._write(f"[dim]  {escape(h)}[/dim]")
                    self._write("")

        except FileNotFoundError:
            tool = cmd.split()[0] if cmd.split() else cmd
            self._write(f"[red]Command not found: {escape(tool)}[/red]")
            install = _install_hint(tool)
            if install:
                self._write(f"[yellow]  Install: {escape(install)}[/yellow]")
            self._write("")
        except Exception as exc:
            self._write(f"[red]Error: {escape(str(exc))}[/red]")
            self._write("")


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

    TabbedContent {
        height: 1fr;
    }

    TabbedContent ContentSwitcher {
        height: 1fr;
    }

    TabPane {
        padding: 0;
        height: 100%;
    }

    Tabs {
        background: $panel;
    }

    Tab {
        background: $panel;
        color: $text;
        padding: 0 2;
    }

    Tab:hover {
        background: $surface;
        color: $text;
    }

    Tab.-active {
        background: $surface;
        color: $primary;
        text-style: bold;
    }

    Tab:focus {
        background: $surface;
        color: $primary;
        text-style: bold;
    }

    .tab-layout {
        height: 100%;
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
        Binding("s", "save", "Save txt"),
        Binding("j", "save_json", "Save JSON"),
        Binding("t", "next_theme", "Theme"),
        Binding("1", "switch_tab('tab-network')",   "Network",   show=False),
        Binding("2", "switch_tab('tab-web')",        "Web",       show=False),
        Binding("3", "switch_tab('tab-offensive')",  "Offensive", show=False),
        Binding("4", "switch_tab('tab-brief')",      "Brief",     show=False),
        Binding("5", "switch_tab('tab-exploit')",    "Exploit",   show=False),
        Binding("ctrl+c", "quit", "Quit", show=False),
    ]

    def __init__(
        self,
        target: str,
        config: dict[str, str],
        watch_interval: int | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.target = target
        self.config = config
        self._theme_idx   = 0
        self._watch_interval = watch_interval
        self._watch_mode     = watch_interval is not None
        self._watch_prev: dict[str, set[str]] = {}
        self._watch_count = 0

        self._module_map: list[tuple[ReconModule, str]] = [
            (DNSModule(config),        "dns"),
            (WHOISModule(config),      "whois"),
            (SpoofModule(config),      "spoof"),
            (CrtShModule(config),      "crtsh"),
            (WaybackModule(config),    "wayback"),
            (URLScanModule(config),    "urlscan"),
            (ShodanModule(config),     "shodan"),
            (ASNModule(config),        "asn"),
            (VirusTotalModule(config), "virustotal"),
            (GitHubModule(config),     "github"),
            (HunterModule(config),     "hunter"),
            (EmployeesModule(config),  "employees"),
            (TakeoverModule(config),   "takeover"),
            (BreachModule(config),     "breach"),
            (DarkWebModule(config),    "darkweb"),
            (JSScanModule(config),     "jsscan"),
            (ParamsModule(config),     "params"),
            (DNSHistoryModule(config), "dnshistory"),
            (BucketsModule(config),    "buckets"),
        ]
        # Modules that read from other panels — appended last
        self._module_map.append(
            (CVEModule(config, self._collect_panel_data), "cve")
        )
        self._module_map.append(
            (ExploitsModule(config, self._collect_panel_data), "exploits")
        )
        self._module_map.append(
            (AttackBriefModule(config, self._collect_panel_data), "brief")
        )
        self._module_map.append(
            (PlaybookModule(config, self._collect_panel_data), "playbook")
        )

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(
            f"[dim]>[/dim] [bold]{self.target}[/bold]"
            + ("  [yellow]◉ WATCH[/yellow]" if self._watch_mode else "")
            + "  [dim]|[/dim]  [dim]1 Network  2 Web  3 Offensive  4 Brief  5 Exploit[/dim]",
            id="status-bar",
        )

        with TabbedContent(initial="tab-network"):
            with TabPane("Network", id="tab-network"):
                with Horizontal(classes="tab-layout"):
                    with Vertical(classes="col"):
                        yield ReconPanel("DNS Records", "dns")
                    with Vertical(classes="col"):
                        yield ReconPanel("WHOIS",         "whois")
                        yield ReconPanel("Spoofability",  "spoof")
                    with Vertical(classes="col"):
                        yield ReconPanel("Shodan",        "shodan")
                        yield ReconPanel("ASN / Ranges",  "asn")
                    with Vertical(classes="col"):
                        yield ReconPanel("DNS History",     "dnshistory")
                        yield ReconPanel("CVE Correlation", "cve")

            with TabPane("Web", id="tab-web"):
                with Horizontal(classes="tab-layout"):
                    with Vertical(classes="col"):
                        yield ReconPanel("Subdomains (crt.sh)", "crtsh")
                    with Vertical(classes="col"):
                        yield ReconPanel("Wayback Machine", "wayback")
                    with Vertical(classes="col"):
                        yield ReconPanel("URLScan.io", "urlscan")
                    with Vertical(classes="col"):
                        yield ReconPanel("Cloud Buckets", "buckets")

            with TabPane("Offensive", id="tab-offensive"):
                with Horizontal(classes="tab-layout"):
                    with Vertical(classes="col"):
                        yield ReconPanel("VirusTotal",       "virustotal")
                        yield ReconPanel("GitHub",           "github")
                    with Vertical(classes="col"):
                        yield ReconPanel("Hunter.io",        "hunter")
                        yield ReconPanel("Takeover",         "takeover")
                    with Vertical(classes="col"):
                        yield ReconPanel("Breach Intel",     "breach")
                        yield ReconPanel("Employee Targets", "employees")
                    with Vertical(classes="col"):
                        yield ReconPanel("Dark Web",         "darkweb")

            with TabPane("Brief", id="tab-brief"):
                with Horizontal(classes="tab-layout"):
                    with Vertical(classes="col"):
                        yield ReconPanel("Attack Brief", "brief")
                    with Vertical(classes="col"):
                        yield ReconPanel("Playbook",     "playbook")
                    with Vertical(classes="col"):
                        yield ReconPanel("JS Secrets",   "jsscan")
                        yield ReconPanel("URL Params",   "params")

            with TabPane("Exploit", id="tab-exploit"):
                with Horizontal(classes="tab-layout"):
                    with Vertical(classes="col"):
                        yield ReconPanel("Exploit Reference", "exploits")
                    with Vertical(classes="col"):
                        yield ExecTerminal()

        yield Footer()

    def on_mount(self) -> None:
        self.register_theme(MATRIX_THEME)
        self.register_theme(BLOOD_THEME)

        # Build cycle list: pinned customs first, then every dark Textual theme
        available = set(self.available_themes.keys())
        rest = sorted(
            t for t in available
            if t not in _PINNED_THEMES
            and not any(skip in t.lower() for skip in _SKIP_THEMES)
        )
        self._themes: list[str] = [t for t in _PINNED_THEMES if t in available] + rest
        self._theme_idx = 0

        self.theme = self._themes[0]
        self.title = f"MERIDIAN  >  {self.target}"
        for module, panel_id in self._module_map:
            self._run_module(module, panel_id)
        if self._watch_mode:
            self._watch_loop()

    @work(exclusive=False, thread=False)
    async def _watch_loop(self) -> None:
        """Background worker: re-scans on interval, highlights new findings."""
        assert self._watch_interval is not None
        while True:
            await asyncio.sleep(self._watch_interval * 60)
            self._watch_count += 1
            # Snapshot current findings before clearing
            self._watch_prev = {}
            for _, panel_id in self._module_map:
                try:
                    panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
                    self._watch_prev[panel_id] = set(panel.export_lines())
                except Exception:
                    pass
            self.notify(
                f"Watch scan #{self._watch_count} — new findings will be highlighted",
                timeout=4,
            )
            self.action_rerun()

    def _collect_panel_data(self) -> dict[str, dict]:
        """Read all panel findings — called by AttackBriefModule to synthesize."""
        result: dict[str, dict] = {}
        for _, panel_id in self._module_map:
            if panel_id == "brief":
                continue
            try:
                panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
                result[panel_id] = {
                    "status":   panel.status,
                    "count":    panel.count,
                    "findings": panel.export_lines(),
                }
            except Exception:
                pass
        return result

    # ── Workers ───────────────────────────────────────────────────────────────

    @work(exclusive=False, thread=False)
    async def _run_module(self, module: ReconModule, panel_id: str) -> None:
        panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
        panel.set_running()
        prev = self._watch_prev.get(panel_id, set())
        try:
            async for finding in module.run(self.target):
                if finding.progress:
                    panel.write_line(finding.line)
                else:
                    if prev and finding.format_plain().strip() and finding.format_plain() not in prev:
                        marked = Finding(finding.module, f"[yellow]◆[/yellow] {finding.line}")
                        panel.write_finding(marked)
                    else:
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
        self._theme_idx = (self._theme_idx + 1) % len(self._themes)
        name = self._themes[self._theme_idx]
        self.theme = name
        label = name.replace("-", " ").title()
        self.notify(f"Theme: {label}  ({self._theme_idx + 1}/{len(self._themes)})", timeout=2)

    def action_switch_tab(self, tab_id: str) -> None:
        self.query_one(TabbedContent).active = tab_id

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        if event.pane.id == "tab-exploit":
            try:
                self.query_one("#term-input", TermInput).focus()
            except Exception:
                pass

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
            f"Date   : {datetime.now().isoformat()}",            "=" * 70,
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

    def action_save_json(self) -> None:
        safe_target = self.target.replace(".", "_").replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path(f"meridian_{safe_target}_{ts}.json")

        payload: dict = {
            "target": self.target,
            "date": datetime.now().isoformat(),
            "version": "0.72.2",
            "modules": {},
        }

        for _, panel_id in self._module_map:
            panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
            payload["modules"][panel_id] = {
                "name": panel._title,
                "count": panel.count,
                "findings": panel.export_lines(),
            }

        out.write_text(json.dumps(payload, indent=2))
        self.notify(f"Saved: {out}", severity="information")
