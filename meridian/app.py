from __future__ import annotations

import asyncio
import json
import platform
import re
import time

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
from textual.screen import ModalScreen
from textual.widgets import Footer, Header, Input, RichLog, Static, Tab, TabbedContent, TabPane

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
    EmailIntelModule,
    EmployeesModule,
    ExploitsModule,
    Finding,
    GitHubModule,
    HunterModule,
    JSScanModule,
    NmapModule,
    ParamsModule,
    PersonModule,
    PlaybookModule,
    ReconModule,
    ShodanModule,
    SpoofModule,
    TargetMode,
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


# ── Skip-module placeholder ───────────────────────────────────────────────────

class _SkipModule(ReconModule):
    """Placeholder for panels not applicable to the current target mode."""

    def __init__(self, reason: str = "") -> None:
        super().__init__({})
        self._reason = reason

    async def run(self, target: str):  # type: ignore[override]
        note = f"─ Not run in {self._reason} mode ─" if self._reason else "─ Not applicable ─"
        yield Finding("skip", f"[dim]{note}[/dim]", progress=True)


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
        self._start_time: float | None = None
        self._elapsed: float | None = None

    def compose(self) -> ComposeResult:
        yield Static(self._render_header(), id=f"hdr-{self._pid}", classes="panel-header")
        yield RichLog(id=f"log-{self._pid}", highlight=True, markup=True, wrap=True)

    def _render_header(self) -> str:
        icon = self._STATUS_ICONS.get(self.status, "○")
        count_str = f"  [dim]({self.count})[/dim]" if self.count > 0 else ""
        time_str  = f"  [dim]{self._elapsed:.1f}s[/dim]" if self._elapsed is not None and self.status in ("done", "error") else ""
        return f"{icon} {self._title}{count_str}{time_str}"

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
        self._start_time = time.monotonic()
        self.status = "running"

    def set_done(self) -> None:
        if self._start_time is not None:
            self._elapsed = time.monotonic() - self._start_time
        self.status = "done"

    def set_error(self, msg: str) -> None:
        if self._start_time is not None:
            self._elapsed = time.monotonic() - self._start_time
        self.status = "error"
        self.write_line(f"[red]✗ {msg}[/red]")

    def clear(self) -> None:
        self.query_one(RichLog).clear()
        self._findings.clear()
        self._all_lines.clear()
        self.count = 0
        self._start_time = None
        self._elapsed = None
        self.status = "idle"

    def export_lines(self) -> list[str]:
        return list(self._findings)

    def on_click(self, event: Click) -> None:
        # y=0 is the header bar — click to copy ALL findings
        if event.y == 0:
            if self._findings:
                ok = _copy_to_clipboard("\n".join(self._findings))
                self.app.notify(
                    f"Copied all {len(self._findings)} findings from {self._title}" if ok
                    else "Clipboard unavailable",
                    severity="information" if ok else "warning",
                    timeout=2,
                )
            return

        # y=1+ is the log area — click to copy individual line
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


# ── Help overlay ─────────────────────────────────────────────────────────────

class HelpScreen(ModalScreen[None]):
    """Keybinding reference overlay — press ?, Esc, or q to close."""

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    HelpScreen Vertical {
        width: 56;
        height: auto;
        background: $panel;
        border: solid $primary;
        padding: 1 2;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss", show=False),
        Binding("q",      "dismiss", show=False),
        Binding("?",      "dismiss", show=False),
    ]

    def compose(self) -> ComposeResult:
        with Vertical():
            yield Static(
                " [bold]MERIDIAN — KEYBINDINGS[/bold]\n"
                " ─────────────────────────────────────────────\n"
                "\n"
                " [dim]Tabs[/dim]\n"
                "   [bold cyan]1–5[/bold cyan]   Network / Web / Offensive / Brief / Exploit\n"
                "\n"
                " [dim]Actions[/dim]\n"
                "   [bold cyan]r[/bold cyan]     Re-run all modules\n"
                "   [bold cyan]s[/bold cyan]     Save plain-text report\n"
                "   [bold cyan]j[/bold cyan]     Save JSON report\n"
                "   [bold cyan]t[/bold cyan]     Cycle theme\n"
                "\n"
                " [dim]Exploit tab[/dim]\n"
                "   [bold cyan]p[/bold cyan]     Send nearest command → terminal input\n"
                "   [bold cyan]↑ ↓[/bold cyan]  Terminal command history\n"
                "   [dim]clear[/dim]  Wipe terminal output\n"
                "\n"
                " [dim]General[/dim]\n"
                "   [bold cyan]n[/bold cyan]     Jump to next tab with findings\n"
                "   [bold cyan]b[/bold cyan]     Jump to previous tab\n"
                "   [bold cyan]g[/bold cyan]     Scroll panels to top\n"
                "   [bold cyan]G[/bold cyan]     Scroll panels to bottom\n"
                "   [bold cyan]?[/bold cyan]     This help screen\n"
                "   [bold cyan]q[/bold cyan]     Quit\n"
                "\n"
                " [dim]Target modes[/dim]\n"
                "   [bold cyan]-d[/bold cyan]    domain (default)    meridian -d example.com\n"
                "   [bold cyan]-ip[/bold cyan]   IP address           meridian -ip 1.2.3.4\n"
                "   [bold cyan]-e[/bold cyan]    email address        meridian -e user@example.com\n"
                "   [bold cyan]-or[/bold cyan]   organisation name    meridian -or \"Acme Corp\"\n"
                "   [bold cyan]-p[/bold cyan]    person name          meridian -p \"John Smith\"\n"
                "\n"
                " [dim]Click panel header to copy all findings.[/dim]\n"
                " [dim]Click any line to copy it to the clipboard.[/dim]\n"
                " [dim]Press Esc / q / ? to close.[/dim]",
                markup=True,
            )


# ── Tab navigation helpers ────────────────────────────────────────────────────

_TAB_ORDER = ["tab-network", "tab-web", "tab-offensive", "tab-brief", "tab-exploit"]

_TAB_PANELS: dict[str, set[str]] = {
    "tab-network":   {"dns", "whois", "spoof", "shodan", "asn", "nmap", "dnshistory", "cve"},
    "tab-web":       {"crtsh", "wayback", "urlscan", "buckets"},
    "tab-offensive": {"virustotal", "github", "hunter", "takeover", "breach", "employees", "darkweb", "email_intel"},
    "tab-brief":     {"brief", "playbook", "jsscan", "params"},
    "tab-exploit":   {"exploits"},
}

_TAB_LABELS: dict[str, str] = {
    "tab-network":   "Network",
    "tab-web":       "Web",
    "tab-offensive": "Offensive",
    "tab-brief":     "Brief",
    "tab-exploit":   "Exploit",
}

# Alert rules: panel_id → [(substring to match in findings, toast message, severity)]
_ALERT_RULES: dict[str, list[tuple[str, str, str]]] = {
    "spoof":       [("SPOOFABLE", "Domain is spoofable — phishing ready", "warning")],
    "takeover":    [("VULN", "Subdomain takeover candidates found", "warning")],
    "breach":      [("breach(es) found", "Breach data in HIBP", "warning")],
    "darkweb":     [("credential(s) found", "Leaked credentials on dark web", "error"),
                   ("record(s) in Dehashed", "Records found in Dehashed", "warning")],
    "buckets":     [("PUBLIC", "Open cloud storage bucket found!", "error")],
    "jsscan":      [("Found", "JS secrets detected", "warning")],
    "nmap":        [("HIGH-RISK", "High-risk service exposed", "warning")],
    "email_intel": [("credentials_leaked", "Email credentials leaked", "warning"),
                   ("Gravatar account found", "Gravatar profile found", "information")],
}


# ── Main app ──────────────────────────────────────────────────────────────────

class MeridianApp(App[None]):
    """Meridian - Offensive Recon Aggregator"""

    TITLE = "MERIDIAN"

    _done:   reactive[int] = reactive(0)
    _errors: reactive[int] = reactive(0)

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
        Binding("question_mark", "show_help", "Help"),
        Binding("1", "switch_tab('tab-network')",   "Network",   show=False),
        Binding("2", "switch_tab('tab-web')",        "Web",       show=False),
        Binding("3", "switch_tab('tab-offensive')",  "Offensive", show=False),
        Binding("4", "switch_tab('tab-brief')",      "Brief",     show=False),
        Binding("5", "switch_tab('tab-exploit')",    "Exploit",   show=False),
        Binding("p", "paste_exploit",                "Paste cmd", show=False),
        Binding("n", "next_finding_tab",             "Next tab",  show=False),
        Binding("b", "prev_tab",                     "Prev tab",  show=False),
        Binding("g", "scroll_top",                   "Top",       show=False),
        Binding("G", "scroll_bottom",                "Bottom",    show=False),
        Binding("ctrl+c", "quit", "Quit", show=False),
    ]

    def __init__(
        self,
        target: str,
        config: dict[str, str],
        target_mode: TargetMode = TargetMode.DOMAIN,
        domain_hint: str | None = None,
        watch_interval: int | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.target = target
        self.config = config
        self._target_mode    = target_mode
        self._domain_hint    = domain_hint
        self._theme_idx      = 0
        self._watch_interval = watch_interval
        self._watch_mode     = watch_interval is not None
        self._watch_prev: dict[str, set[str]] = {}
        self._watch_count = 0

        # (module, panel_id, effective_target) — target may differ per module in EMAIL mode
        self._module_map: list[tuple[ReconModule, str, str]] = self._build_module_map(
            config, target, domain_hint, target_mode
        )

    def _build_module_map(
        self,
        config: dict[str, str],
        canonical: str,
        domain_hint: str | None,
        mode: TargetMode,
    ) -> list[tuple[ReconModule, str, str]]:
        """Return the (module, panel_id, target) list for the given mode."""
        dom = domain_hint or canonical  # domain used by domain-oriented modules

        def skip(label: str = "") -> _SkipModule:
            return _SkipModule(label or mode.value.upper())

        if mode == TargetMode.PERSON:
            return [
                (PersonModule(config), "person", canonical),
            ]

        if mode == TargetMode.IP:
            entries: list[tuple[ReconModule, str, str]] = [
                (DNSModule(config),        "dns",          canonical),
                (WHOISModule(config),      "whois",        canonical),
                (SpoofModule(config),      "spoof",        canonical),
                (skip(),                   "crtsh",        canonical),
                (skip(),                   "wayback",      canonical),
                (URLScanModule(config),    "urlscan",      canonical),
                (ShodanModule(config),     "shodan",       canonical),
                (ASNModule(config),        "asn",          canonical),
                (VirusTotalModule(config), "virustotal",   canonical),
                (skip(),                   "github",       canonical),
                (skip(),                   "hunter",       canonical),
                (skip(),                   "email_intel",  canonical),
                (skip(),                   "employees",    canonical),
                (skip(),                   "takeover",     canonical),
                (skip(),                   "breach",       canonical),
                (skip(),                   "darkweb",      canonical),
                (skip(),                   "jsscan",       canonical),
                (skip(),                   "params",       canonical),
                (skip(),                   "dnshistory",   canonical),
                (skip(),                   "buckets",      canonical),
                (NmapModule(config),       "nmap",         canonical),
                (CVEModule(config, self._collect_panel_data),         "cve",      canonical),
                (ExploitsModule(config, self._collect_panel_data),    "exploits", canonical),
                (AttackBriefModule(config, self._collect_panel_data), "brief",    canonical),
                (PlaybookModule(config, self._collect_panel_data),    "playbook", canonical),
            ]
            return entries

        if mode == TargetMode.EMAIL:
            email = canonical
            return [
                (DNSModule(config),           "dns",          dom),
                (WHOISModule(config),         "whois",        dom),
                (SpoofModule(config),         "spoof",        dom),
                (CrtShModule(config),         "crtsh",        dom),
                (WaybackModule(config),       "wayback",      dom),
                (URLScanModule(config),       "urlscan",      dom),
                (ShodanModule(config),        "shodan",       dom),
                (ASNModule(config),           "asn",          dom),
                (VirusTotalModule(config),    "virustotal",   dom),
                (GitHubModule(config),        "github",       dom),
                (HunterModule(config),        "hunter",       email),   # verifier + domain search
                (EmailIntelModule(config),    "email_intel",  email),   # emailrep + gravatar
                (skip("EMAIL"),               "employees",    dom),
                (TakeoverModule(config),      "takeover",     dom),
                (BreachModule(config),        "breach",       email),   # domain extracted internally
                (DarkWebModule(config),       "darkweb",      email),   # full email to all sources
                (JSScanModule(config),        "jsscan",       dom),
                (ParamsModule(config),        "params",       dom),
                (DNSHistoryModule(config),    "dnshistory",   dom),
                (BucketsModule(config),       "buckets",      dom),
                (NmapModule(config),          "nmap",         dom),
                (CVEModule(config, self._collect_panel_data),         "cve",      dom),
                (ExploitsModule(config, self._collect_panel_data),    "exploits", dom),
                (AttackBriefModule(config, self._collect_panel_data), "brief",    dom),
                (PlaybookModule(config, self._collect_panel_data),    "playbook", dom),
            ]

        # DOMAIN or ORG — all modules run on the resolved domain
        return [
            (DNSModule(config),           "dns",         dom),
            (WHOISModule(config),         "whois",       dom),
            (SpoofModule(config),         "spoof",       dom),
            (CrtShModule(config),         "crtsh",       dom),
            (WaybackModule(config),       "wayback",     dom),
            (URLScanModule(config),       "urlscan",     dom),
            (ShodanModule(config),        "shodan",      dom),
            (ASNModule(config),           "asn",         dom),
            (VirusTotalModule(config),    "virustotal",  dom),
            (GitHubModule(config),        "github",      dom),
            (HunterModule(config),        "hunter",      dom),
            (skip(),                      "email_intel", dom),
            (EmployeesModule(config),     "employees",   dom),
            (TakeoverModule(config),      "takeover",    dom),
            (BreachModule(config),        "breach",      dom),
            (DarkWebModule(config),       "darkweb",     dom),
            (JSScanModule(config),        "jsscan",      dom),
            (ParamsModule(config),        "params",      dom),
            (DNSHistoryModule(config),    "dnshistory",  dom),
            (BucketsModule(config),       "buckets",     dom),
            (NmapModule(config),          "nmap",        dom),
            (CVEModule(config, self._collect_panel_data),         "cve",      dom),
            (ExploitsModule(config, self._collect_panel_data),    "exploits", dom),
            (AttackBriefModule(config, self._collect_panel_data), "brief",    dom),
            (PlaybookModule(config, self._collect_panel_data),    "playbook", dom),
        ]

    def _build_status(self) -> str:
        total = len(self._module_map)
        done  = self._done
        errs  = self._errors
        parts: list[str] = [f"[dim]>[/dim] [bold]{escape(self.target)}[/bold]"]

        # Mode badge (hidden for plain DOMAIN mode)
        if self._target_mode != TargetMode.DOMAIN:
            label = self._target_mode.value.upper()
            parts.append(f"  [bold magenta]{label}[/bold magenta]")
            if self._domain_hint:
                parts.append(f"  [dim]→  {escape(self._domain_hint)}[/dim]")

        if self._watch_mode:
            parts.append("  [yellow]◉ WATCH[/yellow]")
        if done < total:
            parts.append(f"  [dim]{done}/{total}[/dim]")
        else:
            parts.append(f"  [green]✓ {total}/{total}[/green]")
        if errs:
            parts.append(f"  [red]✗ {errs} error{'s' if errs > 1 else ''}[/red]")
        parts.append("  [dim]|  ? help  1-5 tabs[/dim]")
        return "".join(parts)

    def _refresh_status_bar(self) -> None:
        try:
            self.query_one("#status-bar", Static).update(self._build_status())
        except Exception:
            pass

    def watch__done(self, val: int) -> None:
        self._refresh_status_bar()
        self._refresh_tab_labels()
        total = len(self._module_map)
        if val == total and total > 0:
            count = 0
            for _, pid, _ in self._module_map:
                try:
                    count += self.query_one(f"#panel-{pid}", ReconPanel).count
                except Exception:
                    pass
            self.notify(f"✓ Scan complete — {count} total findings", timeout=5)

    def watch__errors(self, _: int) -> None:
        self._refresh_status_bar()
        self._refresh_tab_labels()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static(self._build_status(), id="status-bar")

        if self._target_mode == TargetMode.PERSON:
            with TabbedContent(initial="tab-person"):
                with TabPane("Person Intel", id="tab-person"):
                    with Horizontal(classes="tab-layout"):
                        with Vertical(classes="col"):
                            yield ReconPanel("Person Intel", "person")
                        with Vertical(classes="col"):
                            yield ExecTerminal()
            yield Footer()
            return

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
                        yield ReconPanel("Port Scan",       "nmap")
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
                        yield ReconPanel("Email Intel",      "email_intel")

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

        for module, panel_id, mod_target in self._module_map:
            self._run_module(module, panel_id, mod_target)
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
            for _, panel_id, _ in self._module_map:
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
        for _, panel_id, _ in self._module_map:
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
    async def _run_module(self, module: ReconModule, panel_id: str, target: str) -> None:
        panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
        panel.set_running()
        prev = self._watch_prev.get(panel_id, set())
        try:
            async for finding in module.run(target):
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
            self._errors += 1
            self._done += 1
            raise
        except Exception as exc:
            panel.set_error(str(exc))
            self._errors += 1
            self._done += 1
            return
        panel.set_done()
        self._done += 1
        self._fire_alert(panel_id, panel.export_lines())

    def _fire_alert(self, panel_id: str, findings: list[str]) -> None:
        """Show a toast if the panel contains a high-value indicator."""
        rules = _ALERT_RULES.get(panel_id, [])
        combined = " ".join(findings).lower()
        for keyword, message, severity in rules:
            if keyword.lower() in combined:
                self.notify(f"⚠  {message}", severity=severity, timeout=7)  # type: ignore[arg-type]
                return  # one alert per panel

    def _refresh_tab_labels(self) -> None:
        """Update tab label badges with current finding totals."""
        for tab_id, panels in _TAB_PANELS.items():
            total = 0
            for pid in panels:
                try:
                    total += self.query_one(f"#panel-{pid}", ReconPanel).count
                except Exception:
                    pass
            base = _TAB_LABELS.get(tab_id, tab_id)
            label = f"{base}  ({total})" if total > 0 else base
            try:
                self.query_one(f"Tab#{tab_id}", Tab).label = label
            except Exception:
                pass

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
        pass

    def action_show_help(self) -> None:
        self.push_screen(HelpScreen())

    def action_paste_exploit(self) -> None:
        """Copy the nearest exploit command from the reference panel into the terminal input."""
        try:
            tc = self.query_one(TabbedContent)
            if tc.active != "tab-exploit":
                self.notify("Switch to the Exploit tab first  (press 5)", timeout=2)
                return
            panel = self.query_one("#panel-exploits", ReconPanel)
            log   = panel.query_one(RichLog)
            lines = panel._all_lines
            scroll_y = int(log.scroll_y)
            cmd = None
            # Search downward from scroll position, then upward
            for idx in list(range(scroll_y, len(lines))) + list(range(scroll_y - 1, -1, -1)):
                text = lines[idx].strip()
                if text.startswith("$ "):
                    cmd = text[2:]
                    break
            if cmd:
                inp = self.query_one("#term-input", TermInput)
                inp.value = cmd
                inp.cursor_position = len(cmd)
                inp.focus()
                self.notify(f"Pasted: {cmd[:55]}{'…' if len(cmd) > 55 else ''}", timeout=2)
            else:
                self.notify("No command found in Exploit Reference", severity="warning", timeout=2)
        except Exception:
            pass

    def action_next_finding_tab(self) -> None:
        """Jump to the next tab that has at least one finding."""
        if self._target_mode == TargetMode.PERSON:
            return  # only one tab in PERSON mode

        tc = self.query_one(TabbedContent)
        current = tc.active
        try:
            start = _TAB_ORDER.index(current)
        except ValueError:
            start = 0
        for i in range(1, len(_TAB_ORDER) + 1):
            tab_id = _TAB_ORDER[(start + i) % len(_TAB_ORDER)]
            for pid in _TAB_PANELS.get(tab_id, set()):
                try:
                    if self.query_one(f"#panel-{pid}", ReconPanel).count > 0:
                        tc.active = tab_id
                        return
                except Exception:
                    pass

    def action_prev_tab(self) -> None:
        """Jump to the previous tab."""
        if self._target_mode == TargetMode.PERSON:
            return
        tc = self.query_one(TabbedContent)
        current = tc.active
        try:
            idx = _TAB_ORDER.index(current)
        except ValueError:
            idx = 0
        tc.active = _TAB_ORDER[(idx - 1) % len(_TAB_ORDER)]

    def action_scroll_top(self) -> None:
        """Scroll all panels in the active tab to the top."""
        try:
            pane = self.query_one(f"#{self.query_one(TabbedContent).active}")
            for log in pane.query(RichLog):
                if log.id != "term-log":
                    log.scroll_home(animate=False)
        except Exception:
            pass

    def action_scroll_bottom(self) -> None:
        """Scroll all panels in the active tab to the bottom."""
        try:
            pane = self.query_one(f"#{self.query_one(TabbedContent).active}")
            for log in pane.query(RichLog):
                if log.id != "term-log":
                    log.scroll_end(animate=False)
        except Exception:
            pass

    def action_rerun(self) -> None:
        self._done = 0
        self._errors = 0
        # Reset tab labels
        for tab_id, base in _TAB_LABELS.items():
            try:
                self.query_one(f"Tab#{tab_id}", Tab).label = base
            except Exception:
                pass
        for _, panel_id, _ in self._module_map:
            try:
                panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
                panel.clear()
            except Exception:
                pass
        for module, panel_id, mod_target in self._module_map:
            self._run_module(module, panel_id, mod_target)
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

        for _, panel_id, _ in self._module_map:
            try:
                panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
                lines.append(f"\n{'-' * 60}")
                lines.append(f"[{panel._title}]  ({panel.count} findings)")
                lines.append("-" * 60)
                lines.extend(panel.export_lines())
            except Exception:
                pass

        out.write_text("\n".join(lines))
        self.notify(f"Saved: {out}", severity="information")

    def action_save_json(self) -> None:
        safe_target = self.target.replace(".", "_").replace("/", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path(f"meridian_{safe_target}_{ts}.json")

        payload: dict = {
            "target": self.target,
            "date": datetime.now().isoformat(),
            "version": "0.85.0",
            "modules": {},
        }

        for _, panel_id, _ in self._module_map:
            try:
                panel = self.query_one(f"#panel-{panel_id}", ReconPanel)
                payload["modules"][panel_id] = {
                    "name": panel._title,
                    "count": panel.count,
                    "findings": panel.export_lines(),
                }
            except Exception:
                pass

        out.write_text(json.dumps(payload, indent=2))
        self.notify(f"Saved: {out}", severity="information")
