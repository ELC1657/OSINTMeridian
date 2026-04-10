"""
Doom-fire boot animation for Meridian.
Runs in the raw terminal before Textual starts.
Requires pyfiglet — silently skipped if not installed.
"""
from __future__ import annotations

import os
import random
import signal
import sys
import time
from dataclasses import dataclass, field

try:
    import pyfiglet as _pyfiglet  # type: ignore[import-untyped]
    _HAVE_PYFIGLET = True
except ImportError:
    _pyfiglet      = None  # type: ignore[assignment]
    _HAVE_PYFIGLET = False


# ── Colour + character tables ─────────────────────────────────────────────────
_BANDS = [
    (  1,  60,  80, 140,   0,   0,   0,   0,  ' .'),
    ( 61, 120, 180, 220,  20,  20,   0,   0,  ':|()'),
    (121, 180, 255, 255,  80, 140,   0,   0,  '{}*'),
    (181, 230, 255, 255, 200, 230,   0,   0,  '#$'),
    (231, 255, 255, 255, 240, 240, 100, 100,  '@'),
]


def _build_luts() -> tuple[list[tuple[int, int, int]], list[str]]:
    color: list[tuple[int, int, int]] = [(0, 0, 0)] * 256
    chars: list[str]                  = [' ']       * 256
    for lo, hi, r0, r1, g0, g1, b0, b1, cs in _BANDS:
        span = max(hi - lo, 1)
        n    = len(cs)
        for h in range(lo, hi + 1):
            t        = (h - lo) / span
            color[h] = (
                int(r0 + t * (r1 - r0)),
                int(g0 + t * (g1 - g0)),
                int(b0 + t * (b1 - b0)),
            )
            chars[h] = cs[min(int(t * n), n - 1)]
    return color, chars


_COLOR_LUT, _CHAR_LUT = _build_luts()

_FONT_PREFERENCE = ["doom", "banner3", "banner3-D", "block", "big", "standard"]
_WHITE  = '\033[1;37m'
_RESET  = '\033[0m'

_FPS        = 13
_FRAME_DUR  = 1.0 / _FPS
_MAX_SPARKS = 25


# ── Spark dataclass ───────────────────────────────────────────────────────────

@dataclass
class Spark:
    x:    float
    y:    float
    heat: float
    vy:   float   # upward velocity (negative = up)
    vx:   float   # horizontal drift


# ── Grid helpers ──────────────────────────────────────────────────────────────

def _make_grid(rows: int, cols: int) -> list[list[float]]:
    grid = [[0.0] * cols for _ in range(rows)]
    for x in range(cols):
        grid[rows - 1][x] = 240.0
    return grid


def _build_solid(rows: int, cols: int,
                 logo_lines: list[str], logo_y: int, logo_x: int
                 ) -> list[list[bool]]:
    solid = [[False] * cols for _ in range(rows)]
    for ly, line in enumerate(logo_lines):
        gy = logo_y + ly
        if gy < 0 or gy >= rows:
            continue
        for lx, ch in enumerate(line):
            gx = logo_x + lx
            if ch not in (' ', '\n', '\r') and 0 <= gx < cols:
                solid[gy][gx] = True
    return solid


# ── Fire step ─────────────────────────────────────────────────────────────────

def _step(
    grid:      list[list[float]],
    rows:      int,
    cols:      int,
    solid:     list[list[bool]],
    rng:       random.Random,
    frame_idx: int,
) -> None:
    # Re-seed sections of the bottom row every 3rd frame ("gusts")
    if frame_idx % 3 == 0:
        bot = rows - 1
        section_w = rng.randint(cols // 6, cols // 3)
        section_x = rng.randint(0, cols - section_w)
        for x in range(section_x, section_x + section_w):
            grid[bot][x] = rng.uniform(200, 255)

    # Propagate upward with temporal smoothing
    for y in range(rows - 2, -1, -1):
        y1 = y + 1
        y2 = y + 2 if y + 2 < rows else y1
        below  = grid[y1]
        below2 = grid[y2]
        cur    = grid[y]
        for x in range(cols):
            drift = rng.randint(-1, 1)
            xd    = (x + drift) % cols
            new   = (below[x] + below[xd] + below2[x]) / 3.0 \
                    - rng.uniform(2, 18)
            if new < 0:
                new = 0.0
            # Temporal smoothing — blends with previous value for organic roll
            cur[x] = cur[x] * 0.6 + new * 0.4

    # Solid cells are heat barriers — zero them after every propagation pass
    for y in range(rows):
        sol = solid[y]
        row = grid[y]
        for x in range(cols):
            if sol[x]:
                row[x] = 0.0


# ── Spark management ──────────────────────────────────────────────────────────

def _update_sparks(
    sparks:    list[Spark],
    grid:      list[list[float]],
    rows:      int,
    cols:      int,
    solid:     list[list[bool]],
    rng:       random.Random,
    frame_idx: int,
) -> None:
    # Move and age existing sparks
    dead: list[int] = []
    for i, s in enumerate(sparks):
        s.y    += s.vy
        s.x    += s.vx
        s.heat -= rng.uniform(8, 15)
        if s.heat <= 0 or s.y < 0 or s.y >= rows or s.x < 0 or s.x >= cols:
            dead.append(i)
    for i in reversed(dead):
        sparks.pop(i)

    # Spawn new sparks every few frames if under the cap
    if len(sparks) < _MAX_SPARKS and frame_idx % 2 == 0:
        # Find the heat transition zone: rows where heat drops from ~80 to ~20
        # Scan from top downward to find highest row with heat > 60
        spawn_y = -1
        for y in range(rows - 1):
            for x in range(cols):
                if grid[y][x] > 60:
                    spawn_y = y
                    break
            if spawn_y >= 0:
                break

        if spawn_y >= 0:
            sx = rng.uniform(0, cols - 1)
            sparks.append(Spark(
                x    = sx,
                y    = float(spawn_y),
                heat = rng.uniform(60, 120),
                vy   = rng.uniform(-1.5, -0.5),
                vx   = rng.uniform(-0.4, 0.4),
            ))


# ── Renderer ──────────────────────────────────────────────────────────────────

def _render(
    grid:       list[list[float]],
    rows:       int,
    cols:       int,
    solid:      list[list[bool]],
    sparks:     list[Spark],
    logo_lines: list[str],
    logo_y:     int,
    logo_x:     int,
) -> str:
    color_lut = _COLOR_LUT
    char_lut  = _CHAR_LUT

    # Build a sparse dict of spark positions for quick lookup
    spark_map: dict[tuple[int, int], Spark] = {}
    for s in sparks:
        sy, sx = int(s.y), int(s.x)
        if 0 <= sy < rows and 0 <= sx < cols:
            # If multiple sparks on same cell keep hottest
            key = (sy, sx)
            if key not in spark_map or s.heat > spark_map[key].heat:
                spark_map[key] = s

    buf: list[str] = ['\033[H']

    for y in range(rows):
        sol  = solid[y]
        row  = grid[y]
        line: list[str] = []
        prev_esc = ''

        for x in range(cols):
            if sol[x]:
                # Logo cell — bold white, always on top
                ly = y - logo_y
                lx = x - logo_x
                if 0 <= ly < len(logo_lines):
                    ll = logo_lines[ly]
                    ch = ll[lx] if lx < len(ll) else ' '
                else:
                    ch = ' '
                esc = _WHITE
                if esc != prev_esc:
                    line.append(esc)
                    prev_esc = esc
                line.append(ch)

            elif (y, x) in spark_map:
                # Spark cell — orange/yellow true-color
                s    = spark_map[(y, x)]
                h    = int(s.heat)
                t    = min(h, 255) / 255.0
                # Sparks: dark orange → bright yellow
                r    = int(180 + t * 75)
                g    = int(60  + t * 180)
                b    = 0
                ch   = '+' if h > 90 else ('*' if h > 50 else '.')
                esc  = f'\033[38;2;{r};{g};{b}m'
                if esc != prev_esc:
                    line.append(esc)
                    prev_esc = esc
                line.append(ch)

            else:
                # Fire cell
                h        = int(row[x])
                r, g, b  = color_lut[h]
                ch       = char_lut[h]
                esc      = f'\033[38;2;{r};{g};{b}m'
                if esc != prev_esc:
                    line.append(esc)
                    prev_esc = esc
                line.append(ch)

        buf.append(''.join(line))
        if y < rows - 1:
            buf.append('\n')

    buf.append(_RESET)
    return ''.join(buf)


# ── Logo helpers ──────────────────────────────────────────────────────────────

def _render_logo(cols: int) -> list[str]:
    if _pyfiglet is None:
        return []
    for font in _FONT_PREFERENCE:
        try:
            text  = _pyfiglet.Figlet(font=font, width=cols - 2).renderText("MERIDIAN")
            lines = text.split('\n')
            while lines and not lines[-1].strip():
                lines.pop()
            if lines:
                # Pad every line to the same width so centering is exact
                w = max(len(l) for l in lines)
                return [l.ljust(w) for l in lines]
        except Exception:
            continue
    return []


def _layout(rows: int, cols: int, logo_h: int, logo_w: int) -> tuple[int, int]:
    # True horizontal center
    lx = (cols - logo_w) // 2
    lx = max(0, lx)
    # Vertical: true center of screen
    ly = max(0, (rows - logo_h) // 2)
    ly = min(ly, rows - logo_h - 9)
    return ly, lx


# ── Entry point ───────────────────────────────────────────────────────────────

def run_fire_splash(target: str, duration: float = 5.5) -> None:
    """Doom-fire animation. Silent no-op if pyfiglet missing or not a tty."""
    if not _HAVE_PYFIGLET or not sys.stdout.isatty():
        return

    try:
        ts   = os.get_terminal_size()
        cols = ts.columns
        rows = ts.lines
    except OSError:
        cols, rows = 80, 24

    logo_lines = _render_logo(cols)
    if not logo_lines:
        return

    logo_h = len(logo_lines)
    logo_w = max(len(l) for l in logo_lines)

    rng = random.Random()

    def _init(rows: int, cols: int):
        ly, lx = _layout(rows, cols, logo_h, logo_w)
        g = _make_grid(rows, cols)
        s = _build_solid(rows, cols, logo_lines, ly, lx)
        # Warm up off-screen
        for fi in range(120):
            _step(g, rows, cols, s, rng, fi)
        return g, s, ly, lx

    grid, solid, logo_y, logo_x = _init(rows, cols)
    sparks: list[Spark] = []

    _resize = [False]
    def _sigwinch(*_):
        _resize[0] = True
    try:
        signal.signal(signal.SIGWINCH, _sigwinch)
    except (AttributeError, OSError):
        pass

    stdout = sys.stdout
    stdout.write('\033[?25l\033[?7l\033[2J')
    stdout.flush()

    frame_idx = 0
    end_t     = time.monotonic() + duration

    try:
        while time.monotonic() < end_t:
            if _resize[0]:
                _resize[0] = False
                try:
                    ts   = os.get_terminal_size()
                    cols = ts.columns
                    rows = ts.lines
                except OSError:
                    pass
                sparks.clear()
                grid, solid, logo_y, logo_x = _init(rows, cols)
                frame_idx = 0

            t0 = time.monotonic()

            _step(grid, rows, cols, solid, rng, frame_idx)
            _update_sparks(sparks, grid, rows, cols, solid, rng, frame_idx)
            stdout.write(
                _render(grid, rows, cols, solid, sparks, logo_lines, logo_y, logo_x)
            )
            stdout.flush()

            frame_idx += 1
            elapsed = time.monotonic() - t0
            if elapsed < _FRAME_DUR:
                time.sleep(_FRAME_DUR - elapsed)

    except KeyboardInterrupt:
        pass
    finally:
        stdout.write('\033[0m\033[2J\033[H\033[?25h\033[?7h')
        stdout.flush()
        try:
            signal.signal(signal.SIGWINCH, signal.SIG_DFL)
        except (AttributeError, OSError):
            pass
