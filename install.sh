#!/usr/bin/env bash
set -euo pipefail

# ── Meridian installer ────────────────────────────────────────────────────────
# Creates a venv, installs dependencies, and symlinks `meridian` into
# ~/.local/bin so it's available on your PATH without manual activation.

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$INSTALL_DIR/.venv"
BIN_DIR="${HOME}/.local/bin"
LINK="$BIN_DIR/meridian"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

die()  { echo -e "${RED}error:${NC} $*" >&2; exit 1; }
info() { echo -e "${GREEN}▸${NC} $*"; }
warn() { echo -e "${YELLOW}warning:${NC} $*"; }

# ── Python version check ──────────────────────────────────────────────────────
PYTHON=$(command -v python3 || command -v python || die "python3 not found")
VERSION=$("$PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
MAJOR=$(echo "$VERSION" | cut -d. -f1)
MINOR=$(echo "$VERSION" | cut -d. -f2)

[[ "$MAJOR" -ge 3 && "$MINOR" -ge 11 ]] \
    || die "Python 3.11+ required (found $VERSION)"

info "Using Python $VERSION at $PYTHON"

# ── Virtual environment ───────────────────────────────────────────────────────
if [[ ! -d "$VENV" ]]; then
    info "Creating venv at $VENV"
    "$PYTHON" -m venv "$VENV"
else
    info "Venv already exists, updating"
fi

info "Installing dependencies"
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -e "$INSTALL_DIR"

# ── Symlink into PATH ─────────────────────────────────────────────────────────
mkdir -p "$BIN_DIR"

# Remove stale link if pointing elsewhere
if [[ -L "$LINK" && "$(readlink "$LINK")" != "$VENV/bin/meridian" ]]; then
    warn "Replacing existing symlink at $LINK"
    rm "$LINK"
fi

if [[ ! -e "$LINK" ]]; then
    ln -s "$VENV/bin/meridian" "$LINK"
    info "Linked: $LINK → $VENV/bin/meridian"
else
    info "Symlink already up to date"
fi

# ── PATH check ────────────────────────────────────────────────────────────────
echo ""
if echo ":$PATH:" | grep -q ":$BIN_DIR:"; then
    echo -e "${GREEN}✓ Done!${NC}  Run:  meridian <target>"
else
    echo -e "${GREEN}✓ Done!${NC}  Add this to your shell config (~/.zshrc or ~/.bashrc):"
    echo ""
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "  Then restart your shell, or run:"
    echo ""
    echo "    source ~/.zshrc   # or ~/.bashrc"
    echo ""
    echo "  After that:  meridian <target>"
fi
