# Meridian

Passive recon aggregator for penetration testers. Type a target, get results from every source simultaneously in a live terminal UI - no browser tabs, no manual copy-paste.

```
┌─────────────────────────┬──────────────────────────┬─────────────────────────┐
│ ✓ DNS Records      (25) │ ✓ Subdomains (crt.sh)(11)│ ✓ Shodan           (4)  │
│                         │                          │                         │
│ A      104.26.0.16      │ Total unique: 9          │ Search requires paid    │
│ A      104.26.1.16      │ api.target.com           │ plan. DNS lookup:       │
│ AAAA   2606:4700::...   │ dev.target.com           │   cdn.target.com        │
│ MX     10 mx1.target... │ mail.target.com          │   mail.target.com       │
│ NS     lily.ns.cloud... │ panel.target.com         ├─────────────────────────┤
│ TXT    v=spf1 +mx...    │ ...                      │ ✓ VirusTotal      (22)  │
│ CAA    0 issue ssl.com  ├──────────────────────────┤                         │
│                         │ ◉ Wayback Machine        │ Detections: 0/94        │
│ ✓ WHOIS            (6)  │                          │ Reputation: +0          │
│                         │ Archived URLs: 1,204     │ Subdomains (9):         │
│ Registrar: Cloudflare   │ Interesting URLs (14):   │   cdn.target.com        │
│ Created:   2012-04-11   │   200 /api/v1/users      │   dev.target.com        │
│ Expires:   2026-04-11   │   200 /admin/login       ├─────────────────────────┤
│ Org:       Target Inc.  │   404 /.git/config       │ ✓ GitHub          (20)  │
│ Country:   US           ├──────────────────────────┤                         │
│                         │ ✓ Hunter.io        (8)   │ password  (10 results)  │
│                         │                          │   joshhk72/prodigy      │
│                         │ Org: Target Inc.         │ secret   (119 results)  │
│                         │ Pattern: {f}{last}@...   │   tech234a/annotation   │
│                         │ Emails found: 42         │ .env files  (3 results) │
│                         │  94%  j.smith@target.com │   target/config         │
│                         │  87%  a.jones@target.com ├─────────────────────────┤
└─────────────────────────┴──────────────────────────┴─────────────────────────┘
```

## Sources

| Panel | Source | API key |
|---|---|---|
| DNS Records | `8.8.8.8` / `1.1.1.1` - A, AAAA, MX, NS, TXT, CNAME, SOA, CAA + AXFR attempt | - |
| WHOIS | `python-whois` | - |
| Subdomains | [crt.sh](https://crt.sh) certificate transparency logs | - |
| Wayback Machine | [CDX API](https://web.archive.org/cdx/) - flags `.env`, `.bak`, `/admin`, `/api`, etc. | - |
| Shodan | Host search + DNS subdomains endpoint, CVEs surfaced inline | `SHODAN_API_KEY` |
| VirusTotal | Domain report, detection stats, historical IPs, subdomains | `VT_API_KEY` |
| GitHub | 10 dork queries - passwords, secrets, `.env`, private keys, configs | `GITHUB_TOKEN` |
| Hunter.io | Email discovery, org info, email pattern inference, confidence scores | `HUNTER_API_KEY` |

Four sources work with zero configuration. The other four need free API keys.

## Install

```bash
git clone https://github.com/ELC1657/OSINTMeridian
cd OSINTMeridian
./install.sh
```

The script creates a `.venv`, installs all dependencies, and symlinks `meridian` into `~/.local/bin`. If that directory isn't on your `$PATH` yet, the script will tell you what to add to your shell config.

**Requirements:** Python 3.11+

## Usage

```bash
meridian example.com
```

```bash
# Pass keys inline
meridian example.com --shodan-key=xxx --vt-key=yyy --github-token=zzz

# Keys from environment
export SHODAN_API_KEY=xxx
meridian example.com
```

### Keybindings

| Key | Action |
|---|---|
| `t` | Cycle through themes |
| `s` | Save a plain-text report to `meridian_<target>_<timestamp>.txt` |
| `r` | Re-run all modules against the same target |
| `q` | Quit |

## Themes

Press `t` to cycle through 10 built-in themes:

Matrix, Blood, Nord, Gruvbox, Catppuccin, Dracula, Tokyo Night, Monokai, Rose Pine, Default Dark

## API keys

All keys are free tier unless you need higher rate limits.

| Key | Where to get it | What it unlocks |
|---|---|---|
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io/) | Host enumeration, open ports, CVEs, DNS subdomains |
| `VT_API_KEY` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Detections, reputation, historical IPs, subdomains |
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) (public_repo scope) | Code search dorks - 30 req/min instead of 10 |
| `HUNTER_API_KEY` | [hunter.io/users/sign_up](https://hunter.io/users/sign_up) | Email discovery, org info, email pattern inference |

Store your keys in `~/.config/meridian/.env` so they work from any directory:

```bash
mkdir -p ~/.config/meridian
cp .env.example ~/.config/meridian/.env
# edit ~/.config/meridian/.env and fill in your keys
```

Keys are loaded in this order (later overrides earlier):

1. `~/.config/meridian/keys.toml`
2. `~/.config/meridian/.env`
3. Environment variables
4. `.env` in current directory
5. CLI flags (`--shodan-key`, `--vt-key`, `--github-token`)

## Updating

```bash
cd OSINTMeridian
git pull
make update
```

## Uninstall

```bash
make uninstall   # removes ~/.local/bin/meridian
rm -rf .venv     # optionally remove the venv
```

## Legal

Meridian performs **passive reconnaissance only** - it queries public APIs and databases, not the target directly. You are still responsible for ensuring you have authorization before running any recon against a target. See [SECURITY.md](SECURITY.md).
