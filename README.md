# Meridian `v0.14.1`

Passive recon aggregator for penetration testers. Type a target, get results from every source simultaneously in a live terminal UI - no browser tabs, no manual copy-paste.

```
┌─────────────────────────┬──────────────────────────┬─────────────────────────┐
│ ✓ DNS Records      (25) │ ✓ Subdomains (crt.sh)(11)│ ✓ Shodan           (4)  │
│                         │                          │                         │
│ A      104.26.0.16      │ Total unique: 9          │ Search requires paid    │
│ MX     10 mx1.target... │ api.target.com           │ plan. DNS lookup:       │
│ NS     lily.ns.cloud... │ dev.target.com           │   cdn.target.com        │
│ TXT    v=spf1 +mx...    │ mail.target.com          ├─────────────────────────┤
│ CAA    0 issue ssl.com  ├──────────────────────────┤ ✓ VirusTotal      (22)  │
│                         │ ◉ Wayback Machine        │                         │
│ ✓ WHOIS            (6)  │                          │ Detections: 0/94        │
│                         │ Archived URLs: 1,204     │ Reputation: +0          │
│ Registrar: Cloudflare   │ Interesting URLs (14):   │ Subdomains (9)          │
│ Created:   2012-04-11   │   200 /api/v1/users      ├─────────────────────────┤
│ Expires:   2026-04-11   │   200 /admin/login       │ ✓ GitHub          (20)  │
│ Org:       Target Inc.  ├──────────────────────────┤                         │
│ Country:   US           │ ✓ URLScan.io        (8)  │ password  (10 results)  │
│                         │                          │ secret   (119 results)  │
│                         │ Scans on record: 42      │ .env files  (3 results) │
│                         │ IP: 104.26.0.16  (US)    ├─────────────────────────┤
│                         │ Server: cloudflare       │ ✓ Hunter.io        (8)  │
│                         │ Malicious: No  score: 0  │                         │
│                         │ Tech stack:              │ Pattern: {f}{last}@...  │
│                         │   Cloudflare  CDN        │ Emails found: 42        │
│                         │   React  JavaScript      │  94%  j.smith@target    │
│                         │ Missing headers:         │  87%  a.jones@target    │
│                         │   content-security-pol.. └─────────────────────────┘
└─────────────────────────┴──────────────────────────┘
```

## Sources

| Panel | Source | API key |
|---|---|---|
| DNS Records | `8.8.8.8` / `1.1.1.1` - A, AAAA, MX, NS, TXT, CNAME, SOA, CAA + AXFR attempt | - |
| WHOIS | `python-whois` | - |
| Subdomains | [crt.sh](https://crt.sh) certificate transparency logs | - |
| Wayback Machine | [CDX API](https://web.archive.org/cdx/) - flags `.env`, `.bak`, `/admin`, `/api`, etc. | - |
| URLScan.io | Tech stack, security headers, IPs contacted, malicious verdict | - |
| Shodan | Host search + DNS subdomains endpoint, CVEs surfaced inline | `SHODAN_API_KEY` |
| VirusTotal | Domain report, detection stats, historical IPs, subdomains | `VT_API_KEY` |
| GitHub | 10 dork queries - passwords, secrets, `.env`, private keys, configs | `GITHUB_TOKEN` |
| Hunter.io | Email discovery, org info, email pattern inference, confidence scores | `HUNTER_API_KEY` |

Five sources work with zero configuration. The other four need free API keys.

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
| `j` | Save a JSON report to `meridian_<target>_<timestamp>.json` |
| `r` | Re-run all modules against the same target |
| `q` | Quit |

Click any finding to copy it to your clipboard.

## Themes

Press `t` to cycle through 10 built-in themes:

Matrix, Blood, Nord, Gruvbox, Catppuccin, Dracula, Tokyo Night, Monokai, Rose Pine, Default Dark

## JSON export

Press `j` to save a machine-readable report. Pipe findings into other tools with `jq`:

```bash
# All subdomains
jq '.modules.crtsh.findings[]' meridian_example_com_*.json

# All DNS records
jq '.modules.dns.findings[]' meridian_example_com_*.json

# Feed subdomains into another tool
jq -r '.modules.crtsh.findings[]' meridian_example_com_*.json | ffuf ...
```

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
