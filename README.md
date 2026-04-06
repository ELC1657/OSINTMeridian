# Meridian

Passive recon aggregator for penetration testers. Type a target, get results from every source simultaneously in a live terminal UI - no browser tabs, no manual copy-paste.

```
┌─────────────────────────┬──────────────────────────┬─────────────────────────┐
│ ✓ DNS Records      (10) │ ✓ Subdomains (crt.sh)(47)│ ✓ Shodan           (12) │
│                         │                          │                         │
│ A      104.18.26.120    │ *.target.com             │ 104.18.26.120:443/tcp   │
│ A      104.18.27.120    │ api.target.com           │   nginx 1.25.3          │
│ AAAA   2606:4700::...   │ admin.target.com         │   ⚠ CVE-2023-44487      │
│ MX     0 .              │ dev.target.com           │ 104.18.27.120:80/tcp    │
│ NS     ns1.cloudflare.. │ staging.target.com       │ DNS subdomains (23)     │
│ TXT    v=spf1 -all      │ ...                      │   api.target.com        │
│                         ├──────────────────────────┤ ◉ VirusTotal            │
│ ✓ WHOIS            (8)  │ ◉ Wayback Machine        │                         │
│                         │                          │ Detections: 0/93        │
│ Registrar: Cloudflare   │ Archived URLs: 1,204     │ Reputation: +5          │
│ Created:   2012-04-11   │ Unique hosts: 8          │ Categories: technology  │
│ Expires:   2026-04-11   │ Interesting URLs (14):   │ ◉ GitHub                │
│ Org:       Target Inc.  │   200 /api/v1/users      │                         │
│ Country:   US           │   200 /admin/login       │ .env files  (3 results) │
│ DNSSEC:    unsigned     │   404 /.git/config       │   target/config ↗       │
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

Four sources work with zero configuration. The other three need free API keys.

## Install

```bash
git clone https://github.com/you/meridian
cd meridian
./install.sh
```

The script creates a `.venv`, installs all dependencies, and symlinks `meridian` into `~/.local/bin`. If that directory isn't on your `$PATH` yet, the script will tell you what to add to your shell config.

**Requirements:** Python 3.11+

## Usage

```bash
# Domain
meridian example.com

# With keys in a .env file
cp .env.example .env   # fill in your keys
meridian example.com

# Pass keys inline
meridian example.com --shodan-key=xxx --vt-key=yyy --github-token=zzz

# Keys from environment
export SHODAN_API_KEY=xxx
meridian example.com
```

### Keybindings

| Key | Action |
|---|---|
| `s` | Save a plain-text report to `meridian_<target>_<timestamp>.txt` |
| `r` | Re-run all modules against the same target |
| `q` | Quit |

## API keys

All keys are free tier unless you need higher rate limits.

| Key | Where to get it | What it unlocks |
|---|---|---|
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io/) | Host enumeration, open ports, CVEs, DNS subdomains |
| `VT_API_KEY` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Detections, reputation, historical IPs, subdomains |
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) (public_repo scope) | Code search dorks - 30 req/min instead of 10 |

Keys are loaded in this order (later overrides earlier):

1. `~/.config/meridian/keys.toml`
2. Environment variables
3. `.env` file in the current directory
4. CLI flags (`--shodan-key`, `--vt-key`, `--github-token`)

## Updating

```bash
cd meridian
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
