<<<<<<< HEAD
# Meridian `v0.14.1`
=======
# Meridian v0.50.0
>>>>>>> 571e894 (v0.50.0 - major feature release)

Offensive recon aggregator for penetration testers. Type a target, get results from 18 sources simultaneously in a live tabbed terminal UI — no browser tabs, no copy-paste, no context switching.

```
Network  Web  Offensive  Brief
+--------------------+--------------------+--------------------+
| Attack Brief  (12) | Playbook      (18) | JS Secrets     (3) |
|                    |                    |                    |
| MERIDIAN BRIEF     | ATTACK PLAYBOOK    | Found 12 JS URLs   |
| Risk: CRITICAL     | target.com         | No secrets found   |
|                    |                    +--------------------+
| CRITICAL           | STEP 1  PHISHING   | URL Params     (9) |
|  1. PHISHING READY |   CRITICAL         |                    |
|     Spoofable +42  |   Basis: spoofable | SSRF candidates    |
|     emails (Hunter)|   + 42 emails      |   url=   (14 URLs) |
|  2. SUBDOMAIN      |                    |   redirect= (8)    |
|     TAKEOVER: 2    |   swaks --from     |                    |
|     candidates     |   ceo@target.com \ | Interesting paths  |
|                    |   --to victim@...  |   Admin  (3)       |
| HIGH               |                    |   /.env  (1) [!]   |
|  1. BREACH DATA    | STEP 2  CRED STUFF |   /api/v1/  (14)   |
|     3 breaches     |   HIGH             |                    |
|     in HIBP        |   hydra -L ...     |                    |
+--------------------+--------------------+--------------------+
```

## Tabs

| Tab | Key | Panels |
|---|---|---|
| Network | `1` | DNS Records, WHOIS, Spoofability, Shodan, ASN / IP Ranges |
| Web | `2` | Subdomains (crt.sh), Wayback Machine, URLScan.io |
| Offensive | `3` | VirusTotal, GitHub, Hunter.io, Employee Targets, Takeover, Breach Intel |
| Brief | `4` | Attack Brief, Playbook, JS Secrets, URL Params |

## Sources

| Panel | What it does | API key |
|---|---|---|
| DNS Records | A, AAAA, MX, NS, TXT, CNAME, SOA, CAA via `8.8.8.8` / `1.1.1.1` + AXFR attempt | - |
| WHOIS | Registrar, org, dates, nameservers, DNSSEC, contact emails | - |
| Spoofability | Resolves SPF + DMARC, gives SPOOFABLE / PARTIAL / PROTECTED verdict | - |
| Subdomains | [crt.sh](https://crt.sh) certificate transparency logs | - |
| Wayback Machine | CDX API - archived URLs, flags `.env`, `.bak`, `/admin`, `/api` | - |
| URLScan.io | Tech stack, security headers, IPs, malicious verdict | - |
| Shodan | Host search, open ports, CVEs, DNS subdomains | `SHODAN_API_KEY` |
| ASN / IP Ranges | BGPView - ASN number, org name, all owned IPv4/IPv6 prefixes | - |
| VirusTotal | Detection stats, reputation, historical IPs, subdomains | `VT_API_KEY` |
| GitHub | 10 dork queries - passwords, secrets, `.env`, private keys, configs | `GITHUB_TOKEN` |
| Hunter.io | Email discovery, org info, email pattern, confidence scores | `HUNTER_API_KEY` |
| Employee Targets | Ranks every discovered employee by attack value (role + breach exposure) | `HUNTER_API_KEY` |
| Takeover | Checks all crt.sh subdomains for dangling CNAMEs across 20 known services | - |
| Breach Intel | HIBP public breach list - domain + name match, pwn counts, data types | - |
| JS Secrets | Fetches archived JS files, scans for AWS keys, tokens, JWTs, passwords | - |
| URL Params | Mines 8,000 archived URLs for SSRF candidates, injection params, sensitive paths | - |
| Attack Brief | Waits for all modules, synthesizes findings into CRITICAL / HIGH / MEDIUM / INFO | - |
| Playbook | Generates a numbered, tool-ready attack plan based on what was actually found | - |

Seven sources work with zero configuration. Four need free API keys.

## Install

```bash
git clone https://github.com/ELC1657/OSINTMeridian
cd OSINTMeridian
./install.sh
```

The script creates a `.venv`, installs all dependencies, and symlinks `meridian` into `~/.local/bin`. If that directory is not on your `$PATH`, the script will tell you what to add to your shell config.

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

### Watch mode

Re-scan the target automatically on a timer. New findings are highlighted with `◆` in yellow.

```bash
meridian example.com --watch                  # re-scan every 30 minutes
meridian example.com --watch --interval 15    # re-scan every 15 minutes
```

The status bar shows `◉ WATCH` when active. A notification fires before each re-scan.

### Keybindings

| Key | Action |
|---|---|
| `1` / `2` / `3` / `4` | Switch tabs (Network / Web / Offensive / Brief) |
| `t` | Cycle through all available themes |
| `s` | Save plain-text report to `meridian_<target>_<timestamp>.txt` |
| `j` | Save JSON report to `meridian_<target>_<timestamp>.json` |
| `r` | Re-run all modules against the same target |
| `q` | Quit |

Click any finding to copy it to the clipboard.

## Themes

Press `t` to cycle through every installed Textual theme. Custom themes — Matrix and Blood — are always first in the cycle. The notify shows your position: `Theme: Dracula  (4/14)`.

## Attack Brief and Playbook

The **Brief** and **Playbook** panels wait silently for all other modules to complete, then synthesize everything.

**Brief** produces a risk-tiered summary:
- `CRITICAL` — phishing-ready spoofable domain with emails, subdomain takeovers, hardcoded JS secrets
- `HIGH` — breach data, significant GitHub exposure, SSRF candidates
- `MEDIUM` — SPF softfail, missing security headers, sensitive archived paths
- `INFO` — subdomain count, ASN, tech stack

**Playbook** produces numbered attack steps with specific CLI commands:
```
STEP 1  PHISHING CAMPAIGN  CRITICAL
  swaks --from ceo@target.com --to victim@target.com \
        --server mx1.target.com \
        --header "Subject: Urgent wire transfer"

STEP 2  CREDENTIAL STUFFING  HIGH
  hydra -L emails.txt -P passwords.txt \
        -s 443 target.com https-post-form \
        "/login:username=^USER^&password=^PASS^:Invalid"
```

## Employee Targets

The **Employee Targets** panel (Offensive tab) scores every employee discovered via Hunter.io by attack value:

- Score 9-10 (red `HIGH VALUE`): CEO, CFO, CTO, CISO, president, founder
- Score 7-8 (yellow `MED VALUE`): IT director, sysadmin, finance, devops, cloud
- Score 3-6: Engineering, sales, support

Each entry shows name, role, email, Hunter confidence percentage, and a visual score bar.

## JSON export

Press `j` to save a machine-readable report. Pipe into other tools with `jq`:

```bash
# All subdomains
jq '.modules.crtsh.findings[]' meridian_example_com_*.json

# All DNS records
jq '.modules.dns.findings[]' meridian_example_com_*.json

# Employee target list
jq '.modules.employees.findings[]' meridian_example_com_*.json

# Attack brief
jq '.modules.brief.findings[]' meridian_example_com_*.json

# Feed subdomains into ffuf
jq -r '.modules.crtsh.findings[]' meridian_example_com_*.json | ffuf ...
```

## API keys

All keys are free tier.

| Key | Where to get it | What it unlocks |
|---|---|---|
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io/) | Host enumeration, open ports, CVEs, DNS subdomains |
| `VT_API_KEY` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Detections, reputation, historical IPs, subdomains |
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) (public_repo scope) | Code search dorks - 30 req/min instead of 10 |
| `HUNTER_API_KEY` | [hunter.io/users/sign_up](https://hunter.io/users/sign_up) | Email discovery, employee scoring, org intel |

Store keys in `~/.config/meridian/.env` so they work from any directory:

```bash
mkdir -p ~/.config/meridian
cp .env.example ~/.config/meridian/.env
# fill in your keys
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

Meridian performs passive reconnaissance only — it queries public APIs and databases, not the target directly. You are still responsible for ensuring you have authorization before running any recon against a target. See [SECURITY.md](SECURITY.md).
