# Meridian `v0.75.0`

> ⚠️ **LEGAL DISCLAIMER — READ BEFORE USE**
>
> Meridian is intended for **authorized penetration testing, bug bounty programs, CTF competitions, and security research on systems you own or have explicit written permission to assess**. Running this tool against any system without explicit written authorization is illegal. The developer accepts no liability for misuse or damage. By using Meridian you confirm you have proper authorization. See [DISCLAIMER.md](DISCLAIMER.md) for full terms.

Offensive recon aggregator for penetration testers. Type a target, get results from 22 sources simultaneously in a live tabbed terminal UI — no browser tabs, no copy-paste, no context switching. Includes an integrated exploit reference and execution terminal.

```
Network  Web  Offensive  Brief  Exploit
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
|     candidates     |   ceo@target.com   | Interesting paths  |
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
| Network | `1` | DNS Records, WHOIS, Spoofability, Shodan, ASN / IP Ranges, Port Scan, DNS History, CVE Correlation |
| Web | `2` | Subdomains (crt.sh), Wayback Machine, URLScan.io, Cloud Buckets |
| Offensive | `3` | VirusTotal, GitHub, Hunter.io, Employee Targets, Takeover, Breach Intel, Dark Web |
| Brief | `4` | Attack Brief, Playbook, JS Secrets, URL Params |
| Exploit | `5` | Exploit Reference, Execution Terminal |

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
| Port Scan | Active nmap scan — two phases: fast top-1000 TCP, then `-sV -sC` on open ports. Flags high-risk services (RDP, SMB, Redis, etc.) in red. Requires `nmap` installed. | - |
| ASN / IP Ranges | BGPView - ASN number, org name, all owned IPv4/IPv6 prefixes | - |
| VirusTotal | Detection stats, reputation, historical IPs, subdomains | `VT_API_KEY` |
| GitHub | 10 dork queries - passwords, secrets, `.env`, private keys, configs | `GITHUB_TOKEN` |
| Hunter.io | Email discovery, org info, email pattern, confidence scores | `HUNTER_API_KEY` |
| Employee Targets | Hunter.io + Apollo.io + GitHub org members, ranked by attack value | `HUNTER_API_KEY` / `APOLLO_API_KEY` / `GITHUB_TOKEN` |
| Takeover | Checks all crt.sh subdomains for dangling CNAMEs across 20 known services | - |
| Breach Intel | HIBP public breach list - domain + name match, pwn counts, data types | - |
| Dark Web | IntelligenceX, BreachDirectory, Dehashed — leaked credentials, dark web mentions | `INTELX_API_KEY` / `RAPIDAPI_KEY` / `DEHASHED_API_KEY` |
| JS Secrets | Fetches archived JS files, scans for AWS keys, tokens, JWTs, passwords | - |
| URL Params | Mines 8,000 archived URLs for SSRF candidates, injection params, sensitive paths | - |
| DNS History | SecurityTrails — all historical A, MX, NS records with date ranges | `SECTRAILS_API_KEY` |
| Cloud Buckets | Probes 78 permutations across AWS S3, GCP Storage, Azure Blob for open/existing buckets | - |
| CVE Correlation | Cross-references detected tech stack against NVD for HIGH/CRITICAL CVEs | `NVD_API_KEY` (optional) |
| Exploit Reference | Auto-generated exploit commands from CVEs, spoofability, leaked creds, SSRF, buckets | - |
| Attack Brief | Waits for all modules, synthesizes findings into CRITICAL / HIGH / MEDIUM / INFO | - |
| Playbook | Generates a numbered, tool-ready attack plan based on what was actually found | - |

## Install

```bash
git clone https://github.com/ELC1657/OSINTMeridian
cd OSINTMeridian
./install.sh
```

The script creates a `.venv`, installs all dependencies, and symlinks `meridian` into `~/.local/bin`. If that directory is not on your `$PATH`, the script will tell you what to add to your shell config.

**Requirements:** Python 3.11+, `nmap` for the Port Scan panel (`brew install nmap`), `pyfiglet` (installed automatically via pip)

## Usage

```bash
meridian example.com
```

Meridian will prompt you to confirm you have written authorization before starting. To skip the prompt (e.g. in scripts):

```bash
meridian example.com -y
```

```bash
# Pass keys inline
meridian example.com -y --shodan-key=xxx --vt-key=yyy --github-token=zzz

# Keys from environment
export SHODAN_API_KEY=xxx
meridian example.com -y
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
| `1` / `2` / `3` / `4` / `5` | Switch tabs (Network / Web / Offensive / Brief / Exploit) |
| `n` | Jump to next tab that has findings |
| `t` | Cycle through all available themes |
| `s` | Save plain-text report to `meridian_<target>_<timestamp>.txt` |
| `j` | Save JSON report to `meridian_<target>_<timestamp>.json` |
| `r` | Re-run all modules against the same target |
| `?` | Show keybinding help overlay |
| `p` | Paste nearest Exploit Reference command into the terminal input (Exploit tab) |
| `q` | Quit |

**Click any panel header** to copy all findings from that panel at once. Click any individual line to copy just that line. In the Exploit Reference panel, clicking a command line strips the `$ ` prefix automatically.

### Status bar

The status bar shows live scan progress — `8/23` modules done, turning `✓ 23/23` green when complete. If any module fails it shows `✗ N errors` in red.

### Panel headers

Each panel header shows the module status icon, finding count, and — once complete — the elapsed time (e.g. `✓ Shodan  (12)  3.2s`). This makes it easy to spot slow or timed-out modules.

## Themes

Press `t` to cycle through every installed Textual theme. Custom themes — Matrix and Blood — are always first in the cycle. The notify shows your position: `Theme: Dracula  (4/14)`.

## Exploit Tab

The **Exploit** tab (press `5`) is split into two panels:

**Left — Exploit Reference** (auto-populates after recon finishes):
- CVE → Metasploit `use exploit/...` command + Nuclei template + ExploitDB link
- Open ports (nmap) → targeted attack commands per service: RDP spray, SMB/EternalBlue, SSH brute, Redis/Elasticsearch/MongoDB unauthenticated access, WinRM, SNMP enum, FTP anonymous login
- Spoofable domain → `swaks` phishing command using real MX server from DNS panel
- Open S3/GCP/Azure buckets → `aws s3 ls` + sync dump commands
- Leaked plaintext passwords → `hydra` spray commands for SSH, web login, OWA/Exchange
- SSRF candidates → `curl` AWS metadata probe commands
- Subdomain takeovers → instructions to claim the service

**Right — Execution Terminal**:
- Type any command, press Enter — output streams live
- `↑` / `↓` to cycle through command history (shell-style)
- Type `clear` to wipe the terminal output
- Press `p` while on the Exploit tab to paste the nearest command from the Reference panel directly into the terminal input
- On failure: contextual fix suggestions (blocklist workarounds, missing tools, auth errors)
- On command not found: install command shown immediately (`brew install ...`)
- Click any output line to copy it

> All exploit commands are for use during **authorized engagements only**. You are solely responsible for what you execute.

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

The **Employee Targets** panel (Offensive tab) queries three sources and merges/deduplicates results:

| Source | Returns | Key |
|---|---|---|
| Hunter.io | Emails, names, roles, confidence scores | `HUNTER_API_KEY` |
| Apollo.io | Names, titles, emails, LinkedIn URLs, location | `APOLLO_API_KEY` |
| GitHub org | Public org members — name, bio, email, GitHub URL | `GITHUB_TOKEN` |

Each employee is scored by attack value (0–10) based on role keyword matching:
- Score 9-10 (red `HIGH VALUE`): CEO, CFO, CTO, CISO, president, founder
- Score 7-8 (yellow `MED VALUE`): IT director, sysadmin, finance, devops, cloud
- Score 3-6: Engineering, sales, support

## Dark Web

The **Dark Web** panel (Offensive tab) queries up to three breach intelligence sources:

| Source | What it finds | Key |
|---|---|---|
| IntelligenceX | Dark web forum posts, Tor site mentions, ransomware group leaks, paste sites | `INTELX_API_KEY` |
| BreachDirectory | Email:password and email:hash pairs from public dumps | `RAPIDAPI_KEY` |
| Dehashed | 15B+ records — plaintext passwords, hashed passwords, usernames, database names | `DEHASHED_API_KEY` |

## DNS History

The **DNS History** panel (Network tab) queries SecurityTrails for every historical A, MX, and NS record with first-seen and last-seen dates. Finds decommissioned infrastructure, old mail servers, and previous hosting providers.

## Cloud Buckets

The **Cloud Buckets** panel (Web tab) probes 78 name permutations across AWS S3, GCP Cloud Storage, and Azure Blob Storage — no API key needed:

- `PUBLIC` (HTTP 200) — open read access
- `EXISTS (private)` (HTTP 403/400) — bucket exists but locked down

## CVE Correlation

The **CVE Correlation** panel (Network tab) waits for URLScan.io and Shodan to finish, extracts the tech stack, then queries NVD for HIGH/CRITICAL CVEs. `NVD_API_KEY` is optional but raises the rate limit significantly.

## JSON export

Press `j` to save a machine-readable report:

```bash
jq '.modules.crtsh.findings[]'     meridian_example_com_*.json  # subdomains
jq '.modules.dnshistory.findings[]' meridian_example_com_*.json  # DNS history
jq '.modules.buckets.findings[]'   meridian_example_com_*.json  # cloud buckets
jq '.modules.cve.findings[]'       meridian_example_com_*.json  # CVE matches
jq '.modules.darkweb.findings[]'   meridian_example_com_*.json  # dark web
jq '.modules.exploits.findings[]'  meridian_example_com_*.json  # exploit commands
jq '.modules.brief.findings[]'     meridian_example_com_*.json  # attack brief
jq -r '.modules.crtsh.findings[]'  meridian_example_com_*.json | ffuf ...
```

## API keys

| Key | Where to get it | Cost | What it unlocks |
|---|---|---|---|
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io/) | Free | Host enumeration, open ports, CVEs, DNS subdomains |
| `VT_API_KEY` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Free | Detections, reputation, historical IPs, subdomains |
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) (public_repo scope) | Free | Code search dorks + GitHub org member enumeration |
| `HUNTER_API_KEY` | [hunter.io/users/sign_up](https://hunter.io/users/sign_up) | Free | Email discovery, employee scoring, org intel |
| `APOLLO_API_KEY` | [apollo.io](https://apollo.io) | Free (75 credits/mo) | Employee names, titles, LinkedIn URLs |
| `INTELX_API_KEY` | [intelx.io](https://intelx.io) | Free (10 searches/mo) | Dark web mentions, paste sites, ransomware leaks |
| `RAPIDAPI_KEY` | [rapidapi.com](https://rapidapi.com) → BreachDirectory | Free (50 req/mo) | Email:password pairs from public dumps |
| `DEHASHED_API_KEY` | [dehashed.com](https://dehashed.com) | Paid (~$5/mo) | 15B+ records with plaintext passwords |
| `SECTRAILS_API_KEY` | [securitytrails.com](https://securitytrails.com) | Free (50 queries/mo) | DNS history — past IPs, nameservers, mail servers |
| `NVD_API_KEY` | [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) | Free | CVE queries at 50 req/30s instead of 5 req/30s |

Store keys in `~/.config/meridian/.env`:

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
5. CLI flags (`--shodan-key`, `--vt-key`, `--github-token`, etc.)

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

## License

MIT — see [LICENSE](LICENSE).

## Legal

See [DISCLAIMER.md](DISCLAIMER.md) for full terms. Meridian performs passive reconnaissance and provides an exploit reference for use during authorized engagements only. You are solely responsible for ensuring you have authorization before running Meridian against any target.
