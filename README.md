# Meridian `v0.85.0`

> ⚠️ **LEGAL DISCLAIMER — READ BEFORE USE**
>
> Meridian is intended for **authorized penetration testing, bug bounty programs, CTF competitions, and security research on systems you own or have explicit written permission to assess**. Running this tool against any system without explicit written authorization is illegal. The developer accepts no liability for misuse or damage. By using Meridian you confirm you have proper authorization. See [DISCLAIMER.md](DISCLAIMER.md) for full terms.

Offensive recon aggregator for penetration testers. Type a target, get results from multiple sources simultaneously in a live tabbed terminal UI — no browser tabs, no copy-paste, no context switching. Includes an integrated exploit reference and execution terminal.

Five target modes let you pivot from domains to IPs, email addresses, organisations, and named individuals without changing tools.

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
| Offensive | `3` | VirusTotal, GitHub, Hunter.io, Employee Targets, Takeover, Breach Intel, Dark Web, Email Intel |
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
| Hunter.io | Email discovery, org info, email pattern, confidence scores. In email mode: also runs the email verifier endpoint (deliverability, MX, disposable/webmail flags). | `HUNTER_API_KEY` |
| Employee Targets | Hunter.io + Apollo.io + GitHub org members, ranked by attack value | `HUNTER_API_KEY` / `APOLLO_API_KEY` / `GITHUB_TOKEN` |
| Takeover | Checks all crt.sh subdomains for dangling CNAMEs across 20 known services | - |
| Breach Intel | HIBP public breach list - domain + name match, pwn counts, data types. In email mode: searches the extracted domain. | - |
| Dark Web | IntelligenceX, BreachDirectory, Dehashed — leaked credentials, dark web mentions. In email mode: all three sources query the full email address directly. | `INTELX_API_KEY` / `RAPIDAPI_KEY` / `DEHASHED_API_KEY` |
| Email Intel | EmailRep.io reputation + breach flags + social profiles; Gravatar profile, linked accounts, bio, location. Active in email mode only. | - |
| JS Secrets | Fetches archived JS files, scans for AWS keys, tokens, JWTs, passwords | - |
| URL Params | Mines 8,000 archived URLs for SSRF candidates, injection params, sensitive paths | - |
| DNS History | SecurityTrails — all historical A, MX, NS records with date ranges | `SECTRAILS_API_KEY` |
| Cloud Buckets | Probes 78 permutations across AWS S3, GCP Storage, Azure Blob for open/existing buckets | - |
| CVE Correlation | Cross-references detected tech stack against NVD for HIGH/CRITICAL CVEs | `NVD_API_KEY` (optional) |
| Exploit Reference | Auto-generated exploit commands from CVEs, spoofability, leaked creds, SSRF, buckets | - |
| Attack Brief | Waits for all modules, synthesizes findings into CRITICAL / HIGH / MEDIUM / INFO | - |
| Playbook | Generates a numbered, tool-ready attack plan based on what was actually found | - |
| Person Intel | GitHub profiles, email permutations, Dehashed name search, code mentions. Active in person mode only. | `GITHUB_TOKEN` / `DEHASHED_API_KEY` |

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

## Target modes

Meridian supports five target types, each loading only the modules relevant to that target. The positional argument is always domain mode for backwards compatibility.

| Flag | Mode | What runs |
|---|---|---|
| *(positional)* or `-d` / `--domain` | Domain | All modules |
| `-ip` / `--ip` | IP address | DNS, WHOIS, Shodan, ASN, Nmap, VirusTotal, URLScan + synthesis |
| `-e` / `--email` | Email address | All domain modules on the domain part; Hunter verifier + EmailRep + Gravatar + Breach + Dark Web on the full email |
| `-or` / `--org` | Organisation | Domain resolved via Clearbit → DuckDuckGo; all domain modules run on that domain |
| `-p` / `--person` | Person name | GitHub profiles, email permutations, Dehashed name search, GitHub code mentions |

```bash
meridian example.com                   # domain (positional — default)
meridian -d example.com                # domain (explicit)
meridian -ip 192.168.1.1               # IP address
meridian -e user@example.com           # email address
meridian -or "Acme Corp"               # organisation name
meridian -p "John Smith"               # person name
```

The status bar shows the active mode and the resolved domain hint when applicable:

```
> user@example.com  EMAIL  →  example.com   8/25
> Acme Corp         ORG    →  acme.com      ✓ 25/25
> 192.168.1.1       IP                      ✓ 25/25
```

Only one mode flag may be used at a time. They are mutually exclusive.

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
| `b` | Jump to previous tab |
| `g` | Scroll all panels in the active tab to the top |
| `G` | Scroll all panels in the active tab to the bottom |
| `t` | Cycle through all available themes |
| `s` | Save plain-text report to `meridian_<target>_<timestamp>.txt` |
| `j` | Save JSON report to `meridian_<target>_<timestamp>.json` |
| `r` | Re-run all modules against the same target |
| `?` | Show keybinding help overlay |
| `p` | Paste nearest Exploit Reference command into the terminal input (Exploit tab) |
| `q` | Quit |

**Click any panel header** to copy all findings from that panel at once. Click any individual line to copy just that line. In the Exploit Reference panel, clicking a command line strips the `$ ` prefix automatically.

### Status bar

The status bar shows live scan progress — `8/25` modules done, turning `✓ 25/25` green when complete. If any module fails it shows `✗ N errors` in red. In non-domain modes a mode badge and resolved domain appear next to the target.

### Tab badges

Tab labels update live as findings arrive — `Offensive (47)`, `Network (12)` — so you can see where the action is without switching tabs. Counts reset when you re-run with `r`.

### Critical finding alerts

Meridian automatically fires toast notifications when high-value indicators are detected:

| Trigger | Alert |
|---|---|
| Spoofable domain | Domain is spoofable — phishing ready |
| Open cloud bucket | Open cloud storage bucket found! |
| Leaked credentials on dark web | Leaked credentials on dark web |
| Subdomain takeover candidate | Subdomain takeover candidates found |
| JS secrets detected | JS secrets detected |
| High-risk port exposed | High-risk service exposed |
| Email credentials leaked | Email credentials leaked |

A summary toast fires when all modules complete: `✓ Scan complete — N total findings`.

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

## Email mode

Run with `-e` to target a specific email address. All domain modules run on the extracted domain, and the following panels receive the full email address:

| Panel | What it does with the email |
|---|---|
| Email Intel | EmailRep.io reputation, breach flags, social profiles; Gravatar profile, linked accounts |
| Hunter.io | Email verifier — deliverability, MX host, disposable/webmail/gibberish detection |
| Breach Intel | HIBP breach lookup on the email's domain |
| Dark Web | IntelX, BreachDirectory, and Dehashed all query the exact email address |

```bash
meridian -e ceo@example.com -y
```

## Person Intel

The **Person Intel** panel (activated with `-p "Full Name"`) gathers OSINT on a named individual. The core checks require no API keys at all.

### Platform presence (no key required)

Generates up to six username variants from the name (`johnsmith`, `john.smith`, `jsmith`, `j.smith`, `smithjohn`, `john`) then checks all of them concurrently:

| Platform | What it returns |
|---|---|
| Reddit | Profile URL, total karma |
| Keybase | Profile URL, display name |
| HackerNews | Profile URL, karma |
| DEV.to | Profile URL, display name |
| Docker Hub | Profile URL, full name |
| npm | Profile URL |
| Gravatar | Avatar presence on most likely email addresses |

### Email permutations (no key required)

Generates full `pattern@provider` addresses across gmail / outlook / yahoo for each pattern — `first.last`, `flast`, `firstl`, `first_last`, `last.first`, `first` — ready to copy into breach checkers or spray tools.

### OSINT dork strings (no key required)

Eight ready-to-paste Google/Bing queries:
- `"John Smith" site:linkedin.com/in`
- `"John Smith" site:twitter.com`
- `"John Smith" filetype:pdf resume OR CV`
- `"John Smith" "@gmail.com" OR "@outlook.com" OR "@yahoo.com"`
- `"John Smith" password OR credentials site:github.com`
- `"John Smith" site:pastebin.com OR site:paste.ee`

### Optional key-based sources

| Source | What it finds | Key |
|---|---|---|
| GitHub user search | Matching profiles — login, URL, relevance score | `GITHUB_TOKEN` |
| Dehashed | Name-matched leaks — email, plaintext password, database | `DEHASHED_EMAIL` / `DEHASHED_API_KEY` |
| GitHub code search | Source files that mention the person's name | `GITHUB_TOKEN` |

```bash
meridian -p "John Smith" -y
```

Person mode uses a focused two-panel layout (Person Intel + Execution Terminal) instead of the standard multi-tab view.

## Employee Targets

The **Employee Targets** panel (Offensive tab, domain mode) queries three sources and merges/deduplicates results:

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

In email mode (`-e`), all three sources receive the full email address. Dehashed queries `email:<address>` instead of `domain:<domain>`.

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
jq '.modules.crtsh.findings[]'      meridian_example_com_*.json  # subdomains
jq '.modules.dnshistory.findings[]' meridian_example_com_*.json  # DNS history
jq '.modules.buckets.findings[]'    meridian_example_com_*.json  # cloud buckets
jq '.modules.cve.findings[]'        meridian_example_com_*.json  # CVE matches
jq '.modules.darkweb.findings[]'    meridian_example_com_*.json  # dark web
jq '.modules.exploits.findings[]'   meridian_example_com_*.json  # exploit commands
jq '.modules.brief.findings[]'      meridian_example_com_*.json  # attack brief
jq '.modules.email_intel.findings[]' meridian_example_com_*.json # email intel
jq '.modules.person.findings[]'     meridian_example_com_*.json  # person intel
jq -r '.modules.crtsh.findings[]'   meridian_example_com_*.json | ffuf ...
```

## API keys

| Key | Where to get it | Cost | What it unlocks |
|---|---|---|---|
| `SHODAN_API_KEY` | [account.shodan.io](https://account.shodan.io/) | Free | Host enumeration, open ports, CVEs, DNS subdomains |
| `VT_API_KEY` | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) | Free | Detections, reputation, historical IPs, subdomains |
| `GITHUB_TOKEN` | [github.com/settings/tokens](https://github.com/settings/tokens) (public_repo scope) | Free | Code search dorks + GitHub org member enumeration + person intel |
| `HUNTER_API_KEY` | [hunter.io/users/sign_up](https://hunter.io/users/sign_up) | Free | Email discovery, employee scoring, org intel, email verifier |
| `APOLLO_API_KEY` | [apollo.io](https://apollo.io) | Free (75 credits/mo) | Employee names, titles, LinkedIn URLs |
| `INTELX_API_KEY` | [intelx.io](https://intelx.io) | Free (10 searches/mo) | Dark web mentions, paste sites, ransomware leaks |
| `RAPIDAPI_KEY` | [rapidapi.com](https://rapidapi.com) → BreachDirectory | Free (50 req/mo) | Email:password pairs from public dumps |
| `DEHASHED_API_KEY` | [dehashed.com](https://dehashed.com) | Paid (~$5/mo) | 15B+ records with plaintext passwords; also used by person mode |
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
