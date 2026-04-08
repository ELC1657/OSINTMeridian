# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.72.1  | yes |
| 0.70.0  | no |
| 0.58.0  | no |
| 0.55.0  | no |
| 0.50.0  | no |
| 0.14.1  | no |
| 0.13.1  | no |
| 0.12.0  | no |
| 0.10.0  | no |

## Intended use

Meridian is an offensive security tool designed for use during **authorized penetration testing engagements, bug bounty programs, CTF competitions, and security research on systems you own or have explicit written permission to assess**.

Meridian operates in two modes:

**Passive recon** — the majority of modules query public third-party databases and APIs (Shodan, VirusTotal, crt.sh, HIBP, etc.). These modules do not send packets directly to the target.

**Active capability** — the Exploit tab includes an integrated execution terminal that can run arbitrary commands against a target, including tools such as `nuclei`, `hydra`, `swaks`, `nmap`, and Metasploit. This constitutes active testing and must only be used against systems you have explicit written authorization to test.

The Attack Brief, Playbook, and Exploit Reference panels generate attack chain suggestions and ready-to-run commands based on discovered data. These are informational references — executing them against any system without explicit written authorization is illegal.

The Dark Web panel queries breach intelligence services (IntelligenceX, BreachDirectory, Dehashed) for leaked credentials associated with the target domain. This data is read-only and sourced from existing public or commercial breach databases.

A mandatory authorization prompt is shown at startup. Users must confirm they have written permission before the tool proceeds. This can be bypassed with `-y` in scripted/automated contexts where authorization is already established.

## Authorized use only

Running reconnaissance or exploitation tools against systems without explicit written authorization is illegal in most jurisdictions. Examples of applicable law include:

- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Cybercrime laws in the EU, Australia, Canada, and elsewhere

**You are solely responsible for ensuring you have proper authorization before running Meridian against any target.**

See [DISCLAIMER.md](DISCLAIMER.md) for the full terms of use.

## Data handling

Meridian does not collect or transmit any data about you or your targets to the developer. All queries go directly from your machine to the respective third-party APIs. Each provider's privacy policy governs what they log:

- Shodan: [shodan.io/privacy](https://www.shodan.io/privacy)
- VirusTotal / Google: [virustotal.com/about/terms-of-service](https://www.virustotal.com/about/terms-of-service/)
- GitHub: [docs.github.com/en/site-policy/privacy-policies](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)
- Hunter.io: [hunter.io/privacy-policy](https://hunter.io/privacy-policy)
- Apollo.io: [apollo.io/privacy-policy](https://www.apollo.io/privacy-policy)
- HaveIBeenPwned: [haveibeenpwned.com/Privacy](https://haveibeenpwned.com/Privacy)
- BGPView: [bgpview.io](https://bgpview.io)
- IntelligenceX: [intelx.io/privacy](https://intelx.io/privacy)
- BreachDirectory / RapidAPI: [rapidapi.com/privacy](https://rapidapi.com/privacy)
- Dehashed: [dehashed.com/privacy](https://dehashed.com/privacy)
- SecurityTrails: [securitytrails.com/privacy-policy](https://securitytrails.com/privacy-policy)
- NVD / NIST: [nvd.nist.gov](https://nvd.nist.gov)

API keys are stored locally in `~/.config/meridian/.env` or `~/.config/meridian/keys.toml` and are never sent anywhere except to their respective services. They are never committed to git.

Reports saved with `s` or `j` are written to local files in your current directory. They are never uploaded anywhere.

## Reporting a vulnerability in Meridian

If you find a security vulnerability in Meridian itself (e.g. command injection, credential leakage, unsafe deserialization of API responses), please report it responsibly:

1. **Do not open a public GitHub issue** for security vulnerabilities.
2. Email a description of the issue, steps to reproduce, and potential impact. Include `[MERIDIAN SECURITY]` in the subject line.
3. You will receive an acknowledgement within 72 hours.

We will coordinate a fix and disclosure timeline with you.

## Scope of this policy

This policy covers the Meridian source code and its direct dependencies. Vulnerabilities in third-party APIs (Shodan, VirusTotal, Dehashed, etc.) should be reported to those vendors directly.
