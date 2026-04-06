# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.14.0  | ✓ |
| 0.13.1  | ✗ |
| 0.12.0  | ✗ |
| 0.10.0  | ✗ |

## Intended use

Meridian is a passive reconnaissance tool designed for use during **authorized penetration testing engagements, bug bounty programs, CTF competitions, and security research on systems you own or have explicit written permission to assess**.

Passive reconnaissance means Meridian only queries public third-party databases (Shodan, crt.sh, VirusTotal, Wayback Machine, WHOIS, GitHub, DNS resolvers). It does not send packets directly to the target, exploit vulnerabilities, or perform active scanning.

## Authorized use only

Running reconnaissance against systems without explicit written authorization is illegal in most jurisdictions, regardless of how the tool works. Examples of applicable law include:

- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom
- Cybercrime laws in the EU, Australia, Canada, and elsewhere

**You are solely responsible for ensuring you have proper authorization before running Meridian against any target.**

## Data handling

Meridian does not collect or transmit any data about you or your targets. All queries go directly from your machine to the respective third-party APIs. Each provider's privacy policy governs what they log:

- Shodan: [shodan.io/privacy](https://www.shodan.io/privacy)
- VirusTotal / Google: [virustotal.com/about/terms-of-service](https://www.virustotal.com/about/terms-of-service/)
- GitHub: [docs.github.com/en/site-policy/privacy-policies](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)

API keys are stored locally in `~/.config/meridian/.env` or `~/.config/meridian/keys.toml` and are never sent anywhere except to their respective services. They are never committed to git.

Reports saved with `s` are written to a local `.txt` file in your current directory. They are never uploaded anywhere.

## Reporting a vulnerability in Meridian

If you find a security vulnerability in Meridian itself (e.g. command injection, credential leakage, unsafe deserialization of API responses), please report it responsibly:

1. **Do not open a public GitHub issue** for security vulnerabilities.
2. Email a description of the issue, steps to reproduce, and potential impact. Include `[MERIDIAN SECURITY]` in the subject line.
3. You will receive an acknowledgement within 72 hours.

We will coordinate a fix and disclosure timeline with you.

## Scope of this policy

This policy covers the Meridian source code and its direct dependencies. Vulnerabilities in third-party APIs (Shodan, VirusTotal, etc.) should be reported to those vendors directly.
