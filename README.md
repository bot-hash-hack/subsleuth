# SubSleuth 🔍

**A fast, multi-source subdomain enumeration tool combining passive intelligence (Certificate Transparency logs + HackerTarget) with active DNS brute-forcing, wildcard-DNS filtering, and optional live HTTP probing.**

> ⚠️ For authorized security testing and research only. See [DISCLAIMER.md](DISCLAIMER.md) before use.

## Features

- **Multi-source passive recon**
  - [crt.sh](https://crt.sh) Certificate Transparency logs, with automatic retries/backoff
  - [HackerTarget](https://hackertarget.com) hostsearch API as a redundant second source
- **Active DNS brute-force** — multithreaded, against a built-in (~170 word) or custom wordlist
- **Wildcard DNS detection** — automatically detects catch-all DNS records and filters out the false positives they'd otherwise cause during brute-force
- **Live validation** — confirms which discovered subdomains actually resolve (A / AAAA / CNAME)
- **Optional HTTP(S) probing** (`--probe`) — checks which hosts are actually serving a website, reporting status code and page title
- **Source attribution** — every result shows which technique(s) found it
- **Rate limiting** — optional delay between brute-force requests to be gentler on the target
- **JSON or plain-text export**, with full DNS/probe metadata in JSON mode
- Graceful Ctrl+C handling, input validation, thread-safe output
- Zero-config, single-file Python script

## Installation

```bash
git clone https://github.com/yourusername/subsleuth.git
cd subsleuth
pip install -r requirements.txt --break-system-packages
```

## Usage

```bash
# Full scan (CT logs + HackerTarget + DNS brute-force)
python3 subdomain_scanner.py example.com

# Passive only — fastest, safest, no traffic to target
python3 subdomain_scanner.py example.com --no-bruteforce

# Custom wordlist and thread count
python3 subdomain_scanner.py example.com --wordlist mywords.txt --threads 50

# Check which discovered hosts are actually live over HTTP(S)
python3 subdomain_scanner.py example.com --probe

# Go easy on the target's DNS servers
python3 subdomain_scanner.py example.com --rate-limit 0.2

# Save results
python3 subdomain_scanner.py example.com --output results.json   # structured, with DNS/probe data
python3 subdomain_scanner.py example.com --output results.txt    # plain list
```

### Options

| Flag | Description |
|---|---|
| `domain` | Target root domain (required), e.g. `example.com` |
| `--wordlist PATH` | Custom wordlist file, one subdomain per line |
| `--threads N` | Threads for DNS brute-force / probing (default: 20) |
| `--rate-limit SEC` | Delay between brute-force requests per thread (default: 0) |
| `--no-bruteforce` | Skip DNS brute-force |
| `--no-ctlogs` | Skip crt.sh CT log lookup |
| `--no-hackertarget` | Skip HackerTarget secondary source |
| `--probe` | Probe discovered hosts over HTTP(S) for status code + title |
| `--output FILE` | Save results — `.json` for structured output, anything else for a plain text list |
| `--verbose` | Show extra progress detail |

## Example Output

```
==============================================================
  SubSleuth v2.0 — Subdomain Scan: example.com
  Started: 2026-09-18T10:00:00
  Only scan domains you own or are authorized to test.
==============================================================
[*] Querying crt.sh (Certificate Transparency logs) for *.example.com ...
[+] crt.sh returned 12 unique names
[*] Querying HackerTarget hostsearch for example.com ...
[+] HackerTarget returned 9 unique names
[*] Checking for wildcard DNS...
[+] No wildcard DNS detected.
[*] Brute-forcing 170 candidate subdomains (20 threads)...
[+] www.example.com -> A: 93.184.216.34
[+] mail.example.com -> CNAME: mail.example.com.mx-provider.net
[+] Brute-force resolved 14 live subdomains (156 filtered/dead)

==============================================================
  RESULTS: 19 unique subdomains found in 11.4s
==============================================================
  api.example.com                         (crt.sh)
  mail.example.com                         (crt.sh+dns-bruteforce)  [CNAME: mail.example.com.mx-provider.net]
  www.example.com                         (crt.sh+hackertarget+dns-bruteforce)  [A: 93.184.216.34]
  ...
```

## How It Works

1. **Certificate Transparency (CT) logs**: Every publicly trusted SSL/TLS certificate is logged publicly. SubSleuth queries crt.sh's database for any name matching `*.yourdomain.com` — entirely passively, with automatic retries if the service is briefly rate-limited.
2. **HackerTarget hostsearch**: A second, independent passive data source, queried in parallel with crt.sh so a single source going down doesn't blind the scan.
3. **Wildcard DNS detection**: Before brute-forcing, SubSleuth resolves a few random, near-certainly-nonexistent subdomains. If they resolve anyway, the domain has a wildcard DNS record — SubSleuth notes the IP(s) involved and filters any brute-force "hit" that matches them, so you don't get a false positive for every guess.
4. **DNS brute-force**: Tests common subdomain names (`www`, `api`, `staging`, `vpn`, etc.) against the target's DNS in parallel, reporting only names that resolve to something real (and aren't wildcard artifacts).
5. **HTTP(S) probing** (optional): For each confirmed subdomain, tries HTTPS then HTTP and reports the status code and `<title>` of the response, so you can quickly see which hosts are actually serving something interesting.

## Legal & Ethical Use

This tool is intended for:
- Security research on domains you own
- Authorized penetration testing / bug bounty programs (within scope)
- Educational purposes in a lab environment

**Do not** use this tool against any domain without explicit, documented authorization. See [DISCLAIMER.md](DISCLAIMER.md).

## Contributing

Issues and pull requests are welcome. Please keep contributions focused on defensive/authorized-use functionality.

## License

Released under the [MIT License](LICENSE).
