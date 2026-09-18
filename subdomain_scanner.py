#!/usr/bin/env python3
"""
SubSleuth — Subdomain Enumeration Tool
========================================
Finds subdomains for a given domain using multiple techniques:
  1. Passive: Certificate Transparency logs (crt.sh)
  2. Passive: HackerTarget hostsearch API (secondary, redundant source)
  3. Active:  DNS brute-force against a wordlist, with live resolution
  4. Active:  Wildcard DNS detection (prevents false positives)
  5. Optional: HTTP(S) probing of discovered hosts (status code + title)

USE ONLY ON DOMAINS YOU OWN OR ARE AUTHORIZED TO TEST.
Unauthorized scanning of systems you don't control may be illegal.
See DISCLAIMER.md.

Usage:
    python3 subdomain_scanner.py example.com
    python3 subdomain_scanner.py example.com --wordlist mywords.txt --threads 50
    python3 subdomain_scanner.py example.com --no-bruteforce   # passive only
    python3 subdomain_scanner.py example.com --probe           # check live HTTP status
    python3 subdomain_scanner.py example.com --output results.json

Dependencies:
    pip install requests dnspython --break-system-packages
"""

import argparse
import concurrent.futures
import ipaddress
import json
import random
import re
import string
import sys
import threading
import time
from datetime import datetime

try:
    import requests
except ImportError:
    print("Missing dependency: pip install requests --break-system-packages")
    sys.exit(1)

try:
    import dns.resolver
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

VERSION = "2.0"

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "vpn", "m", "shop", "app", "api",
    "dev", "staging", "stage", "test", "testing", "qa", "uat", "demo", "beta",
    "admin", "administrator", "portal", "cpanel", "whm", "blog", "forum",
    "store", "support", "help", "docs", "wiki", "status", "monitor",
    "cdn", "static", "assets", "img", "images", "media", "video", "download",
    "downloads", "files", "upload", "backup", "old", "new", "beta2", "secure",
    "ssl", "vpn2", "remote", "gateway", "gw", "proxy", "cache", "git", "gitlab",
    "github", "svn", "jenkins", "ci", "cd", "build", "jira", "confluence",
    "sso", "auth", "login", "signin", "register", "account", "accounts",
    "my", "dashboard", "panel", "console", "manage", "management", "internal",
    "intranet", "extranet", "partner", "partners", "client", "clients",
    "customer", "customers", "billing", "pay", "payments", "checkout",
    "mobile", "ios", "android", "web", "web1", "web2", "server", "server1",
    "server2", "host", "hosting", "db", "database", "sql", "mysql", "redis",
    "cache1", "elk", "kibana", "grafana", "prometheus", "metrics", "logs",
    "mail1", "mail2", "email", "imap", "autodiscover", "autoconfig", "mx",
    "ns", "owa", "exchange", "chat", "im", "voip", "sip", "ws", "wss",
    "socket", "stream", "live", "tv", "news", "press", "careers", "jobs",
    "hr", "legal", "docs2", "kb", "faq", "community", "social", "events",
    "api1", "api2", "v1", "v2", "graphql", "ws1", "edge", "origin", "lb",
    "assets2", "images2", "cdn2", "static2", "uploads", "s3", "storage",
]

print_lock = threading.Lock()


def safe_print(*a, **kw):
    with print_lock:
        print(*a, **kw)


def validate_domain(domain):
    """Basic sanity check so we don't send garbage to DNS/crt.sh."""
    if not DOMAIN_RE.match(domain):
        return False
    if len(domain) > 253:
        return False
    return True


def normalize_domain(raw):
    domain = raw.strip().lower()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/", 1)[0]
    domain = domain.split(":", 1)[0]  # strip port if present
    domain = domain.rstrip(".")
    return domain


def belongs_to_domain(name, domain):
    """Correct suffix check — avoids 'notexample.com' matching 'example.com'."""
    name = name.strip().lower().rstrip(".")
    return name == domain or name.endswith("." + domain)


def check_dependencies_for_bruteforce():
    if not HAVE_DNSPYTHON:
        safe_print("[!] dnspython not installed — brute-force DNS resolution disabled.")
        safe_print("    Install with: pip install dnspython --break-system-packages")
        return False
    return True


def query_crtsh(domain, timeout=15, retries=3):
    """Passive: query crt.sh Certificate Transparency log search for subdomains."""
    safe_print(f"[*] Querying crt.sh (Certificate Transparency logs) for *.{domain} ...")
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    found = set()

    for attempt in range(1, retries + 1):
        try:
            resp = requests.get(
                url, params=params, timeout=timeout,
                headers={"User-Agent": "SubSleuth/%s" % VERSION},
            )
            resp.raise_for_status()
            data = resp.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and belongs_to_domain(name, domain) and "*" not in name:
                        found.add(name)
            safe_print(f"[+] crt.sh returned {len(found)} unique names")
            return found
        except requests.exceptions.RequestException as e:
            safe_print(f"[!] crt.sh attempt {attempt}/{retries} failed: {e}")
        except (json.JSONDecodeError, ValueError):
            safe_print(f"[!] crt.sh attempt {attempt}/{retries}: unexpected response (rate-limited?)")
        if attempt < retries:
            wait = 2 ** attempt
            safe_print(f"    retrying in {wait}s...")
            time.sleep(wait)

    safe_print("[!] crt.sh query ultimately failed — continuing without it")
    return found


def query_hackertarget(domain, timeout=15):
    """Passive: secondary source, HackerTarget's free hostsearch API (redundancy)."""
    safe_print(f"[*] Querying HackerTarget hostsearch for {domain} ...")
    found = set()
    try:
        resp = requests.get(
            "https://api.hackertarget.com/hostsearch/",
            params={"q": domain}, timeout=timeout,
            headers={"User-Agent": "SubSleuth/%s" % VERSION},
        )
        resp.raise_for_status()
        text = resp.text.strip()
        if "error" in text.lower() or "API count exceeded" in text:
            safe_print(f"[!] HackerTarget unavailable: {text[:80]}")
            return found
        for line in text.splitlines():
            name = line.split(",")[0].strip().lower()
            if name and belongs_to_domain(name, domain):
                found.add(name)
        safe_print(f"[+] HackerTarget returned {len(found)} unique names")
    except requests.exceptions.RequestException as e:
        safe_print(f"[!] HackerTarget query failed: {e}")
    return found


def detect_wildcard(domain, resolver, samples=3):
    """
    Detect wildcard DNS (*.domain resolves to something for ANY name).
    If present, brute-force results are unreliable unless we filter out
    the wildcard's own IP set. Returns a set of IPs to treat as 'not real'.
    """
    safe_print("[*] Checking for wildcard DNS...")
    wildcard_ips = set()
    hits = 0
    for _ in range(samples):
        rand_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
        fqdn = f"{rand_label}.{domain}"
        try:
            answers = resolver.resolve(fqdn, "A", lifetime=5)
            hits += 1
            wildcard_ips.update(str(r) for r in answers)
        except Exception:
            continue
    if hits > 0:
        safe_print(f"[!] Wildcard DNS detected — {hits}/{samples} random names resolved to: "
                    f"{', '.join(wildcard_ips) or 'unknown'}")
        safe_print("    Brute-force results matching these IPs will be filtered as false positives.")
    else:
        safe_print("[+] No wildcard DNS detected.")
    return wildcard_ips


def resolve_subdomain(sub_fqdn, resolver, record_types=("A", "AAAA", "CNAME")):
    """Try to resolve a single subdomain; return (fqdn, rtype, values) or None."""
    for rtype in record_types:
        try:
            answers = resolver.resolve(sub_fqdn, rtype, lifetime=5)
            values = [str(r) for r in answers]
            return sub_fqdn, rtype, values
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except dns.resolver.NoNameservers:
            continue
        except dns.exception.Timeout:
            continue
        except Exception:
            continue
    return None


def bruteforce_dns(domain, wordlist, threads=20, rate_limit=0.0, verbose=False):
    """Active: DNS brute-force against a wordlist, resolving each candidate,
    with wildcard-DNS filtering to avoid false positives."""
    if not check_dependencies_for_bruteforce():
        return set(), {}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    wildcard_ips = detect_wildcard(domain, resolver)

    # Normalize + dedupe wordlist
    clean_words = sorted({w.strip().lower() for w in wordlist if w.strip()})
    candidates = [f"{word}.{domain}" for word in clean_words]

    safe_print(f"[*] Brute-forcing {len(candidates)} candidate subdomains ({threads} threads)...")

    found = set()
    records = {}  # fqdn -> {"type": ..., "values": [...]}
    completed = 0
    total = len(candidates)

    def worker(fqdn):
        if rate_limit:
            time.sleep(rate_limit)
        return resolve_subdomain(fqdn, resolver)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(worker, fqdn): fqdn for fqdn in candidates}
        try:
            for future in concurrent.futures.as_completed(futures):
                completed += 1
                result = future.result()
                if result:
                    fqdn, rtype, values = result
                    # Filter out wildcard false positives (A/AAAA matching wildcard IP set)
                    if wildcard_ips and rtype in ("A", "AAAA") and set(values) & wildcard_ips:
                        if verbose:
                            safe_print(f"    (skipped {fqdn} — matches wildcard IP)")
                        continue
                    found.add(fqdn)
                    records[fqdn] = {"type": rtype, "values": values}
                    safe_print(f"[+] {fqdn} -> {rtype}: {', '.join(values)}")
                if verbose and completed % 25 == 0:
                    safe_print(f"    ...{completed}/{total} checked")
        except KeyboardInterrupt:
            safe_print("\n[!] Brute-force interrupted by user, cancelling remaining tasks...")
            executor.shutdown(wait=False, cancel_futures=True)
            raise

    safe_print(f"[+] Brute-force resolved {len(found)} live subdomains "
               f"({total - len(found)} filtered/dead)")
    return found, records


def probe_http(subdomains, threads=20, timeout=6):
    """Optional: check which discovered subdomains serve HTTP(S) and grab status/title."""
    safe_print(f"[*] Probing {len(subdomains)} hosts over HTTP(S)...")
    results = {}

    def try_probe(host):
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                resp = requests.get(
                    url, timeout=timeout, allow_redirects=True,
                    headers={"User-Agent": "SubSleuth/%s" % VERSION},
                    verify=False,
                )
                title_match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.I | re.S)
                title = title_match.group(1).strip()[:80] if title_match else ""
                return host, {
                    "scheme": scheme,
                    "status": resp.status_code,
                    "final_url": resp.url,
                    "title": title,
                }
            except requests.exceptions.RequestException:
                continue
        return host, None

    # Suppress noisy urllib3 warnings for verify=False during probing
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(try_probe, host): host for host in subdomains}
        for future in concurrent.futures.as_completed(futures):
            host, info = future.result()
            if info:
                results[host] = info
                safe_print(f"[+] {info['scheme']}://{host} -> {info['status']}"
                           f"{'  [' + info['title'] + ']' if info['title'] else ''}")

    safe_print(f"[+] {len(results)}/{len(subdomains)} hosts responded over HTTP(S)")
    return results


def load_wordlist(path):
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        if not words:
            safe_print(f"[!] Wordlist '{path}' is empty — falling back to default list")
            return DEFAULT_WORDLIST
        return words
    except OSError as e:
        safe_print(f"[!] Could not read wordlist file: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="SubSleuth — passive + active subdomain enumeration tool. "
                     "Only use on domains you own or are authorized to test."
    )
    parser.add_argument("domain", help="Target root domain, e.g. example.com")
    parser.add_argument("--wordlist", help="Path to custom wordlist file (one subdomain per line)")
    parser.add_argument("--threads", type=int, default=20, help="Threads for DNS brute-force (default: 20)")
    parser.add_argument("--rate-limit", type=float, default=0.0,
                         help="Delay in seconds between brute-force requests per thread (default: 0)")
    parser.add_argument("--no-bruteforce", action="store_true", help="Skip DNS brute-force")
    parser.add_argument("--no-ctlogs", action="store_true", help="Skip crt.sh CT log lookup")
    parser.add_argument("--no-hackertarget", action="store_true", help="Skip HackerTarget secondary source")
    parser.add_argument("--probe", action="store_true", help="Probe discovered hosts over HTTP(S) for status/title")
    parser.add_argument("--output", help="Save results (JSON if endswith .json, else plain text list)")
    parser.add_argument("--verbose", action="store_true", help="Show extra progress detail")
    args = parser.parse_args()

    domain = normalize_domain(args.domain)
    if not validate_domain(domain):
        safe_print(f"[!] '{domain}' doesn't look like a valid domain name. Aborting.")
        sys.exit(1)

    safe_print("=" * 62)
    safe_print(f"  SubSleuth v{VERSION} — Subdomain Scan: {domain}")
    safe_print(f"  Started: {datetime.now().isoformat(timespec='seconds')}")
    safe_print("  Only scan domains you own or are authorized to test.")
    safe_print("=" * 62)

    start = time.time()
    sources = {}  # subdomain -> set of source names
    dns_records = {}

    def merge(new_set, source_name):
        for s in new_set:
            sources.setdefault(s, set()).add(source_name)

    try:
        if not args.no_ctlogs:
            merge(query_crtsh(domain), "crt.sh")

        if not args.no_hackertarget:
            merge(query_hackertarget(domain), "hackertarget")

        if not args.no_bruteforce:
            wordlist = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_WORDLIST
            bf_found, bf_records = bruteforce_dns(
                domain, wordlist, threads=args.threads,
                rate_limit=args.rate_limit, verbose=args.verbose,
            )
            merge(bf_found, "dns-bruteforce")
            dns_records.update(bf_records)
    except KeyboardInterrupt:
        safe_print("\n[!] Scan interrupted by user. Showing partial results...")

    elapsed = time.time() - start
    sorted_results = sorted(sources.keys())

    probe_results = {}
    if args.probe and sorted_results:
        probe_results = probe_http(sorted_results, threads=min(args.threads, 30))

    safe_print("\n" + "=" * 62)
    safe_print(f"  RESULTS: {len(sorted_results)} unique subdomains found in {elapsed:.1f}s")
    safe_print("=" * 62)
    for s in sorted_results:
        src = "+".join(sorted(sources[s]))
        extra = ""
        if s in dns_records:
            extra = f"  [{dns_records[s]['type']}: {', '.join(dns_records[s]['values'])}]"
        if s in probe_results:
            p = probe_results[s]
            extra += f"  [{p['scheme'].upper()} {p['status']}]"
        safe_print(f"  {s:<40} ({src}){extra}")

    if not sorted_results:
        safe_print("  No subdomains found. Try a larger wordlist or check the domain spelling.")

    if args.output:
        if args.output.endswith(".json"):
            with open(args.output, "w") as f:
                json.dump({
                    "tool": "SubSleuth",
                    "version": VERSION,
                    "domain": domain,
                    "scanned_at": datetime.now().isoformat(),
                    "elapsed_seconds": round(elapsed, 2),
                    "count": len(sorted_results),
                    "subdomains": [
                        {
                            "name": s,
                            "sources": sorted(sources[s]),
                            "dns": dns_records.get(s),
                            "http_probe": probe_results.get(s),
                        }
                        for s in sorted_results
                    ],
                }, f, indent=2)
        else:
            with open(args.output, "w") as f:
                f.write("\n".join(sorted_results) + "\n")
        safe_print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        safe_print("\n[!] Interrupted. Exiting.")
        sys.exit(130)
