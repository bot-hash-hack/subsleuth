# Disclaimer

## Authorized Use Only

SubSleuth is a security research and reconnaissance tool provided for **educational purposes and authorized security testing only**.

By downloading, installing, or using this tool, you agree that:

1. **You will only scan domains and systems that you own, or for which you have received explicit, documented, written authorization to test** (e.g., a signed penetration testing agreement or a bug bounty program's published scope).

2. **You are solely responsible** for ensuring your use of this tool complies with all applicable local, state, national, and international laws — including but not limited to computer fraud and abuse laws (e.g., the U.S. Computer Fraud and Abuse Act), unauthorized access statutes, and any relevant data protection regulations.

3. **The authors and contributors of this tool**:
   - Are not responsible or liable for any misuse, damage, legal consequences, or losses resulting from the use or misuse of this software.
   - Do not condone or support unauthorized scanning, reconnaissance, or any illegal activity against systems you do not own or lack permission to test.
   - Provide this software "as is," with no guarantee of accuracy, completeness, or fitness for any particular purpose.

4. **Technique-specific considerations**:
   - **Certificate Transparency (CT) log lookups** (crt.sh) are purely passive — they query a public third-party log, not the target itself.
   - **HackerTarget hostsearch** is also a passive third-party lookup, but is subject to that service's own rate limits and terms of use — heavy or automated use may violate their acceptable use policy.
   - **DNS brute-force** sends queries directly to DNS resolvers associated with the target domain and may be logged by the target's infrastructure or upstream providers.
   - **HTTP(S) probing** (`--probe`) sends live HTTP/HTTPS requests directly to discovered hosts. This is active, direct interaction with the target's infrastructure and requires the same level of authorization as any other active scanning technique. TLS certificate validation is disabled during probing for compatibility, which is appropriate only in an authorized testing context.

   Treat all of the above as requiring proper authorization before use.

5. **No warranty**: This software is provided without warranty of any kind. Subdomain results may be incomplete, outdated, or inaccurate (including false positives from wildcard DNS in edge cases not caught by detection, or false negatives from rate-limited sources), and should not be solely relied upon for security decisions.

## If You Are Unsure

If you are unsure whether you have authorization to scan a target, **do not run this tool against it**. Seek explicit written permission first.

## Reporting Misuse

This project does not host, distribute, or endorse any use of this tool against unauthorized targets. If you become aware of such misuse, please do not involve the project maintainers, as they have no ability to monitor or control end-user activity.
