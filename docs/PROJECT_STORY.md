## Inspiration

Over 70% of small business owners lack dedicated IT or cybersecurity personnel. When non-technical business owners try to audit their web posture, standard vulnerability scanners act like "military weapons": they launch intrusive probes that risk crashing services or output 40-page PDF reports filled with raw cryptographic acronyms like DMARC $p=\text{quarantine}$, HSTS $\text{max-age}=31536000$, and TLS cipher suites.

Small business owners don't need terrifying vulnerability dumps — they need a zero-risk posture grade with plain-language remediations they can act on immediately. That inspired us to build **Netgrade**: a passive, non-intrusive security posture scanner designed specifically for small business resilience.

## What it does

Netgrade audits any public domain across **7 key passive security controls** without ever attempting exploitation, password testing, or intrusive probing:

1. **Email Spoofing (SPF/DKIM/DMARC)**: Detects whether scammers can impersonate your domain via email.
2. **TLS/SSL Configuration**: Evaluates certificate validity, days until expiry, and modern protocol enforcement (TLS 1.3).
3. **HTTP Security Headers**: Checks for HSTS, Content-Security-Policy (CSP), X-Frame-Options, and X-Content-Type-Options.
4. **Session Cookie Flags**: Verifies Secure, HttpOnly, and SameSite flags on session tokens to prevent XSS hijacking.
5. **Exposed Artefacts**: Audits known sensitive paths (such as `.git`, `.env`, `.DS_Store`) that leak credentials.
6. **DNS Hygiene & NS Spread**: Checks nameserver redundancy and zone transfer exposure to prevent single points of outage failure.
7. **Certificate Transparency Logs**: Queries public CT logs via two independent aggregators (crt.sh, with Cert Spotter as automatic fallback) to uncover forgotten or exposed subdomains.

Netgrade synthesizes these findings into a weighted score $S \in [0, 100]$ and grade $G \in \{A, B, C, D, F\}$. It generates an instant **30-second spoken AI audio briefing** powered by ElevenLabs voice synthesis, provides an interactive **Plain-Language FAQ Guide**, and supports **Side-by-Side Competitor Benchmarking** so business owners can audit their posture relative to industry peers.

## How we built it

Netgrade is built with Python 3.13, FastAPI, and an asynchronous inspection engine:

- **Asynchronous Inspection Orchestrator**: Uses `asyncio.wait` to fan out all 7 risk checks concurrently.
- **Process-Wide Outbound Semaphore**: Bounds socket usage at $N_{\text{max}} = 24$ concurrent connections globally across all users, preventing connection exhaustion during traffic bursts.
- **Raw DER TLS Certificate Parsing**: Rather than relying on `ssl.getpeercert()`, which fails on unverified sockets, Netgrade parses raw DER bytes directly with `cryptography` to explain *why* an untrusted or expired certificate was rejected.
- **Frozen Schema Contract**: A Pydantic `ScanResult` schema strictly decouples the passive inspection engine from presentation rendering.
- **Frontend & Accessibility**: Built with custom HSL dark glassmorphism styling, high-contrast WCAG 2.1 AA accessibility, keyboard navigation focus rings (`--focus-ring`), ARIA roles, anti-spam submission guards, and dynamic scan step overlays.
- **Deployment & Testing**: Containerized with Docker and `docker-compose.yml`, deployed live at `netgrade.certifa.net`, and backed by a Pytest suite of **428 passing unit and integration tests**.

## Challenges we ran into

1. **"A Failure to Look is Not a Finding"**:
   Scoring an unreached check as a failure produces reports that are confidently wrong during temporary DNS blips or third-party outages. We designed a scoring rule where errored checks are **excluded from the denominator** rather than penalized with an F grade. To prevent flattering unmeasured domains, we implemented a grade cap when fewer than 4 checks complete:
   $$\text{Grade} = \min\left(\text{CalculatedGrade}, \text{'C'}\right) \quad \text{if } N_{\text{completed}} < 4$$

2. **Parsing Unverified TLS Certificates**:
   Standard Python socket verification closes the connection on bad certificates. We implemented a two-pass TLS handshake: first attempting strict verification, and if rejected, retrying unverified purely to extract DER certificate bytes and explain the exact failure reason to the user.

3. **A Third-Party Dependency That Actually Failed**:
   CT logs are append-only Merkle trees indexed by certificate rather than by domain, so answering "which certificates exist for this name" requires an aggregator that has already indexed them — an unavoidable third-party dependency. We documented crt.sh as a single point of failure we did not control, alongside tight 6-second request timeouts, single-retry policies, 5-minute TTL caching, and token-bucket rate limiting.

   Then it failed. crt.sh returned HTTP 502s to every query form, then read timeouts, and stayed down. Certificate history reported "could not check" on every scan. Rather than leave a documented risk unaddressed, we added a second aggregator: crt.sh is tried first, Cert Spotter answers when it cannot, and the report records which source responded. The payloads differ enough to need separate parsers, both reducing to one internal representation so the summarising logic never learns where the data came from. Production logs now show the failover working, with all seven checks completing.

## Accomplishments that we're proud of

- **Green Suite Across Every Layer**: Built a test suite of **428 passing tests** (`pytest -v`) covering edge cases, scoring math, check isolation, and custom 404/500 exception handlers.
- **Production Deployment**: Successfully deployed live to [https://netgrade.certifa.net](https://netgrade.certifa.net).
- **Spoken AI Audio Briefings**: Integrated ElevenLabs AI voice synthesis with local spoken fallback engines for offline testing.
- **Zero Intrusive Risk**: Guaranteed 100% passive, read-only inspection that small businesses can run with complete confidence.

## What we learned

- **Decoupling Security Logic from Presentation**: Establishing a frozen Pydantic schema early allowed us to iterate on engine checks and UI styling independently without contract breakages.
- **Process-Wide Resource Management**: Bounding outbound concurrency at the application process level rather than per-request is essential for web scanners handling concurrent users.
- **Designing for Non-Technical Users**: Translating complex security concepts into plain-language fixes and spoken briefings makes security actionable rather than overwhelming.

## What's next for Netgrade - Passive Security Posture Scanner

- **Automated Policy Drift Alerts**: Email notifications when a business domain's certificate is approaching expiry or DMARC record disappears.
- **Distributed Edge Scanner Nodes**: Running passive checks from multi-region edge locations to detect geo-specific CDN and DNS discrepancies.
- **Executive PDF Export**: Generating 1-page printable executive summary reports for board meetings and insurance compliance audits.
- **API Access**: Developer API keys for automated CI/CD posture checks.
