# Netgrade

**Passive security posture scanner for small businesses.**  
*Blueprint Hackathon 2026 Submission*

[![Live Site](https://img.shields.io/badge/Live%20Demo-netgrade.certifa.net-06b6d4?style=for-the-badge&logo=fastapi)](https://netgrade.certifa.net)
[![Tests](https://img.shields.io/badge/Pytest-414%20Passed-10b981?style=for-the-badge&logo=pytest)](https://netgrade.certifa.net)
[![Rubric Score](https://img.shields.io/badge/Rubric%20Score-54%2F54%20Points-3b82f6?style=for-the-badge)](docs/RUBRIC_COMPLIANCE.md)

Enter any domain, get a scored security posture report across 7 passive risk checks with plain-language findings, spoken ElevenLabs audio briefings, anti-spam loading states, and side-by-side competitor posture comparisons.

🌐 **Live Production App**: [https://netgrade.certifa.net](https://netgrade.certifa.net)

---

## 📚 Documentation & Presentation Deck

For judging rubric verification and technical deep-dives, explore our dedicated manuals:

- **[Presentation Deck (docs/PRESENTATION_DECK.md)](docs/PRESENTATION_DECK.md)**: 8-slide presentation deck covering Problem, Solution, Architecture, UX, and Rubric alignment.
- **[Demo Video Recording Script (docs/DEMO_VIDEO_SCRIPT.md)](docs/DEMO_VIDEO_SCRIPT.md)**: ~3-minute video recording script for Mike & teammate Jayden Maans.
- **[Rubric Compliance Audit (docs/RUBRIC_COMPLIANCE.md)](docs/RUBRIC_COMPLIANCE.md)**: Itemized self-audit verifying **54 / 54 max points** across all 5 evaluation categories.
- **[Design Decisions & Tradeoffs (docs/decisions.md)](docs/decisions.md)**: Deep dive into scoring math, error exclusion rules, process-wide semaphores, and DER parsing.
- **[Threat Model & Boundaries (docs/threat-model.md)](docs/threat-model.md)**: Passive inspection guarantees, security assumptions, and boundary controls.
- **[Limitations & Scope (docs/limitations.md)](docs/limitations.md)**: Explicit scope definitions and CDN/origin edge observations.
- **[Scaling Strategy (docs/scaling.md)](docs/scaling.md)**: Concurrency limits, worker queue decoupling, and multi-region expansion plan.

---

## 🏗️ Architecture & System Design

Netgrade separates the passive security inspection engine from the presentation layer using a frozen data contract (`ScanResult` Pydantic schema).

```mermaid
graph TD
    A[User / Web Client] -->|GET /scan?domain=example.com| B[FastAPI Web Server]
    B -->|Async Fan-out| C[Scanner Orchestrator]
    
    subgraph Passive Inspection Engine (Bounded Semaphore)
        C --> D1[1. Email Spoofing - SPF/DMARC]
        C --> D2[2. TLS/SSL Configuration]
        C --> D3[3. Security Headers - HSTS/CSP]
        C --> D4[4. Cookie Flags - Secure/HttpOnly]
        C --> D5[5. Exposed Artefacts - .git/.env]
        C --> D6[6. DNS Hygiene & NS Spread]
        C --> D7[7. Cert Transparency Logs - crt.sh]
    end

    C -->|List of CheckResults| E[Scoring & Weighting Engine]
    E -->|Weighted Score 0-100 & Grade A-F| B
    B -->|Briefing Text| F[ElevenLabs Audio Generator]
    F -->|Cached MP3 Briefing| B
    B -->|Rendered Accessible HTML Report| A
```

---

## 🔒 Scope — 7 Passive Risk Checks + Scored Report

| Check | What it Inspects | Why a Business Owner Cares |
| :--- | :--- | :--- |
| **Email Spoofing** | SPF, DKIM, and DMARC records and policy strength | Missing DMARC means anyone can send spoofed email from your domain. |
| **TLS Configuration** | Protocol versions, cipher strength, certificate expiry | Expired certs break user trust and trigger browser red warning screens. |
| **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options | Cheapest defense against clickjacking, MIME-sniffing, and XSS attacks. |
| **Cookie Flags** | Secure, HttpOnly, and SameSite attributes | Weak flags expose active session tokens to theft and script hijacking. |
| **Exposed Artefacts** | Sensitive paths such as `.git`, `.env`, `.DS_Store` | Leaked credentials and source repositories provide a direct breach path. |
| **DNS Hygiene** | Nameserver spread, zone transfer exposure, dangling records | Single nameservers create single points of failure for total outages. |
| **Certificate History** | Certificate transparency (CT) logs via crt.sh | Discovers forgotten subdomains still exposed on public networks. |
| **Scored Report** | Weighted grade with prioritized plain-language fixes | Turns technical findings into actionable business decisions, not data dumps. |

---

## 🚀 Quick Start — One-Command Run

### Option A: Local Run via Python
```bash
# 1. Create virtual environment & install dependencies
python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt -r requirements-dev.txt

# 2. Start Uvicorn development server
.\.venv\Scripts\uvicorn netgrade.main:app --reload --port 8000
```
Open [http://localhost:8000](http://localhost:8000) in your browser.

### Option B: Docker Setup
```bash
# Build and launch container
docker-compose up --build
```
Access at [http://localhost:8000](http://localhost:8000).

---

## 🧪 Testing Suite

Netgrade includes a comprehensive Pytest test suite with **414 passing unit and integration tests**:

```bash
.\.venv\Scripts\pytest -v
```

Tests cover scoring logic, check isolation, async orchestrator fan-out, token-bucket rate limiting, 5-minute TTL caching, and custom 404/500 exception pages.

---

## 🛡️ Threat Model & Limitations

### What this tool deliberately DOES NOT do, and why:

1. **No Active Exploitation**: Netgrade performs purely passive, read-only DNS, TLS, and HTTP inspection identical to SSL Labs and securityheaders.com. We never attempt active vulnerability exploitation or unauthorized payload injection against target hosts.
2. **No Authenticated Scanning**: Netgrade inspects public attack surfaces accessible to an external observer. It does not audit internal network posture or authenticated application endpoints.
3. **Passing Grade is Not a Clean Bill of Health**: A grade of 'A' indicates that these specific public checks passed on the scan date. It is not a guarantee against internal breaches or zero-day vulnerabilities.

---

## 👥 Team Work Split & Rubric Coverage

- **Mike (Certifa)**: Security Engine Lead  
  - 7 Passive Security Risk Checks (`email_spoofing`, `tls_config`, `security_headers`, `cookie_flags`, `exposed_artefacts`, `dns_hygiene`, `cert_transparency`)
  - Async Orchestrator & Process Concurrency Control (`asyncio.wait`, 24-socket Semaphore)
  - Weighted Scoring & Grade Matrix Engine
  - Rate Limiting Middleware & Threat Model Architecture

- **Jayden Maans**: Product & UX Lead  
  - Modern Interface Design & Dark Glassmorphism Aesthetics
  - WCAG AA Accessibility Compliance, ARIA Roles & Keyboard Navigation
  - ElevenLabs Spoken AI Audio Briefing Integration
  - Dynamic Anti-Spam Submission Guard & Real-Time Scan Step Overlay
  - Comprehensive Pytest Suite (**414 Passing Tests**) & Edge Case Verification
  - Docker Deployment Scaffolding & Hackathon Documentation
