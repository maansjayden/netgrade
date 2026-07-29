# Netgrade - Demo Video Recording Script for Mike
*Blueprint Hackathon 2026 Submission*

> **Target Duration**: ~3 minutes (Strictly within the 2–5 minute hackathon limit).  
> **Presenter**: Mike (Certifa)  
> **Teammate**: Jayden Maans (Product & UX Lead)  
> **Live Site URL**: [https://netgrade.certifa.net](https://netgrade.certifa.net)

---

## ⏱️ Video Timeline & Teleprompter Script for Mike

### 0:00 – 0:45 | Problem Statement & Introduction
**Visual**: Start on camera or with screen showing [https://netgrade.certifa.net](https://netgrade.certifa.net) in full-screen dark mode.

> **Mike**:  
> "Hey everyone, I'm Mike! On behalf of my teammate Jayden Maans and myself, I'm demonstrating **Netgrade**, our passive security posture scanner for small businesses built for the Blueprint Hackathon.  
> 
> Over 70% of small businesses have zero dedicated IT or security staff. When non-technical business owners try to audit their web posture, standard scanners either launch intrusive vulnerability probes or output 40-page PDF reports filled with raw cryptographic jargon that no one understands.  
> 
> Small business owners don't need terrifying vulnerability dumps - they need a quick, zero-risk posture grade with plain-language remediations they can fix immediately."

---

### 0:45 – 2:00 | Live Product Walkthrough (netgrade.certifa.net)
**Visual**: Browser navigation on [netgrade.certifa.net](https://netgrade.certifa.net).

> **Mike**:  
> "Our site is live at `netgrade.certifa.net`. Jayden designed the UI with modern dark glassmorphism, responsive controls, and high-contrast WCAG AA accessibility.  
> 
> Let's test a domain right now - I'll type `example.com` and click **Scan Domain**.  
> Notice how the button immediately displays an active loading state with a spinning indicator while our scanner cycles through 7 passive security checks in real time."

*(Wait 2-3 seconds as scan completes and report opens)*

> **Mike**:  
> "Here is our posture report! `example.com` received a Posture Score of 61/100 and a **Grade C**.  
> 
> Right at the top, Netgrade features a **Spoken AI Audio Briefing** using ElevenLabs synthesis so an owner can listen to their posture while on the move."

*(Click 'Listen Briefing' button to play 4-5 seconds of audio)*

> **Mike**:  
> "Every finding is ordered by priority. Under **Email Spoofing**, Netgrade explains in plain English that missing DMARC allows anyone to impersonate the business via email, and gives the exact DNS TXT record needed to fix it. We also have an interactive **Plain-Language FAQ Guide** right on the homepage explaining DMARC, security headers, and passive scanning in simple terms.  
> 
> We also have **Side-by-Side Competitor Comparison**. Let's click comparison, enter two domain names, and scan. Both domains are evaluated concurrently against the engine pool so business owners can benchmark their security against peers."

---

### 2:00 – 2:50 | Technical Stack & Architecture Deep-Dive
**Visual**: Switch to architecture diagram or terminal code view.

**Visual cue for principle 2** — cut to `railway logs` while saying the failover
line. This is real output, not a mockup, and it shows the failover and the
"7 of 7" in two lines:

```
INFO netgrade.checks.cert_history: crt.sh unavailable (ReadTimeout); trying the next source
INFO netgrade.orchestrator: scanned mozilla.org in 9.76s: B (82), 7 of 7 checks completed
```

> **Mike**:  
> "Under the hood, Netgrade is built in Python with **FastAPI** and an async inspection engine.  
> 
> Here are 3 key architectural principles we enforced:
> 1. **Passive Security Only**: Zero active exploitation, zero credential testing, zero payload injection. We inspect public DNS, TLS handshakes, security headers, cookie flags, exposed files like `.git` and `.env`, and Certificate Transparency logs via two independent aggregators — crt.sh, with Cert Spotter as automatic fallback.
> 2. **Errors Are Excluded, Not Failed**: If DNS times out or a third-party service is down, we mark the check as `error` and exclude it from the score rather than penalizing the domain with an F grade.
> 
>    And we didn't just design for that on paper. We wrote down early that crt.sh was a single point of failure we didn't control — then it went down mid-build and stayed down. That's why there are two aggregators. This is from production today: crt.sh times out, Cert Spotter answers, and the scan still completes all seven checks.
> 3. **Concurrency Semaphore & Caching**: Scan tasks execute concurrently with `asyncio.wait`. Sockets are bounded by a process-wide semaphore (24 max) and protected by token-bucket rate limiting and 5-minute TTL caching."

---

### 2:50 – 3:15 | Testing, Deployment & Conclusion
**Visual**: Terminal output showing `pytest -v` with 428 tests passing, or Docker setup.

> **Mike**:  
> "For project completion, Jayden built our Pytest suite which includes **428 passing unit and integration tests** covering scoring math, edge cases, and custom 404/500 error pages.  
> 
> Netgrade is live at `netgrade.certifa.net`, fully dockerized, and ready for use. Thank you!"

---

## 💡 Quick Presentation Checklist for Mike

- [x] Web browser open to `https://netgrade.certifa.net`
- [x] Clear audio microphone setup
- [x] Audio briefing volume enabled
- [x] Video length under 3.5 minutes
