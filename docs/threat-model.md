# Threat model

Engine-side prose for the README. See also `docs/limitations.md` and
`docs/decisions.md`.

This scanner is unusual in one respect that shapes everything below: **it makes
outbound requests to hosts chosen by whoever is using it.** That is the whole
product, and it is also the entire attack surface. Most of what follows is a
consequence of taking that seriously.

Two parties can be harmed here, and they are not the same party. There is the
person using the tool, and there is the operator of the domain being scanned —
who did not ask to be scanned and may not know it happened. Several decisions
below protect the second at the expense of the first's convenience.

---

## What we are protecting

| Asset | Why it matters |
|---|---|
| The hosting environment | Cloud metadata endpoints, internal services, anything reachable from our container but not from the internet |
| Scanned hosts | We generate traffic against third parties on request. Volume and behaviour are our responsibility, not the requester's |
| The container itself | Compromise turns a scanner into an attacker's proxy with our reputation attached |
| Report integrity | A report that says something false about a domain is the worst failure this tool has, worse than being down |
| Client addresses | Personal data, held only in memory and only for rate limiting |

We hold no user accounts, no credentials for scanned domains, and no
persistent storage. There is no database to breach.

---

## Server-side request forgery — the primary risk

**The attack.** An attacker registers a domain whose A record points at
`169.254.169.254`, or `127.0.0.1`, or an internal address in our hosting
provider's network. They submit it for scanning. Our server makes the request
they cannot make themselves, from inside a network they cannot reach, and the
response comes back to them rendered as evidence in a report.

Cloud metadata endpoints are the classic target: on several providers they will
hand out credentials to anything that asks from the right network position.

**What we do.** Every hostname is resolved and every resulting address checked
against public-routability before a connection is opened
(`context.assert_public_host`). Loopback, RFC 1918, link-local — which covers
`169.254.169.254` — carrier-grade NAT, multicast and reserved ranges are all
refused. Both A and AAAA records are checked, and **all** resolved addresses
must be public: one bad address in a set refuses the whole host.

Redirects are followed one hop at a time (`MAX_REDIRECTS = 3`), and each
destination is re-checked before it is requested. Following redirects
automatically would let a public host redirect us inward on the second hop.

Response bodies are capped at 64 KB, read from a streaming response. An
unbounded read from a host under attacker control is a memory exhaustion
vector, and no check needs more than the first few kilobytes.

Evidence never echoes a blocked internal address back to the caller — the
finding says the domain does not point at a public address, without confirming
which one. Tested.

**What remains open, honestly.** This is a check-then-connect design, and the
name is resolved twice: once by us to inspect the addresses, then again by the
HTTP client when it actually connects. An attacker controlling their own
authoritative DNS with a very low TTL can answer the first query with a public
address and the second with a private one. This is DNS rebinding, and we do not
close it.

Closing it means pinning the connection to the address we vetted, which
requires a custom transport that dials a specific IP while preserving both SNI
and the `Host` header. That is the correct fix and it is not built. The
exposure is bounded by there being no credentials to steal in this container
and by the response body cap, but it is a real gap, not a theoretical one, and
we would rather say so than imply the guard is complete.

## Being turned into an attack tool

**The attack.** Someone scripts our scan endpoint against a domain they dislike.
Every scan is roughly fifteen outbound requests. Unlimited, we become a traffic
amplifier aimed wherever a stranger points us, with our IP address and our
project name on the traffic.

That every individual request is passive and read-only does not make ten
thousand of them reasonable. Volume changes the nature of the act.

**What we do.** A token bucket per client, five scans a minute with a burst of
five, applied as middleware so it covers the HTML pages and the JSON API
equally — limiting one front door and not the other would not be a limit.

Requests are priced by outbound footprint rather than by count: a comparison
runs two scans and costs two. The empty comparison form scans nothing and
costs one, because charging a page load the price of work it did not do would
rate limit somebody for opening a page.

Outbound concurrency is bounded process-wide at 24 sockets, shared across every
scan rather than per scan. Seven checks is not a load problem; seventy
simultaneous scans is.

Results are cached per domain for five minutes, so repeatedly requesting the
same domain does not repeatedly hit it. The TTL is short because the product
invites people to fix something and scan again, and a cache that outlived the
fix would make the tool look broken.

**What remains open.** The limit is per process and held in memory. Two
instances mean two independent limits, and a restart clears them. Both are
documented in the scaling section, and both are the reason the limiter sits
behind a protocol that a Redis implementation can replace.

## Rate limit evasion by forging the client address

**The attack.** The limiter identifies clients by IP, taken from a header that
a proxy sets. Headers are attacker-controlled unless something trustworthy
overwrites them. Vary the header per request, get a fresh bucket per request,
and the limiter is decorative.

**This was a live bug, not a hypothetical.** The first implementation read the
leftmost `X-Forwarded-For` entry. Each proxy *appends* the peer it received
from, so a client sending `X-Forwarded-For: 1.2.3.4` produces
`1.2.3.4, <their real address>` — and the leftmost entry is whatever they
typed.

It cannot be caught by testing against the deployed URL. With one real source
address, a spoofable implementation and a correct one behave identically, and
the broken one fails closed, so it looks healthy from outside. It has to be
reasoned about, and it is now pinned by tests instead.

**What we do.** The address is read from the right, one position per trusted
proxy hop, with the hop count configured rather than assumed
(`NETGRADE_TRUSTED_PROXY_HOPS`). Zero ignores the header entirely and uses the
socket peer, which is correct when nothing sits in front. A chain shorter than
configured falls back to the socket peer rather than guessing at an index.

Where Cloudflare is in front, `CF-Connecting-IP` is preferred, because it is a
single value Cloudflare sets after terminating the connection and it does not
depend on counting hops — a hop count is silently wrong the moment the topology
changes, which is exactly what happened to us when Cloudflare was added.

That preference is **opt-in** (`NETGRADE_TRUST_CLOUDFLARE`), not "believe it
whenever present". `CF-Connecting-IP` is an ordinary header any caller can set;
trusting it on a deployment not behind Cloudflare would reintroduce the same
hole in a new place.

**What remains open.** Enabling it asserts the process is only reachable
through Cloudflare. While the platform origin URL still answers directly, that
assertion is not strictly true, and a request to the origin can carry a forged
header. No header choice fixes this — a forged `X-Forwarded-For` at the
configured hop count has the identical bypass. Closing it means restricting the
origin to the CDN's addresses or requiring a shared secret at the edge. Neither
is done. The exposure is bounded: an attacker can evade their own rate limit,
via a URL that is not the advertised one.

## Reporting something false

**The risk.** Not an attack — a defect, and the one we treat most seriously.
A security report that states something untrue about a domain is worse than no
report, because it is acted on.

**Where it nearly happened.** The application originally caught every exception
from a scan and rendered the sample fixture instead. A failing engine produced
a complete, plausible, entirely fabricated report about a real domain, with no
indication anything had gone wrong. It was removed before the engine was wired
in, and the failure is now a visible 503.

The comparison page had the same defect in worse form: it rendered invented
findings for a **named third party**, including a hardcoded score. It is now
two real scans.

**What we do.** Sample data is served only from a route whose name says so, and
`load_mock_scan` carries a docstring stating it must never substitute for a
real result. A check that cannot complete returns status `error` and is
excluded from the grade rather than counted as a pass. The fixture is
regenerated from the check functions and pinned by tests, after two hand-written
entries were found to disagree with the code that would have produced them.

Findings that rest on a guess say so in their own text: DKIM selector probing
cannot prove absence, and session-cookie detection is a judgement about a name.

## Position-dependent results

Covered fully in `docs/limitations.md`, and repeated here because it is a
correctness risk rather than only a caveat.

A scan reports what is observable from where the scanner stands. Where a CDN
applies protections the origin does not, a scanner inside the origin's network
measures the origin and reports accurately about an endpoint no visitor uses.
We hit this with our own deployment. Findings now record `served_by` so the
discrepancy is traceable rather than mysterious.

## Denial of service against ourselves

A hostile or broken target could hold connections open indefinitely. Three
bounds apply: per-check budgets, a 20-second whole-scan deadline after which
unfinished checks are cancelled and reported as "could not check", and the
process-wide socket cap. Partial results beat no results, and both bounds exist
because either alone leaves a gap — a check can be slow without having timed
out.

Cache and rate-limiter keys both derive from user input, so both structures are
bounded (512 domains, 4096 clients) with least-recently-used eviction. An
unbounded dictionary keyed on attacker input is a memory exhaustion vector.
Limiter eviction fails toward leniency: under pressure a long-idle client gets
a fresh allowance rather than being locked out, because a rate limiter that
denies real users under load is a denial-of-service tool aimed at ourselves.

## Container and supply chain

The image runs as a non-root user (UID 10001). It is genuinely two-stage: the
build toolchain stays in the builder and never reaches the published image, so
a shell in the container finds no compiler. Direct dependencies are exact-pinned
after a floating Starlette release changed an API underneath us and turned the
suite red. Secrets come from the environment; `.env` is excluded from both git
and the image, along with internal material that must not be published.

## Privacy

Client IP addresses are held in memory for rate limiting and are not persisted.
They are logged only when `NETGRADE_DEBUG_CLIENT_KEY` is enabled, which is off
by default — deliberately a switch rather than a temporary code change, so
there is nothing to forget to remove, and so continuous collection of personal
data is never the accidental default.

Scan results describe public configuration and are cached in memory for five
minutes. Evidence carries observed public data only.

---

## Summary of what is open

Stated plainly, because a threat model that lists only solved problems is
marketing.

1. **DNS rebinding** between the address check and the connection. Real. Fix is
   connection pinning; not built.
2. **Origin bypass** of the CDN, allowing a forged client address on a URL that
   is not the advertised one. Affects any header choice equally.
3. **Single-instance state.** Rate limits and cache are per process; two
   instances mean two independent limits.
4. **No request coalescing.** Fifty simultaneous requests for the same cold
   domain run fifty scans. The cache helps only after the first completes.
