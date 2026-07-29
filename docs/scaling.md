# Scaling

Engine-side prose for the README. See also `docs/threat-model.md`,
`docs/decisions.md` and `docs/limitations.md`.

What this runs on today, what breaks first as load grows, and what each fix
costs. The order below is the order the problems actually arrive in, not the
order they are interesting in.

---

## What it is today

A single stateless-looking container: FastAPI on uvicorn, one process, no
database, no queue, no external services beyond the hosts being scanned and
crt.sh.

**It is not stateless, and calling it stateless would be wrong.** Two things
live in process memory:

- the result cache — 512 domains, five-minute TTL
- the rate limiter — token buckets for up to 4096 client addresses

Both are deliberate for one instance and both are the first thing to move. They
sit behind protocols (`cache.ScanCache`, `ratelimit.RateLimiter`) precisely so
that moving them is a new implementation rather than a rewrite, and both
protocols are conformance-tested — the annotation `cache: ScanCache =
TTLScanCache()` makes mypy reject a drift, so "swappable" is a checked claim
rather than a README sentence.

## Where the time actually goes

Almost all of it is spent waiting on other people's networks. A scan is roughly
fifteen outbound requests across DNS, TLS, HTTP and one third-party API, and
the measured wall clock is 2–6 seconds depending mostly on how crt.sh is
feeling.

CPU is close to irrelevant: parsing a certificate and a few headers is
microseconds against seconds of waiting. This is what makes asyncio the right
model and it is why the scaling story is about connection counts and shared
state, not about compute.

The concurrency speedup within one scan is **1.3×–1.7×** measured, not 7×. A
scan costs what its slowest check costs. Running more scans concurrently is
where the throughput is, not making one scan faster.

---

## What breaks first, in order

### 1. Two instances mean two rate limits

The moment a second container starts, a client gets its allowance twice — once
per instance — and the effective limit doubles per instance added. The cache
degrades the same way: a domain cached on instance A is a miss on instance B,
so hit rate falls roughly as `1/n`.

**The fix.** Redis, and only Redis — no other architectural change. Two new
implementations of protocols that already exist:

```python
class RedisScanCache:          # SETEX key, GET, DEL
    def get(self, domain) -> ScanResult | None: ...
    def set(self, domain, result) -> None: ...
    def invalidate(self, domain) -> None: ...

class RedisRateLimiter:        # one Lua script, atomic
    def acquire(self, client, cost=1) -> Decision: ...
```

The limiter is the more delicate of the two: read-modify-write across a network
is a race, so the token bucket arithmetic has to run inside a single Lua script
rather than as separate `GET`/`SET` calls. That is a well-trodden pattern and
about twenty lines.

Two things become genuinely easier once results are shared: the cache warms
across every instance rather than per instance, and a scan result becomes
inspectable outside the process, which helps when a report is disputed.

**Cost.** One managed Redis, and a dependency that can now be down. Both
implementations should fail open — a Redis outage should degrade to "no cache,
no limit" rather than to "no service", because a scanner that stops working
when its cache is unavailable is worse than one that briefly scans too much.

### 2. Fifty people scanning the same domain ran fifty scans — fixed

The cache only helps once a scan has finished. Under a burst of interest in
one domain — the exact shape of traffic a demo, a shared link or a CI
integration produces — concurrent requests all missed, all scanned, and all
hit the target host simultaneously. Wasteful for us, and inconsiderate to a
server that did not ask to be scanned at all.

**Now coalesced.** A map of domain to in-flight task lets concurrent callers
for the same domain await the scan already running instead of starting their
own. Measured against the real engine: twelve concurrent requests for one cold
domain now run **one** scan instead of twelve, saving roughly 165 outbound
requests to somebody else's server, with every caller still receiving a
complete report.

Three details it needed beyond the obvious dictionary.

The join is shielded. A plain `await` on a task propagates cancellation into
it, so whoever asked first would take the scan down with them by closing the
tab, and everyone waiting on it would get a cancellation instead of a report.
Shielded, the scan finishes and warms the cache regardless of who is still
listening, bounded by the scan deadline rather than by any request.

A forced re-scan does not join. The point of forcing is to measure again, not
to await a measurement that may have started before the user made the change
they are re-scanning to see.

Each caller gets a copy. The audio layer assigns onto the report it is handed,
and joiners would otherwise all hold the same object.

Across instances this needs a Redis lock, at which point the second requester
either waits on a pub/sub notification or polls the cache key. Within one
instance the local version is exact and free.

### 3. Long scans hold an HTTP connection open

Every scan currently occupies a request for its whole duration. At a few
seconds each this is fine, and it keeps the product simple: one URL, one
result, no polling.

It stops being fine when a platform's request timeout is shorter than a slow
scan, or when enough concurrent scans exhaust the worker pool. The symptom is
504s that look like the scanner is broken when it is merely busy.

**The fix.** Submit-and-poll: `POST /api/v1/scans` returns an id immediately,
`GET /api/v1/scans/{id}` returns status or result. Workers pull from a queue;
the web process only accepts and reads.

**Cost, and why it is not done.** It is a real contract change and it makes the
frontend stateful — the single most expensive item here in work and in user
experience. It buys nothing at current volumes. The honest trigger is: when the
p99 scan duration approaches the platform request timeout, or when queueing is
visible to users.

### 4. Outbound sockets, not CPU, are the ceiling

The process-wide bound is 24 concurrent sockets, shared across every scan
rather than per scan. At roughly fifteen requests per scan that supports a
handful of concurrent scans comfortably and queues beyond that — which is the
correct behaviour, since queueing is preferable to opening several hundred
sockets.

Vertical headroom is small: raising the bound raises memory and file
descriptors, and the gain flattens once the remote hosts are the constraint.
Horizontal scaling is the answer, and it works cleanly once state is in Redis,
because nothing else in the process is shared.

**One caveat that matters more than the throughput.** Every additional instance
is another source address hitting scanned hosts. Fanning out to ten instances
means a target sees traffic from ten addresses and our per-client rate limiting
is the only thing bounding the total. A shared limiter (item 1) is therefore a
prerequisite for horizontal scaling, not an optimisation alongside it.

### 5. crt.sh is a single point of failure we do not control

Certificate history depends on one third party that is regularly slow and
intermittently returns 502s. It already degrades correctly — 15-second budget,
6-second request timeout, one retry, then `error` status excluded from the
grade — but "degrades correctly" still means the check is unavailable.

**The fix, in increasing order of effort.** Cache CT results far longer than
scan results, since certificate history changes slowly and a day-old answer is
almost as good as a fresh one. Then read the CT logs directly rather than
through an aggregator. Then treat it as a background feed refreshed
independently of scans, so a scan reads local data and never waits on anybody.

---

## Two things that would change the engine's shape

Everything above is operational. These two would alter how a scan works.

### Dangling-record detection needs subdomains

Today the DNS check tests the apex and `www` only. That is honest but thin: real
subdomain takeover risk lives in forgotten names, and finding those means
knowing what the subdomains are.

The version worth building feeds certificate transparency results into the DNS
check — CT already tells us which hostnames exist without any enumeration, so
the names come from a public record rather than from guessing. It was
deliberately deferred: it breaks the pure fan-out model into two phases and
gates every scan on crt.sh latency, which is the dependency we least want on
the critical path.

It becomes straightforward once CT is a background feed rather than a live
call (item 5). That is the natural order: make the data local, then let another
check depend on it.

### Historical tracking

Nothing is stored, so nobody can see whether their posture improved. Per-domain
history — grade over time, what changed between scans, an alert when a
certificate is about to expire or a header disappears in a deployment — is the
obvious product direction and the first thing that needs a real database.

It also changes what this is. Storing scan history for domains people do not own
raises questions the current design avoids entirely by keeping nothing. Worth
deciding deliberately rather than arriving at by adding a table.

---

## Summary

| Concern | Today | Next step | Trigger |
|---|---|---|---|
| Rate limiting | In process | Redis + Lua, atomic | Second instance |
| Result cache | In process, 512 / 5 min | Redis, shared | Second instance |
| Duplicate scans | Coalesced in process | Redis lock for cross-instance | Second instance |
| Long requests | Synchronous | Submit-and-poll + workers | p99 nears request timeout |
| Outbound sockets | 24, process-wide | Horizontal, after shared limiter | Sustained queueing |
| crt.sh | Live, degrades to `error` | Long cache, then background feed | Availability complaints |
| Dangling records | Apex and `www` | CT-fed, two phase | After CT is a local feed |
| History | Not stored | Database, with a privacy decision first | Product direction |

The short version: **the architecture is already the right shape and the state
is in the wrong place.** Moving two protocol implementations into Redis is the
whole of the next step, and nothing above it on this list is blocked by a design
decision that would need revisiting.
