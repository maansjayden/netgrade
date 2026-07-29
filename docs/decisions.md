# Decisions and tradeoffs

Engine-side prose for the README. See also `docs/threat-model.md`,
`docs/limitations.md` and `docs/scaling.md`.

Each entry is a decision that could reasonably have gone the other way, what we
chose, and what it costs. Several were changed after evidence contradicted the
first answer; those are marked, because how a decision was reached is worth as
much as what it was.

---

## A failure to look is not a finding

**The decision.** A check that cannot complete returns status `error` and is
excluded from the score entirely, rather than being counted as a failure.

Everything else in the engine follows from this. A domain whose DNS times out
has not earned an F, and a certificate log being unavailable says nothing about
the domain being scanned. Scoring an unknown as a failure produces reports that
are confidently wrong, which is the failure mode we care about most.

**The cost, and what it forced.** A scan where almost everything errored would
otherwise report a high grade on almost no evidence - start at 100, and if only
two checks can deduct, the result flatters a domain nobody could measure. So
the grade is capped at C below four completed checks, and `checks_scored` is in
the contract so a report can say "graded on 6 of 7".

**The alternative** - scoring errors as failures - is simpler and needs no cap.
It is also wrong often enough to make the tool untrustworthy the first time
someone scans a domain during a DNS blip.

## Subtraction, not a ratio

**The decision.** A domain starts at 100 and loses points per finding, weighted
by severity. `A ≥ 90`, `B ≥ 80`, `C ≥ 70`, `D ≥ 60`, otherwise `F`.

Two reasons. It is one sentence to explain, which matters when the audience is
a small-business owner. And the score moves in the direction a user expects
when they fix something, which is what makes the fix-and-rescan loop work - a
ratio over completed checks can move *down* when a previously-errored check
starts working, which is indefensible in a demo and worse in real use.

**The cost.** The weights are our judgement. Someone else would pick different
numbers and get different grades. They are written down here rather than buried
so the disagreement can be had directly.

## Severity describes the finding, not the check

**The decision.** Severity is set per finding, not fixed per check. The email
check returns `high` for no DMARC at all and `low` for DMARC at `p=none`,
because those are different risks discovered by the same code.

**The cost.** More branches in each check, and severity has to be assigned
thoughtfully in every path rather than declared once. The alternative - a fixed
weight per check - is simpler and produces meaningless scores, since it cannot
distinguish "no email protection whatsoever" from "protection configured but
not yet enforcing".

## Certificate history is discounted

**The decision.** Findings from certificate history carry 0.4 of their weight.
The only per-check adjustment in the system.

It reports history rather than a live misconfiguration the owner can act on
today, and it depends on a third-party service whose availability has nothing
to do with the domain. A `high` finding there costs 10 points where the same
severity elsewhere costs 25.

**The cost.** One number that needs justifying, which is why it is the only one.
Every other check is weighted purely by the severity of what it found.

## One missing header warns; two fail

**Changed after seeing real output.** Originally a lone absent header failed if
its own severity was medium, which meant a single missing
Content-Security-Policy failed.

Most sites have no CSP. Grading that the same as a missing DMARC policy - which
is exploitable today rather than a missing layer of defence in depth - pushed
otherwise-decent domains into a failing check and cost the grade its ability to
discriminate. Two or more absent headers still fails: that is a pattern of them
not being configured at all rather than one gap.

**The cost.** A site missing only CSP now reads as a warning, which understates
it for a site that runs a lot of third-party JavaScript. Accepted, because a
grade that fails almost everyone communicates nothing.

## The engine sorts; the frontend renders

**The decision.** `ScanResult.checks` arrives ordered by remediation priority,
worst first. The presentation layer loops over the list as given.

Deciding that a missing DMARC record outranks a missing CSP is a security
judgement, and the frontend developer on this project has no security
background and should not have to make it. Errors sort above passes, because an
unknown deserves attention in a way a confirmed pass does not.

**The cost.** The API is opinionated about presentation order. A consumer
wanting a different order has to re-sort, and the ordering rules live in the
engine where a designer cannot adjust them.

## Domains are stored as punycode

**The decision.** `ScanResult.domain` holds the A-label. `bücher.de` is scanned
and reported as `xn--bcher-kva.de`.

Rendering the Unicode form would let a homograph domain display in our own
security report as the brand it is impersonating - a Cyrillic lookalike of a
bank appearing as that bank, in a document telling someone whether to trust it.

**The cost.** Less readable for legitimate international domains. A frontend
that wants to show the Unicode form can decode it and choose how to flag mixed
scripts; the engine will not hand it something that misleads by default.

## Checks never raise; one function guarantees it

**The decision.** `checks.base.execute` wraps every check, converts any failure
into an error result, and applies the time budget. Individual checks are
written as if nothing fails.

Putting the guarantee in one place means seven modules cannot each forget it
differently. The broad `except Exception` there is deliberate and is the last
clause: one defect should cost one finding, not the whole report. It is logged
with a traceback so it surfaces as a bug rather than being absorbed silently.

`asyncio.CancelledError` derives from `BaseException` and passes through
untouched, which is what lets shutdown work. This mattered concretely: a
hand-rolled reimplementation of `asyncio.timeout` was briefly added for
compatibility with an older Python, and it converted every cancellation into a
timeout - including the scan deadline's own cancellation and shutdown. It was
unreachable on the version we ship, and removed.

## Two nested timeouts

**The decision.** Each check has a budget; the whole scan has a 20-second
deadline. Both.

A per-check budget does not bound the total - a check can be slow without
having timed out, and a user waiting on a page cares about the wall clock. When
the deadline fires, finished work is kept and unfinished checks are cancelled
and reported as "could not check". Partial results beat no results, and they
beat waiting.

This is why `asyncio.wait` rather than `wait_for` around a `gather`: wrapping
the gather would cancel everything on timeout and throw away six finished
results because one check stalled.

**Changed after evidence.** Certificate history originally had a 45-second
budget, sized for a slow-but-working crt.sh. That was wrong. A scan is only as
fast as its slowest check, so a degraded third party set the wall clock for
every scan. Cut to 15 seconds, with a 6-second request timeout and one retry.

## The concurrency claim, stated accurately

Seven checks run at once, but the measured speedup is **1.3× to 1.7×**, not 7×.
A scan costs what its slowest check costs, not what all seven cost, and one
check usually dominates.

`duration_ms` is on every finding so the claim is demonstrable rather than
asserted: sum the check durations, compare against the scan's wall clock.
Claiming seven times faster would be trivially disprovable by anyone who
checked, and we would rather state the real number.

## The outbound concurrency bound is process-wide

**The decision.** One semaphore, 24 sockets, shared by every scan in the
process rather than one per scan.

Bounding the seven checks of a single scan would be theatre - seven tasks is
not a load problem. The bound that matters is across concurrent users, where
fifty simultaneous scans would otherwise open several hundred sockets.

## Cache TTL is five minutes, deliberately short

Long enough to absorb refreshes and shared links, short enough that "fix it and
scan again" works. An hour-long cache would make the tool look broken at
exactly the moment it should look useful. `force=true` bypasses it for the
explicit re-scan.

Scans where nothing could be measured are **not** cached. That is a fact about a
bad minute, not about the domain, and caching it would make a transient outage
stick for the full TTL - the user who retries, as the report tells them to,
would get the same failure back instantly with nothing having been retried.

## Certificate parsing does not use `ssl.getpeercert`

**The decision.** DER is parsed directly with `cryptography`.

`ssl.getpeercert()` returns nothing useful on an unverified socket - which is
precisely the expired, self-signed and hostname-mismatched cases the check
exists to catch. Verification is attempted first; if it fails, the connection is
retried unverified purely to read what is being served, because telling a user
*why* their certificate is rejected requires reading the certificate that was
rejected.

**The cost.** A dependency, and more code than the standard library route. Not
optional: the standard library route cannot see the failures that matter.

## `verify=False` on the HTTP client

We are inspecting TLS, not trusting it. A certificate that fails verification is
a finding for the TLS check to report, not a reason the header check cannot run.
The client never sends credentials to a scanned host, so there is nothing to
leak to a host presenting a bad certificate.

## Configuration lives in the environment, with safe defaults

Rate limits, proxy topology and debug logging are environment variables whose
defaults are the conservative published values. Raising a limit for one
deployment does not weaken what the documentation says an unconfigured instance
does.

A malformed value logs a warning and keeps the default - a typo in a platform
variable should not take the service down. A comparison cost above the burst
size *does* fail at startup, because it would 429 every comparison forever,
which is a misconfiguration rather than a limit.

## The mock fixture is generated, not written

**Changed after being caught wrong twice.** The fixture is simultaneously the
frontend's reference, the integration fixture, and the input the scoring tests
assert against. It was hand-written, and two of seven entries disagreed with the
code that would have produced them - a session cookie graded `medium` where the
cookie check says `high`, and a header finding graded `warn` where the header
check says `fail`.

The scoring tests could not catch it: they assert the declared score and
ordering are consistent with the declared severities, and they were  - 
consistently wrong. Entries are now regenerated by running the real check
functions, and a consistency test replays each finding's own evidence through
the logic meant to produce it.

Only two checks are covered that way. For the rest the evidence does not
round-trip without reshaping either the check or the fixture, and two real tests
are worth more than seven that only look like coverage.

## Registration is explicit

The check registry is a written list, validated against the contract at import.
Package auto-discovery would let a half-finished module join a live scan by
being dropped in a directory, and it hides the answer to "what does this tool
actually do?" behind runtime behaviour instead of a readable list. A check
registered under an unknown id fails startup rather than scoring as an unknown
and rendering as an unstyled badge.

## Malformed input is the one failure that raises

Every remote failure is data. Input that is not a domain raises
`InvalidDomainError`, which the API turns into a 400.

A malformed request is a fault in the request, not a finding about a domain.
Returning a report of seven failures for a typo would be a claim about
something never looked at, and the API could not distinguish it from a real
result.

RFC 2606 reserved names (`.example`, `.invalid`, `.test`) are refused for the
same reason: they cannot resolve, so a report about one would be fiction.

## Sample data is unreachable from any real path

The application originally fell back to the sample fixture whenever a scan
raised, producing a complete, plausible, fabricated report about a real domain
with no indication anything had failed. That path is gone; the failure is a
visible 503.

The comparison page did the same thing in worse form, inventing a named third
party's posture including a hardcoded score, on a public URL. It now runs two
real scans concurrently.

**This is the decision to lead with if asked what the project got wrong.** It
was caught in production, on a real domain, and it is the kind of defect that
makes a security tool actively harmful rather than merely broken.
