# What this tool deliberately does not do, and why

Written for the README. Engine-side prose; see also `docs/threat-model.md`
and `docs/decisions.md`.

A passing grade means **these specific public checks passed, from one vantage
point, on the date shown**. It is not a statement that a business is secure.

---

## It does not attack anything

Every check is passive and read-only - the same class of inspection SSL Labs
and securityheaders.com perform against any public host. It reads DNS records,
completes a TLS handshake, requests a small number of pages, and reads public
certificate transparency logs.

It does not attempt exploitation, does not fuzz, does not test credentials, and
does not enumerate. The exposed-files check requests three fixed paths, once
each: no wordlist, no directory brute force.

The one check that gets asked about is the zone transfer attempt in DNS
hygiene. A zone transfer is an ordinary DNS query that a correctly configured
nameserver refuses; asking is how you learn whether it refuses. We class it as
passive on that basis, we make one attempt per nameserver, and we say so here
rather than leaving it to be discovered.

## It cannot see anything that requires an account

Everything is measured as an anonymous visitor. Cookies set after login,
authenticated pages, admin interfaces and internal systems are all invisible to
it. The cookie check says so in its own finding rather than implying it
examined more than it did.

This is the largest single gap between a passing grade and being secure. Most
of what actually goes wrong in a small business - a reused admin password, a
staff member phished, an unpatched server with no public symptom - sits
entirely outside what any anonymous scan can observe.

## It reports what is observable from where it stands

A scan describes what one client, on one network, at one moment, could see.

That is not a formality. Security headers and TLS settings are frequently
applied by a CDN rather than by the application behind it, and the two do not
have to agree. A scanner running inside the origin's own network can reach the
origin without traversing the CDN, and will then report the origin's
configuration - accurately - while a visitor's browser sees something
different.

We hit this with our own deployment. Scanning `netgrade.certifa.net` from a
laptop reports all four security headers present, because Cloudflare adds them
at the edge. The same scan run from inside the hosting platform reports all
four missing, because the request reaches the application directly and the
application does not set them. Both answers are correct about the endpoint they
reached. Neither is correct about the other one.

Each finding therefore records `served_by`, taken from the response's `Server`
header, so a report that disagrees with a browser can be traced to which
endpoint answered rather than assumed to be a parsing error.

The practical consequence for a reader: if headers are added by a CDN, confirm
the origin sets them too. Anything that reaches the origin directly - a
misconfigured DNS record, a leaked origin address, a request from inside the
same network - bypasses protection that only exists at the edge.

## It makes no claim about internal networks

Nothing here observes internal systems, endpoints, staff devices or anything
behind a firewall. A grade describes a domain's public attack surface only.

## It is a point-in-time reading

Certificates expire, DNS changes, headers get removed during an unrelated
deployment. A grade is accurate for the moment it was taken and decays from
there. Re-scanning is the only way to know the current state, which is why the
result cache is deliberately short-lived.

## Some checks depend on third parties

Certificate history reads crt.sh, which is outside our control and is
frequently slow or briefly unavailable. When it cannot be read, the check
reports "could not check" and is **excluded from the grade** rather than
counted as a pass or a failure. A report showing fewer than seven checks scored
says so, and the grade is capped when too little could be measured.

We would rather show an incomplete report honestly than a complete one that
quietly guesses.

## Findings are heuristics, not proofs

Two are worth naming.

**Session cookie detection** classifies a cookie as session-carrying from its
name. A cookie called `sid` is treated as more sensitive than one called
`theme`. That is a reasonable guess and it is sometimes wrong in both
directions.

**DKIM** is checked by probing common selector names. DKIM keys may be
published under any selector, so finding none is not evidence that none exist.
The finding says this rather than reporting an absence it cannot establish.

## The grade is a prioritisation aid, not a certification

Weights are our judgement about what matters most to a small business. They are
documented in `docs/decisions.md` and are open to disagreement. The grade
exists to answer "what should I fix first" - not to be displayed as a badge, and
not to be compared across tools that weigh things differently.
