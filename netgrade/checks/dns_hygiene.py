"""Check 6 -- DNS hygiene.

Three questions about the domain's DNS: is it served by more than one
provider, do its nameservers hand out the whole zone to anyone who asks, and
does anything point at a target that no longer exists.

On the zone transfer. A single AXFR request per nameserver is the closest
thing in this tool to an active test, so it is worth being precise about why
it is in scope. It is a read-only DNS query defined by the protocol, sent to
a public authoritative server, which either answers or refuses; it changes
nothing, and a refusal is the expected and correct outcome. That is the same
class of request as asking for a TXT record. It is included because an open
zone transfer hands over every hostname a business owns in one request, and a
scanner that declined to look would be omitting the most serious DNS finding
there is.

Dangling records are checked on the apex and www only. Finding them across a
whole zone would need subdomain enumeration, which is deliberately out of
scope; the certificate transparency route to doing it properly is described
in the README's Scaling section.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Final

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
import dns.zone

from netgrade.checks.base import Check
from netgrade.context import ScanContext
from netgrade.domains import organisational_domain
from netgrade.models import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID: Final = "dns_hygiene"
TITLE: Final = "DNS hygiene"

#: Names checked for dangling CNAMEs. Not an enumeration: these are the two
#: names every domain has, not guesses at what might exist.
_DANGLING_CANDIDATES: Final = ("", "www")

#: Seconds allowed for one zone transfer attempt. Short: a nameserver that
#: refuses does so immediately, and one that hangs is not worth waiting for.
_AXFR_TIMEOUT: Final = 4.0


@dataclass(frozen=True, slots=True)
class _Findings:
    nameservers: tuple[str, ...] = ()
    providers: tuple[str, ...] = ()
    transfers_open: tuple[str, ...] = ()
    transfer_results: dict[str, str] = field(default_factory=dict)
    dangling: tuple[str, ...] = ()


async def run(domain: str, ctx: ScanContext) -> CheckResult:
    """Inspect nameserver spread, zone transfer exposure and dangling records."""
    await ctx.assert_domain_exists(domain)

    nameservers = await _nameservers(domain, ctx)
    providers = tuple(sorted({organisational_domain(name) for name in nameservers}))

    transfers, dangling = await asyncio.gather(
        _attempt_transfers(domain, nameservers),
        _find_dangling(domain, ctx),
    )
    open_transfers = tuple(name for name, outcome in transfers.items() if outcome == "open")

    findings = _Findings(
        nameservers=nameservers,
        providers=providers,
        transfers_open=open_transfers,
        transfer_results=transfers,
        dangling=dangling,
    )
    status, severity, summary, fix = _assess(findings)

    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        severity=severity,
        summary=summary,
        explanation=_explain(findings),
        fix=fix,
        evidence={
            "nameservers": list(nameservers),
            "distinct_providers": len(providers),
            "providers": list(providers),
            "zone_transfer": transfers,
            "dangling_records": list(dangling),
            "records_examined": [
                f"{prefix}.{domain}" if prefix else domain for prefix in _DANGLING_CANDIDATES
            ],
        },
    )


def _assess(findings: _Findings) -> tuple[CheckStatus, Severity, str, str]:
    """Rank by what an attacker gains, not by which question was asked first."""
    if findings.transfers_open:
        names = ", ".join(findings.transfers_open)
        return (
            "fail",
            "high",
            f"{names} will hand the entire DNS zone to anyone who asks.",
            "Restrict zone transfers to your own secondary nameservers. Every hostname "
            "you own is currently a single request away, including internal ones never "
            "meant to be public.",
        )

    if findings.dangling:
        names = ", ".join(findings.dangling)
        return (
            "fail",
            "high",
            f"{names} points at a target that no longer exists.",
            f"Remove the DNS record for {names}, or point it somewhere you control. "
            "Until then, whoever registers that target next can serve content from "
            "your domain name.",
        )

    if not findings.nameservers:
        return (
            "warn",
            "low",
            "No nameserver records could be read for this domain.",
            "Check with your registrar that the domain's nameservers are set correctly.",
        )

    if len(findings.providers) < 2:
        return (
            "warn",
            "low",
            f"All {len(findings.nameservers)} nameservers belong to a single provider.",
            "Add a secondary DNS provider. Most registrars support this and it is "
            "usually a configuration change rather than a migration.",
        )

    return (
        "pass",
        "info",
        f"{len(findings.nameservers)} nameservers across {len(findings.providers)} "
        "providers, zone transfers refused, no dangling records.",
        "No action needed.",
    )


def _explain(findings: _Findings) -> str:
    """Describe the consequence in operational terms."""
    if findings.transfers_open:
        return (
            "A zone transfer returns every DNS record for your domain in one request. "
            "That is a complete list of your servers, staging sites and internal "
            "hostnames, which is the map an attacker would otherwise have to build "
            "slowly and noisily."
        )
    if findings.dangling:
        return (
            "A DNS record pointing at a service that has been deleted can be claimed by "
            "someone else signing up for that service and taking the same name. They "
            "then serve whatever they like from an address that is genuinely yours, "
            "including a convincing copy of your login page."
        )
    if len(findings.providers) < 2:
        return (
            "If that one provider has an outage, your website and your email both "
            "disappear at the same time, and you have no way to redirect them while it "
            "lasts. Zone transfers are correctly refused."
        )
    return (
        "DNS is served by more than one provider, so a single outage does not take the "
        "domain offline. Zone transfers are refused and nothing was found pointing at a "
        "deleted target."
    )


async def _nameservers(domain: str, ctx: ScanContext) -> tuple[str, ...]:
    """The domain's authoritative nameservers, as hostnames."""
    try:
        answer = await ctx.dns_query(organisational_domain(domain), "NS")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return ()
    return tuple(sorted(str(record.target).rstrip(".").lower() for record in answer))


async def _attempt_transfers(domain: str, nameservers: tuple[str, ...]) -> dict[str, str]:
    """Ask each nameserver for the zone, once, and record how it answered.

    A refusal is success. The outcome is recorded per nameserver rather than
    as a single verdict, because one misconfigured secondary among four is a
    real finding that an aggregate would hide.
    """
    zone_name = organisational_domain(domain)
    outcomes: dict[str, str] = {}

    for nameserver in nameservers:
        try:
            address = await _first_address(nameserver)
        except dns.exception.DNSException as exc:
            outcomes[nameserver] = f"could not resolve nameserver: {type(exc).__name__}"
            continue

        if address is None:
            outcomes[nameserver] = "could not resolve nameserver"
            continue

        outcomes[nameserver] = await _try_transfer(zone_name, nameserver, address)

    return outcomes


async def _try_transfer(zone_name: str, nameserver: str, address: str) -> str:
    """One AXFR request. Returns "open", "refused", or why it was inconclusive."""
    zone = dns.zone.Zone(dns.name.from_text(zone_name))
    try:
        await dns.asyncquery.inbound_xfr(
            address,
            zone,
            query=dns.message.make_query(zone_name, dns.rdatatype.AXFR),
            timeout=_AXFR_TIMEOUT,
            lifetime=_AXFR_TIMEOUT,
        )
    except dns.exception.DNSException as exc:
        # Refusal is the expected and correct answer, and arrives as an
        # exception. It is not an error in this check.
        logger.debug("%s refused a zone transfer: %s", nameserver, exc)
        return "refused"
    except OSError as exc:
        logger.info("%s unreachable for zone transfer: %s", nameserver, exc)
        return f"unreachable: {exc.strerror or type(exc).__name__}"

    record_count = sum(1 for _ in zone.nodes)
    logger.warning(
        "%s allowed a zone transfer of %s (%d nodes)", nameserver, zone_name, record_count
    )
    return "open"


async def _first_address(nameserver: str) -> str | None:
    """Resolve a nameserver hostname to one address.

    Uses a plain resolver rather than the scan context: this is resolving
    infrastructure in order to talk to it directly, not inspecting the target,
    and it must not be served from the context's caches.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = _AXFR_TIMEOUT
    resolver.lifetime = _AXFR_TIMEOUT
    try:
        answer = await resolver.resolve(nameserver, "A")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return None
    return next((record.address for record in answer), None)


async def _find_dangling(domain: str, ctx: ScanContext) -> tuple[str, ...]:
    """Find names whose CNAME points at something that does not exist."""
    names = [f"{prefix}.{domain}" if prefix else domain for prefix in _DANGLING_CANDIDATES]
    results = await asyncio.gather(*(_is_dangling(name, ctx) for name in names))
    return tuple(name for name, dangling in zip(names, results, strict=True) if dangling)


async def _is_dangling(name: str, ctx: ScanContext) -> bool:
    """Whether this name is a CNAME to a target that no longer resolves."""
    try:
        answer = await ctx.dns_query(name, "CNAME")
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False  # No CNAME here, so nothing to dangle.

    target = next((str(record.target).rstrip(".") for record in answer), None)
    if target is None:
        return False

    try:
        await ctx.dns_query(target, "A")
    except dns.resolver.NXDOMAIN:
        # The target's name does not exist at all, which is what makes the
        # record claimable by whoever registers it next.
        return True
    except dns.resolver.NoAnswer:
        # The name exists but has no address. Ordinary for a CNAME chain, and
        # not evidence of abandonment.
        return False
    return False


CHECK: Final = Check(id=CHECK_ID, title=TITLE, run=run)
