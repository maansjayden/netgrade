"""Check 1 -- email spoofing protection.

Reads the three DNS records that decide whether someone else can send mail
that appears to come from this domain: SPF, DMARC and DKIM.

The verdict is driven by DMARC, because DMARC is the only one of the three
that tells a receiving mail server what to *do* about a forgery. SPF without
DMARC publishes an opinion nobody is obliged to act on.
"""

import asyncio
import logging
import secrets
from dataclasses import dataclass, field
from typing import Final

import dns.resolver

from netgrade.checks.base import Check
from netgrade.context import ScanContext
from netgrade.domains import organisational_domain
from netgrade.models import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID: Final = "email_spoofing"
TITLE: Final = "Email spoofing protection"

#: Well-known DKIM selectors published by the major mail providers.
#:
#: A fixed list, not a wordlist: selectors are arbitrary strings, so no probe
#: can prove DKIM is absent. That asymmetry is why a DKIM miss is reported as
#: information and never as a failure -- claiming a domain has no DKIM because
#: six guesses missed would be the kind of overclaim this tool exists to avoid.
_DKIM_SELECTORS: Final = ("google", "default", "selector1", "selector2", "k1", "mail")

#: SPF's final mechanism decides what a receiver does with mail from an
#: unlisted server. Ordered worst to best.
_SPF_QUALIFIERS: Final = {
    "+all": "passes everything",
    "?all": "neutral",
    "~all": "soft fail",
    "-all": "hard fail",
}


@dataclass(frozen=True, slots=True)
class _Spf:
    records: tuple[str, ...] = ()
    qualifier: str | None = None

    @property
    def present(self) -> bool:
        return bool(self.records)

    @property
    def duplicated(self) -> bool:
        """More than one SPF record makes SPF fail entirely, per RFC 7208."""
        return len(self.records) > 1


@dataclass(frozen=True, slots=True)
class _Dkim:
    """What selector probing could establish, which is often nothing.

    ``wildcarded`` means the domain answers for every selector name, so the
    probe proves neither presence nor absence.
    """

    selectors: tuple[str, ...] = ()
    wildcarded: bool = False


@dataclass(frozen=True, slots=True)
class _Dmarc:
    record: str | None = None
    policy: str | None = None
    percentage: int = 100
    inherited_from: str | None = None
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def present(self) -> bool:
        return self.record is not None


async def run(domain: str, ctx: ScanContext) -> CheckResult:
    """Inspect SPF, DMARC and DKIM for one domain."""
    # Every check needs the domain to exist; without it there is nothing to
    # report an absence of. Cached on the context, so this costs one lookup
    # for the whole scan rather than one per check.
    await ctx.assert_domain_exists(domain)

    spf, dmarc, dkim = await asyncio.gather(
        _read_spf(domain, ctx),
        _read_dmarc(domain, ctx),
        _probe_dkim(domain, ctx),
    )

    status, severity, summary, fix = _assess(spf, dmarc)

    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        severity=severity,
        summary=summary,
        explanation=_explain(spf, dmarc, dkim),
        fix=fix,
        evidence={
            "spf_record": spf.records[0] if spf.present else None,
            "spf_record_count": len(spf.records),
            "spf_qualifier": spf.qualifier,
            "dmarc_record": dmarc.record,
            "dmarc_policy": dmarc.policy,
            "dmarc_percentage": dmarc.percentage,
            "dmarc_inherited_from": dmarc.inherited_from,
            "dkim_selectors_found": list(dkim.selectors),
            "dkim_wildcarded": dkim.wildcarded,
            "organisational_domain": organisational_domain(domain),
        },
    )


def _assess(spf: _Spf, dmarc: _Dmarc) -> tuple[CheckStatus, Severity, str, str]:
    """Turn the records into a verdict, worst problem first.

    Ordered by how much damage the configuration actually permits rather than
    by which record is missing, so the summary names the thing worth fixing
    today instead of listing everything that is imperfect.
    """
    if spf.qualifier == "+all":
        return (
            "fail",
            "critical",
            "The SPF record authorises every server on the internet to send as this domain.",
            "Change the SPF record's final mechanism from +all to -all, listing only the "
            "services that legitimately send your mail. +all is worse than having no SPF "
            "record at all.",
        )

    if spf.duplicated:
        return (
            "fail",
            "high",
            f"There are {len(spf.records)} SPF records; the standard permits one.",
            "Merge them into a single SPF record. While more than one exists, receiving "
            "servers are required to ignore SPF for this domain entirely.",
        )

    if not dmarc.present:
        detail = "and no SPF record either" if not spf.present else "though SPF is published"
        return (
            "fail",
            "high",
            f"No DMARC policy is published, {detail}.",
            "Publish a DMARC record starting at p=none so you can see who is sending as "
            "you, then tighten it to p=quarantine and finally p=reject once the reports "
            "look clean.",
        )

    if dmarc.policy == "none":
        return (
            "warn",
            "medium",
            "DMARC is published but set to monitor only, so nothing is blocked.",
            "Once your DMARC reports show only your own mail services, move the policy "
            "from p=none to p=quarantine, then to p=reject.",
        )

    if dmarc.percentage < 100:
        return (
            "warn",
            "low",
            f"DMARC is enforcing on only {dmarc.percentage}% of mail.",
            f"Raise pct={dmarc.percentage} to pct=100 so the policy applies to every "
            "message rather than a sample.",
        )

    if dmarc.policy == "quarantine":
        return (
            "warn",
            "low",
            "DMARC sends forged mail to spam rather than rejecting it.",
            "Move the policy from p=quarantine to p=reject so forged mail is refused "
            "outright instead of landing in a spam folder where it can still be read.",
        )

    if not spf.present:
        return (
            "warn",
            "low",
            "DMARC is enforced, but no SPF record is published.",
            "Publish an SPF record listing the services that send your mail. DMARC is "
            "doing the work alone at the moment.",
        )

    return (
        "pass",
        "info",
        "SPF and DMARC are published, and DMARC is set to reject forgeries.",
        "No action needed. Keep the SPF record current when you change mail providers.",
    )


def _explain(spf: _Spf, dmarc: _Dmarc, dkim: _Dkim) -> str:
    """Say why it matters, in the language of the person reading the report."""
    if not dmarc.present:
        base = (
            "Anyone can send email that appears to come from your domain. Receiving mail "
            "servers have no instruction to reject those messages, so invoice fraud and "
            "staff impersonation arrive looking legitimate."
        )
    elif dmarc.policy == "none":
        base = (
            "Your DMARC record is collecting reports but is not yet telling mail servers "
            "to block anything, so forged mail still reaches inboxes."
        )
    else:
        base = (
            "Mail servers receiving a forged message from your domain are told to reject "
            "it, which is what stops your name being used for invoice fraud."
        )

    if dkim.wildcarded:
        base += (
            " Whether DKIM signing is in use could not be established: this domain answers "
            "to every possible signing-key name, so the usual check tells us nothing."
        )
    elif dkim.selectors:
        base += f" DKIM signing keys were found ({', '.join(dkim.selectors)})."
    else:
        base += (
            " No DKIM key was found at the usual names, though DKIM keys can be published "
            "under any name, so this is not conclusive."
        )
    return base


async def _read_spf(domain: str, ctx: ScanContext) -> _Spf:
    """Read SPF from the domain's TXT records."""
    records = tuple(
        record for record in await _txt_records(domain, ctx) if record.lower().startswith("v=spf1")
    )
    if not records:
        return _Spf()

    lowered = records[0].lower()
    qualifier = next((q for q in _SPF_QUALIFIERS if q in lowered), None)
    return _Spf(records=records, qualifier=qualifier)


async def _read_dmarc(domain: str, ctx: ScanContext) -> _Dmarc:
    """Read DMARC, falling back to the organisational domain.

    A subdomain with no DMARC record of its own inherits the organisational
    domain's policy. Reporting the subdomain as unprotected without checking
    the parent would be a false finding.
    """
    organisational = organisational_domain(domain)
    candidates = [domain] if domain == organisational else [domain, organisational]

    for candidate in candidates:
        for record in await _txt_records(f"_dmarc.{candidate}", ctx):
            if not record.lower().startswith("v=dmarc1"):
                continue
            tags = _parse_tags(record)
            return _Dmarc(
                record=record,
                policy=tags.get("p"),
                percentage=_parse_percentage(tags.get("pct")),
                inherited_from=None if candidate == domain else candidate,
                tags=tags,
            )
    return _Dmarc()


async def _probe_dkim(domain: str, ctx: ScanContext) -> _Dkim:
    """Look for DKIM keys at well-known selector names.

    Probes one deliberately random selector alongside the real ones. A domain
    publishing a wildcard under _domainkey answers for every name, so without
    that control every selector appears to hold a key and the result is
    nonsense. example.com does exactly this.
    """
    control = f"netgrade-control-{secrets.token_hex(6)}"
    names = (*_DKIM_SELECTORS, control)

    results = await asyncio.gather(
        *(_txt_records(f"{selector}._domainkey.{domain}", ctx) for selector in names),
    )
    found = {
        selector
        for selector, records in zip(names, results, strict=True)
        if any(_is_dkim_key(record) for record in records)
    }

    if control in found:
        logger.info("%s wildcards _domainkey; DKIM selector probing is inconclusive", domain)
        return _Dkim(wildcarded=True)

    return _Dkim(selectors=tuple(s for s in _DKIM_SELECTORS if s in found))


def _is_dkim_key(record: str) -> bool:
    """Whether a TXT record actually carries a DKIM public key.

    An empty ``p=`` is not a key. It is the standard way to publish a revoked
    selector, and treating it as a key would report signing where the domain
    owner has explicitly withdrawn it.
    """
    tags = _parse_tags(record)
    if tags.get("v", "DKIM1").upper() != "DKIM1":
        return False
    return bool(tags.get("p"))


async def _txt_records(name: str, ctx: ScanContext) -> list[str]:
    """Read TXT records, treating "no such record" as an empty list.

    A missing record is a finding, not an error: the whole point of this check
    is to notice absence. A resolver failure is different and is allowed to
    propagate, so the check reports "could not check" rather than inventing a
    missing DMARC policy for a domain whose DNS was simply unreachable.
    """
    try:
        answer = await ctx.dns_query(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []

    # Long TXT values arrive split into 255-byte chunks that must be rejoined.
    return [
        "".join(part.decode("utf-8", "replace") for part in record.strings) for record in answer
    ]


def _parse_tags(record: str) -> dict[str, str]:
    """Parse a DMARC record's semicolon-separated tag=value pairs."""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, separator, value = part.partition("=")
        if separator:
            tags[key.strip().lower()] = value.strip()
    return tags


def _parse_percentage(raw: str | None) -> int:
    """Read DMARC's pct tag, defaulting to 100 when absent or unparseable."""
    if raw is None:
        return 100
    try:
        return max(0, min(100, int(raw)))
    except ValueError:
        logger.warning("unparseable DMARC pct value %r", raw)
        return 100


CHECK: Final = Check(id=CHECK_ID, title=TITLE, run=run)
