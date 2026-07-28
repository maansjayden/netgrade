"""Check 7 -- certificate history.

Reads the public certificate transparency logs for every certificate issued
for this domain. Every certificate a public authority issues is published to
these logs by design, so this is a matter of reading a public record.

This check is an inventory rather than a verdict. Certificates for names the
owner has forgotten about are the reason to look, but deciding whether a name
is forgotten needs a resolution pass over every name found, which is the
subdomain-enumeration territory this tool stays out of. So it reports what
exists and flags the shape of it, and the README's Scaling section describes
what the fuller version would do.

It also depends on a third-party service, which makes it the check most
likely to be unavailable. That is exactly what status "error" is for: it
reports honestly that it could not look, and is left out of the grade rather
than counted as a pass.
"""

import logging
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

import httpx

from netgrade.checks.base import Check
from netgrade.context import ScanContext
from netgrade.models import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID: Final = "cert_history"
TITLE: Final = "Certificate history"

#: crt.sh aggregates the public logs and is the only source used. It is
#: frequently slow, so the budget is deliberately tight -- a scan that stalls
#: for the user is worse than a check that reports it could not look.
_SOURCE: Final = "crt.sh"
_SOURCE_URL: Final = "https://crt.sh/?q=%25.{domain}&output=json&exclude=expired"
_REQUEST_TIMEOUT: Final = 20.0

#: crt.sh returns a transient 502 often enough that a single attempt reports
#: "could not check" for a service that is actually working. One retry, not
#: several: the point is to ride out a blip, not to insist.
_RETRIES: Final = 1
_CHECK_TIMEOUT: Final = 45.0

#: Above this many distinct names, the certificate footprint is worth a look
#: from the owner. Not a vulnerability -- a prompt to check that every name
#: still belongs to something they run.
_LARGE_FOOTPRINT: Final = 25


@dataclass(frozen=True, slots=True)
class _History:
    names: tuple[str, ...] = ()
    issuers: tuple[str, ...] = ()
    certificate_count: int = 0
    most_recent: str | None = None
    wildcards: tuple[str, ...] = ()


async def run(domain: str, ctx: ScanContext) -> CheckResult:
    """Read the certificate transparency record for this domain."""
    await ctx.assert_domain_exists(domain)

    entries = await _fetch_entries(domain, ctx)
    history = _summarise(entries, domain)
    status, severity, summary, fix = _assess(history)

    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        severity=severity,
        summary=summary,
        explanation=_explain(history),
        fix=fix,
        evidence={
            "source": _SOURCE,
            "certificates_found": history.certificate_count,
            "distinct_names": len(history.names),
            # Capped: the full list can run to hundreds of entries, and the
            # report is for a person to read rather than a data dump.
            "names": list(history.names[:40]),
            "names_truncated": len(history.names) > 40,
            "wildcard_names": list(history.wildcards),
            "issuers": list(history.issuers[:10]),
            "most_recent_issue": history.most_recent,
        },
    )


def _assess(history: _History) -> tuple[CheckStatus, Severity, str, str]:
    """Report the footprint. This check informs; it does not accuse."""
    if history.certificate_count == 0:
        return (
            "pass",
            "info",
            "No unexpired certificates are recorded in the public transparency logs.",
            "No action needed. If this domain serves a website over HTTPS, it is worth "
            "confirming why nothing appears here.",
        )

    if len(history.names) > _LARGE_FOOTPRINT:
        return (
            "warn",
            "low",
            f"{len(history.names)} distinct hostnames have certificates in the public logs.",
            "Review the list and confirm each name is still something you run. Names "
            "belonging to retired services are worth removing from DNS, since a "
            "certificate proves the name was live at some point.",
        )

    return (
        "pass",
        "info",
        f"{history.certificate_count} unexpired certificates across "
        f"{len(history.names)} hostname{'s' if len(history.names) != 1 else ''}.",
        "No action needed. Certificate transparency is public, so it is worth "
        "occasionally checking this list for names you do not recognise.",
    )


def _explain(history: _History) -> str:
    """Explain what the log reveals, and to whom."""
    if history.certificate_count == 0:
        return (
            "Certificate transparency logs are public records of every certificate issued "
            "for a domain. Nothing current is recorded here, so there is no forgotten "
            "hostname to find by this route."
        )
    if len(history.names) > _LARGE_FOOTPRINT:
        return (
            "These logs are public, and attackers read them to find the hostnames a "
            "business does not advertise -- staging sites, old admin panels, systems "
            "retired without being taken down. A long list is not itself a problem, but "
            "every name on it is a door someone else can see."
        )
    return (
        "These logs are public and searchable by anyone, which is what makes them useful "
        "to an attacker looking for hostnames you have not advertised. The list here is "
        "short enough to review by eye."
    )


async def _fetch_entries(domain: str, ctx: ScanContext) -> list[dict[str, Any]]:
    """Query crt.sh for unexpired certificates covering this domain.

    Network and parse failures are allowed to propagate. This check depends on
    a service outside our control, and reporting "could not check" is honest
    where reporting "no certificates found" would be a fabrication.
    """
    url = _SOURCE_URL.format(domain=domain)
    last_error: httpx.HTTPStatusError | None = None

    for attempt in range(_RETRIES + 1):
        async with ctx.limiter:
            response = await ctx.http.get(
                url, timeout=_REQUEST_TIMEOUT, headers={"Accept": "application/json"}
            )
        if not response.is_server_error:
            break
        last_error = httpx.HTTPStatusError(
            f"{_SOURCE} returned {response.status_code}", request=response.request,
            response=response,
        )
        logger.info("%s returned %s, attempt %d", _SOURCE, response.status_code, attempt + 1)
    else:
        raise last_error  # type: ignore[misc]

    response.raise_for_status()

    payload = response.json()
    if not isinstance(payload, list):
        raise ValueError(f"{_SOURCE} returned {type(payload).__name__}, expected a list")
    return payload


def _summarise(entries: list[dict[str, Any]], domain: str) -> _History:
    """Reduce raw log entries to the few facts worth reporting."""
    names: set[str] = set()
    issuers: Counter[str] = Counter()
    most_recent: datetime | None = None

    for entry in entries:
        # One entry can cover several names, newline separated.
        for raw in str(entry.get("name_value", "")).splitlines():
            name = raw.strip().lower().rstrip(".")
            if name and (name == domain or name.endswith(f".{domain}") or name.startswith("*.")):
                names.add(name)

        issuer = str(entry.get("issuer_name", "")).strip()
        if issuer:
            issuers[_issuer_label(issuer)] += 1

        logged = _parse_timestamp(entry.get("entry_timestamp") or entry.get("not_before"))
        if logged and (most_recent is None or logged > most_recent):
            most_recent = logged

    return _History(
        names=tuple(sorted(names)),
        issuers=tuple(name for name, _ in issuers.most_common()),
        certificate_count=len(entries),
        most_recent=most_recent.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        if most_recent
        else None,
        wildcards=tuple(sorted(name for name in names if name.startswith("*."))),
    )


def _issuer_label(issuer: str) -> str:
    """Pull the organisation name out of a distinguished name."""
    for part in issuer.split(","):
        key, separator, value = part.strip().partition("=")
        if separator and key.upper() == "O":
            return value.strip()
    return issuer[:60]


def _parse_timestamp(raw: object) -> datetime | None:
    """Parse one of crt.sh's timestamps, which carry no timezone."""
    if not isinstance(raw, str) or not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        logger.info("unparseable %s timestamp %r", _SOURCE, raw)
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


CHECK: Final = Check(id=CHECK_ID, title=TITLE, run=run, timeout=_CHECK_TIMEOUT)
