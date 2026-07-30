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
import os
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

import httpx

from netgrade.checks.base import Check, error_result
from netgrade.config import ENV_CERTSPOTTER_TOKEN
from netgrade.context import ScanContext
from netgrade.models import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID: Final = "cert_history"
TITLE: Final = "Certificate history"

#: Certificate transparency is read through aggregators rather than from the
#: logs directly, because the logs are append-only Merkle trees and searching
#: them by domain is not something they offer. That makes the aggregator a
#: dependency we do not control, so there are two of them.
#:
#: crt.sh is first: it is the most complete and it is what a security person
#: will check our output against. It is also the least reliable, returning 502s
#: for hours at a time. Cert Spotter answers in under a second when crt.sh is
#: down, which is most of the value here -- one flaky provider makes a check
#: unavailable, two independent ones make it merely slower on a bad day.
_CRT_SH: Final = "crt.sh"
_CRT_SH_URL: Final = "https://crt.sh/?q=%25.{domain}&output=json&exclude=expired"

_CERT_SPOTTER: Final = "Cert Spotter"
_CERT_SPOTTER_URL: Final = (
    "https://api.certspotter.com/v1/issuances"
    "?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer"
)

_REQUEST_TIMEOUT: Final = 6.0

#: crt.sh returns a transient 502 often enough that a single attempt reports
#: "could not check" for a service that is actually working. One retry, not
#: several: the point is to ride out a blip, not to insist.
_RETRIES: Final = 1

#: Both sources, two attempts each at _REQUEST_TIMEOUT, fit inside this with
#: room to spare, so an unresponsive aggregator is reported by this module --
#: which knows what it was talking to -- rather than by the generic budget in
#: checks.base. The ceiling is a backstop, not the mechanism.
#:
#: It was 45s, sized for a slow-but-working crt.sh. That was wrong: a scan is
#: only as fast as its slowest check, so a degraded third party set the wall
#: clock for every scan. A tight budget loses the occasional slow success and
#: keeps the report responsive, which is the better trade for this check.
_CHECK_TIMEOUT: Final = 15.0

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

    try:
        source, entries = await _fetch_entries(domain, ctx)
    except (httpx.HTTPError, ValueError) as exc:
        return _source_unavailable(exc)

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
            "source": source,
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


def _source_unavailable(exc: Exception) -> CheckResult:
    """Report that the log service could not be read, and say which one.

    Every other check talks to the domain being scanned, so the generic
    handling in checks.base -- "the site could not be reached" -- names the
    right host. This one talks to a third-party aggregator, and letting that
    message through would tell an owner their site was unreachable when the
    only thing that was down is a log service they have never heard of.
    """
    detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
    logger.warning("no certificate transparency source could be read: %s", detail)
    return error_result(
        CHECK,
        summary=(
            "Could not check: the public certificate log services did not respond. "
            "This is not a problem with your domain."
        ),
        detail=detail,
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


@dataclass(frozen=True, slots=True)
class _Entry:
    """One certificate, in a shape both aggregators can be reduced to.

    Normalising here rather than teaching the summariser two response formats
    means a third source would be one function, and means the summariser has
    no idea which provider answered.
    """

    names: tuple[str, ...] = ()
    issuer: str = ""
    logged_at: datetime | None = None


async def _fetch_entries(domain: str, ctx: ScanContext) -> tuple[str, list[_Entry]]:
    """Read the transparency record, trying each aggregator in turn.

    Returns the name of whichever source answered alongside its entries, so the
    evidence can say where the data came from. A report that disagrees with
    somebody's own check of crt.sh should be traceable to having read a
    different aggregator rather than looking like a parsing error.

    Raises:
        httpx.HTTPError: if no source could be read. Reporting "could not
            check" is honest where reporting "no certificates found" would be
            a fabrication.
    """
    failures: list[str] = []

    for source, fetch in (
        (_CRT_SH, _fetch_crt_sh),
        (_CERT_SPOTTER, _fetch_cert_spotter),
    ):
        try:
            return source, await fetch(domain, ctx)
        except (httpx.HTTPError, ValueError) as exc:
            detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            logger.info("%s unavailable (%s); trying the next source", source, detail)
            failures.append(f"{source}: {detail}")

    raise httpx.HTTPError("; ".join(failures))


async def _fetch_crt_sh(domain: str, ctx: ScanContext) -> list[_Entry]:
    """Query crt.sh, retrying once past a transient 502."""
    payload = await _get_json(_CRT_SH_URL.format(domain=domain), _CRT_SH, ctx)

    return [_entry_from_crt_sh(r) for r in payload if isinstance(r, dict)]


def _entry_from_crt_sh(record: dict[str, Any]) -> _Entry:
    """Normalise one crt.sh record. One record can cover several names."""
    return _Entry(
        names=tuple(
            name
            for raw in str(record.get("name_value", "")).splitlines()
            if (name := raw.strip().lower().rstrip("."))
        ),
        issuer=str(record.get("issuer_name", "")).strip(),
        logged_at=_parse_timestamp(record.get("entry_timestamp") or record.get("not_before")),
    )


async def _fetch_cert_spotter(domain: str, ctx: ScanContext) -> list[_Entry]:
    """Query Cert Spotter, keeping only certificates that have not expired.

    crt.sh is asked to exclude expired certificates in the query itself. Cert
    Spotter has no such parameter, so the filter is applied here -- otherwise
    the two sources would answer the same question differently and the count
    would jump depending on which one happened to be up.
    """
    payload = await _get_json(
        _CERT_SPOTTER_URL.format(domain=domain),
        _CERT_SPOTTER,
        ctx,
        headers=_cert_spotter_headers(),
    )
    now = datetime.now(UTC)
    return [
        _entry_from_cert_spotter(record)
        for record in payload
        if isinstance(record, dict) and not _has_expired(record, now)
    ]


def _has_expired(record: dict[str, Any], now: datetime) -> bool:
    """Whether a Cert Spotter record is already out of date."""
    expires = _parse_timestamp(record.get("not_after"))
    return expires is not None and expires < now


def _entry_from_cert_spotter(record: dict[str, Any]) -> _Entry:
    """Normalise one Cert Spotter issuance."""
    issuer = record.get("issuer")
    return _Entry(
        names=tuple(
            name
            for raw in record.get("dns_names") or ()
            if (name := str(raw).strip().lower().rstrip("."))
        ),
        issuer=str(issuer.get("name", "")).strip() if isinstance(issuer, dict) else "",
        logged_at=_parse_timestamp(record.get("not_before")),
    )


def _cert_spotter_headers() -> dict[str, str]:
    """Authenticate to Cert Spotter when a token is configured.

    Cert Spotter answers unauthenticated requests, but rate limits them per
    source address, and the ceiling is low enough that a handful of scans in a
    minute exhausts it -- which then reports "could not check" to everyone
    sharing our address, including someone trying the live site for themselves.
    A free token raises that ceiling.

    Read from the environment on each call rather than captured at import, so
    setting it does not require a rebuild, only a restart. Absent or blank, the
    request still goes out unauthenticated: a low limit beats no second source.
    """
    headers = {"Accept": "application/json"}
    token = os.getenv(ENV_CERTSPOTTER_TOKEN, "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _get_json(
    url: str,
    source: str,
    ctx: ScanContext,
    headers: dict[str, str] | None = None,
) -> list[Any]:
    """Fetch a JSON array, retrying once past a transient server error."""
    last_error: httpx.HTTPStatusError | None = None
    request_headers = headers or {"Accept": "application/json"}

    for attempt in range(_RETRIES + 1):
        async with ctx.limiter:
            response = await ctx.http.get(
                url, timeout=_REQUEST_TIMEOUT, headers=request_headers
            )
        # A rate limit is not a transient server error and retrying it makes it
        # worse, so it breaks out here with the rest of the 4xx family and is
        # reported below with the wait the service asked for.
        if response.status_code == httpx.codes.TOO_MANY_REQUESTS:
            logger.warning(
                "%s rate limited us; it asks for %s seconds. %s",
                source,
                response.headers.get("retry-after", "an unspecified number of"),
                "A token is configured."
                if "Authorization" in request_headers
                else f"No token configured; set {ENV_CERTSPOTTER_TOKEN} to raise the limit.",
            )
            break
        if not response.is_server_error:
            break
        last_error = httpx.HTTPStatusError(
            f"{source} returned {response.status_code}",
            request=response.request,
            response=response,
        )
        logger.info("%s returned %s, attempt %d", source, response.status_code, attempt + 1)
    else:
        raise last_error  # type: ignore[misc]

    response.raise_for_status()

    payload = response.json()
    if not isinstance(payload, list):
        raise ValueError(f"{source} returned {type(payload).__name__}, expected a list")
    return payload


def _summarise(entries: list[_Entry], domain: str) -> _History:
    """Reduce normalised log entries to the few facts worth reporting."""
    names: set[str] = set()
    issuers: Counter[str] = Counter()
    most_recent: datetime | None = None

    for entry in entries:
        for name in entry.names:
            if name == domain or name.endswith(f".{domain}") or name.startswith("*."):
                names.add(name)

        if entry.issuer:
            issuers[_issuer_label(entry.issuer)] += 1

        if entry.logged_at and (most_recent is None or entry.logged_at > most_recent):
            most_recent = entry.logged_at

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
        logger.info("unparseable certificate transparency timestamp %r", raw)
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


CHECK: Final = Check(id=CHECK_ID, title=TITLE, run=run, timeout=_CHECK_TIMEOUT)
