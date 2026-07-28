"""Check 5 -- exposed development files.

Requests three specific, well-known paths that should never be reachable on a
live site: a git repository config, an environment file, and a macOS folder
index. One GET each, no wordlist, no directory enumeration.

The hard part is not finding these files. It is not claiming to have found
one when the site has simply returned its own 404 page with a 200 status,
which a great many do. Every positive is therefore confirmed against the
content of the response rather than its status code, and a random control
path establishes what "not found" looks like on this particular site before
any conclusion is drawn.
"""

import logging
import re
import secrets
from dataclasses import dataclass
from typing import Final

import httpx

from netgrade.checks.base import Check
from netgrade.context import ScanContext
from netgrade.models import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID: Final = "exposed_artefacts"
TITLE: Final = "Exposed development files"

#: How much of a body to inspect. These files are identified by their opening
#: bytes, so a prefix is enough and reading more of a file we should not be
#: able to read is not something to do casually.
_INSPECT_BYTES: Final = 2048


@dataclass(frozen=True, slots=True)
class _Artefact:
    """One path worth checking, and how to recognise the real thing."""

    path: str
    label: str
    severity: Severity
    #: Matched against the response body. A path returning 200 without this
    #: is a soft 404, a placeholder, or someone else's error page.
    signature: re.Pattern[bytes]
    consequence: str


_ARTEFACTS: Final = (
    _Artefact(
        path="/.env",
        label="environment file",
        severity="critical",
        # KEY=VALUE lines using the names these files actually carry.
        signature=re.compile(
            rb"(?im)^\s*(APP_KEY|APP_SECRET|DB_(HOST|PASSWORD|USERNAME)|DATABASE_URL"
            rb"|SECRET_KEY|AWS_(ACCESS|SECRET)_[A-Z_]+|STRIPE_[A-Z_]+|API_KEY)\s*="
        ),
        consequence=(
            "An environment file holds the passwords and API keys the site runs on. "
            "Anyone who reads it can usually reach the database directly, without "
            "needing to attack the website at all."
        ),
    ),
    _Artefact(
        path="/.git/config",
        label="git repository config",
        severity="high",
        signature=re.compile(rb"(?im)^\s*\[core\]|repositoryformatversion"),
        consequence=(
            "A reachable git config usually means the whole repository is reachable. "
            "That gives an attacker your source code, and very often credentials "
            "committed to it at some point in the past."
        ),
    ),
    _Artefact(
        path="/.DS_Store",
        label="macOS folder index",
        severity="low",
        # These begin with a four-byte alignment header followed by "Bud1".
        signature=re.compile(rb"^\x00\x00\x00\x01Bud1"),
        consequence=(
            "This file lists the names of everything in the folder, including files "
            "that were never meant to be linked to. It is a map of what to look for "
            "next rather than a breach on its own."
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class _Probe:
    """The outcome of requesting one path."""

    artefact: _Artefact
    status_code: int | None
    exposed: bool
    reason: str


async def run(domain: str, ctx: ScanContext) -> CheckResult:
    """Request each known path once and confirm anything that looks exposed."""
    await ctx.assert_domain_exists(domain)

    base = f"https://{domain}"
    soft_404 = await _detect_soft_404(base, ctx)

    # Sequential, not concurrent. Three requests to one small business's web
    # server should look like a visitor, not like a scanner. The whole check
    # still finishes well inside its budget.
    probes = [await _probe(base, artefact, ctx) for artefact in _ARTEFACTS]

    exposed = tuple(probe for probe in probes if probe.exposed)
    status, severity, summary, fix = _assess(exposed, soft_404)

    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        severity=severity,
        summary=summary,
        explanation=_explain(exposed, soft_404),
        fix=fix,
        evidence={
            "paths_checked": [artefact.path for artefact in _ARTEFACTS],
            "responses": {probe.artefact.path: probe.status_code for probe in probes},
            "exposed": [probe.artefact.path for probe in exposed],
            "verdicts": {probe.artefact.path: probe.reason for probe in probes},
            "site_returns_200_for_missing_pages": soft_404,
        },
    )


def _assess(
    exposed: tuple[_Probe, ...], soft_404: bool
) -> tuple[CheckStatus, Severity, str, str]:
    """Grade on the most damaging file found."""
    if not exposed:
        note = (
            " This site answers 200 for pages that do not exist, so results were "
            "confirmed by file contents rather than status codes."
            if soft_404
            else ""
        )
        return (
            "pass",
            "info",
            f"None of the three checked paths are reachable.{note}",
            "No action needed.",
        )

    worst = max(exposed, key=lambda probe: _SEVERITY_ORDER.index(probe.artefact.severity))
    labels = ", ".join(probe.artefact.path for probe in exposed)

    return (
        "fail",
        worst.artefact.severity,
        f"{'A file' if len(exposed) == 1 else 'Files'} that should not be public "
        f"can be downloaded: {labels}.",
        f"Remove {labels} from the web server, or block access to it in your server "
        "configuration. Treat any password or key it contains as compromised and "
        "rotate it, because you cannot know who has already read it.",
    )


def _explain(exposed: tuple[_Probe, ...], soft_404: bool) -> str:
    """Explain what the worst exposed file gives away."""
    if not exposed:
        base = (
            "Development files left on a live server can expose source code, database "
            "passwords and API keys to anyone who requests them directly. None of the "
            "three checked here were readable."
        )
        if soft_404:
            base += (
                " This site returns a page rather than an error for addresses that do "
                "not exist, so each result was confirmed by what the file contained."
            )
        return base

    worst = max(exposed, key=lambda probe: _SEVERITY_ORDER.index(probe.artefact.severity))
    return worst.artefact.consequence


async def _detect_soft_404(base: str, ctx: ScanContext) -> bool:
    """Find out whether this site returns 200 for addresses that do not exist.

    Without this, any site with a catch-all route would be reported as leaking
    all three files. The path is randomly generated so it cannot collide with
    anything real.
    """
    probe_path = f"/netgrade-control-{secrets.token_hex(8)}"
    try:
        response = await ctx.fetch(f"{base}{probe_path}")
    except httpx.HTTPError as exc:
        logger.info("soft-404 control request failed: %s", exc)
        return False
    return response.status_code == httpx.codes.OK


async def _probe(base: str, artefact: _Artefact, ctx: ScanContext) -> _Probe:
    """Request one path and decide whether the real file came back."""
    try:
        response = await ctx.fetch(f"{base}{artefact.path}")
    except httpx.HTTPError as exc:
        logger.info("%s could not be requested: %s", artefact.path, exc)
        return _Probe(artefact, None, exposed=False, reason=f"request failed: {exc}")

    if response.status_code != httpx.codes.OK:
        return _Probe(
            artefact, response.status_code, exposed=False, reason=f"HTTP {response.status_code}"
        )

    if not artefact.signature.search(response.body_prefix[:_INSPECT_BYTES]):
        # A 200 that does not contain the file is the site's own error page.
        # Reporting it would be the single most likely false positive here.
        return _Probe(
            artefact,
            response.status_code,
            exposed=False,
            reason="HTTP 200 but the content is not this file",
        )

    return _Probe(
        artefact, response.status_code, exposed=True, reason="HTTP 200 and content confirmed"
    )


_SEVERITY_ORDER: Final = ("info", "low", "medium", "high", "critical")

CHECK: Final = Check(id=CHECK_ID, title=TITLE, run=run)
