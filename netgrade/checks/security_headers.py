"""Check 3 -- HTTP security headers.

Reads the four response headers that cost nothing to add and remove whole
classes of attack: HSTS, Content-Security-Policy, X-Frame-Options and
X-Content-Type-Options.

Headers are read from the *final* response after redirects. A site that
redirects http to https to www sets its real headers on the last hop, and
grading the first one would report almost every site as unprotected.
"""

import logging
from dataclasses import dataclass
from typing import Final

from netgrade.checks.base import Check, redirect_note
from netgrade.context import HttpResult, ScanContext
from netgrade.models import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID: Final = "security_headers"
TITLE: Final = "HTTP security headers"

#: Six months. Browsers only honour HSTS for as long as max-age says, so a
#: max-age of a few minutes provides almost none of the protection. The
#: preload list requires a year; six months is the point below which the
#: header is more decorative than useful.
_MIN_HSTS_MAX_AGE: Final = 15_768_000

#: How bad the absence of each header is. Content-Type sniffing is the least
#: damaging of the four on its own, so it is the only one rated low.
_ABSENCE_SEVERITY: Final[dict[str, Severity]] = {
    "strict-transport-security": "medium",
    "content-security-policy": "medium",
    "x-frame-options": "medium",
    "x-content-type-options": "low",
}

_FRIENDLY_NAMES: Final = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}

_SEVERITY_ORDER: Final = ("info", "low", "medium", "high", "critical")


@dataclass(frozen=True, slots=True)
class _Assessment:
    """Which headers are absent, and which are present but not doing much."""

    missing: tuple[str, ...] = ()
    weaknesses: tuple[str, ...] = ()


async def run(domain: str, ctx: ScanContext) -> CheckResult:
    """Inspect the security headers on the domain's homepage."""
    await ctx.assert_domain_exists(domain)

    response = await ctx.fetch(f"https://{domain}/")
    assessment = _assess_headers(response)
    status, severity, summary, fix = _verdict(assessment)

    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        severity=severity,
        summary=summary + redirect_note(domain, response.url),
        explanation=_explain(assessment),
        fix=fix,
        evidence={
            name: response.headers.get(name) for name in _ABSENCE_SEVERITY
        }
        | {
            "final_url": response.url,
            "status_code": response.status_code,
            "redirect_chain": list(response.redirect_chain),
            "hsts_max_age_seconds": _hsts_max_age(response),
            "hsts_includes_subdomains": "includesubdomains"
            in (response.headers.get("strict-transport-security") or "").lower(),
            "csp_report_only": response.headers.get("content-security-policy-report-only")
            is not None,
            "missing": list(assessment.missing),
            "weaknesses": list(assessment.weaknesses),
        },
    )


def _assess_headers(response: HttpResult) -> _Assessment:
    """Decide which headers are absent and which are present but weak."""
    missing: list[str] = []
    weaknesses: list[str] = []

    for name in _ABSENCE_SEVERITY:
        if response.headers.get(name) is None:
            missing.append(name)

    # A CSP frame-ancestors directive supersedes X-Frame-Options entirely, and
    # every current browser prefers it. Reporting XFO as missing when CSP
    # already covers framing would be telling the user to add a header that
    # would have no effect.
    csp = (response.headers.get("content-security-policy") or "").lower()
    if "frame-ancestors" in csp and "x-frame-options" in missing:
        missing.remove("x-frame-options")

    max_age = _hsts_max_age(response)
    if max_age is not None and max_age < _MIN_HSTS_MAX_AGE:
        weaknesses.append(f"HSTS max-age is only {max_age} seconds")

    if not csp and response.headers.get("content-security-policy-report-only"):
        weaknesses.append("Content-Security-Policy is in report-only mode and blocks nothing")

    if "unsafe-inline" in csp:
        weaknesses.append("the Content-Security-Policy allows unsafe-inline scripts")

    return _Assessment(missing=tuple(missing), weaknesses=tuple(weaknesses))


def _verdict(assessment: _Assessment) -> tuple[CheckStatus, Severity, str, str]:
    """Grade on how many headers are absent, and how bad each absence is."""
    missing = assessment.missing
    names = [_FRIENDLY_NAMES[name] for name in missing]

    if len(missing) >= 3:
        return (
            "fail",
            "high",
            f"{len(missing)} of the four security headers are missing.",
            f"Add {_join(names)} to your web server or CDN configuration. These are "
            "response headers, not code changes, and most hosting panels expose them "
            "directly.",
        )

    if missing:
        severity = max(
            (_ABSENCE_SEVERITY[name] for name in missing), key=_SEVERITY_ORDER.index
        )
        return (
            "fail" if severity == "medium" else "warn",
            severity,
            f"{_join(names)} {'is' if len(names) == 1 else 'are'} not set.",
            _fix_for(missing),
        )

    if assessment.weaknesses:
        return (
            "warn",
            "low",
            f"All four headers are present, but {assessment.weaknesses[0]}.",
            "Tighten the existing headers rather than adding new ones. "
            + _weakness_fix(assessment.weaknesses[0]),
        )

    return (
        "pass",
        "info",
        "All four security headers are set.",
        "No action needed. Re-check these after any change of hosting or CDN, since "
        "they are configuration rather than part of the site.",
    )


def _explain(assessment: _Assessment) -> str:
    """Explain the consequence of the most significant gap."""
    missing = set(assessment.missing)

    if "content-security-policy" in missing:
        return (
            "A Content-Security-Policy tells the browser which scripts it is allowed to "
            "run. Without one, a single injected script anywhere on the page runs with "
            "full access to what your visitors see and type."
        )
    if "strict-transport-security" in missing:
        return (
            "Without HSTS, a visitor who types your address without https can be silently "
            "kept on an unencrypted connection by anyone sharing their network, and never "
            "notice."
        )
    if "x-frame-options" in missing:
        return (
            "Another site can load yours inside an invisible frame and trick your visitors "
            "into clicking things they cannot see, using their existing login."
        )
    if "x-content-type-options" in missing:
        return (
            "Browsers may guess at the type of a file rather than trusting what you say it "
            "is, which can turn an uploaded file into a script that runs on your site."
        )
    if assessment.weaknesses:
        return (
            "The headers are present, so the structure is right. What remains is that one "
            "of them is configured loosely enough to weaken the protection it provides."
        )
    return (
        "These four headers instruct the visitor's browser to refuse a whole class of "
        "attacks. All four are set, which is a stronger position than most small business "
        "sites are in."
    )


def _fix_for(missing: tuple[str, ...]) -> str:
    """Name the specific header value to add."""
    suggestions = {
        "strict-transport-security": "Strict-Transport-Security: max-age=31536000; "
        "includeSubDomains",
        "content-security-policy": "a Content-Security-Policy, starting in report-only "
        "mode so you can see what it would block before it breaks anything",
        "x-frame-options": "X-Frame-Options: SAMEORIGIN",
        "x-content-type-options": "X-Content-Type-Options: nosniff",
    }
    return "Add " + _join([suggestions[name] for name in missing]) + "."


def _weakness_fix(weakness: str) -> str:
    """Turn a specific weakness into the specific remedy."""
    if "max-age" in weakness:
        return "Raise the HSTS max-age to 31536000, which is one year."
    if "report-only" in weakness:
        return (
            "Once the report-only policy stops flagging legitimate parts of your site, "
            "move it to the Content-Security-Policy header so it actually enforces."
        )
    if "unsafe-inline" in weakness:
        return (
            "Remove unsafe-inline by moving inline scripts into files, or by using a "
            "nonce. Until then the policy permits most of what it exists to prevent."
        )
    return "Review the header's value against current guidance."


def _hsts_max_age(response: HttpResult) -> int | None:
    """Read max-age out of the HSTS header, if it is set and parseable."""
    header = response.headers.get("strict-transport-security")
    if not header:
        return None

    for directive in header.split(";"):
        key, separator, value = directive.strip().partition("=")
        if separator and key.strip().lower() == "max-age":
            try:
                return int(value.strip().strip('"'))
            except ValueError:
                logger.info("unparseable HSTS max-age %r", value)
                return None
    return None


def _join(items: list[str]) -> str:
    """Join names the way a sentence needs them."""
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} and {items[-1]}"


CHECK: Final = Check(id=CHECK_ID, title=TITLE, run=run)
