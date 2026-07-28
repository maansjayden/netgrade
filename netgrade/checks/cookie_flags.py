"""Check 4 -- cookie security flags.

Reads the Set-Cookie headers the homepage returns and reports whether each
cookie carries Secure, HttpOnly and SameSite.

Scope worth being honest about: this sees only the cookies a site sets for an
anonymous visitor on its front page. The session cookie issued after login is
usually the one that matters most, and reaching it would mean authenticating,
which this tool does not do. The report says so rather than implying the
absence of a finding is the absence of a problem.
"""

import logging
from dataclasses import dataclass
from typing import Final

from netgrade.checks.base import Check
from netgrade.context import ScanContext
from netgrade.models import CheckResult, CheckStatus, Severity

logger = logging.getLogger(__name__)

CHECK_ID: Final = "cookie_flags"
TITLE: Final = "Cookie security flags"

#: Substrings that suggest a cookie carries a login session. A cookie that
#: identifies a logged-in user is worth more to an attacker than one holding
#: a language preference, so the same missing flag is graded differently.
_SESSION_HINTS: Final = ("sess", "sid", "auth", "token", "login", "user", "jwt", "csrf")

#: SameSite=None is only meaningful alongside Secure, and browsers reject the
#: combination without it.
_VALID_SAMESITE: Final = ("strict", "lax", "none")


@dataclass(frozen=True, slots=True)
class _Cookie:
    """One Set-Cookie header, parsed into the attributes that matter."""

    name: str
    secure: bool
    httponly: bool
    samesite: str | None

    @property
    def session_like(self) -> bool:
        """Whether the name suggests this identifies a logged-in user."""
        lowered = self.name.lower()
        return any(hint in lowered for hint in _SESSION_HINTS)

    @property
    def problems(self) -> tuple[str, ...]:
        """Which protections this cookie is missing."""
        missing: list[str] = []
        if not self.secure:
            missing.append("Secure")
        if not self.httponly:
            missing.append("HttpOnly")
        if self.samesite is None:
            missing.append("SameSite")
        return tuple(missing)


async def run(domain: str, ctx: ScanContext) -> CheckResult:
    """Inspect the cookies set on the domain's homepage."""
    await ctx.assert_domain_exists(domain)

    response = await ctx.fetch(f"https://{domain}/")
    cookies = tuple(_parse_cookie(header) for header in response.set_cookie)
    status, severity, summary, fix = _assess(cookies)

    return CheckResult(
        id=CHECK_ID,
        title=TITLE,
        status=status,
        severity=severity,
        summary=summary,
        explanation=_explain(cookies),
        fix=fix,
        evidence={
            "cookies_examined": len(cookies),
            "findings": [
                {
                    "name": cookie.name,
                    "secure": cookie.secure,
                    "httponly": cookie.httponly,
                    "samesite": cookie.samesite,
                    "session_like": cookie.session_like,
                }
                for cookie in cookies
            ],
            "final_url": response.url,
            "scope": "cookies set for an anonymous visitor on the homepage",
        },
    )


def _assess(cookies: tuple[_Cookie, ...]) -> tuple[CheckStatus, Severity, str, str]:
    """Grade on the weakest cookie, weighted by whether it looks like a session."""
    if not cookies:
        return (
            "pass",
            "info",
            "The homepage sets no cookies.",
            "No action needed. If cookies are set elsewhere on the site, or after login, "
            "check those separately.",
        )

    insecure = [cookie for cookie in cookies if not cookie.secure]
    exposed = [cookie for cookie in cookies if not cookie.httponly]
    session_exposed = [cookie for cookie in exposed if cookie.session_like]
    cross_site = [cookie for cookie in cookies if cookie.samesite is None]

    if session_exposed:
        names = _join([cookie.name for cookie in session_exposed])
        return (
            "fail",
            "high",
            f"The session cookie {names} can be read by scripts on the page.",
            f"Set HttpOnly on {names}. In most frameworks this is one configuration "
            "setting rather than a code change.",
        )

    if insecure:
        names = _join([cookie.name for cookie in insecure])
        return (
            "fail",
            "medium",
            f"{names} {'is' if len(insecure) == 1 else 'are'} sent without the Secure flag.",
            f"Add Secure to {names} so the browser only ever sends it over HTTPS.",
        )

    if exposed:
        names = _join([cookie.name for cookie in exposed])
        return (
            "warn",
            "medium",
            f"{names} can be read by scripts running on the page.",
            f"Add HttpOnly to {names} unless your own JavaScript genuinely needs to read "
            "it, which is unusual.",
        )

    if cross_site:
        names = _join([cookie.name for cookie in cross_site])
        return (
            "warn",
            "low",
            f"{names} {'has' if len(cross_site) == 1 else 'have'} no SameSite setting.",
            f"Add SameSite=Lax to {names}. Browsers increasingly default to this, so "
            "setting it explicitly also protects you from that default changing.",
        )

    return (
        "pass",
        "info",
        f"All {len(cookies)} cookie{'s' if len(cookies) > 1 else ''} carry Secure, "
        "HttpOnly and SameSite.",
        "No action needed. Check any cookies set after login separately, since those are "
        "not visible to an anonymous scan.",
    )


def _explain(cookies: tuple[_Cookie, ...]) -> str:
    """Explain the consequence in terms of what an attacker gains."""
    if not cookies:
        return (
            "No cookies were set for an anonymous visitor on the homepage, so there is "
            "nothing here to protect. This does not cover cookies issued after someone "
            "logs in, which a scan without an account cannot see."
        )

    if any(not cookie.httponly and cookie.session_like for cookie in cookies):
        return (
            "Without HttpOnly, any script running on the page can read the session cookie. "
            "That turns a single cross-site scripting bug anywhere on the site into a full "
            "account takeover, because the attacker can copy the session rather than "
            "needing the password."
        )
    if any(not cookie.secure for cookie in cookies):
        return (
            "A cookie without the Secure flag is sent over unencrypted connections too, so "
            "anyone sharing a network with your visitor can read it in transit."
        )
    if any(not cookie.httponly for cookie in cookies):
        return (
            "Scripts on the page can read these cookies. That matters less for a "
            "preference than for a session, but it is still more access than most cookies "
            "need to be given."
        )
    if any(cookie.samesite is None for cookie in cookies):
        return (
            "Without SameSite, the browser attaches these cookies to requests started by "
            "other websites, which is what lets a malicious page act on a visitor's behalf "
            "while they are logged in to yours."
        )
    return (
        "The cookies set on the homepage all carry the three protections that keep them "
        "out of reach of scripts, unencrypted connections and other websites."
    )


def _parse_cookie(header: str) -> _Cookie:
    """Parse one Set-Cookie header value.

    Parsed by hand rather than with http.cookies, whose parser silently drops
    cookies it dislikes and normalises away the distinction between an absent
    attribute and an empty one -- which is the entire finding here.
    """
    name, _, remainder = header.partition("=")
    attributes = [part.strip().lower() for part in remainder.split(";")[1:]]

    samesite: str | None = None
    for attribute in attributes:
        key, separator, value = attribute.partition("=")
        if key == "samesite" and separator and value in _VALID_SAMESITE:
            samesite = value.capitalize() if value != "none" else "None"

    return _Cookie(
        name=name.strip() or "(unnamed)",
        secure="secure" in attributes,
        httponly="httponly" in attributes,
        samesite=samesite,
    )


def _join(items: list[str]) -> str:
    """Join cookie names the way a sentence needs them."""
    if len(items) == 1:
        return items[0]
    return f"{', '.join(items[:-1])} and {items[-1]}"


CHECK: Final = Check(id=CHECK_ID, title=TITLE, run=run)
