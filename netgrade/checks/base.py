"""The uniform check interface, and the guarantee that a check never raises.

A check module answers one question about a domain and returns a CheckResult
saying what it found. It is allowed to fail -- DNS times out, hosts refuse
connections, public log services go down -- and when it does, that failure is
data, not an exception. ``execute`` is where that promise is kept, so no
individual check has to remember to keep it.
"""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

import httpx

from netgrade.context import BlockedAddressError, DomainNotFoundError, ScanContext
from netgrade.models import CheckResult

logger = logging.getLogger(__name__)

#: What every check module's ``run`` looks like.
CheckRunner = Callable[[str, ScanContext], Awaitable[CheckResult]]


@dataclass(frozen=True, slots=True)
class Check:
    """One registered check.

    Identity is held here rather than inside the check body so the orchestrator
    can name a check in an error result without having called it successfully.
    """

    id: str
    title: str
    run: CheckRunner

    #: Overrides the scan-wide budget for this check alone. Only cert_history
    #: uses it: it queries a third-party log aggregator whose latency has
    #: nothing to do with the domain being scanned, and holding it to the same
    #: budget as a local DNS lookup means reporting "could not check" for what
    #: is really just a slow but working service.
    timeout: float | None = None


async def execute(check: Check, domain: str, ctx: ScanContext) -> CheckResult:
    """Run one check under its time budget. Never raises.

    Any failure becomes a CheckResult with status "error", which the scoring
    engine excludes from the grade rather than counting as a failure. A host
    we could not reach has not earned an F.
    """
    started = time.perf_counter()
    budget = check.timeout or ctx.timeouts.check

    try:
        async with asyncio.timeout(budget):
            result = await check.run(domain, ctx)
    except TimeoutError:
        logger.warning("check %s timed out after %.1fs", check.id, budget)
        result = error_result(
            check,
            summary="Could not check: the domain took too long to respond.",
            detail=f"exceeded the {budget:.0f}s budget for this check",
        )
    except DomainNotFoundError as exc:
        logger.info("check %s: %s", check.id, exc)
        result = error_result(
            check,
            summary="Could not check: this domain does not exist.",
            detail=str(exc),
        )
    except BlockedAddressError as exc:
        logger.warning("check %s blocked: %s", check.id, exc)
        result = error_result(
            check,
            summary="Could not check: this domain does not point at a public address.",
            detail=str(exc),
        )
    except httpx.HTTPError as exc:
        # httpx timeout exceptions stringify to nothing at all, so the type
        # name has to carry the meaning or the log line says only "failure: ".
        detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
        logger.warning("check %s network failure: %s", check.id, detail)
        result = error_result(
            check,
            summary="Could not check: the site could not be reached.",
            detail=detail,
        )
    except Exception as exc:
        # Deliberately broad, and deliberately the last clause. A defect in one
        # check must not take down the other six or the whole scan. It is
        # logged with a traceback so it surfaces as a bug rather than being
        # quietly absorbed. asyncio.CancelledError derives from BaseException
        # and so passes through untouched, which is what lets shutdown work.
        logger.exception("check %s raised unexpectedly", check.id)
        result = error_result(
            check,
            summary="Could not check: something went wrong running this check.",
            detail=f"{type(exc).__name__}: {exc}",
        )

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    return result.model_copy(update={"duration_ms": elapsed_ms})


def redirect_note(domain: str, final_url: str) -> str:
    """A clause naming where a finding was actually measured, or nothing.

    Sites redirect across domains -- hogeschoolutrecht.nl serves from hu.nl --
    and following that is right, because it is what a visitor experiences. But
    a summary reading "example.com is missing four headers" when a different
    host was measured is not a claim we can stand behind, so the summary says
    which host answered.
    """
    measured = httpx.URL(final_url).host
    if not measured or measured == domain:
        return ""
    return f" Measured at {measured}, after a redirect."


def error_result(check: Check, *, summary: str, detail: str) -> CheckResult:
    """Build the result for a check that could not be completed.

    Severity is "info" because an unknown is not a risk statement. The user
    sees plain language; the technical cause goes in evidence, where it is
    available for debugging without being presented as a finding.
    """
    return CheckResult(
        id=check.id,
        title=check.title,
        status="error",
        severity="info",
        summary=summary,
        explanation=(
            "This check could not be completed, so nothing can be said about it "
            "either way. It is not counted towards the grade."
        ),
        fix="No action needed from you. Try scanning again in a few minutes.",
        evidence={"error": detail},
    )
