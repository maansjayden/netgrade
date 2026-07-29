"""Running the seven checks and assembling a report.

The concurrency model in one paragraph. All seven checks start at once, because
they are independent and nearly all of their time is spent waiting on somebody
else's network. Each is bounded by its own time budget, enforced in
``checks.base.execute``. The scan as a whole is bounded again here, because a
per-check budget alone does not bound the total: a check may be slow without
having timed out, and a user waiting on a web page cares about the wall clock,
not about which check is responsible for it.

When the scan deadline fires, whatever has finished is kept and whatever has
not is cancelled and reported as "could not check". Partial results beat no
results, and they beat waiting.

Nothing here bounds how many sockets are open. That bound belongs across
concurrent scans rather than within one, so it lives on the shared semaphore in
ScanContext. Seven tasks is not a load problem; seventy simultaneous scans is.
"""

import asyncio
import logging
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final

from netgrade.checks.base import Check, error_result, execute
from netgrade.checks.registry import REGISTRY
from netgrade.context import ScanContext
from netgrade.domains import normalise_domain
from netgrade.models import CheckResult, ScanResult
from netgrade.scoring import prioritise, score_scan

logger = logging.getLogger(__name__)

#: Wall-clock ceiling for a whole scan, in seconds.
#:
#: Sized so it exceeds every per-check budget -- so a check normally reports its
#: own precise timeout message -- while still bounding the page load when a
#: dependency degrades rather than fails. certificate transparency is the case
#: that forces the issue: crt.sh answers in under a second when healthy and
#: hangs indefinitely when it is not, and neither the scanned domain nor the
#: user has anything to do with which of those is happening today.
SCAN_DEADLINE: Final = 20.0


async def scan(
    domain: str,
    ctx: ScanContext,
    *,
    checks: Sequence[Check] = REGISTRY,
    deadline: float = SCAN_DEADLINE,
) -> ScanResult:
    """Scan one domain and return a complete, scored report.

    Args:
        domain: Raw user input. Normalised here, not by the caller.
        ctx: Shared network resources. Not closed by this function.
        checks: Which checks to run. Injectable so tests can drive the
            orchestrator without seven real network checks behind it.
        deadline: Wall-clock ceiling for the whole scan.

    Returns:
        A ScanResult whose checks are ordered by remediation priority.

    Raises:
        InvalidDomainError: if the input is not a domain we will scan. This is
            the one failure that is not returned as data: it is a fault in the
            request rather than a finding about a domain, so the API layer can
            answer 400 instead of rendering a report about nothing.
    """
    normalised = normalise_domain(domain)
    started = time.perf_counter()

    results = await _run_all(normalised, ctx, checks=checks, deadline=deadline)
    ordered = prioritise(results)
    score = score_scan(ordered)

    elapsed = time.perf_counter() - started
    logger.info(
        "scanned %s in %.2fs: %s (%d), %d of %d checks completed%s",
        normalised,
        elapsed,
        score.grade,
        score.score,
        score.checks_scored,
        len(ordered),
        " [grade capped]" if score.grade_capped else "",
    )

    return ScanResult(
        domain=normalised,
        scanned_at=datetime.now(UTC),
        grade=score.grade,
        score=score.score,
        checks=ordered,
        checks_scored=score.checks_scored,
    )


async def _run_all(
    domain: str,
    ctx: ScanContext,
    *,
    checks: Sequence[Check],
    deadline: float,
) -> list[CheckResult]:
    """Run every check concurrently, under a shared wall-clock deadline.

    Results come back in registry order regardless of completion order, so a
    scan is reproducible and a test can index into it. Ordering for the reader
    is a separate concern and belongs to scoring.
    """
    tasks = {
        asyncio.create_task(execute(check, domain, ctx), name=f"check:{check.id}"): check
        for check in checks
    }

    done, pending = await asyncio.wait(tasks, timeout=deadline)

    for task in pending:
        task.cancel()
    if pending:
        # Let the cancellations actually land before the context is torn down,
        # so sockets close cleanly rather than surfacing as noise on shutdown.
        await asyncio.gather(*pending, return_exceptions=True)
        logger.warning(
            "scan of %s hit the %.0fs deadline; %d check(s) cancelled: %s",
            domain,
            deadline,
            len(pending),
            ", ".join(sorted(tasks[task].id for task in pending)),
        )

    return [_result_for(task, tasks[task], done) for task in tasks]


def _result_for(
    task: asyncio.Task[CheckResult],
    check: Check,
    done: set[asyncio.Task[CheckResult]],
) -> CheckResult:
    """Take one task's result, or explain why there isn't one.

    ``execute`` already guarantees it does not raise, so the exception branch
    here is not expected to fire. It exists because "not expected" is not
    "impossible", and one defect should cost one finding rather than the
    whole report.
    """
    if task not in done:
        return error_result(
            check,
            summary="Could not check: the scan ran out of time before this finished.",
            detail=f"cancelled at the {SCAN_DEADLINE:.0f}s scan deadline",
        )

    exception = task.exception()
    if exception is not None:
        logger.error("check %s escaped its own error handling", check.id, exc_info=exception)
        return error_result(
            check,
            summary="Could not check: something went wrong running this check.",
            detail=f"{type(exception).__name__}: {exception}",
        )

    return task.result()


async def scan_once(domain: str, *, deadline: float = SCAN_DEADLINE) -> ScanResult:
    """Scan a domain with a context of its own.

    For tests, scripts and the command line. The web application shares one
    context across requests instead, so that the connection pool and the
    concurrency bound are shared by every scan in the process.
    """
    async with ScanContext.open() as ctx:
        return await scan(domain, ctx, deadline=deadline)
