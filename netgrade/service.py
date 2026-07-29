"""The application's entry point into the engine.

One object owning the things that must be shared across requests: the
connection pool, the DNS resolver, the outbound concurrency bound and the
result cache. Routes call this; they do not assemble scans themselves.

The separation earns its keep in two places. The HTML routes and the JSON API
are two front doors onto identical behaviour, and neither should be able to
drift into caching differently or bounding concurrency differently. And a
comparison is two scans that must not become two connection pools.
"""

import asyncio
import logging
from types import TracebackType
from typing import Final, Self

from netgrade.cache import ScanCache, TTLScanCache
from netgrade.context import ScanContext
from netgrade.domains import normalise_domain
from netgrade.models import ScanResult
from netgrade.orchestrator import scan

logger = logging.getLogger(__name__)

#: Outbound sockets allowed across every scan running in this process. Sized
#: for one small container: seven checks each opening a connection or two, with
#: room for a handful of concurrent users before anyone waits. The bound
#: belongs here rather than per-scan, because one scan is not a load problem
#: and fifty simultaneous ones are.
MAX_OUTBOUND_CONCURRENCY: Final = 24


class ScanService:
    """Scans domains, remembering recent answers."""

    def __init__(self, ctx: ScanContext, cache: ScanCache) -> None:
        self._ctx = ctx
        self._cache = cache

        #: Scans currently running, by domain. The cache only helps once a
        #: scan has finished, so without this a burst of interest in one
        #: domain -- a shared link, a demo, several people at once -- misses
        #: the cache every time and hits the target host once per request.
        #: Wasteful for us and inconsiderate to a server that did not ask to
        #: be scanned at all, which is the half that actually matters.
        self._inflight: dict[str, asyncio.Task[ScanResult]] = {}

        #: How many callers are currently waiting on each in-flight scan. Only
        #: consulted by ``compare``, which needs to distinguish a scan nobody is
        #: waiting for from one another request has joined -- cancelling the
        #: latter would hand that request a cancellation instead of a report.
        self._waiting: dict[str, int] = {}

    @classmethod
    def open(cls) -> Self:
        """Build a service with its own pool, resolver and cache."""
        return cls(
            ctx=ScanContext.open(max_concurrency=MAX_OUTBOUND_CONCURRENCY),
            cache=TTLScanCache(),
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Release the connection pool."""
        await self._ctx.aclose()

    async def scan(self, domain: str, *, force: bool = False) -> ScanResult:
        """Scan a domain, serving a recent result if there is one.

        Args:
            domain: Raw user input; normalised here.
            force: Skip and replace any cached result. This is what makes the
                fix-it-and-scan-again flow work -- without it the user would
                fix something, re-scan, and be shown the stale grade they were
                trying to change.

        Raises:
            InvalidDomainError: if the input is not a domain we will scan.
        """
        # Normalised before the cache is consulted, so "Example.COM/" and
        # "https://example.com" are one entry rather than three.
        normalised = normalise_domain(domain)

        if force:
            self._cache.invalidate(normalised)
        else:
            cached = self._cache.get(normalised)
            if cached is not None:
                return cached

            running = self._inflight.get(normalised)
            if running is not None:
                logger.info("joining the scan of %s already in progress", normalised)
                return await self._join(normalised, running)

        return await self._start(normalised)

    async def _start(self, domain: str) -> ScanResult:
        """Run a scan, letting concurrent callers for the same domain join it."""
        task = asyncio.create_task(self._scan_and_store(domain), name=f"scan:{domain}")
        self._inflight[domain] = task
        try:
            return await self._join(domain, task)
        finally:
            # Only if it is still ours. A forced re-scan starting meanwhile
            # replaces the entry, and removing that one would leave its own
            # joiners unable to find it.
            if self._inflight.get(domain) is task:
                del self._inflight[domain]

    async def _join(self, domain: str, task: asyncio.Task[ScanResult]) -> ScanResult:
        """Await a scan without being able to kill it.

        Shielded because a plain ``await`` on a task propagates cancellation
        into it: whoever asked first would take the scan down with them by
        closing the tab, and every caller waiting on the same one would get a
        cancellation instead of the report they asked for. Shielded, the scan
        finishes and populates the cache regardless of who is still listening,
        and it is bounded by the scan deadline rather than by the request.

        The copy matters for the same reason the cache returns one: callers
        mutate what they are given -- the audio layer assigns onto it -- and
        joiners would otherwise all hold the same object.

        The waiter count exists only so ``compare`` can tell the difference
        between a scan nobody is waiting for and one that somebody else joined.
        """
        self._waiting[domain] = self._waiting.get(domain, 0) + 1
        try:
            result = await asyncio.shield(task)
            return result.model_copy()
        finally:
            remaining = self._waiting[domain] - 1
            if remaining:
                self._waiting[domain] = remaining
            else:
                del self._waiting[domain]

    async def _scan_and_store(self, domain: str) -> ScanResult:
        """The scan itself, plus remembering it."""
        result = await scan(domain, self._ctx)
        self._cache.set(domain, result)
        return result

    async def compare(
        self,
        first: str,
        second: str,
        *,
        force: bool = False,
    ) -> tuple[ScanResult, ScanResult]:
        """Scan two domains at once.

        Concurrently, because a comparison that took twice as long as a scan
        would be a worse feature than one that takes about as long. They share
        this service's connection pool and concurrency bound, so running two
        does not mean opening two pools' worth of sockets.

        Raises:
            InvalidDomainError: if either input is not a domain we will scan.
                Raised before either scan starts, so a typo in the second box
                does not cost a scan of the first.
        """
        left, right = normalise_domain(first), normalise_domain(second)

        if left == right:
            # Comparing a domain against itself is a user error rather than a
            # request for two scans. Answering with one result twice is both
            # cheaper and more obviously what happened.
            logger.info("compare called with the same domain twice: %s", left)
            only = await self.scan(left, force=force)
            return only, only

        left_scan = asyncio.create_task(self.scan(left, force=force), name=f"compare:{left}")
        right_scan = asyncio.create_task(self.scan(right, force=force), name=f"compare:{right}")

        # FIRST_EXCEPTION rather than gather, so a typo in one box stops the
        # other scan instead of leaving it to run for a response nobody will
        # read. gather propagates the first error without touching its sibling.
        done, pending = await asyncio.wait(
            (left_scan, right_scan), return_when=asyncio.FIRST_EXCEPTION
        )
        for wrapper in pending:
            domain = left if wrapper is left_scan else right

            # The scan itself, not just our wait on it. _join shields the task
            # precisely so a departing caller cannot kill a scan others may be
            # joined to, which means cancelling the wrapper alone leaves the
            # scan running to completion -- measured, not assumed. Reached here
            # before the wrapper is cancelled, because _start's cleanup removes
            # the registry entry as it unwinds.
            #
            # Skipped when anyone else is waiting: a count above our own single
            # wait means another request joined this scan and is owed its
            # report. And skipped entirely for a caller who simply goes away --
            # a scan already paid for still warms the cache for whoever asks
            # next. This is narrower: the sibling of a comparison that has
            # already failed, whose result was never going to be read.
            running = self._inflight.get(domain)
            if running is not None and not running.done() and self._waiting.get(domain, 0) <= 1:
                logger.info("stopping the scan of %s: the comparison it belonged to failed", domain)
                running.cancel()

            wrapper.cancel()

        if pending:
            # Awaited so the cancellations have actually landed before we
            # return, rather than being finalised at some later point.
            await asyncio.wait(pending)

        for task in done:
            error = task.exception()
            if error is not None:
                # Re-raised as itself, not wrapped: the routes distinguish
                # InvalidDomainError and DomainNotFoundError to choose 400 or
                # 404, and a TaskGroup's ExceptionGroup would defeat both and
                # surface as a 500.
                raise error

        return left_scan.result(), right_scan.result()
