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

        result = await scan(normalised, self._ctx)
        self._cache.set(normalised, result)
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

        return await asyncio.gather(
            self.scan(left, force=force),
            self.scan(right, force=force),
        )
