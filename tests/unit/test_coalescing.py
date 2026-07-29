"""Concurrent requests for one domain run one scan.

The cache only helps once a scan has finished. A burst of interest in a single
domain -- a shared link, a demo, several people at once -- misses the cache on
every request and hits the target host once per requester. These tests pin the
in-flight join that collapses that, and the awkward cases around it: the first
caller leaving, a forced re-scan arriving mid-flight, and a scan that fails.
"""

import asyncio
from datetime import UTC, datetime

import pytest

from netgrade.cache import TTLScanCache
from netgrade.context import DomainNotFoundError
from netgrade.models import ScanResult
from netgrade.service import ScanService


def a_result(domain: str) -> ScanResult:
    return ScanResult(
        domain=domain,
        scanned_at=datetime.now(UTC),
        grade="B",
        score=85,
        checks_scored=7,
    )


class RecordingService(ScanService):
    """A service whose scans are scripted rather than real.

    Subclassed at the seam where the orchestrator is called, so everything
    above it -- the cache lookup, the in-flight join, the cleanup -- is the
    real code under test.
    """

    def __init__(self, *, delay: float = 0.05, fails_with: Exception | None = None) -> None:
        super().__init__(ctx=None, cache=TTLScanCache())  # type: ignore[arg-type]
        self.scans: list[str] = []
        self._delay = delay
        self._fails_with = fails_with
        self.release = asyncio.Event()
        self.started = asyncio.Event()

    async def _scan_and_store(self, domain: str) -> ScanResult:
        self.scans.append(domain)
        self.started.set()
        await asyncio.sleep(self._delay)
        if self._fails_with is not None:
            raise self._fails_with
        result = a_result(domain)
        self._cache.set(domain, result)
        return result


class FailingDomainService(ScanService):
    """A service where "nope.com" does not exist and everything else is slow.

    Scripted at ``_scan_and_store`` rather than at ``scan``, so the cache
    lookup, the in-flight join and the cleanup are all the real code -- and so
    the failure arrives from inside the scan, which is where
    DomainNotFoundError is actually raised in production.
    """

    def __init__(self, *, delay: float = 0.2) -> None:
        super().__init__(ctx=None, cache=TTLScanCache())  # type: ignore[arg-type]
        self._delay = delay
        self.started: list[str] = []
        self.completed: list[str] = []
        self.cancelled: list[str] = []
        self.began = asyncio.Event()

    async def _scan_and_store(self, domain: str) -> ScanResult:
        if domain == "nope.com":
            raise DomainNotFoundError("nope.com does not exist.")

        self.started.append(domain)
        self.began.set()
        try:
            await asyncio.sleep(self._delay)
        except asyncio.CancelledError:
            self.cancelled.append(domain)
            raise
        self.completed.append(domain)
        result = a_result(domain)
        self._cache.set(domain, result)
        return result


class TestConcurrentRequestsShareOneScan:
    async def test_ten_callers_produce_one_scan(self) -> None:
        service = RecordingService()
        results = await asyncio.gather(*(service.scan("example.com") for _ in range(10)))

        assert len(service.scans) == 1
        assert len(results) == 10

    async def test_every_caller_gets_the_report(self) -> None:
        service = RecordingService()
        results = await asyncio.gather(*(service.scan("example.com") for _ in range(5)))

        assert all(r.domain == "example.com" for r in results)
        assert all(r.grade == "B" for r in results)

    async def test_different_domains_are_not_collapsed(self) -> None:
        service = RecordingService()
        await asyncio.gather(service.scan("one.com"), service.scan("two.com"))

        assert sorted(service.scans) == ["one.com", "two.com"]

    async def test_the_same_domain_written_differently_is_one_scan(self) -> None:
        """Normalisation happens before the in-flight lookup, not after."""
        service = RecordingService()
        await asyncio.gather(
            service.scan("Example.COM"),
            service.scan("https://example.com/pricing"),
            service.scan("example.com."),
        )

        assert service.scans == ["example.com"]

    async def test_callers_do_not_share_one_mutable_report(self) -> None:
        """The audio layer assigns onto whatever it is handed."""
        service = RecordingService()
        first, second = await asyncio.gather(
            service.scan("example.com"), service.scan("example.com")
        )

        first.audio_briefing_url = "/static/audio_cache/first.mp3"
        assert second.audio_briefing_url is None


class TestAfterTheScanFinishes:
    async def test_the_entry_is_released(self) -> None:
        service = RecordingService()
        await service.scan("example.com")
        assert service._inflight == {}

    async def test_a_later_request_is_served_from_cache(self) -> None:
        service = RecordingService()
        await service.scan("example.com")
        again = await service.scan("example.com")

        assert len(service.scans) == 1
        assert again.cached is True

    async def test_a_failed_scan_leaves_nothing_behind(self) -> None:
        """Otherwise one failure would wedge that domain until restart."""
        service = RecordingService(fails_with=DomainNotFoundError("example.com does not exist."))

        with pytest.raises(DomainNotFoundError):
            await service.scan("example.com")

        assert service._inflight == {}


class TestFailuresReachEveryCaller:
    async def test_all_joiners_see_the_same_exception(self) -> None:
        service = RecordingService(fails_with=DomainNotFoundError("nope"))
        results = await asyncio.gather(
            *(service.scan("example.com") for _ in range(4)), return_exceptions=True
        )

        assert len(service.scans) == 1
        assert all(isinstance(r, DomainNotFoundError) for r in results)


class TestTheFirstCallerLeaving:
    """Whoever asked first must not be able to take the scan down with them."""

    async def test_a_cancelled_initiator_does_not_cancel_the_scan(self) -> None:
        service = RecordingService(delay=0.2)

        initiator = asyncio.create_task(service.scan("example.com"))
        await service.started.wait()
        joiner = asyncio.create_task(service.scan("example.com"))
        await asyncio.sleep(0)

        initiator.cancel()
        result = await joiner

        assert result.domain == "example.com"
        assert len(service.scans) == 1

    async def test_the_result_still_reaches_the_cache(self) -> None:
        """A scan already paid for should warm the cache even if nobody waits."""
        service = RecordingService(delay=0.1)

        initiator = asyncio.create_task(service.scan("example.com"))
        await service.started.wait()
        initiator.cancel()
        with pytest.raises(asyncio.CancelledError):
            await initiator

        await asyncio.sleep(0.2)
        assert service._cache.get("example.com") is not None


class TestAFailedComparisonStopsItsSibling:
    """A typo in one box must not cost a stranger a scan they never asked for.

    compare used to gather both sides, and gather propagates the first error
    without touching its sibling -- so a 404 was returned while the other
    domain was still being scanned to completion, generating traffic to a third
    party for a response nobody would read.

    Cancelling the wrapper is not enough and these tests would pass if it were:
    _join shields the scan, so the scan survives its waiter. The cancellation
    has to reach the task itself.
    """

    async def test_the_sibling_scan_is_cancelled(self) -> None:
        service = FailingDomainService(delay=0.2)

        with pytest.raises(DomainNotFoundError):
            await service.compare("nope.com", "example.com")

        await asyncio.sleep(0.4)
        assert service.cancelled == ["example.com"]
        assert service.completed == [], "the sibling ran to completion anyway"

    async def test_a_scan_somebody_else_joined_is_left_alone(self) -> None:
        """The safety property. Another request is owed its report, and
        cancelling a shared scan would hand it a cancellation instead."""
        service = FailingDomainService(delay=0.2)

        joiner = asyncio.create_task(service.scan("example.com"))
        await service.began.wait()
        await asyncio.sleep(0)

        with pytest.raises(DomainNotFoundError):
            await service.compare("nope.com", "example.com")

        report = await joiner
        assert service.started == ["example.com"], "the joiner did not actually join"
        assert service.cancelled == []
        assert report.grade == "B"

    async def test_the_registry_is_clean_afterwards(self) -> None:
        service = FailingDomainService(delay=0.05)

        with pytest.raises(DomainNotFoundError):
            await service.compare("nope.com", "example.com")

        await asyncio.sleep(0.2)
        assert service._inflight == {}
        assert service._waiting == {}


class TestForcedRescan:
    async def test_force_does_not_join_an_in_flight_scan(self) -> None:
        """The point of forcing is to measure again, not to await a measurement
        that may have started before the user made their change."""
        service = RecordingService(delay=0.1)

        ordinary = asyncio.create_task(service.scan("example.com"))
        await service.started.wait()
        forced = asyncio.create_task(service.scan("example.com", force=True))

        await asyncio.gather(ordinary, forced)
        assert len(service.scans) == 2

    async def test_force_still_leaves_the_registry_clean(self) -> None:
        service = RecordingService(delay=0.05)

        ordinary = asyncio.create_task(service.scan("example.com"))
        await service.started.wait()
        forced = asyncio.create_task(service.scan("example.com", force=True))
        await asyncio.gather(ordinary, forced)

        assert service._inflight == {}
