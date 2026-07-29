"""Per-domain TTL caching."""

from datetime import datetime, timezone

UTC = getattr(datetime, "UTC", timezone.utc)

import pytest

from netgrade.cache import DEFAULT_TTL, ScanCache, TTLScanCache
from netgrade.models import CheckResult, ScanResult


def result(domain: str = "example.com", *, checks_scored: int = 7) -> ScanResult:
    return ScanResult(
        domain=domain,
        scanned_at=datetime.now(UTC),
        grade="B",
        score=85,
        checks_scored=checks_scored,
        checks=[
            CheckResult(
                id="tls_config",
                title="TLS configuration",
                status="pass",
                severity="info",
                summary="summary",
                explanation="explanation",
                fix="fix",
            )
        ],
    )


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """A hand-cranked monotonic clock, so TTL tests do not sleep."""
    now = [1000.0]
    monkeypatch.setattr("netgrade.cache._now", lambda: now[0])
    return now


def test_it_satisfies_the_cache_protocol() -> None:
    """The seam a Redis implementation slots into.

    The annotation is the assertion: mypy rejects this if TTLScanCache ever
    stops matching ScanCache, so the claim that the backend is swappable is
    checked rather than just written in the README.
    """
    cache: ScanCache = TTLScanCache()
    assert cache.get("example.com") is None


class TestStoreAndRetrieve:
    def test_a_miss_returns_nothing(self) -> None:
        assert TTLScanCache().get("example.com") is None

    def test_a_stored_result_comes_back(self) -> None:
        cache = TTLScanCache()
        cache.set("example.com", result())
        assert cache.get("example.com") is not None

    def test_domains_do_not_share_entries(self) -> None:
        cache = TTLScanCache()
        cache.set("example.com", result("example.com"))
        assert cache.get("other.com") is None

    def test_a_hit_is_marked_as_cached(self) -> None:
        """So the report can say it is showing a stored result."""
        cache = TTLScanCache()
        cache.set("example.com", result())
        hit = cache.get("example.com")

        assert hit is not None
        assert hit.cached is True

    def test_the_stored_copy_stays_unmarked(self) -> None:
        """Callers mutate what they are given; the cache must not be aliased."""
        cache = TTLScanCache()
        stored = result()
        cache.set("example.com", stored)

        first = cache.get("example.com")
        assert first is not None
        first.audio_briefing_url = "/static/audio_cache/leaked.mp3"

        second = cache.get("example.com")
        assert second is not None
        assert second.audio_briefing_url is None
        assert stored.cached is False


class TestExpiry:
    def test_entries_survive_until_the_ttl(self, clock: list[float]) -> None:
        cache = TTLScanCache(ttl=DEFAULT_TTL)
        cache.set("example.com", result())

        clock[0] += DEFAULT_TTL - 1
        assert cache.get("example.com") is not None

    def test_entries_expire_after_the_ttl(self, clock: list[float]) -> None:
        cache = TTLScanCache(ttl=DEFAULT_TTL)
        cache.set("example.com", result())

        clock[0] += DEFAULT_TTL + 1
        assert cache.get("example.com") is None

    def test_an_expired_entry_is_dropped_not_just_hidden(self, clock: list[float]) -> None:
        cache = TTLScanCache(ttl=10)
        cache.set("example.com", result())

        clock[0] += 11
        cache.get("example.com")
        assert len(cache) == 0

    def test_storing_again_refreshes_the_deadline(self, clock: list[float]) -> None:
        cache = TTLScanCache(ttl=10)
        cache.set("example.com", result())

        clock[0] += 9
        cache.set("example.com", result())
        clock[0] += 9
        assert cache.get("example.com") is not None


class TestWhatIsNotWorthCaching:
    def test_a_scan_that_learned_nothing_is_not_stored(self) -> None:
        """A transient outage must not stick to a domain for the whole TTL."""
        cache = TTLScanCache()
        cache.set("example.com", result(checks_scored=0))
        assert cache.get("example.com") is None

    def test_a_partial_scan_is_still_stored(self) -> None:
        cache = TTLScanCache()
        cache.set("example.com", result(checks_scored=1))
        assert cache.get("example.com") is not None


class TestBoundedSize:
    def test_it_does_not_grow_past_its_ceiling(self) -> None:
        """Keys come from user input, so unbounded growth is a DoS vector."""
        cache = TTLScanCache(max_entries=10)
        for index in range(50):
            cache.set(f"domain{index}.com", result(f"domain{index}.com"))
        assert len(cache) == 10

    def test_the_oldest_entry_goes_first(self) -> None:
        cache = TTLScanCache(max_entries=2)
        cache.set("first.com", result("first.com"))
        cache.set("second.com", result("second.com"))
        cache.set("third.com", result("third.com"))

        assert cache.get("first.com") is None
        assert cache.get("third.com") is not None

    def test_reading_an_entry_keeps_it_alive(self) -> None:
        cache = TTLScanCache(max_entries=2)
        cache.set("first.com", result("first.com"))
        cache.set("second.com", result("second.com"))

        cache.get("first.com")
        cache.set("third.com", result("third.com"))

        assert cache.get("first.com") is not None
        assert cache.get("second.com") is None


class TestInvalidation:
    def test_invalidate_drops_the_entry(self) -> None:
        cache = TTLScanCache()
        cache.set("example.com", result())
        cache.invalidate("example.com")
        assert cache.get("example.com") is None

    def test_invalidating_an_absent_domain_is_harmless(self) -> None:
        TTLScanCache().invalidate("never-seen.com")

    def test_clear_empties_everything(self) -> None:
        cache = TTLScanCache()
        cache.set("a.com", result("a.com"))
        cache.set("b.com", result("b.com"))
        cache.clear()
        assert len(cache) == 0
