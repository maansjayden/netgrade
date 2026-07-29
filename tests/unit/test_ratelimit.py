"""Token bucket rate limiting."""

import pytest

from netgrade.ratelimit import RateLimiter, TokenBucketRateLimiter


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """A hand-cranked monotonic clock, so refill tests do not sleep."""
    now = [1000.0]
    monkeypatch.setattr("netgrade.ratelimit._now", lambda: now[0])
    return now


def test_it_satisfies_the_limiter_protocol() -> None:
    """The seam a Redis implementation slots into; see test_cache for why."""
    limiter: RateLimiter = TokenBucketRateLimiter()
    assert limiter.acquire("client").allowed is True


class TestBurst:
    def test_a_new_client_starts_with_a_full_bucket(self) -> None:
        limiter = TokenBucketRateLimiter(burst=5)
        assert all(limiter.acquire("client").allowed for _ in range(5))

    def test_the_request_after_the_burst_is_refused(self) -> None:
        limiter = TokenBucketRateLimiter(burst=3)
        for _ in range(3):
            limiter.acquire("client")
        assert limiter.acquire("client").allowed is False

    def test_clients_have_separate_allowances(self) -> None:
        limiter = TokenBucketRateLimiter(burst=1)
        assert limiter.acquire("first").allowed is True
        assert limiter.acquire("second").allowed is True
        assert limiter.acquire("first").allowed is False


class TestRefill:
    def test_allowance_returns_over_time(self, clock: list[float]) -> None:
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=1)
        assert limiter.acquire("client").allowed is True
        assert limiter.acquire("client").allowed is False

        clock[0] += 1.0
        assert limiter.acquire("client").allowed is True

    def test_refill_is_continuous_not_stepped(self, clock: list[float]) -> None:
        """The reason for a bucket rather than a fixed window.

        A window would let a client spend a whole period's budget at its end
        and the next period's at its start. Here the sustained rate holds at
        every offset.
        """
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=1)
        limiter.acquire("client")

        clock[0] += 0.5
        assert limiter.acquire("client").allowed is False
        clock[0] += 0.5
        assert limiter.acquire("client").allowed is True

    def test_the_bucket_does_not_fill_past_its_burst(self, clock: list[float]) -> None:
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=2)
        clock[0] += 3600
        assert limiter.acquire("client").allowed is True
        assert limiter.acquire("client").allowed is True
        assert limiter.acquire("client").allowed is False


class TestRetryAfter:
    def test_an_allowed_request_needs_no_wait(self) -> None:
        assert TokenBucketRateLimiter().acquire("client").retry_after == 0.0

    def test_a_refusal_says_when_to_come_back(self, clock: list[float]) -> None:
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=1)
        limiter.acquire("client")

        decision = limiter.acquire("client")
        assert decision.allowed is False
        assert decision.retry_after == pytest.approx(1.0, abs=0.01)

    def test_the_wait_shrinks_as_the_bucket_refills(self, clock: list[float]) -> None:
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=1)
        limiter.acquire("client")

        first = limiter.acquire("client").retry_after
        clock[0] += 0.5
        assert limiter.acquire("client").retry_after < first


class TestBoundedMemory:
    def test_tracked_clients_do_not_grow_without_limit(self) -> None:
        """Client keys come from a request header an attacker controls."""
        limiter = TokenBucketRateLimiter(max_clients=10)
        for index in range(100):
            limiter.acquire(f"client{index}")
        assert len(limiter) <= 10

    def test_the_stalest_client_is_evicted(self, clock: list[float]) -> None:
        limiter = TokenBucketRateLimiter(max_clients=2, burst=1)
        limiter.acquire("old")
        clock[0] += 10
        limiter.acquire("recent")
        clock[0] += 10
        limiter.acquire("newcomer")

        # "old" was evicted, so it is treated as unseen and gets a fresh bucket.
        assert len(limiter) == 2
        assert limiter.acquire("old").allowed is True

    def test_eviction_is_lenient_rather_than_locking_out(self, clock: list[float]) -> None:
        """The failure mode under pressure must not be refusing real users."""
        limiter = TokenBucketRateLimiter(max_clients=1, burst=1)
        limiter.acquire("victim")
        limiter.acquire("attacker")
        assert limiter.acquire("victim").allowed is True


class TestCost:
    """Allowance is charged by outbound footprint, not by request count."""

    def test_a_costly_request_spends_more_of_the_bucket(self) -> None:
        limiter = TokenBucketRateLimiter(burst=4)
        assert limiter.acquire("client", cost=2).allowed is True
        assert limiter.acquire("client", cost=2).allowed is True
        assert limiter.acquire("client").allowed is False

    def test_a_costly_request_is_refused_when_the_bucket_is_low(self) -> None:
        limiter = TokenBucketRateLimiter(burst=3)
        limiter.acquire("client", cost=2)
        assert limiter.acquire("client", cost=2).allowed is False
        assert limiter.acquire("client").allowed is True

    def test_the_wait_covers_the_whole_cost(self, clock: list[float]) -> None:
        limiter = TokenBucketRateLimiter(rate_per_minute=60, burst=2)
        limiter.acquire("client", cost=2)

        decision = limiter.acquire("client", cost=2)
        assert decision.retry_after == pytest.approx(2.0, abs=0.01)

    def test_a_cost_beyond_the_burst_is_rejected_as_a_bug(self) -> None:
        """Never satisfiable, so it is a misconfiguration rather than a refusal."""
        with pytest.raises(ValueError, match="exceeds the burst capacity"):
            TokenBucketRateLimiter(burst=1).acquire("client", cost=2)

    def test_a_nonpositive_cost_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="cost must be at least 1"):
            TokenBucketRateLimiter().acquire("client", cost=0)


class TestConfiguration:
    @pytest.mark.parametrize("rate", [0, -1])
    def test_a_nonpositive_rate_is_rejected(self, rate: float) -> None:
        with pytest.raises(ValueError, match="rate_per_minute"):
            TokenBucketRateLimiter(rate_per_minute=rate)

    def test_a_burst_below_one_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="burst"):
            TokenBucketRateLimiter(burst=0)

    def test_reset_restores_a_client(self) -> None:
        limiter = TokenBucketRateLimiter(burst=1)
        limiter.acquire("client")
        limiter.reset("client")
        assert limiter.acquire("client").allowed is True
