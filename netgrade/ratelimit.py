"""Request rate limiting.

A scan is expensive and most of that expense lands on somebody else: each one
makes roughly fifteen outbound requests to a host chosen by whoever typed the
domain. Unlimited, this tool is a traffic amplifier pointed wherever a stranger
likes, and the fact that every individual request is passive and read-only does
not make ten thousand of them reasonable. The limit protects the hosts we scan
at least as much as it protects us.

A token bucket rather than a fixed window, because a fixed window lets someone
spend a whole minute's budget in its last second and the next minute's in its
first. Buckets refill continuously, so the sustained rate holds at every offset
while still allowing a small burst -- which is what a person opening a few tabs
actually looks like.

Like the cache, this is per-process state behind a protocol. Two instances mean
two independent limits, which is a real limitation and is written up in the
Scaling section rather than glossed over.
"""

import logging
import time
from dataclasses import dataclass
from typing import Final, Protocol

logger = logging.getLogger(__name__)

#: Sustained allowance, in scans per minute per client.
DEFAULT_RATE_PER_MINUTE: Final = 5.0

#: How many scans may be spent at once before the sustained rate applies.
DEFAULT_BURST: Final = 5

#: How many clients to track. Client keys derive from a request header, so an
#: unbounded dictionary is a memory exhaustion vector. At the ceiling the least
#: recently seen bucket is dropped, which at worst hands a long-idle client a
#: fresh allowance -- the failure mode is leniency, not lockout.
DEFAULT_MAX_CLIENTS: Final = 4096


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of one rate limit check."""

    allowed: bool

    #: Seconds until the next token. Zero when allowed. Surfaced as the
    #: Retry-After header so a caller is told when to come back rather than
    #: being left to guess.
    retry_after: float = 0.0


class RateLimiter(Protocol):
    """What the application needs from a limiter."""

    def acquire(self, client: str) -> Decision:
        """Spend one unit of allowance for this client, if there is any."""
        ...


@dataclass(slots=True)
class _Bucket:
    tokens: float
    updated_at: float


class TokenBucketRateLimiter:
    """An in-process token bucket per client.

    Unsynchronised for the same reason as the cache: no await inside any
    method, so on one event loop each call runs to completion uninterrupted.
    """

    def __init__(
        self,
        *,
        rate_per_minute: float = DEFAULT_RATE_PER_MINUTE,
        burst: int = DEFAULT_BURST,
        max_clients: int = DEFAULT_MAX_CLIENTS,
    ) -> None:
        if rate_per_minute <= 0:
            raise ValueError("rate_per_minute must be positive")
        if burst < 1:
            raise ValueError("burst must be at least 1")

        self._refill_per_second = rate_per_minute / 60.0
        self._capacity = float(burst)
        self._max_clients = max_clients
        self._buckets: dict[str, _Bucket] = {}

    def acquire(self, client: str) -> Decision:
        """Spend one token, or say how long until one exists."""
        now = _now()
        bucket = self._buckets.get(client)

        if bucket is None:
            self._evict_if_full()
            bucket = _Bucket(tokens=self._capacity, updated_at=now)
            self._buckets[client] = bucket
        else:
            elapsed = now - bucket.updated_at
            bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._refill_per_second)
            bucket.updated_at = now

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return Decision(allowed=True)

        retry_after = (1.0 - bucket.tokens) / self._refill_per_second
        logger.info("rate limited %s; %.1fs until next scan", client, retry_after)
        return Decision(allowed=False, retry_after=retry_after)

    def reset(self, client: str) -> None:
        """Forget one client's bucket. For tests and manual intervention."""
        self._buckets.pop(client, None)

    def clear(self) -> None:
        """Forget every bucket."""
        self._buckets.clear()

    def _evict_if_full(self) -> None:
        """Make room by dropping the least recently used bucket.

        Full LRU bookkeeping is not worth it here: eviction is rare, the
        dictionary is small, and a linear scan at the ceiling is cheaper than
        maintaining ordering on every request.
        """
        if len(self._buckets) < self._max_clients:
            return

        stalest = min(self._buckets, key=lambda key: self._buckets[key].updated_at)
        del self._buckets[stalest]
        logger.debug("rate limiter evicted %s at capacity", stalest)

    def __len__(self) -> int:
        """How many clients are currently tracked."""
        return len(self._buckets)


def _now() -> float:
    """Monotonic seconds; see cache._now for why not wall-clock time."""
    return time.monotonic()
