"""Per-domain result caching.

A scan costs several seconds and puts fifteen or so requests on somebody else's
infrastructure. Repeating that for every viewer of the same report is rude to
the scanned host and slow for the user, so results are held briefly.

The TTL is short on purpose. The product invites people to fix something and
scan again, so a cache that holds results for an hour would make the tool look
broken at exactly the moment it is meant to look useful. Five minutes absorbs
refreshes and link-sharing without hiding a real change; the ``force`` path
exists for the case where someone has just made one.

This implementation keeps everything in the process, which means each instance
has its own cache and a restart empties it. That is a deliberate limit rather
than an oversight: it is the right amount of machinery for one container, and
the ScanCache protocol is the seam a Redis implementation slots into when there
is more than one. The Scaling section of the README says so out loud.
"""

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Final, Protocol

from netgrade.models import ScanResult

logger = logging.getLogger(__name__)

#: How long a result stays fresh, in seconds.
DEFAULT_TTL: Final = 300.0

#: How many domains to remember. Cache keys come from user input, so an
#: unbounded dictionary is a memory exhaustion vector: anyone can mint new keys
#: forever by scanning made-up subdomains. The oldest entry is evicted at the
#: ceiling.
DEFAULT_MAX_ENTRIES: Final = 512


class ScanCache(Protocol):
    """What the application needs from a cache.

    Deliberately small. Anything wider -- pattern deletes, counters, pub/sub --
    would be a Redis interface wearing a protocol, and would make the in-process
    implementation the awkward one.
    """

    def get(self, domain: str) -> ScanResult | None:
        """Return a fresh result for this domain, or None."""
        ...

    def set(self, domain: str, result: ScanResult) -> None:
        """Store a result. Storing is best-effort and never raises."""
        ...


@dataclass(frozen=True, slots=True)
class _Entry:
    result: ScanResult
    expires_at: float


class TTLScanCache:
    """An in-process cache with a time-to-live and a bounded size.

    Not synchronised. Every method is straight-line synchronous code with no
    await in it, so on one event loop it cannot be interrupted partway through
    and a lock would protect nothing. A threaded server would need one, and
    that is a reason to reach for Redis rather than a mutex.
    """

    def __init__(
        self,
        *,
        ttl: float = DEFAULT_TTL,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ) -> None:
        self._ttl = ttl
        self._max_entries = max_entries
        self._entries: OrderedDict[str, _Entry] = OrderedDict()

    def get(self, domain: str) -> ScanResult | None:
        """Return a fresh result for this domain, marked as cached."""
        entry = self._entries.get(domain)
        if entry is None:
            return None

        if entry.expires_at <= _now():
            del self._entries[domain]
            logger.debug("cache expired for %s", domain)
            return None

        self._entries.move_to_end(domain)
        logger.info("cache hit for %s", domain)

        # A copy, so the stored result cannot be mutated by whoever receives
        # it -- main.py assigns audio_briefing_url onto the report it is given.
        return entry.result.model_copy(update={"cached": True})

    def set(self, domain: str, result: ScanResult) -> None:
        """Store a result, unless it says nothing worth remembering.

        A scan where every check errored is not a fact about the domain, it is
        a fact about a bad minute. Caching it would make a transient outage
        stick to a domain for the whole TTL, and the user who retries -- which
        is exactly what the report tells them to do -- would get the same
        failure back instantly without anything having been retried.
        """
        if result.checks_scored == 0:
            logger.info("not caching %s: no checks completed", domain)
            return

        self._entries[domain] = _Entry(result=result, expires_at=_now() + self._ttl)
        self._entries.move_to_end(domain)

        while len(self._entries) > self._max_entries:
            evicted, _ = self._entries.popitem(last=False)
            logger.debug("cache evicted %s at capacity", evicted)

    def invalidate(self, domain: str) -> None:
        """Drop any stored result for this domain.

        Used by the force-rescan path, so that a re-scan replaces the cached
        report rather than racing it.
        """
        self._entries.pop(domain, None)

    def clear(self) -> None:
        """Drop everything. For tests and for a manual flush."""
        self._entries.clear()

    def __len__(self) -> int:
        """How many entries are held, including any not yet reaped."""
        return len(self._entries)


def _now() -> float:
    """Monotonic seconds.

    Not wall-clock time: an NTP correction or a daylight-saving jump must not
    make cached entries immortal or expire them all at once.
    """
    return time.monotonic()
