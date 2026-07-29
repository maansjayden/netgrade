"""Runtime settings, read from the environment once at startup.

Everything here has a conservative default that is safe to publish. The
environment raises limits for a particular deployment; it is not required for
the application to run, and the documented default is what an unconfigured
instance does.

Kept deliberately small. This is not a settings framework -- it is the four
values that legitimately differ between a laptop, a demo host and whatever we
deploy on next.
"""

import logging
import os
from dataclasses import dataclass
from typing import Final, Self

logger = logging.getLogger(__name__)

#: Scans per minute per client, sustained.
ENV_RATE_PER_MINUTE: Final = "NETGRADE_RATE_PER_MINUTE"

#: How many may be spent at once before the sustained rate applies.
ENV_RATE_BURST: Final = "NETGRADE_RATE_BURST"

#: Allowance charged for a comparison, which runs two scans.
ENV_COMPARE_COST: Final = "NETGRADE_COMPARE_COST"

#: How many proxies sit in front of this process. See trusted_proxy_hops.
ENV_TRUSTED_PROXY_HOPS: Final = "NETGRADE_TRUSTED_PROXY_HOPS"

#: Whether Cloudflare is in front and its CF-Connecting-IP may be believed.
ENV_TRUST_CLOUDFLARE: Final = "NETGRADE_TRUST_CLOUDFLARE"

#: Log the client key each request resolves to. Off by default.
ENV_DEBUG_CLIENT_KEY: Final = "NETGRADE_DEBUG_CLIENT_KEY"


@dataclass(frozen=True, slots=True)
class Settings:
    """Values that differ between deployments."""

    rate_per_minute: float = 5.0
    rate_burst: int = 5
    compare_cost: int = 2

    #: Number of proxies between the internet and this process.
    #:
    #: This is the value the rate limiter's correctness rests on, so it is
    #: configuration rather than an assumption baked into the code.
    #:
    #: Each proxy appends the address it received the request from, so the
    #: rightmost entry in X-Forwarded-For is the peer the nearest proxy saw.
    #: With one trusted hop the real client is the last entry; with two it is
    #: the second from last. Everything to the left of that is caller-supplied
    #: and must never be trusted -- a client that sets the header itself would
    #: otherwise get a fresh rate limit bucket on every request.
    #:
    #: 1 is correct for Railway and Fly, which both terminate at a single edge
    #: proxy. 0 means the process is directly exposed, and the header is
    #: ignored entirely in favour of the socket's peer address.
    trusted_proxy_hops: int = 1

    #: Whether to believe Cloudflare's CF-Connecting-IP header.
    #:
    #: Cloudflare sets this itself after terminating the connection, so behind
    #: Cloudflare it is a single unambiguous value that does not depend on
    #: counting hops -- which matters because the hop count changes whenever a
    #: proxy is added or removed in front of us, silently and without failing.
    #:
    #: Opt-in rather than "believe it whenever it is present", because the
    #: header is an ordinary request header that any caller can set. Trusting
    #: it on a deployment that is not behind Cloudflare would reintroduce
    #: exactly the spoofable bucket-per-request hole that reading the leftmost
    #: X-Forwarded-For entry created.
    #:
    #: Enabling it asserts that this process is only reachable through
    #: Cloudflare. Where the origin is also directly reachable -- a Railway or
    #: Fly URL that still answers -- that assertion is not strictly true, and
    #: the residual risk is written up in the threat model rather than papered
    #: over here.
    trust_cloudflare: bool = False

    #: Whether to log the client key each request resolves to. For verifying
    #: that two different networks land in two different buckets. Off by
    #: default because client addresses are personal data and logging them
    #: continuously is not something to leave switched on by accident.
    debug_client_key: bool = False

    @classmethod
    def from_env(cls) -> Self:
        """Read settings, falling back to the published defaults."""
        defaults = cls()
        settings = cls(
            rate_per_minute=_float(ENV_RATE_PER_MINUTE, defaults.rate_per_minute),
            rate_burst=_int(ENV_RATE_BURST, defaults.rate_burst),
            compare_cost=_int(ENV_COMPARE_COST, defaults.compare_cost),
            trusted_proxy_hops=_int(ENV_TRUSTED_PROXY_HOPS, defaults.trusted_proxy_hops),
            trust_cloudflare=_bool(ENV_TRUST_CLOUDFLARE, defaults.trust_cloudflare),
            debug_client_key=_bool(ENV_DEBUG_CLIENT_KEY, defaults.debug_client_key),
        )

        if settings.compare_cost > settings.rate_burst:
            raise ValueError(
                f"{ENV_COMPARE_COST}={settings.compare_cost} exceeds "
                f"{ENV_RATE_BURST}={settings.rate_burst}; a comparison could never be served"
            )
        if settings.trusted_proxy_hops < 0:
            raise ValueError(f"{ENV_TRUSTED_PROXY_HOPS} cannot be negative")

        return settings


def _float(name: str, default: float) -> float:
    """Read a float, keeping the default if the value is unusable."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        logger.warning("ignoring %s=%r: not a number, using %s", name, raw, default)
        return default


def _int(name: str, default: int) -> int:
    """Read an integer, keeping the default if the value is unusable."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("ignoring %s=%r: not an integer, using %s", name, raw, default)
        return default


def _bool(name: str, default: bool) -> bool:
    """Read a boolean. Anything other than a recognised truthy value is false."""
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}
