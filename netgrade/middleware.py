"""Rate limiting, applied to every route.

Middleware rather than a route dependency, because the HTML pages and the JSON
API are two front doors onto the same expensive work and a limit on one of them
is not a limit.
"""

import logging
from collections.abc import Awaitable, Callable
from typing import Final

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from netgrade.config import Settings
from netgrade.ratelimit import RateLimiter, TokenBucketRateLimiter

logger = logging.getLogger(__name__)

#: Paths that do no scanning and cost nothing to serve. The platform polls
#: /health every few seconds; rate limiting it would eventually mark a healthy
#: container as down.
_EXEMPT_PREFIXES: Final = ("/health", "/static", "/docs", "/openapi.json", "/favicon.ico")

#: Header the platform's edge proxy uses to report the original client.
_FORWARDED_FOR: Final = "x-forwarded-for"

#: Cloudflare's own record of the client it terminated the connection from.
#: Believed only when configured to; see Settings.trust_cloudflare.
_CF_CONNECTING_IP: Final = "cf-connecting-ip"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Spend a client's allowance per request, priced by outbound footprint."""

    def __init__(
        self,
        app: ASGIApp,
        limiter: RateLimiter | None = None,
        settings: Settings | None = None,
    ) -> None:
        super().__init__(app)
        self._settings = settings or Settings.from_env()
        self._limiter = limiter or TokenBucketRateLimiter(
            rate_per_minute=self._settings.rate_per_minute,
            burst=self._settings.rate_burst,
        )
        logger.info(
            "rate limit: %.0f/min, burst %d, comparison costs %d, client address from %s",
            self._settings.rate_per_minute,
            self._settings.rate_burst,
            self._settings.compare_cost,
            (
                f"{_CF_CONNECTING_IP}, falling back to "
                f"{self._settings.trusted_proxy_hops} proxy hop(s)"
                if self._settings.trust_cloudflare
                else f"{self._settings.trusted_proxy_hops} proxy hop(s)"
            ),
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path.startswith(_EXEMPT_PREFIXES):
            return await call_next(request)

        client = client_key(
            request,
            self._settings.trusted_proxy_hops,
            trust_cloudflare=self._settings.trust_cloudflare,
        )
        if self._settings.debug_client_key:
            logger.info(
                "client key %r from %s=%r peer=%s",
                client,
                _FORWARDED_FOR,
                request.headers.get(_FORWARDED_FOR),
                request.client.host if request.client else None,
            )

        decision = self._limiter.acquire(client, cost=self._cost_of(request))
        if decision.allowed:
            return await call_next(request)

        retry_after = max(1, round(decision.retry_after))
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(retry_after)},
            content={
                "detail": (
                    "Too many scans from this address. "
                    f"Try again in {retry_after} second{'s' if retry_after != 1 else ''}."
                )
            },
        )

    def _cost_of(self, request: Request) -> int:
        """How much allowance this request spends.

        Charged by outbound footprint rather than by request count. A
        comparison is a single HTTP call that runs two full scans against two
        unrelated third parties, so billing it as one request would under-count
        exactly the thing the limit exists to bound.

        The comparison page with nothing filled in is the empty form and scans
        nothing, so it is priced as an ordinary request. Charging the form the
        price of the work would rate limit someone for opening a page.
        """
        if not request.url.path.rstrip("/").endswith("/compare"):
            return 1

        params = request.query_params
        will_scan_two = bool(params.get("domain1")) and bool(params.get("domain2"))
        return self._settings.compare_cost if will_scan_two else 1


def client_key(
    request: Request,
    trusted_proxy_hops: int,
    *,
    trust_cloudflare: bool = False,
) -> str:
    """Identify the caller for rate limiting purposes.

    Two ways to learn the client address, in order of preference.

    Cloudflare's CF-Connecting-IP is a single value it sets itself after
    terminating the connection. It is preferred where available because it does
    not depend on counting: a hop count is silently wrong the moment a proxy is
    added or removed in front of the application, and being silently wrong is
    how a rate limiter becomes decorative without anyone noticing.

    Otherwise X-Forwarded-For, which is a list each proxy appends to with the
    address it received the request from. The rightmost entry is the peer our
    nearest proxy saw, the one before it is the peer that proxy's upstream saw,
    and so on leftwards. Everything to the left of the trusted hops is whatever
    the original caller chose to send.

    Neither header is trusted by default, and for the same reason. Reading the
    leftmost X-Forwarded-For entry -- the obvious choice, and what this did
    first -- hands a client that sets the header itself a fresh rate limit
    bucket on every request. Believing CF-Connecting-IP merely because it is
    present has that identical flaw on any deployment not behind Cloudflare.
    Neither failure is visible from outside: with one real source address a
    spoofable implementation and a correct one behave the same, so this has to
    be reasoned about rather than tested by hitting the URL a few times.

    Args:
        request: The incoming request.
        trusted_proxy_hops: How many proxies sit in front of this process.
            Zero ignores X-Forwarded-For entirely and uses the socket peer,
            which is correct when nothing is in front of us and the header is
            therefore pure user input.
        trust_cloudflare: Whether this process is only reachable through
            Cloudflare, and CF-Connecting-IP may be believed.
    """
    peer = request.client.host if request.client else "unknown"

    if trust_cloudflare:
        cloudflare_client = (request.headers.get(_CF_CONNECTING_IP) or "").strip()
        if cloudflare_client:
            return cloudflare_client
        # Configured for Cloudflare, but this request did not come through it.
        # Worth saying out loud: it means the origin is reachable directly, so
        # the assumption the setting rests on does not hold for every path in.
        logger.warning(
            "%s configured but absent; request did not arrive via Cloudflare",
            _CF_CONNECTING_IP,
        )

    if trusted_proxy_hops < 1:
        return peer

    forwarded = request.headers.get(_FORWARDED_FOR)
    if not forwarded:
        return peer

    entries = [entry.strip() for entry in forwarded.split(",") if entry.strip()]
    if len(entries) < trusted_proxy_hops:
        # Fewer entries than proxies means the chain is not what we were told
        # it is. The socket peer is the only address here we did not take on
        # trust, so fall back to it rather than guessing at an index.
        logger.warning(
            "expected at least %d %s entries, got %d; falling back to peer address",
            trusted_proxy_hops,
            _FORWARDED_FOR,
            len(entries),
        )
        return peer

    return entries[-trusted_proxy_hops]
