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

from netgrade.ratelimit import RateLimiter, TokenBucketRateLimiter

logger = logging.getLogger(__name__)

#: Paths that do no scanning and cost nothing to serve. The platform polls
#: /health every few seconds; rate limiting it would eventually mark a healthy
#: container as down.
_EXEMPT_PREFIXES: Final = ("/health", "/static", "/docs", "/openapi.json", "/favicon.ico")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Spend one unit of a client's allowance per request."""

    def __init__(self, app: ASGIApp, limiter: RateLimiter | None = None) -> None:
        super().__init__(app)
        self._limiter = limiter or TokenBucketRateLimiter()

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if request.url.path.startswith(_EXEMPT_PREFIXES):
            return await call_next(request)

        decision = self._limiter.acquire(client_key(request), cost=_cost_of(request.url.path))
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


def _cost_of(path: str) -> int:
    """How much allowance a request to this path spends.

    Charged by outbound footprint rather than by request count. A comparison is
    a single HTTP call that runs two full scans against two unrelated third
    parties, so billing it as one request would under-count exactly the thing
    the limit exists to bound.
    """
    return 2 if path.rstrip("/").endswith("/compare") else 1


def client_key(request: Request) -> str:
    """Identify the caller for rate limiting purposes.

    X-Forwarded-For is trusted only because this application is reachable
    solely through the platform's proxy, which overwrites it. Exposed directly,
    the header is caller-controlled and anyone could mint a fresh allowance per
    request by varying it -- so this is a deployment assumption the limit rests
    on, not a property of the header. It is stated in the threat model.

    The leftmost entry is the originating client; the rest are proxies.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host if request.client else "unknown"
