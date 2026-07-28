"""Shared per-scan resources and the outbound network policy.

Every check reaches the network through this object. That is deliberate: the
connection pool, the concurrency bound, the timeouts and the refusal to talk
to private address space are all decisions that have to hold across all seven
checks, and a check that could open its own socket could quietly opt out of
any of them.

Concurrency note. Bounding the seven checks of a single scan would be
theatre -- seven tasks is not a load problem. The bound that matters is the
one across concurrent users: fifty simultaneous scans would otherwise open
several hundred sockets. So the semaphore lives here, is shared by every scan
in the process, and is held only for the duration of an individual network
operation rather than for a whole check.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from types import TracebackType
from typing import Final, Self

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import httpx

from netgrade.domains import is_public_address

logger = logging.getLogger(__name__)

#: Read at most this much of any response body. Header and cookie checks need
#: none of it; the artefact check needs only enough to tell a real .env from a
#: styled 404 page. An unbounded read is a memory exhaustion vector when the
#: host on the other end is chosen by the caller.
MAX_BODY_BYTES: Final = 64 * 1024

#: Redirects are followed one hop at a time so each destination can be checked
#: before it is requested. Three is enough for the http -> https -> www chains
#: that real sites use.
MAX_REDIRECTS: Final = 3

_USER_AGENT: Final = "Netgrade/1.0 (+passive security posture scanner)"


class BlockedAddressError(RuntimeError):
    """A host resolved to an address the scanner will not send traffic to."""


class DomainNotFoundError(RuntimeError):
    """The domain does not exist in DNS.

    Distinct from a domain that exists but publishes nothing. "No DMARC record"
    is a finding; "there is no such domain" is not, and reporting the second as
    the first would hand an F to a typo.
    """


@dataclass(frozen=True, slots=True)
class Timeouts:
    """Time budgets, in seconds.

    ``check`` is the ceiling the orchestrator enforces per check. The others
    are lower so that a single slow operation fails inside the check and is
    reported precisely, rather than blowing the whole check's budget and
    reporting only that it timed out.
    """

    check: float = 10.0
    dns: float = 4.0
    connect: float = 5.0
    read: float = 6.0


@dataclass(frozen=True, slots=True)
class HttpResult:
    """A capped, framework-neutral view of one HTTP response.

    Checks receive this rather than an httpx object so that the transport can
    change without touching seven modules, and so a check cannot accidentally
    stream an unbounded body.
    """

    url: str
    status_code: int
    headers: httpx.Headers
    set_cookie: tuple[str, ...]
    body_prefix: bytes
    redirect_chain: tuple[str, ...] = ()


@dataclass(slots=True)
class ScanContext:
    """Resources shared by every check in a scan, and by every concurrent scan."""

    http: httpx.AsyncClient
    resolver: dns.asyncresolver.Resolver
    limiter: asyncio.Semaphore
    timeouts: Timeouts = field(default_factory=Timeouts)

    #: Memoised GETs, keyed by URL. security_headers and cookie_flags both
    #: need the homepage response. Sharing it here keeps the check modules
    #: independent of each other while still putting one request on the wire
    #: instead of two -- politeness toward a host that did not ask to be
    #: scanned, and a decision the modules do not have to know about.
    _responses: dict[str, HttpResult] = field(default_factory=dict)
    _address_cache: dict[str, bool] = field(default_factory=dict)
    _existence_cache: dict[str, bool] = field(default_factory=dict)

    @classmethod
    def open(cls, *, timeouts: Timeouts | None = None, max_concurrency: int = 24) -> Self:
        """Build a context with its own connection pool and resolver."""
        budget = timeouts or Timeouts()

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = budget.dns
        resolver.lifetime = budget.dns

        client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=budget.connect,
                read=budget.read,
                write=budget.read,
                pool=budget.read,
            ),
            limits=httpx.Limits(max_connections=max_concurrency, max_keepalive_connections=8),
            # Redirects are walked by hand in fetch() so each hop can be
            # vetted; letting httpx follow them would send the request first.
            follow_redirects=False,
            headers={"User-Agent": _USER_AGENT},
            # We are inspecting TLS, not trusting it. A certificate that fails
            # verification is a finding for the TLS check to report, not a
            # reason the header check cannot run.
            verify=False,  # noqa: S501 - see docstring; this client never sends credentials
        )
        return cls(
            http=client,
            resolver=resolver,
            limiter=asyncio.Semaphore(max_concurrency),
            timeouts=budget,
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
        await self.http.aclose()

    async def dns_query(self, name: str, rdtype: str) -> dns.resolver.Answer:
        """Resolve one record type, under the shared concurrency bound.

        Propagates dnspython's own exceptions -- NXDOMAIN, NoAnswer, Timeout.
        Distinguishing "no record exists" from "could not ask" is the whole
        job of several checks, so flattening them here would destroy the
        information they need.
        """
        async with self.limiter:
            return await self.resolver.resolve(name, rdtype)

    async def assert_domain_exists(self, domain: str) -> None:
        """Raise if the domain does not exist in DNS.

        Every check needs this precondition, and none of them can produce a
        meaningful finding without it: a domain that does not exist has no SPF
        record, no headers and no certificate, and reporting seven failures for
        a mistyped name would be actively misleading. Cached, so the
        orchestrator's single lookup serves all seven checks.

        NXDOMAIN is the only answer treated as non-existence. A domain that
        exists but publishes no address record answers NoAnswer, which is a
        perfectly ordinary configuration and not an error.
        """
        cached = self._existence_cache.get(domain)
        if cached is False:
            raise DomainNotFoundError(f"{domain} does not exist.")
        if cached:
            return

        try:
            await self.dns_query(domain, "A")
        except dns.resolver.NXDOMAIN:
            self._existence_cache[domain] = False
            raise DomainNotFoundError(f"{domain} does not exist.") from None
        except dns.resolver.NoAnswer:
            pass  # Exists, just has no address record of that type.

        self._existence_cache[domain] = True

    async def fetch(self, url: str, *, method: str = "GET") -> HttpResult:
        """Request a URL, following redirects one vetted hop at a time.

        Raises:
            BlockedAddressError: if any hop resolves outside public address space.
            httpx.HTTPError: on transport failure.
        """
        cache_key = f"{method} {url}"
        cached = self._responses.get(cache_key)
        if cached is not None:
            return cached

        chain: list[str] = []
        current = url

        for _ in range(MAX_REDIRECTS + 1):
            await self.assert_public_host(httpx.URL(current).host)

            async with self.limiter:
                request = self.http.build_request(method, current)
                response = await self.http.send(request, stream=True)
                try:
                    body = await _read_capped(response)
                finally:
                    await response.aclose()

            location = response.headers.get("location")
            if response.is_redirect and location:
                chain.append(current)
                current = str(response.url.join(location))
                continue

            result = HttpResult(
                url=current,
                status_code=response.status_code,
                headers=response.headers,
                set_cookie=tuple(response.headers.get_list("set-cookie")),
                body_prefix=body,
                redirect_chain=tuple(chain),
            )
            self._responses[cache_key] = result
            return result

        raise httpx.TooManyRedirects(f"more than {MAX_REDIRECTS} redirects", request=request)

    async def resolved_addresses(self, host: str) -> list[str]:
        """Every A and AAAA address for a host, ignoring record types absent."""
        addresses: list[str] = []
        for rdtype in ("A", "AAAA"):
            try:
                answer = await self.dns_query(host, rdtype)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                continue
            addresses.extend(record.address for record in answer)
        return addresses

    async def assert_public_host(self, host: str | None) -> None:
        """Refuse to send traffic to anything not publicly routable.

        The scanner fetches URLs derived from user input, which is the shape of
        a server-side request forgery primitive. Checking here means a domain
        whose A record points at 127.0.0.1 or at a cloud metadata endpoint is
        refused before a connection is opened.

        This is a pre-flight check and the name is resolved again by the
        connection itself, so a sufficiently fast DNS rebind can still slip
        between the two. Closing that needs pinning the connection to the
        vetted address; it is documented in the threat model rather than
        claimed to be solved.
        """
        if not host:
            raise BlockedAddressError("Request has no host to check.")

        cached = self._address_cache.get(host)
        if cached is False:
            raise BlockedAddressError(f"{host} resolves outside public address space.")
        if cached:
            return

        addresses = await self.resolved_addresses(host)
        allowed = bool(addresses) and all(is_public_address(address) for address in addresses)
        self._address_cache[host] = allowed

        if not allowed:
            logger.warning("refusing request to %s; resolved addresses %s", host, addresses)
            raise BlockedAddressError(f"{host} resolves outside public address space.")


async def _read_capped(response: httpx.Response) -> bytes:
    """Read at most MAX_BODY_BYTES of a streaming response."""
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        chunks.append(chunk)
        total += len(chunk)
        if total >= MAX_BODY_BYTES:
            break
    return b"".join(chunks)[:MAX_BODY_BYTES]
