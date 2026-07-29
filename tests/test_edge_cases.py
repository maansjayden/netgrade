"""The whole engine, against domains that behave badly.

Unit tests cover each check's parsing in isolation. These run the real seven
checks through the real orchestrator against the conditions that actually
break scanners: names that do not resolve, hosts that refuse the connection,
services that never answer, and domains whose names are not ASCII.

The contract these pin is the one everything else rests on -- a scan always
returns a scored report, and nothing a remote host does turns into an
exception the API layer has to handle. A domain that cannot be reached is
data, not a failure.
"""

import asyncio
from typing import ClassVar, Final

import dns.resolver
import httpx
import pytest

from netgrade.checks.base import Check
from netgrade.checks.registry import REGISTRY
from netgrade.context import DomainNotFoundError, ScanContext, Timeouts
from netgrade.domains import InvalidDomainError
from netgrade.models import CHECK_IDS, ScanResult
from netgrade.orchestrator import scan
from netgrade.service import ScanService
from tests.conftest import PUBLIC_IP, DnsRecords, StubResolver

#: Short budgets, because one check cannot be stubbed at the transport layer.
#:
#: The TLS check opens a raw socket with asyncio.open_connection rather than
#: going through the HTTP client, which is right -- inspecting a handshake
#: means owning the handshake -- but it means the name is resolved by the
#: operating system rather than by the stub, and a fictional domain hangs
#: until something times out. Real network access from a test suite is worth
#: avoiding regardless of speed: it makes CI flaky in a way that looks like a
#: code failure. Bounding it here keeps the attempt to under a second while
#: still exercising the real check.
FAST: Final = Timeouts(check=1.5, dns=0.4, connect=0.4, read=0.4)


def context_with(
    records: DnsRecords,
    handler: object,
    *,
    timeouts: Timeouts | None = None,
) -> ScanContext:
    """A context with stubbed DNS and a scripted HTTP transport."""
    return ScanContext(
        http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),  # type: ignore[arg-type]
        resolver=StubResolver(records),  # type: ignore[arg-type]
        limiter=asyncio.Semaphore(8),
        timeouts=timeouts or FAST,
    )


@pytest.fixture(autouse=True)
def no_real_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub the one connection that does not go through the HTTP transport.

    The TLS check opens a raw socket, which is correct -- inspecting a
    handshake means owning the handshake -- but it means httpx.MockTransport
    does not intercept it, and the operating system resolves the name rather
    than the stub resolver. Left alone, every test in this file makes a real
    outbound connection to a domain that does not exist and waits for it to
    fail. That is slow, and worse, it makes the suite depend on the network in
    a way that surfaces as an unrelated-looking failure in CI.
    """

    async def refuse(*args: object, **kwargs: object) -> None:
        raise ConnectionRefusedError("refused by the test harness")

    monkeypatch.setattr(asyncio, "open_connection", refuse)


def refuse_connection(request: httpx.Request) -> httpx.Response:
    """A host that is listening for nobody."""
    raise httpx.ConnectError("connection refused", request=request)


def serve_empty_page(request: httpx.Request) -> httpx.Response:
    """A host that answers, with nothing of interest on it."""
    return httpx.Response(200, text="<html></html>")


def assert_is_a_usable_report(result: ScanResult) -> None:
    """Whatever went wrong, the frontend must receive a complete report."""
    assert isinstance(result, ScanResult)
    assert result.grade in {"A", "B", "C", "D", "F"}
    assert 0 <= result.score <= 100
    assert {check.id for check in result.checks} == set(CHECK_IDS)
    assert result.checks_scored == sum(1 for c in result.checks if c.status != "error")
    for check in result.checks:
        # Every finding is shown to a non-technical reader, including the ones
        # that report a failure to look.
        assert check.summary and check.explanation and check.fix


class TestDomainThatDoesNotExist:
    """A typo must not produce a report at all.

    Previously every check independently discovered the domain was absent and
    reported "could not check", which scored 100 out of 100 -- nothing found
    wrong, because nothing was looked at. The grade was capped to C, but a
    perfect score beside a domain name still reads as reassurance, and
    reassuring somebody about a domain that does not exist is the worst
    failure this tool has.
    """

    async def test_it_refuses_rather_than_reporting(self) -> None:
        ctx = context_with({}, refuse_connection)
        try:
            with pytest.raises(DomainNotFoundError):
                await scan("no-such-domain-here-9f3a2b.com", ctx)
        finally:
            await ctx.aclose()

    async def test_the_message_names_the_problem(self) -> None:
        ctx = context_with({}, refuse_connection)
        try:
            with pytest.raises(DomainNotFoundError) as caught:
                await scan("no-such-domain-here-9f3a2b.com", ctx)
        finally:
            await ctx.aclose()

        assert "does not exist" in str(caught.value)

    async def test_a_domain_with_no_address_record_still_scans(self) -> None:
        """Exists but publishes no A record. Ordinary, and not a typo.

        NXDOMAIN is the only answer treated as absence. A domain answering
        NoAnswer is a real domain with a real configuration worth reporting on.
        """
        records: DnsRecords = {"mail-only-domain.com": {"MX": ["10 mx.example.com."]}}
        ctx = context_with(records, refuse_connection)
        try:
            result = await scan("mail-only-domain.com", ctx)
        finally:
            await ctx.aclose()

        assert_is_a_usable_report(result)

    async def test_a_resolver_failure_is_not_treated_as_absence(self) -> None:
        """"Could not ask" is not "there is no such domain"."""

        class FailingResolver(StubResolver):
            async def resolve(self, *args: object, **kwargs: object):
                raise dns.resolver.NoNameservers()

        ctx = ScanContext(
            http=httpx.AsyncClient(transport=httpx.MockTransport(refuse_connection)),
            resolver=FailingResolver({}),  # type: ignore[arg-type]
            limiter=asyncio.Semaphore(8),
            timeouts=FAST,
        )
        try:
            result = await scan("dns-is-broken-today.com", ctx)
        finally:
            await ctx.aclose()

        assert_is_a_usable_report(result)


class TestHostThatRefusesConnections:
    """DNS resolves, nothing is listening. Common for a parked domain."""

    RECORDS: ClassVar[DnsRecords] = {
        "closed-host.com": {"A": [PUBLIC_IP]},
        "www.closed-host.com": {"A": [PUBLIC_IP]},
        "_dmarc.closed-host.com": {"TXT": ["v=DMARC1; p=reject"]},
    }

    async def test_it_still_returns_a_report(self) -> None:
        ctx = context_with(self.RECORDS, refuse_connection)
        try:
            result = await scan("closed-host.com", ctx)
        finally:
            await ctx.aclose()

        assert_is_a_usable_report(result)

    async def test_the_dns_side_still_produces_real_findings(self) -> None:
        """A dead web server does not stop us reading the domain's records.

        This is the case that justifies running the checks independently: the
        email and DNS answers are worth having even when the site is down.
        """
        ctx = context_with(self.RECORDS, refuse_connection)
        try:
            result = await scan("closed-host.com", ctx)
        finally:
            await ctx.aclose()

        by_id = {check.id: check for check in result.checks}
        assert by_id["email_spoofing"].status != "error"
        assert by_id["dns_hygiene"].status != "error"

    async def test_the_http_checks_report_that_they_could_not_look(self) -> None:
        ctx = context_with(self.RECORDS, refuse_connection)
        try:
            result = await scan("closed-host.com", ctx)
        finally:
            await ctx.aclose()

        by_id = {check.id: check for check in result.checks}
        assert by_id["security_headers"].status == "error"
        assert by_id["cookie_flags"].status == "error"

    async def test_a_refused_connection_is_never_scored_against_the_domain(self) -> None:
        ctx = context_with(self.RECORDS, refuse_connection)
        try:
            result = await scan("closed-host.com", ctx)
        finally:
            await ctx.aclose()

        errored = [check for check in result.checks if check.status == "error"]
        assert errored
        assert all(check.severity == "info" for check in errored)


class TestInternationalisedDomains:
    """Non-ASCII names, which are ordinary for European small businesses."""

    async def test_a_unicode_domain_is_scanned_as_its_ascii_form(self) -> None:
        records: DnsRecords = {"xn--bcher-kva.de": {"A": [PUBLIC_IP]}}
        ctx = context_with(records, refuse_connection)
        try:
            result = await scan("bücher.de", ctx)
        finally:
            await ctx.aclose()

        assert result.domain == "xn--bcher-kva.de"
        assert_is_a_usable_report(result)

    async def test_the_report_never_shows_the_unicode_form(self) -> None:
        """A homograph domain must not be able to display as the name it imitates.

        Rendering the Unicode form would let a Cyrillic lookalike appear in our
        own report as the brand it is impersonating.
        """
        records: DnsRecords = {"xn--pple-43d.com": {"A": [PUBLIC_IP]}}
        ctx = context_with(records, refuse_connection)
        try:
            result = await scan("аpple.com", ctx)  # noqa: RUF001 - Cyrillic a, deliberately
        finally:
            await ctx.aclose()

        assert result.domain.startswith("xn--")
        assert result.domain.isascii()

    async def test_an_already_encoded_domain_is_left_alone(self) -> None:
        records: DnsRecords = {"xn--bcher-kva.de": {"A": [PUBLIC_IP]}}
        ctx = context_with(records, refuse_connection)
        try:
            result = await scan("xn--bcher-kva.de", ctx)
        finally:
            await ctx.aclose()

        assert result.domain == "xn--bcher-kva.de"


class TestDomainWithNoMailRecords:
    """A website-only domain. Very common, and not a misconfiguration."""

    RECORDS: ClassVar[DnsRecords] = {
        "web-only-site.com": {"A": [PUBLIC_IP]},
        "www.web-only-site.com": {"A": [PUBLIC_IP]},
    }

    async def test_the_email_check_reports_rather_than_errors(self) -> None:
        """No MX is a finding about the domain, not a failure to look at it."""
        ctx = context_with(self.RECORDS, serve_empty_page)
        try:
            result = await scan("web-only-site.com", ctx)
        finally:
            await ctx.aclose()

        email = next(c for c in result.checks if c.id == "email_spoofing")
        assert email.status != "error"

    async def test_missing_spf_and_dmarc_are_still_reported(self) -> None:
        ctx = context_with(self.RECORDS, serve_empty_page)
        try:
            result = await scan("web-only-site.com", ctx)
        finally:
            await ctx.aclose()

        email = next(c for c in result.checks if c.id == "email_spoofing")
        assert email.status in {"fail", "warn"}
        assert email.evidence.get("dmarc_record") is None

    async def test_the_domain_is_still_graded(self) -> None:
        ctx = context_with(self.RECORDS, serve_empty_page)
        try:
            result = await scan("web-only-site.com", ctx)
        finally:
            await ctx.aclose()

        assert result.checks_scored > 0
        assert_is_a_usable_report(result)


class TestServicesThatNeverAnswer:
    """The failure mode that hangs a scanner rather than breaking it."""

    async def test_a_check_that_hangs_is_bounded_by_its_own_budget(self) -> None:
        async def never_answers(domain: str, ctx: ScanContext) -> None:
            await asyncio.Event().wait()

        stuck = Check(id="tls_config", title="TLS configuration", run=never_answers, timeout=0.1)
        ctx = context_with({"slow-host.com": {"A": [PUBLIC_IP]}}, refuse_connection)
        try:
            result = await scan("slow-host.com", ctx, checks=[stuck], deadline=5.0)
        finally:
            await ctx.aclose()

        assert result.checks[0].status == "error"
        assert "too long" in result.checks[0].summary

    async def test_the_whole_scan_is_bounded_even_when_a_check_is_not(self) -> None:
        """A per-check budget does not bound the total; the deadline does."""

        async def never_answers(domain: str, ctx: ScanContext) -> None:
            await asyncio.Event().wait()

        forever = Check(id="cert_history", title="Certificate history", run=never_answers)
        ctx = context_with({"slow-host.com": {"A": [PUBLIC_IP]}}, refuse_connection)

        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            result = await scan("slow-host.com", ctx, checks=[forever], deadline=0.3)
        finally:
            await ctx.aclose()

        assert loop.time() - started < 3.0
        assert result.checks[0].status == "error"

    async def test_a_slow_dns_answer_does_not_hang_the_scan(self) -> None:
        class SlowResolver(StubResolver):
            async def resolve(self, *args: object, **kwargs: object):
                await asyncio.sleep(30)
                raise dns.resolver.LifetimeTimeout(timeout=30.0, errors=[])

        ctx = ScanContext(
            http=httpx.AsyncClient(transport=httpx.MockTransport(refuse_connection)),
            resolver=SlowResolver({}),  # type: ignore[arg-type]
            limiter=asyncio.Semaphore(8),
            timeouts=Timeouts(check=0.2, dns=0.2),
        )

        loop = asyncio.get_running_loop()
        started = loop.time()
        try:
            result = await scan("slow-dns-host.com", ctx, deadline=1.0)
        finally:
            await ctx.aclose()

        # Bounded by the scan deadline rather than by the resolver. Most checks
        # are stopped by their own budget first; certificate history carries a
        # longer one of its own, so the deadline is what catches it. Both
        # bounds exist precisely because either alone leaves a gap.
        assert loop.time() - started < 3.0
        assert_is_a_usable_report(result)


class TestDnsFailuresThatAreNotNxdomain:
    """"Could not ask" and "there is no record" are different answers."""

    @pytest.mark.parametrize(
        "failure",
        [
            dns.resolver.Timeout(),
            dns.resolver.NoNameservers(),
            dns.resolver.LifetimeTimeout(timeout=4.0, errors=[]),
        ],
    )
    async def test_a_resolver_failure_is_reported_not_raised(
        self, failure: Exception
    ) -> None:
        class FailingResolver(StubResolver):
            async def resolve(self, *args: object, **kwargs: object):
                raise failure

        ctx = ScanContext(
            http=httpx.AsyncClient(transport=httpx.MockTransport(refuse_connection)),
            resolver=FailingResolver({}),  # type: ignore[arg-type]
            limiter=asyncio.Semaphore(8),
        )
        try:
            result = await scan("unreachable-dns-host.com", ctx)
        finally:
            await ctx.aclose()

        assert_is_a_usable_report(result)
        assert result.grade != "F"


class TestInputThatIsNotADomain:
    """The one failure returned as an exception rather than as data."""

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "   ",
            "not a domain",
            "no-dot",
            "http://",
            "https://:8080",
            "..",
            "-leading-hyphen.com",
            "a" * 300 + ".com",
            "192.168.1.1",
            "localhost",
        ],
    )
    async def test_it_raises_rather_than_reporting_seven_failures(self, value: str) -> None:
        """A fault in the request, not a finding about a domain.

        Returning a report of seven failures for a typo would be a claim about
        a domain we never looked at, and the API could not tell the difference
        between that and a real result.
        """
        ctx = context_with({}, refuse_connection)
        try:
            with pytest.raises(InvalidDomainError):
                await scan(value, ctx)
        finally:
            await ctx.aclose()

    async def test_the_message_is_written_for_the_person_who_typed_it(self) -> None:
        ctx = context_with({}, refuse_connection)
        try:
            with pytest.raises(InvalidDomainError) as caught:
                await scan("not a domain", ctx)
        finally:
            await ctx.aclose()

        message = str(caught.value)
        assert message and message[0].isupper()
        assert "Traceback" not in message


class TestPrivateAndInternalAddresses:
    """The scanner fetches URLs derived from user input, which is an SSRF shape."""

    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",  # loopback
            "10.0.0.5",  # RFC 1918
            "192.168.1.10",  # RFC 1918
            "172.16.0.1",  # RFC 1918
            "169.254.169.254",  # cloud metadata
        ],
    )
    async def test_a_domain_pointing_inward_is_refused(self, address: str) -> None:
        """Refused before a connection is opened, not after.

        Asserted on the host actually requested rather than on there being no
        requests at all: the certificate transparency check reads a public log
        service, which is a different host and entirely legitimate. What must
        never happen is a request to the domain that resolves inward.
        """
        records: DnsRecords = {"internal-pointing.com": {"A": [address]}}
        requested_hosts: list[str] = []

        def record_and_refuse(request: httpx.Request) -> httpx.Response:
            requested_hosts.append(request.url.host)
            raise httpx.ConnectError("connection refused", request=request)

        ctx = context_with(records, record_and_refuse)
        try:
            result = await scan("internal-pointing.com", ctx)
        finally:
            await ctx.aclose()

        assert "internal-pointing.com" not in requested_hosts, (
            f"a request was sent to a domain resolving to {address}"
        )
        assert_is_a_usable_report(result)

    async def test_the_user_is_told_why_without_being_shown_the_address(self) -> None:
        """The finding must not echo an internal address back to the caller."""
        records: DnsRecords = {"internal-pointing.com": {"A": ["169.254.169.254"]}}
        ctx = context_with(records, refuse_connection)
        try:
            result = await scan("internal-pointing.com", ctx)
        finally:
            await ctx.aclose()

        blocked = [c for c in result.checks if "public address" in c.summary]
        assert blocked
        assert all("169.254.169.254" not in check.summary for check in blocked)


class TestOneBrokenCheckDoesNotBreakTheScan:
    async def test_a_check_that_raises_costs_only_its_own_finding(self) -> None:
        async def explodes(domain: str, ctx: ScanContext) -> None:
            raise RuntimeError("a defect in this check")

        broken = Check(id="tls_config", title="TLS configuration", run=explodes)
        checks = [broken, *(c for c in REGISTRY if c.id != "tls_config")]

        records: DnsRecords = {
            "partly-broken-site.com": {"A": [PUBLIC_IP]},
            "_dmarc.partly-broken-site.com": {"TXT": ["v=DMARC1; p=reject"]},
        }
        ctx = context_with(records, serve_empty_page)
        try:
            result = await scan("partly-broken-site.com", ctx, checks=checks)
        finally:
            await ctx.aclose()

        by_id = {check.id: check for check in result.checks}
        assert by_id["tls_config"].status == "error"
        assert by_id["email_spoofing"].status != "error"
        assert_is_a_usable_report(result)


class TestTheServiceSurvivesAllOfIt:
    """The same guarantees through the layer the API actually calls."""

    async def test_a_partial_scan_is_still_worth_caching(self) -> None:
        """The domain resolves, so the DNS-based checks produce real findings.

        Refusing to cache anything with an errored check would throw away work
        that is genuinely useful -- the email and DNS answers are worth having
        even when the web server is down. Only a scan that learned nothing at
        all is withheld, and that rule is exercised in the cache's own tests.
        """
        records: DnsRecords = {"exists-but-dead.com": {"A": [PUBLIC_IP]}}
        ctx = context_with(records, refuse_connection)
        service = ScanService(ctx=ctx, cache=_CountingCache())
        try:
            first = await service.scan("exists-but-dead.com")
            second = await service.scan("exists-but-dead.com")
        finally:
            await service.aclose()

        assert first.checks_scored > 0
        assert first.cached is False
        assert second.cached is True

    async def test_comparing_two_broken_domains_still_returns_two_reports(self) -> None:
        records: DnsRecords = {
            "dead-one.com": {"A": [PUBLIC_IP]},
            "dead-two.com": {"A": [PUBLIC_IP]},
        }
        ctx = context_with(records, refuse_connection)
        service = ScanService(ctx=ctx, cache=_CountingCache())
        try:
            first, second = await service.compare("dead-one.com", "dead-two.com")
        finally:
            await service.aclose()

        assert_is_a_usable_report(first)
        assert_is_a_usable_report(second)
        assert first.domain != second.domain

    async def test_one_bad_domain_in_a_comparison_raises_before_either_scan(self) -> None:
        """A typo in the second box should not cost a scan of the first."""
        cache = _CountingCache()
        ctx = context_with({"good-domain.com": {"A": [PUBLIC_IP]}}, serve_empty_page)
        service = ScanService(ctx=ctx, cache=cache)
        try:
            with pytest.raises(InvalidDomainError):
                await service.compare("good-domain.com", "not a domain")
        finally:
            await service.aclose()

        assert cache.writes == 0


class _CountingCache:
    """A cache that records what it was asked to store."""

    def __init__(self) -> None:
        self.writes = 0
        self._entries: dict[str, ScanResult] = {}

    def get(self, domain: str) -> ScanResult | None:
        entry = self._entries.get(domain)
        return entry.model_copy(update={"cached": True}) if entry else None

    def set(self, domain: str, result: ScanResult) -> None:
        if result.checks_scored == 0:
            return
        self.writes += 1
        self._entries[domain] = result

    def invalidate(self, domain: str) -> None:
        self._entries.pop(domain, None)
