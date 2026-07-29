"""Orchestration: concurrency, the scan deadline, and error containment.

Driven with stub checks rather than the real seven. The point of these tests is
the orchestrator's own behaviour under checks that hang, crash or misbehave,
and real network checks would make that neither reproducible nor fast.
"""

import asyncio

import pytest

from netgrade.checks.base import Check
from netgrade.context import ScanContext
from netgrade.domains import InvalidDomainError
from netgrade.models import CheckResult
from netgrade.orchestrator import scan
from tests.conftest import BARE_DOMAIN


@pytest.fixture
def ctx(dns_context) -> ScanContext:
    """A context with stubbed DNS.

    The stub checks below never touch it, but ``scan`` itself does: it confirms
    the domain exists before running anything. This fixture used to be a real
    ``ScanContext.open()``, which was true to its old docstring and became
    wrong when that check was added -- every test in this file then made a live
    lookup for example.com under a 4-second DNS budget. When the budget expired
    under load the orchestrator logged "scanning anyway" and carried on, adding
    four seconds to tests that assert a sub-second wall clock. That was the
    whole of the suite's intermittent failures.
    """
    return dns_context(BARE_DOMAIN)


def stub(check_id: str, *, status: str = "pass", delay: float = 0.0) -> Check:
    """A check that sleeps, then reports what it was told to report."""

    async def run(domain: str, ctx: ScanContext) -> CheckResult:
        if delay:
            await asyncio.sleep(delay)
        return CheckResult(
            id=check_id,
            title=check_id,
            status=status,
            severity="high" if status == "fail" else "info",
            summary="summary",
            explanation="explanation",
            fix="fix",
        )

    return Check(id=check_id, title=check_id, run=run)


def exploding(check_id: str, exc: Exception) -> Check:
    """A check with a defect in it."""

    async def run(domain: str, ctx: ScanContext) -> CheckResult:
        raise exc

    return Check(id=check_id, title=check_id, run=run)


def hanging(check_id: str) -> Check:
    """A check that never returns."""

    async def run(domain: str, ctx: ScanContext) -> CheckResult:
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    return Check(id=check_id, title=check_id, run=run)


class TestChecksRunConcurrently:
    async def test_wall_clock_is_the_slowest_check_not_the_sum(self, ctx: ScanContext) -> None:
        checks = [stub(f"c{i}", delay=0.2) for i in range(6)]

        loop = asyncio.get_running_loop()
        started = loop.time()
        await scan("example.com", ctx, checks=checks)
        elapsed = loop.time() - started

        assert elapsed < 0.6, f"six 0.2s checks took {elapsed:.2f}s; they ran sequentially"

    async def test_every_registered_check_appears_in_the_report(self, ctx: ScanContext) -> None:
        checks = [stub(f"c{i}") for i in range(5)]
        result = await scan("example.com", ctx, checks=checks)
        assert {c.id for c in result.checks} == {f"c{i}" for i in range(5)}

    async def test_each_check_is_timed(self, ctx: ScanContext) -> None:
        result = await scan("example.com", ctx, checks=[stub("slow", delay=0.05)])
        duration = result.checks[0].duration_ms
        assert duration is not None
        assert duration >= 50


class TestScanDeadline:
    async def test_a_hanging_check_does_not_hang_the_scan(self, ctx: ScanContext) -> None:
        loop = asyncio.get_running_loop()
        started = loop.time()
        await scan("example.com", ctx, checks=[hanging("stuck")], deadline=0.2)
        assert loop.time() - started < 1.0

    async def test_finished_work_survives_the_deadline(self, ctx: ScanContext) -> None:
        """Partial results beat no results: the fast checks must be kept."""
        checks = [stub("fast", status="fail"), hanging("stuck")]
        result = await scan("example.com", ctx, checks=checks, deadline=0.2)

        by_id = {c.id: c for c in result.checks}
        assert by_id["fast"].status == "fail"
        assert by_id["stuck"].status == "error"

    async def test_a_cancelled_check_says_why(self, ctx: ScanContext) -> None:
        result = await scan("example.com", ctx, checks=[hanging("stuck")], deadline=0.2)
        assert "ran out of time" in result.checks[0].summary

    async def test_a_cancelled_check_is_not_counted_against_the_grade(
        self, ctx: ScanContext
    ) -> None:
        checks = [stub("ok"), hanging("stuck")]
        result = await scan("example.com", ctx, checks=checks, deadline=0.2)
        assert result.checks_scored == 1


class TestOneDefectCostsOneFinding:
    """A broken check must not take down the other six or the whole scan."""

    @pytest.mark.parametrize(
        "exc",
        [ValueError("bad parse"), RuntimeError("boom"), KeyError("missing"), TypeError("wrong")],
    )
    async def test_a_raising_check_becomes_an_error_result(
        self, ctx: ScanContext, exc: Exception
    ) -> None:
        result = await scan("example.com", ctx, checks=[exploding("broken", exc)])
        assert result.checks[0].status == "error"

    async def test_its_neighbours_still_report(self, ctx: ScanContext) -> None:
        checks = [exploding("broken", RuntimeError("boom")), stub("healthy", status="fail")]
        result = await scan("example.com", ctx, checks=checks)

        by_id = {c.id: c for c in result.checks}
        assert by_id["broken"].status == "error"
        assert by_id["healthy"].status == "fail"

    async def test_the_scan_still_produces_a_grade(self, ctx: ScanContext) -> None:
        result = await scan("example.com", ctx, checks=[exploding("broken", RuntimeError())])
        assert result.grade in {"A", "B", "C", "D", "F"}


class TestReportAssembly:
    async def test_the_domain_is_normalised(self, ctx: ScanContext) -> None:
        result = await scan("HTTPS://Example.COM/pricing?a=1", ctx, checks=[stub("c")])
        assert result.domain == "example.com"

    async def test_invalid_input_raises_rather_than_reporting(self, ctx: ScanContext) -> None:
        """The one failure returned as an exception, not as data.

        A malformed request is a fault in the request, not a finding about a
        domain, so the API layer can answer 400 instead of rendering a report
        about nothing.
        """
        with pytest.raises(InvalidDomainError):
            await scan("not a domain at all", ctx, checks=[stub("c")])

    async def test_findings_come_back_in_remediation_order(self, ctx: ScanContext) -> None:
        checks = [stub("clean"), stub("broken", status="fail")]
        result = await scan("example.com", ctx, checks=checks)
        assert [c.id for c in result.checks] == ["broken", "clean"]

    async def test_the_timestamp_is_timezone_aware(self, ctx: ScanContext) -> None:
        result = await scan("example.com", ctx, checks=[stub("c")])
        assert result.scanned_at.tzinfo is not None
