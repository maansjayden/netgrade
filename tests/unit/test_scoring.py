"""Scoring, weighting and remediation ordering.

These tests pin the rulings the scoring model was built around, so that a
later tweak to a weight cannot quietly change what the grade means.
"""

import json
from pathlib import Path

import pytest

from netgrade.checks.registry import REGISTRY
from netgrade.models import CheckResult, ScanResult
from netgrade.scoring import (
    CAPPED_GRADE,
    MIN_CHECKS_FOR_FULL_GRADE,
    penalty_for,
    prioritise,
    score_scan,
)

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "mock_scan.json"


def check(check_id: str, status: str, severity: str) -> CheckResult:
    """A minimal result; only id, status and severity affect scoring."""
    return CheckResult(
        id=check_id,
        title=check_id,
        status=status,
        severity=severity,
        summary="summary",
        explanation="explanation",
        fix="fix",
    )


def all_passing() -> list[CheckResult]:
    return [check(registered.id, "pass", "info") for registered in REGISTRY]


class TestErrorsAreNotFailures:
    """The central ruling: an unreachable host has not earned an F."""

    def test_errored_check_costs_nothing(self) -> None:
        assert penalty_for(check("email_spoofing", "error", "info")) == 0.0

    def test_errored_checks_are_excluded_from_the_count(self) -> None:
        checks = [
            check("email_spoofing", "pass", "info"),
            check("tls_config", "error", "info"),
        ]
        assert score_scan(checks).checks_scored == 1

    def test_a_wholly_unreachable_domain_does_not_score_zero(self) -> None:
        result = score_scan([check(r.id, "error", "info") for r in REGISTRY])
        assert result.score == 100
        assert result.checks_scored == 0

    def test_an_error_costs_less_than_the_failure_it_might_have_been(self) -> None:
        errored = score_scan([check("email_spoofing", "error", "info")])
        failed = score_scan([check("email_spoofing", "fail", "high")])
        assert errored.score > failed.score


class TestSeverityDrivesWeight:
    """Severity describes the finding, and the finding's cost follows from it."""

    def test_a_clean_domain_scores_full_marks(self) -> None:
        assert score_scan(all_passing()).score == 100

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [("critical", 40.0), ("high", 25.0), ("medium", 12.0), ("low", 5.0), ("info", 0.0)],
    )
    def test_failure_cost_rises_with_severity(self, severity: str, expected: float) -> None:
        assert penalty_for(check("email_spoofing", "fail", severity)) == expected

    def test_a_warning_costs_half_of_a_failure(self) -> None:
        failed = penalty_for(check("email_spoofing", "fail", "high"))
        warned = penalty_for(check("email_spoofing", "warn", "high"))
        assert warned == failed / 2

    def test_a_pass_costs_nothing_regardless_of_severity(self) -> None:
        assert penalty_for(check("email_spoofing", "pass", "critical")) == 0.0

    def test_same_severity_costs_the_same_across_ordinary_checks(self) -> None:
        assert penalty_for(check("tls_config", "fail", "high")) == penalty_for(
            check("cookie_flags", "fail", "high")
        )


class TestCertificateHistoryIsDiscounted:
    """The one deviation from severity-only weighting, and the reason for it."""

    def test_it_costs_less_than_an_equivalent_finding_elsewhere(self) -> None:
        assert penalty_for(check("cert_history", "fail", "high")) == pytest.approx(10.0)
        assert penalty_for(check("email_spoofing", "fail", "high")) == pytest.approx(25.0)

    def test_it_cannot_single_handedly_drop_a_clean_domain_below_an_A(self) -> None:
        checks = [check("cert_history", "fail", "high")] + [
            check(r.id, "pass", "info") for r in REGISTRY if r.id != "cert_history"
        ]
        assert score_scan(checks).grade == "A"


class TestGradeBoundaries:
    @pytest.mark.parametrize(
        ("penalty_severity", "expected_grade"),
        [("info", "A"), ("low", "A"), ("medium", "B"), ("high", "C"), ("critical", "D")],
    )
    def test_single_failure_grades(self, penalty_severity: str, expected_grade: str) -> None:
        checks = [check("email_spoofing", "fail", penalty_severity)] + [
            check(r.id, "pass", "info") for r in REGISTRY[1:]
        ]
        assert score_scan(checks).grade == expected_grade

    def test_score_is_clamped_to_zero(self) -> None:
        checks = [check(r.id, "fail", "critical") for r in REGISTRY]
        assert score_scan(checks).score == 0
        assert score_scan(checks).grade == "F"


class TestThinEvidenceIsCapped:
    """A high grade built on two checks is a claim the tool should not make."""

    def test_grade_is_capped_when_too_few_checks_complete(self) -> None:
        completed = [check(r.id, "pass", "info") for r in REGISTRY[: MIN_CHECKS_FOR_FULL_GRADE - 1]]
        errored = [check(r.id, "error", "info") for r in REGISTRY[MIN_CHECKS_FOR_FULL_GRADE - 1 :]]
        result = score_scan(completed + errored)

        assert result.score == 100
        assert result.grade == CAPPED_GRADE
        assert result.grade_capped is True

    def test_grade_is_not_capped_at_the_threshold(self) -> None:
        completed = [check(r.id, "pass", "info") for r in REGISTRY[:MIN_CHECKS_FOR_FULL_GRADE]]
        errored = [check(r.id, "error", "info") for r in REGISTRY[MIN_CHECKS_FOR_FULL_GRADE:]]
        result = score_scan(completed + errored)

        assert result.grade == "A"
        assert result.grade_capped is False

    def test_the_cap_never_improves_a_bad_grade(self) -> None:
        """The cap is a ceiling, not a floor.

        One critical failure on the only check that completed scores 60, which
        is a D. The cap floor is C, so it must leave the D alone rather than
        lifting a bad result up to meet it.
        """
        checks = [check("email_spoofing", "fail", "critical")] + [
            check(r.id, "error", "info") for r in REGISTRY[1:]
        ]
        result = score_scan(checks)

        assert result.grade == "D"
        assert result.grade_capped is False


class TestRemediationOrder:
    def test_worst_first(self) -> None:
        checks = [
            check("tls_config", "pass", "info"),
            check("cert_history", "error", "info"),
            check("security_headers", "warn", "medium"),
            check("email_spoofing", "fail", "high"),
        ]
        assert [c.id for c in prioritise(checks)] == [
            "email_spoofing",
            "security_headers",
            "cert_history",
            "tls_config",
        ]

    def test_unknowns_outrank_confirmed_passes(self) -> None:
        ordered = prioritise([check("tls_config", "pass", "info"), check("a", "error", "info")])
        assert [c.status for c in ordered] == ["error", "pass"]

    def test_severity_breaks_ties_within_a_status(self) -> None:
        ordered = prioritise(
            [
                check("a", "fail", "low"),
                check("b", "fail", "critical"),
                check("c", "fail", "medium"),
            ]
        )
        assert [c.severity for c in ordered] == ["critical", "medium", "low"]

    def test_ordering_is_stable_for_identical_findings(self) -> None:
        checks = [check("b", "fail", "high"), check("a", "fail", "high")]
        assert [c.id for c in prioritise(checks)] == ["a", "b"]

    def test_no_findings_are_dropped(self) -> None:
        checks = all_passing()
        assert len(prioritise(checks)) == len(checks)


class TestFixtureMatchesTheEngine:
    """The mock is the integration fixture and what the frontend builds on.

    If its declared grade drifts from what the scoring engine would produce,
    the frontend is being built against a number the engine never emits.
    """

    def test_declared_score_and_grade_are_what_scoring_produces(self) -> None:
        fixture = ScanResult.model_validate(json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))
        result = score_scan(fixture.checks)

        assert (result.score, result.grade) == (fixture.score, fixture.grade)
        assert result.checks_scored == fixture.checks_scored

    def test_fixture_is_already_in_remediation_order(self) -> None:
        fixture = ScanResult.model_validate(json.loads(FIXTURE_PATH.read_text(encoding="utf-8")))
        assert [c.id for c in prioritise(fixture.checks)] == [c.id for c in fixture.checks]
