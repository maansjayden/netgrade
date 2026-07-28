"""Turning findings into a grade, and into an order worth reading.

This is the eighth item in the project scope. It produces no CheckResult of its
own; it decides what the other seven add up to.

The model is subtraction, not a ratio: a domain starts at 100 and loses points
for what was found, weighted by how bad the finding is. That is one sentence to
explain, and it means the grade moves in the direction a user expects when they
fix something -- which is the entire point of letting them re-scan.
"""

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Final

from netgrade.models import CheckResult, CheckStatus, Grade, Severity

logger = logging.getLogger(__name__)

#: What a finding costs at full weight, by how serious it is. Severity is set
#: by the check from what it actually found, so "no DMARC at all" and "DMARC at
#: p=none" are different severities from the same check and cost differently.
SEVERITY_POINTS: Final[dict[Severity, float]] = {
    "critical": 40.0,
    "high": 25.0,
    "medium": 12.0,
    "low": 5.0,
    "info": 0.0,
}

#: How much of that cost a given outcome incurs. A warning is half a failure:
#: it marks a real weakness that is not yet an open door.
#:
#: "error" is absent deliberately. A check that could not run is excluded from
#: scoring entirely rather than being given a factor of 0.0, because those are
#: different claims -- 0.0 would say "we looked and found nothing wrong".
STATUS_FACTOR: Final[dict[CheckStatus, float]] = {
    "fail": 1.0,
    "warn": 0.5,
    "pass": 0.0,
}

#: Per-check adjustment. Everything is full weight except certificate history,
#: which is discounted because it reports what has happened rather than a live
#: misconfiguration the owner can act on today, and because it depends on a
#: third-party public log service whose availability is not the domain's fault.
CHECK_MULTIPLIER: Final[dict[str, float]] = {
    "cert_history": 0.4,
}

#: Score at or above which each grade is awarded.
GRADE_THRESHOLDS: Final[tuple[tuple[int, Grade], ...]] = (
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
)

#: Below this many completed checks, the grade is capped (see Score.grade).
MIN_CHECKS_FOR_FULL_GRADE: Final = 4

#: The best grade a scan with poor coverage may be awarded.
CAPPED_GRADE: Final[Grade] = "C"

#: Report order: unresolved problems first, then things we could not determine,
#: then what is already fine. Errors sit above passes because an unknown is
#: worth a user's attention in a way a confirmed pass is not.
_STATUS_ORDER: Final[dict[CheckStatus, int]] = {"fail": 0, "warn": 1, "error": 2, "pass": 3}

_SEVERITY_ORDER: Final[dict[Severity, int]] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


@dataclass(frozen=True, slots=True)
class Score:
    """The outcome of scoring one scan."""

    score: int
    grade: Grade
    checks_scored: int

    #: True when the grade was held down because too little could be measured.
    #: Lets the report explain a grade that the score alone does not account
    #: for, instead of looking like an arithmetic bug.
    grade_capped: bool


def penalty_for(check: CheckResult) -> float:
    """Points a single finding costs. Zero for anything that did not run."""
    factor = STATUS_FACTOR.get(check.status)
    if factor is None:  # status == "error"
        return 0.0
    multiplier = CHECK_MULTIPLIER.get(check.id, 1.0)
    return SEVERITY_POINTS[check.severity] * factor * multiplier


def score_scan(checks: Sequence[CheckResult]) -> Score:
    """Score a completed scan.

    Checks with status "error" are excluded from the score entirely. An
    unreachable host has not earned an F, and a DNS timeout is not evidence of
    a misconfiguration. The cost of that honesty is that a scan which measured
    almost nothing would otherwise report a high grade on thin evidence, so
    below MIN_CHECKS_FOR_FULL_GRADE completed checks the grade is capped.
    """
    scored = [check for check in checks if check.status != "error"]
    total_penalty = sum(penalty_for(check) for check in scored)
    score = max(0, min(100, round(100 - total_penalty)))

    grade = _grade_for(score)
    capped = len(scored) < MIN_CHECKS_FOR_FULL_GRADE and _is_better_than(grade, CAPPED_GRADE)
    if capped:
        logger.info(
            "grade capped from %s to %s; only %d of %d checks completed",
            grade,
            CAPPED_GRADE,
            len(scored),
            len(checks),
        )
        grade = CAPPED_GRADE

    return Score(score=score, grade=grade, checks_scored=len(scored), grade_capped=capped)


def prioritise(checks: Iterable[CheckResult]) -> list[CheckResult]:
    """Order findings by what the owner should deal with first.

    The engine sorts because deciding that a missing DMARC record outranks a
    missing CSP is a security judgement, and the presentation layer has no
    basis for making it. The frontend renders the list in the order given.
    """
    return sorted(
        checks,
        key=lambda check: (
            _STATUS_ORDER[check.status],
            _SEVERITY_ORDER[check.severity],
            -penalty_for(check),
            check.id,
        ),
    )


def _grade_for(score: int) -> Grade:
    """Map a score to its letter grade."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return "F"


def _is_better_than(grade: Grade, floor: Grade) -> bool:
    """True if grade outranks floor. "A" is best, "F" is worst."""
    order: Final = ("A", "B", "C", "D", "F")
    return order.index(grade) < order.index(floor)
