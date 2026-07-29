"""The scan result contract.

This module is the interface between the scanning engine and everything that
consumes it -- the templates, the JSON API and the test fixtures. It is frozen:
changes get announced before they are committed, because they break the other
half of the team silently.

Every check returns a CheckResult, including when it fails. A domain that
cannot be reached produces status="error" as data; it never raises past the
orchestrator.
"""

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer

#: Outcome of a single check.
#:
#: "error" is not a failing grade. It means the check could not be completed --
#: DNS timed out, the host refused the connection, a log server was down. An
#: errored check is excluded from the score denominator and surfaced to the
#: user as "could not check", because scoring an unknown as a failure would
#: hand an unreachable host an F it has not earned.
CheckStatus = Literal["pass", "warn", "fail", "error"]

#: Severity of a finding, not of a check. The same check yields different
#: severities depending on what it found: no SPF and no DMARC at all is not
#: the same risk as SPF present but DMARC at p=none. Scoring weight derives
#: from this field, so it is the check's job to set it honestly.
Severity = Literal["critical", "high", "medium", "low", "info"]

#: Overall letter grade for a scan.
Grade = Literal["A", "B", "C", "D", "F"]

#: The seven checks that produce findings. The eighth item in the project
#: scope, the scored report, is the grade itself and lives in scoring.py.
CHECK_IDS: tuple[str, ...] = (
    "email_spoofing",
    "tls_config",
    "security_headers",
    "cookie_flags",
    "exposed_artefacts",
    "dns_hygiene",
    "cert_history",
)


class CheckResult(BaseModel):
    """One finding from one check.

    Immutable: a check produces this once and nothing downstream edits it.
    Scoring reorders the list but never rewrites a severity, which is a bug
    class worth designing out rather than testing for.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(description="Stable machine identifier, one of CHECK_IDS.")
    title: str = Field(description="Human-readable check name.")
    status: CheckStatus
    severity: Severity
    summary: str = Field(description="One sentence stating what was found.")
    explanation: str = Field(description="Why a non-technical owner should care.")
    fix: str = Field(description="The concrete next action, in plain language.")

    #: Raw values supporting the finding. Free-form because each check has a
    #: different shape of evidence. Rendered to the user and returned over the
    #: API, so it carries observed public data only -- never credentials,
    #: internal addresses or anything not already visible to any observer.
    evidence: dict[str, Any] = Field(default_factory=dict)

    #: Wall-clock time this check took. Carries the concurrency story: the
    #: sum of these against the scan's own duration is the speedup.
    duration_ms: int | None = None


class ScanResult(BaseModel):
    """A complete scan of one domain."""

    #: Not frozen: the audio layer assigns audio_briefing_url after scoring.
    model_config = ConfigDict(extra="forbid")

    #: The domain as scanned. For internationalised domains this is the
    #: A-label (punycode), not the Unicode form -- rendering the Unicode form
    #: would let a homograph domain display as the name it is imitating.
    domain: str = Field(min_length=1)

    scanned_at: datetime
    grade: Grade
    score: int = Field(ge=0, le=100)

    #: Ordered by remediation priority, worst first. The engine sorts; the
    #: frontend renders the list as given. Priority is a security judgement,
    #: so it is not the presentation layer's job to work it out.
    checks: list[CheckResult] = Field(default_factory=list)

    #: How many checks contributed to the grade. Differs from len(checks)
    #: when some errored. Lets the report say "graded on 5 of 7 checks"
    #: instead of presenting a grade that quietly rests on partial data.
    checks_scored: int = 0

    audio_briefing_url: str | None = None
    cached: bool = False

    @field_serializer("scanned_at")
    def _serialize_scanned_at(self, value: datetime) -> str:
        """Emit the contract's timestamp format, e.g. 2026-07-28T14:03:11Z.

        Pydantic would otherwise render +00:00. The wire format is fixed by
        the contract, so it is pinned here rather than left to a default.
        """
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
