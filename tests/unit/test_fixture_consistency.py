"""Does the fixture describe findings the engine would actually produce?

The mock fixture is three things at once: the frontend's styling reference,
the integration test fixture, and the input the scoring tests assert against.
That makes hand-written drift expensive, and it is not hypothetical -- the
fixture graded a session cookie missing HttpOnly as medium while the check
that grades cookies calls that high.

The scoring tests could not catch it, because they check that the declared
score, grade and ordering are consistent with the declared severities. They
are: consistently wrong. What was missing is a test that replays a finding's
own evidence through the logic that is supposed to produce it.

Only two checks are covered here. For those two the evidence round-trips onto
the assess function directly. For the other five it does not without reshaping
either the evidence or the check, and five tests that only look like coverage
are worse than two that are real.
"""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from netgrade.checks.cookie_flags import _assess as assess_cookies
from netgrade.checks.cookie_flags import _Cookie
from netgrade.checks.security_headers import _assess_headers
from netgrade.checks.security_headers import _verdict as verdict_headers
from netgrade.context import HttpResult

FIXTURE_PATH = Path(__file__).resolve().parents[1] / "fixtures" / "mock_scan.json"


def finding(check_id: str) -> dict[str, Any]:
    """The fixture's entry for one check."""
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    for check in fixture["checks"]:
        if check["id"] == check_id:
            return check
    raise AssertionError(f"{check_id} is not in the fixture")


class TestCookieFlags:
    """The check that caught the original drift."""

    @pytest.fixture
    def declared(self) -> dict[str, Any]:
        return finding("cookie_flags")

    @pytest.fixture
    def replayed(self, declared: dict[str, Any]) -> tuple[str, str, str, str]:
        """The fixture's own cookies, through the real grading logic."""
        cookies = tuple(
            _Cookie(
                name=entry["name"],
                secure=entry["secure"],
                httponly=entry["httponly"],
                samesite=entry["samesite"],
            )
            for entry in declared["evidence"]["findings"]
        )
        return assess_cookies(cookies)

    def test_status_matches(
        self, declared: dict[str, Any], replayed: tuple[str, str, str, str]
    ) -> None:
        assert declared["status"] == replayed[0]

    def test_severity_matches(
        self, declared: dict[str, Any], replayed: tuple[str, str, str, str]
    ) -> None:
        """A session cookie readable by page scripts is high, not medium."""
        assert declared["severity"] == replayed[1]

    def test_summary_matches(
        self, declared: dict[str, Any], replayed: tuple[str, str, str, str]
    ) -> None:
        assert declared["summary"] == replayed[2]

    def test_fix_matches(
        self, declared: dict[str, Any], replayed: tuple[str, str, str, str]
    ) -> None:
        assert declared["fix"] == replayed[3]

    def test_evidence_records_which_cookies_look_like_sessions(
        self, declared: dict[str, Any]
    ) -> None:
        """The field the severity turns on must be present and correct."""
        by_name = {entry["name"]: entry for entry in declared["evidence"]["findings"]}
        assert by_name["session_id"]["session_like"] is True
        assert by_name["cart_ref"]["session_like"] is False


class TestSecurityHeaders:
    @pytest.fixture
    def declared(self) -> dict[str, Any]:
        return finding("security_headers")

    @pytest.fixture
    def replayed(self, declared: dict[str, Any]) -> tuple[str, str, str, str]:
        """The fixture's own headers, through the real grading logic.

        A header recorded as null in the evidence was absent from the response,
        so it is omitted here rather than sent as an empty string.
        """
        evidence = declared["evidence"]
        headers = {
            name: value
            for name, value in evidence.items()
            if name.startswith(("strict-transport", "content-security", "x-"))
            and value is not None
        }
        response = HttpResult(
            url=evidence["final_url"],
            status_code=200,
            headers=httpx.Headers(headers),
            set_cookie=(),
            body_prefix=b"",
        )
        return verdict_headers(_assess_headers(response))

    def test_status_matches(
        self, declared: dict[str, Any], replayed: tuple[str, str, str, str]
    ) -> None:
        assert declared["status"] == replayed[0]

    def test_severity_matches(
        self, declared: dict[str, Any], replayed: tuple[str, str, str, str]
    ) -> None:
        assert declared["severity"] == replayed[1]

    def test_summary_matches(
        self, declared: dict[str, Any], replayed: tuple[str, str, str, str]
    ) -> None:
        assert declared["summary"] == replayed[2]
