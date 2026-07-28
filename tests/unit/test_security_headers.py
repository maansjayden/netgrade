"""Unit tests for the security headers check."""

import httpx
import pytest

from netgrade.checks.security_headers import _assess_headers, _hsts_max_age, _verdict
from netgrade.context import HttpResult

ALL_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": "SAMEORIGIN",
    "x-content-type-options": "nosniff",
}


def response(headers: dict[str, str], *, url: str = "https://example.com/") -> HttpResult:
    return HttpResult(
        url=url,
        status_code=200,
        headers=httpx.Headers(headers),
        set_cookie=(),
        body_prefix=b"",
    )


def test_all_headers_present_passes():
    status, severity, summary, _ = _verdict(_assess_headers(response(ALL_HEADERS)))
    assert (status, severity) == ("pass", "info")
    assert "All four" in summary


def test_no_headers_at_all_fails_high():
    status, severity, summary, fix = _verdict(_assess_headers(response({})))
    assert (status, severity) == ("fail", "high")
    assert "4 of the four" in summary
    assert "response headers, not code changes" in fix


def test_missing_csp_alone_fails_medium():
    headers = {k: v for k, v in ALL_HEADERS.items() if k != "content-security-policy"}
    status, severity, summary, _ = _verdict(_assess_headers(response(headers)))

    assert (status, severity) == ("fail", "medium")
    assert "Content-Security-Policy" in summary


def test_missing_nosniff_alone_only_warns():
    """The least damaging of the four on its own, so it must not read as urgent."""
    headers = {k: v for k, v in ALL_HEADERS.items() if k != "x-content-type-options"}
    status, severity, _, _ = _verdict(_assess_headers(response(headers)))

    assert (status, severity) == ("warn", "low")


def test_csp_frame_ancestors_substitutes_for_x_frame_options():
    """Telling the user to add a header that would have no effect is a false finding."""
    headers = {k: v for k, v in ALL_HEADERS.items() if k != "x-frame-options"}
    assessment = _assess_headers(response(headers))

    assert "x-frame-options" not in assessment.missing
    assert _verdict(assessment)[0] == "pass"


def test_x_frame_options_still_required_without_frame_ancestors():
    headers = dict(ALL_HEADERS, **{"content-security-policy": "default-src 'self'"})
    del headers["x-frame-options"]
    assessment = _assess_headers(response(headers))

    assert "x-frame-options" in assessment.missing


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("max-age=31536000", 31536000),
        ("max-age=31536000; includeSubDomains; preload", 31536000),
        ('max-age="600"', 600),
        ("includeSubDomains", None),
        ("max-age=banana", None),
    ],
)
def test_hsts_max_age_parsing(header, expected):
    assert _hsts_max_age(response({"strict-transport-security": header})) == expected


def test_short_hsts_max_age_is_a_weakness_not_an_absence():
    headers = dict(ALL_HEADERS, **{"strict-transport-security": "max-age=300"})
    assessment = _assess_headers(response(headers))

    assert assessment.missing == ()
    assert "300 seconds" in assessment.weaknesses[0]

    status, severity, _, fix = _verdict(assessment)
    assert (status, severity) == ("warn", "low")
    assert "31536000" in fix


def test_unsafe_inline_csp_is_flagged():
    headers = dict(
        ALL_HEADERS,
        **{"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"},
    )
    assessment = _assess_headers(response(headers))

    assert any("unsafe-inline" in weakness for weakness in assessment.weaknesses)
    assert _verdict(assessment)[0] == "warn"


def test_report_only_csp_does_not_count_as_present():
    """A report-only policy blocks nothing, so it cannot satisfy the check."""
    headers = {k: v for k, v in ALL_HEADERS.items() if k != "content-security-policy"}
    headers["content-security-policy-report-only"] = "default-src 'self'"
    assessment = _assess_headers(response(headers))

    assert "content-security-policy" in assessment.missing


def test_header_lookup_is_case_insensitive():
    """Servers send these in every casing; httpx.Headers must absorb that."""
    upper = {name.upper(): value for name, value in ALL_HEADERS.items()}
    assert _assess_headers(response(upper)).missing == ()
