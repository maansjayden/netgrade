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
    assert summary == "All four security headers are missing."
    assert "response headers, not code changes" in fix


def test_missing_csp_alone_only_warns():
    """One absent header is a missing layer, not an open door.

    A lone missing Content-Security-Policy is defence in depth that is not
    there. It is not the same class of problem as a missing DMARC policy,
    which is exploitable today, and grading them alike would push most
    otherwise-decent domains into a failing check.
    """
    headers = {k: v for k, v in ALL_HEADERS.items() if k != "content-security-policy"}
    status, severity, summary, _ = _verdict(_assess_headers(response(headers)))

    assert (status, severity) == ("warn", "medium")
    assert "Content-Security-Policy" in summary


def test_two_missing_headers_fail():
    """Two absent headers is a pattern of them not being configured at all."""
    headers = {
        k: v
        for k, v in ALL_HEADERS.items()
        if k not in ("content-security-policy", "strict-transport-security")
    }
    status, severity, _, _ = _verdict(_assess_headers(response(headers)))

    assert (status, severity) == ("fail", "medium")


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


def csp_weaknesses(policy: str) -> tuple[str, ...]:
    headers = dict(ALL_HEADERS, **{"content-security-policy": policy})
    return _assess_headers(response(headers)).weaknesses


def inline_flagged(policy: str) -> bool:
    return any("unsafe-inline" in weakness for weakness in csp_weaknesses(policy))


class TestInlineScriptDetection:
    """This was a substring search for "unsafe-inline" anywhere in the policy.

    Each case below is one it got wrong, and every one of them is a finding
    stated to a user about their own configuration -- the class of error that
    matters most here, because a false weakness sends someone to change
    something that was already correct.
    """

    @pytest.mark.parametrize(
        "policy",
        [
            "default-src 'self'; script-src 'self' 'unsafe-inline'",
            "default-src 'self' 'unsafe-inline'",
            "script-src-attr 'unsafe-inline'",
            "script-src-elem 'unsafe-inline'",
        ],
    )
    def test_policies_that_really_allow_inline_script_are_flagged(self, policy: str) -> None:
        assert inline_flagged(policy)

    def test_unsafe_inline_in_style_src_is_not_a_script_finding(self) -> None:
        """The bug that prompted this. Relaxing style-src says nothing about
        scripts, and reporting it as one is simply false."""
        assert not inline_flagged("default-src 'self'; style-src 'self' 'unsafe-inline'")

    @pytest.mark.parametrize("token", ["'nonce-Kx9fQ2'", "'sha256-abc123='"])
    def test_a_nonce_or_hash_makes_unsafe_inline_inert(self, token: str) -> None:
        """Browsers drop 'unsafe-inline' when either is present in the same
        directive, so these are strict policies. Flagging them told the most
        careful operators they were the least careful."""
        assert not inline_flagged(f"default-src 'self'; script-src 'unsafe-inline' {token}")

    def test_a_nonce_on_styles_does_not_excuse_inline_script(self) -> None:
        """The nonce has to be in the directive that governs scripts."""
        assert inline_flagged(
            "script-src 'unsafe-inline'; style-src 'unsafe-inline' 'nonce-Kx9fQ2'"
        )

    def test_a_narrower_script_directive_overrides_a_relaxed_default(self) -> None:
        """script-src wins over default-src rather than combining with it."""
        assert not inline_flagged("default-src 'unsafe-inline'; script-src 'self'")

    def test_a_repeated_directive_keeps_the_first(self) -> None:
        """Browsers ignore the duplicate rather than letting it widen the policy."""
        assert not inline_flagged("script-src 'self'; script-src 'unsafe-inline'")

    def test_the_word_appearing_in_a_host_source_is_not_a_match(self) -> None:
        """A substring search would have matched this hostname."""
        assert not inline_flagged("default-src 'self' https://unsafe-inline.example.com")

    def test_a_strict_policy_produces_no_inline_finding(self) -> None:
        assert not inline_flagged("default-src 'self'; frame-ancestors 'none'")


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
