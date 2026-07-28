"""Unit tests for the cookie flags check."""

import pytest

from netgrade.checks.cookie_flags import _assess, _Cookie, _parse_cookie

SECURE_SESSION = "sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        (SECURE_SESSION, _Cookie("sessionid", True, True, "Lax")),
        ("plain=1", _Cookie("plain", False, False, None)),
        ("a=1; Secure", _Cookie("a", True, False, None)),
        ("a=1; HttpOnly", _Cookie("a", False, True, None)),
        ("a=1; SameSite=Strict", _Cookie("a", False, False, "Strict")),
        ("a=1; SameSite=None; Secure", _Cookie("a", True, False, "None")),
        # Attribute names are case-insensitive and servers vary wildly.
        ("a=1; secure; httponly; samesite=lax", _Cookie("a", True, True, "Lax")),
        ("a=1; SECURE; HTTPONLY; SAMESITE=STRICT", _Cookie("a", True, True, "Strict")),
        # A value containing '=' must not be mistaken for an attribute.
        ("token=aGVsbG8=; Secure; HttpOnly", _Cookie("token", True, True, None)),
    ],
)
def test_cookie_parsing(header, expected):
    assert _parse_cookie(header) == expected


def test_unparseable_samesite_is_treated_as_absent():
    """A value browsers reject provides no protection and must not read as set."""
    assert _parse_cookie("a=1; SameSite=banana").samesite is None


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("sessionid", True),
        ("PHPSESSID", True),
        ("auth_token", True),
        ("jwt", True),
        ("csrf_token", True),
        ("language", False),
        ("cart_ref", False),
    ],
)
def test_session_like_names_are_recognised(name, expected):
    assert _Cookie(name, True, True, "Lax").session_like is expected


def test_no_cookies_passes_and_says_what_was_not_covered():
    status, severity, summary, fix = _assess(())
    assert (status, severity) == ("pass", "info")
    assert "no cookies" in summary
    assert "after login" in fix


def test_fully_protected_cookies_pass():
    cookies = (
        _parse_cookie(SECURE_SESSION),
        _parse_cookie("lang=en; Secure; HttpOnly; SameSite=Lax"),
    )
    status, severity, _, _ = _assess(cookies)
    assert (status, severity) == ("pass", "info")


def test_session_cookie_without_httponly_fails_high():
    """The worst case: one XSS bug becomes account takeover."""
    cookies = (_parse_cookie("sessionid=abc; Secure; SameSite=Lax"),)
    status, severity, summary, fix = _assess(cookies)

    assert (status, severity) == ("fail", "high")
    assert "sessionid" in summary
    assert "HttpOnly" in fix


def test_non_session_cookie_without_httponly_only_warns():
    """Same missing flag, lower stakes -- severity describes the finding."""
    cookies = (_parse_cookie("language=en; Secure; SameSite=Lax"),)
    status, severity, _, _ = _assess(cookies)

    assert (status, severity) == ("warn", "medium")


def test_missing_secure_flag_fails():
    cookies = (_parse_cookie("prefs=dark; HttpOnly; SameSite=Lax"),)
    status, severity, summary, _ = _assess(cookies)

    assert (status, severity) == ("fail", "medium")
    assert "Secure" in summary


def test_missing_samesite_alone_warns_low():
    cookies = (_parse_cookie("prefs=dark; Secure; HttpOnly"),)
    status, severity, _, _ = _assess(cookies)

    assert (status, severity) == ("warn", "low")


def test_worst_cookie_drives_the_verdict():
    """One good cookie must not mask a bad one."""
    cookies = (
        _parse_cookie("lang=en; Secure; HttpOnly; SameSite=Lax"),
        _parse_cookie("sessionid=abc; Secure; SameSite=Lax"),
    )
    status, severity, summary, _ = _assess(cookies)

    assert (status, severity) == ("fail", "high")
    assert "sessionid" in summary


def test_multiple_offenders_are_all_named():
    cookies = (_parse_cookie("a=1; HttpOnly"), _parse_cookie("b=2; HttpOnly"))
    _, _, summary, _ = _assess(cookies)

    assert "a and b" in summary


def test_problems_lists_every_missing_flag():
    assert _parse_cookie("a=1").problems == ("Secure", "HttpOnly", "SameSite")
    assert _parse_cookie(SECURE_SESSION).problems == ()
