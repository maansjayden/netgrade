"""Unit tests for the exposed development files check.

Weighted toward false positives. Finding a real .env is easy; not claiming to
have found one because a site returned its own 404 page with a 200 status is
the part that has to be right.
"""

import httpx
import pytest

from netgrade.checks.exposed_artefacts import _ARTEFACTS, _assess, _Probe, _probe
from netgrade.context import HttpResult, ScanContext

REAL_ENV = b"APP_KEY=base64:abc123\nDB_PASSWORD=hunter2\nDB_HOST=localhost\n"
REAL_GIT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n"
REAL_DS_STORE = b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08\x00"
HTML_404 = b"<!doctype html><html><head><title>Page not found</title></head><body>"

BY_PATH = {artefact.path: artefact for artefact in _ARTEFACTS}


class StubContext:
    """A context whose fetch returns canned responses keyed by path."""

    def __init__(self, responses: dict[str, tuple[int, bytes]]) -> None:
        self._responses = responses
        self.requested: list[str] = []

    async def fetch(self, url: str, *, method: str = "GET") -> HttpResult:
        path = httpx.URL(url).path
        self.requested.append(path)
        status, body = self._responses.get(path, (404, b"not found"))
        return HttpResult(
            url=url,
            status_code=status,
            headers=httpx.Headers({}),
            set_cookie=(),
            body_prefix=body,
        )


def context(responses: dict[str, tuple[int, bytes]]) -> ScanContext:
    return StubContext(responses)  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("path", "body"),
    [("/.env", REAL_ENV), ("/.git/config", REAL_GIT_CONFIG), ("/.DS_Store", REAL_DS_STORE)],
)
async def test_real_files_are_detected(path, body):
    ctx = context({path: (200, body)})
    result = await _probe("https://example.com", BY_PATH[path], ctx)

    assert result.exposed is True
    assert "content confirmed" in result.reason


@pytest.mark.parametrize("path", ["/.env", "/.git/config", "/.DS_Store"])
async def test_soft_404_is_not_an_exposure(path):
    """A 200 carrying the site's own error page is the likeliest false positive."""
    ctx = context({path: (200, HTML_404)})
    result = await _probe("https://example.com", BY_PATH[path], ctx)

    assert result.exposed is False
    assert "content is not this file" in result.reason


@pytest.mark.parametrize("status", [301, 403, 404, 500])
async def test_non_200_is_never_an_exposure(status):
    ctx = context({"/.env": (status, REAL_ENV)})
    result = await _probe("https://example.com", BY_PATH["/.env"], ctx)

    assert result.exposed is False
    assert str(status) in result.reason


async def test_env_file_needs_a_recognisable_key():
    """Arbitrary KEY=VALUE text is not evidence of an environment file."""
    ctx = context({"/.env": (200, b"colour=blue\nsize=large\n")})
    result = await _probe("https://example.com", BY_PATH["/.env"], ctx)

    assert result.exposed is False


async def test_ds_store_must_have_the_right_magic_bytes():
    ctx = context({"/.DS_Store": (200, b"Bud1 but not at the start")})
    result = await _probe("https://example.com", BY_PATH["/.DS_Store"], ctx)

    assert result.exposed is False


async def test_request_failure_is_not_an_exposure():
    class Failing:
        async def fetch(self, url: str, *, method: str = "GET") -> HttpResult:
            raise httpx.ConnectError("refused")

    result = await _probe("https://example.com", BY_PATH["/.env"], Failing())  # type: ignore[arg-type]
    assert result.exposed is False
    assert result.status_code is None


def probe_for(path: str, *, exposed: bool) -> _Probe:
    return _Probe(BY_PATH[path], 200 if exposed else 404, exposed, "test")


def test_nothing_exposed_passes():
    status, severity, summary, _ = _assess((), soft_404=False)
    assert (status, severity) == ("pass", "info")
    assert "None of the three" in summary


def test_soft_404_site_is_told_how_the_result_was_reached():
    _, _, summary, _ = _assess((), soft_404=True)
    assert "confirmed by file contents" in summary


def test_exposed_env_is_critical():
    status, severity, summary, fix = _assess((probe_for("/.env", exposed=True),), soft_404=False)
    assert (status, severity) == ("fail", "critical")
    assert "/.env" in summary
    assert "rotate" in fix


def test_exposed_ds_store_alone_is_low():
    status, severity, _, _ = _assess((probe_for("/.DS_Store", exposed=True),), soft_404=False)
    assert (status, severity) == ("fail", "low")


def test_worst_file_drives_severity():
    exposed = (probe_for("/.DS_Store", exposed=True), probe_for("/.env", exposed=True))
    status, severity, summary, _ = _assess(exposed, soft_404=False)

    assert (status, severity) == ("fail", "critical")
    assert "/.env" in summary
    assert "/.DS_Store" in summary
