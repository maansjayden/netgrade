"""Unit tests for the certificate history check."""

import asyncio
from datetime import UTC, datetime
from typing import ClassVar

import httpx
import pytest

from netgrade.checks.cert_history import (
    _assess,
    _cert_spotter_headers,
    _entry_from_cert_spotter,
    _entry_from_crt_sh,
    _fetch_entries,
    _get_json,
    _has_expired,
    _issuer_label,
    _parse_timestamp,
    _summarise,
)
from netgrade.config import ENV_CERTSPOTTER_TOKEN
from netgrade.context import ScanContext


def _summarise_crt_sh(records, domain):
    """Summarise raw crt.sh records, through the real normalisation step.

    The summariser works on normalised entries now that there are two
    aggregators behind this check. Routing these tests through the crt.sh
    parser keeps them testing what they always tested, and covers the parser
    on the way past.
    """
    return _summarise([_entry_from_crt_sh(record) for record in records], domain)

ENTRY = {
    "name_value": "example.com\nwww.example.com",
    "issuer_name": "C=US, O=Let's Encrypt, CN=R11",
    "entry_timestamp": "2026-07-01T09:14:00",
}


def test_summarise_collects_names_across_entries():
    entries = [
        ENTRY,
        {"name_value": "shop.example.com", "issuer_name": "C=US, O=DigiCert Inc, CN=X"},
    ]
    history = _summarise_crt_sh(entries, "example.com")

    assert history.names == ("example.com", "shop.example.com", "www.example.com")
    assert history.certificate_count == 2
    assert set(history.issuers) == {"Let's Encrypt", "DigiCert Inc"}


def test_names_for_other_domains_are_discarded():
    """One log entry can cover unrelated domains on a shared certificate."""
    entries = [{"name_value": "example.com\nsomeone-else.net\nnotexample.com"}]
    history = _summarise_crt_sh(entries, "example.com")

    assert history.names == ("example.com",)


def test_wildcards_are_collected_separately():
    history = _summarise_crt_sh([{"name_value": "*.example.com\nexample.com"}], "example.com")
    assert history.wildcards == ("*.example.com",)


def test_most_recent_issue_is_the_latest_timestamp():
    entries = [
        {"name_value": "a.example.com", "entry_timestamp": "2026-01-01T00:00:00"},
        {"name_value": "b.example.com", "entry_timestamp": "2026-07-01T09:14:00"},
    ]
    assert _summarise_crt_sh(entries, "example.com").most_recent == "2026-07-01T09:14:00Z"


def test_missing_and_unparseable_timestamps_are_tolerated():
    entries = [{"name_value": "a.example.com"}, {"name_value": "b.example.com",
                                                 "entry_timestamp": "not a date"}]
    assert _summarise_crt_sh(entries, "example.com").most_recent is None


def test_naive_timestamps_are_treated_as_utc():
    """crt.sh sends no timezone; assuming local time would shift every date."""
    parsed = _parse_timestamp("2026-07-01T09:14:00")
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert parsed.utcoffset().total_seconds() == 0


def test_issuer_label_extracts_the_organisation():
    assert _issuer_label("C=US, O=Let's Encrypt, CN=R11") == "Let's Encrypt"
    assert _issuer_label("no structure here")[:17] == "no structure here"


def test_no_certificates_passes():
    status, severity, summary, _ = _assess(_summarise_crt_sh([], "example.com"))
    assert (status, severity) == ("pass", "info")
    assert "No unexpired certificates" in summary


def test_small_footprint_passes():
    history = _summarise_crt_sh([ENTRY], "example.com")
    status, severity, summary, _ = _assess(history)

    assert (status, severity) == ("pass", "info")
    assert "2 hostnames" in summary


def test_large_footprint_warns_without_accusing():
    """Many hostnames is a prompt to review, not a vulnerability."""
    entries = [{"name_value": f"host{n}.example.com"} for n in range(30)]
    status, severity, summary, fix = _assess(_summarise_crt_sh(entries, "example.com"))

    assert (status, severity) == ("warn", "low")
    assert "30 distinct hostnames" in summary
    assert "Review the list" in fix


class TestCertSpotterParsing:
    """The second aggregator. Different shape, same normalised entry."""

    RECORD: ClassVar[dict] = {
        "dns_names": ["example.com", "www.example.com"],
        "issuer": {"name": "C=GR, O=Hellenic Academic, CN=GEANT TLS ECC 1"},
        "not_before": "2025-08-14T09:18:16Z",
        "not_after": "2026-08-14T09:18:16Z",
    }

    def test_names_come_from_a_list_not_a_newline_blob(self):
        entry = _entry_from_cert_spotter(self.RECORD)
        assert entry.names == ("example.com", "www.example.com")

    def test_the_issuer_is_read_from_the_nested_object(self):
        assert "GEANT" in _entry_from_cert_spotter(self.RECORD).issuer

    def test_a_missing_issuer_is_tolerated(self):
        assert _entry_from_cert_spotter({"dns_names": ["a.com"]}).issuer == ""

    def test_names_are_normalised_like_the_other_source(self):
        entry = _entry_from_cert_spotter({"dns_names": ["  WWW.Example.COM.  ", ""]})
        assert entry.names == ("www.example.com",)

    def test_both_sources_reduce_to_the_same_entry(self):
        """The point of normalising: the summariser cannot tell them apart."""
        from_spotter = _entry_from_cert_spotter(
            {"dns_names": ["example.com", "www.example.com"], "issuer": {"name": "CN=R11"}}
        )
        from_crt_sh = _entry_from_crt_sh(
            {"name_value": "example.com\nwww.example.com", "issuer_name": "CN=R11"}
        )
        assert from_spotter.names == from_crt_sh.names
        assert from_spotter.issuer == from_crt_sh.issuer


class TestExpiredCertificatesAreExcluded:
    """crt.sh is asked to exclude them in the query; Cert Spotter cannot be.

    Without filtering here the same domain would report a different count
    depending on which aggregator happened to be reachable.
    """

    def test_an_expired_certificate_is_dropped(self):
        expired = {"not_after": "2019-01-01T00:00:00Z"}
        assert _has_expired(expired, datetime(2020, 1, 1, tzinfo=UTC)) is True
        assert _has_expired(expired, datetime.now(UTC)) is True

    def test_expiry_is_judged_against_the_reference_time(self):
        """Not against "now" hidden inside the function, so it is testable."""
        certificate = {"not_after": "2026-06-01T00:00:00Z"}
        assert _has_expired(certificate, datetime(2026, 1, 1, tzinfo=UTC)) is False
        assert _has_expired(certificate, datetime(2027, 1, 1, tzinfo=UTC)) is True

    def test_a_current_certificate_is_kept(self):
        assert _has_expired({"not_after": "2099-01-01T00:00:00Z"}, datetime.now(UTC)) is False

    def test_a_record_without_an_expiry_is_kept(self):
        """Dropping what we cannot date would silently shrink the count."""
        assert _has_expired({}, datetime.now(UTC)) is False


class TestFallingBackBetweenSources:
    """One flaky aggregator should not make the check unavailable.

    crt.sh returns 502s for hours at a time. It is still asked first, because
    it is the most complete and it is what somebody checking our output will
    look at -- but a second independent source turns an outage from "could not
    check" into a slightly slower answer.
    """

    @staticmethod
    def context_answering(handler) -> ScanContext:
        return ScanContext(
            http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            resolver=None,  # type: ignore[arg-type]
            limiter=asyncio.Semaphore(4),
        )

    SPOTTER_BODY: ClassVar[list] = [
        {
            "dns_names": ["example.com"],
            "issuer": {"name": "CN=R11"},
            "not_after": "2099-01-01T00:00:00Z",
        }
    ]

    async def test_crt_sh_is_asked_first(self) -> None:
        asked: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            asked.append(request.url.host)
            return httpx.Response(200, json=[{"name_value": "example.com"}])

        ctx = self.context_answering(handler)
        try:
            source, _ = await _fetch_entries("example.com", ctx)
        finally:
            await ctx.aclose()

        assert asked[0] == "crt.sh"
        assert source == "crt.sh"

    async def test_cert_spotter_answers_when_crt_sh_is_down(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "crt.sh":
                return httpx.Response(502, text="Bad Gateway")
            return httpx.Response(200, json=self.SPOTTER_BODY)

        ctx = self.context_answering(handler)
        try:
            source, entries = await _fetch_entries("example.com", ctx)
        finally:
            await ctx.aclose()

        assert source == "Cert Spotter"
        assert [e.names for e in entries] == [("example.com",)]

    async def test_a_malformed_response_also_falls_through(self) -> None:
        """Not only transport failures. A source answering nonsense is down too."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "crt.sh":
                return httpx.Response(200, json={"error": "rate limited"})
            return httpx.Response(200, json=self.SPOTTER_BODY)

        ctx = self.context_answering(handler)
        try:
            source, _ = await _fetch_entries("example.com", ctx)
        finally:
            await ctx.aclose()

        assert source == "Cert Spotter"

    async def test_both_down_reports_could_not_check(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(502, text="Bad Gateway")

        ctx = self.context_answering(handler)
        try:
            with pytest.raises(httpx.HTTPError) as caught:
                await _fetch_entries("example.com", ctx)
        finally:
            await ctx.aclose()

        message = str(caught.value)
        assert "crt.sh" in message and "Cert Spotter" in message

    async def test_the_evidence_records_which_source_answered(self) -> None:
        """So a report that disagrees with somebody's own crt.sh check is
        traceable to having read a different aggregator."""

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "crt.sh":
                return httpx.Response(502)
            return httpx.Response(200, json=self.SPOTTER_BODY)

        ctx = self.context_answering(handler)
        try:
            source, _ = await _fetch_entries("example.com", ctx)
        finally:
            await ctx.aclose()

        assert source == "Cert Spotter"


class TestCertSpotterAuthentication:
    """Cert Spotter rate limits per source address, and the unauthenticated
    ceiling is low enough that a dozen scans in a minute exhausts it -- which
    reports "could not check" to everyone sharing our address, including
    somebody trying the live site for themselves. A free token raises it.

    Reliability here is not something to arrange in advance for a demo; it has
    to hold for whoever arrives next.
    """

    @staticmethod
    def context_answering(handler) -> ScanContext:
        return ScanContext(
            http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            resolver=None,  # type: ignore[arg-type]
            limiter=asyncio.Semaphore(4),
        )

    def test_no_token_sends_no_authorization(self, monkeypatch) -> None:
        monkeypatch.delenv(ENV_CERTSPOTTER_TOKEN, raising=False)
        assert "Authorization" not in _cert_spotter_headers()

    def test_a_token_is_sent_as_a_bearer_credential(self, monkeypatch) -> None:
        monkeypatch.setenv(ENV_CERTSPOTTER_TOKEN, "tok_abc123")
        assert _cert_spotter_headers()["Authorization"] == "Bearer tok_abc123"

    def test_a_blank_token_is_treated_as_absent(self, monkeypatch) -> None:
        """An unset Railway variable arrives as an empty string, and sending
        "Bearer " would be rejected outright rather than falling back."""
        monkeypatch.setenv(ENV_CERTSPOTTER_TOKEN, "   ")
        assert "Authorization" not in _cert_spotter_headers()

    def test_the_accept_header_survives_authentication(self, monkeypatch) -> None:
        monkeypatch.setenv(ENV_CERTSPOTTER_TOKEN, "tok_abc123")
        assert _cert_spotter_headers()["Accept"] == "application/json"

    async def test_the_token_reaches_the_request(self, monkeypatch) -> None:
        monkeypatch.setenv(ENV_CERTSPOTTER_TOKEN, "tok_abc123")
        seen: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("authorization"))
            if request.url.host == "crt.sh":
                return httpx.Response(502)
            return httpx.Response(200, json=[])

        ctx = self.context_answering(handler)
        try:
            await _fetch_entries("example.com", ctx)
        finally:
            await ctx.aclose()

        # crt.sh is asked first and unauthenticated; the token is Cert
        # Spotter's and must not be sent to anyone else.
        assert seen == [None, None, "Bearer tok_abc123"]


class TestRateLimitsAreNotRetried:
    async def test_a_429_is_requested_once(self) -> None:
        """Retrying a rate limit makes it worse. 429 is not a transient server
        error and must not be treated as one."""
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(429, headers={"Retry-After": "65"}, json={"code": "rate_limited"})

        ctx = TestCertSpotterAuthentication.context_answering(handler)
        try:
            with pytest.raises(httpx.HTTPStatusError) as caught:
                await _get_json("https://api.certspotter.com/v1/issuances", "Cert Spotter", ctx)
        finally:
            await ctx.aclose()

        assert attempts == 1, f"a rate limit was retried {attempts} times"
        assert caught.value.response.status_code == 429

    async def test_a_502_still_is_retried(self) -> None:
        """The contrast that makes the above meaningful: a server error is
        transient and worth one more attempt."""
        attempts = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal attempts
            attempts += 1
            return httpx.Response(502)

        ctx = TestCertSpotterAuthentication.context_answering(handler)
        try:
            with pytest.raises(httpx.HTTPStatusError):
                await _get_json("https://crt.sh/", "crt.sh", ctx)
        finally:
            await ctx.aclose()

        assert attempts == 2
