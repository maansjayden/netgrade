"""Unit tests for the certificate history check."""

from netgrade.checks.cert_history import _assess, _issuer_label, _parse_timestamp, _summarise

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
    history = _summarise(entries, "example.com")

    assert history.names == ("example.com", "shop.example.com", "www.example.com")
    assert history.certificate_count == 2
    assert set(history.issuers) == {"Let's Encrypt", "DigiCert Inc"}


def test_names_for_other_domains_are_discarded():
    """One log entry can cover unrelated domains on a shared certificate."""
    entries = [{"name_value": "example.com\nsomeone-else.net\nnotexample.com"}]
    history = _summarise(entries, "example.com")

    assert history.names == ("example.com",)


def test_wildcards_are_collected_separately():
    history = _summarise([{"name_value": "*.example.com\nexample.com"}], "example.com")
    assert history.wildcards == ("*.example.com",)


def test_most_recent_issue_is_the_latest_timestamp():
    entries = [
        {"name_value": "a.example.com", "entry_timestamp": "2026-01-01T00:00:00"},
        {"name_value": "b.example.com", "entry_timestamp": "2026-07-01T09:14:00"},
    ]
    assert _summarise(entries, "example.com").most_recent == "2026-07-01T09:14:00Z"


def test_missing_and_unparseable_timestamps_are_tolerated():
    entries = [{"name_value": "a.example.com"}, {"name_value": "b.example.com",
                                                 "entry_timestamp": "not a date"}]
    assert _summarise(entries, "example.com").most_recent is None


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
    status, severity, summary, _ = _assess(_summarise([], "example.com"))
    assert (status, severity) == ("pass", "info")
    assert "No unexpired certificates" in summary


def test_small_footprint_passes():
    history = _summarise([ENTRY], "example.com")
    status, severity, summary, _ = _assess(history)

    assert (status, severity) == ("pass", "info")
    assert "2 hostnames" in summary


def test_large_footprint_warns_without_accusing():
    """Many hostnames is a prompt to review, not a vulnerability."""
    entries = [{"name_value": f"host{n}.example.com"} for n in range(30)]
    status, severity, summary, fix = _assess(_summarise(entries, "example.com"))

    assert (status, severity) == ("warn", "low")
    assert "30 distinct hostnames" in summary
    assert "Review the list" in fix
