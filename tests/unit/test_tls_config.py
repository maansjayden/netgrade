"""Unit tests for the TLS check.

Certificates are generated here rather than fetched, so expiry and hostname
cases are exact and the suite needs no network. The handshake itself is left
to integration testing: the bugs in this check were in the judgement, not in
the socket.
"""

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from netgrade.checks.tls_config import (
    _assess,
    _days_remaining,
    _Handshake,
    _issuer,
    _matches_hostname,
    _name_matches,
    _subject_alt_names,
)


def make_certificate(
    *,
    common_name: str = "example.com",
    alt_names: list[str] | None = ("example.com",),
    days_until_expiry: int = 90,
    issuer_name: str = "Test CA",
) -> x509.Certificate:
    """Build a self-signed certificate with the properties under test."""
    key = ed25519.Ed25519PrivateKey.generate()
    now = dt.datetime.now(dt.timezone.utc)
    expires = now + dt.timedelta(days=days_until_expiry)
    # Anchored to the expiry rather than to now, so an already-expired
    # certificate still has a validity window that runs forwards.
    starts = expires - dt.timedelta(days=90)

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(starts)
        .not_valid_after(expires)
    )
    if alt_names:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in alt_names]),
            critical=False,
        )
    return builder.sign(key, None)


def trusted(certificate: x509.Certificate) -> _Handshake:
    return _Handshake(protocol="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
                      certificate=certificate, verified=True)


@pytest.mark.parametrize(
    ("pattern", "domain", "expected"),
    [
        ("example.com", "example.com", True),
        ("example.com", "www.example.com", False),
        ("*.example.com", "www.example.com", True),
        ("*.example.com", "example.com", False),
        ("*.example.com", "a.b.example.com", False),
        ("*.example.com", "evil.com", False),
        ("*.example.com", ".example.com", False),
    ],
)
def test_wildcard_matching_covers_exactly_one_label(pattern, domain, expected):
    assert _name_matches(pattern, domain) is expected


def test_hostname_matches_via_subject_alternative_name():
    certificate = make_certificate(alt_names=["example.com", "www.example.com"])
    assert _matches_hostname(certificate, "www.example.com") is True
    assert _matches_hostname(certificate, "shop.example.com") is False


def test_hostname_falls_back_to_common_name_without_san():
    """Browsers stopped accepting these, but the report should say what is wrong."""
    certificate = make_certificate(common_name="legacy.example.com", alt_names=None)
    assert _subject_alt_names(certificate) == ()
    assert _matches_hostname(certificate, "legacy.example.com") is True


def test_missing_certificate_matches_nothing():
    assert _matches_hostname(None, "example.com") is False


def test_issuer_is_read_from_the_certificate():
    assert _issuer(make_certificate(issuer_name="Let's Encrypt R11")) == "Let's Encrypt R11"


@pytest.mark.parametrize(
    ("days", "expected"),
    [(90, 89), (1, 0), (-5, -6)],
)
def test_days_remaining_counts_whole_days(days, expected):
    certificate = make_certificate(days_until_expiry=days)
    assert _days_remaining(certificate.not_valid_after_utc) == expected


def test_no_connection_is_critical():
    status, severity, summary, _ = _assess(_Handshake(), None, False, ())
    assert (status, severity) == ("fail", "critical")
    assert "port 443" in summary


def test_expired_certificate_outranks_everything_else():
    """An expired certificate blocks every visitor, so it is reported first."""
    certificate = make_certificate(days_until_expiry=-30)
    handshake = _Handshake(protocol="TLSv1.2", certificate=certificate, verified=False)

    status, severity, summary, _ = _assess(
        handshake, certificate.not_valid_after_utc, True, ("TLS 1.0",)
    )
    assert (status, severity) == ("fail", "critical")
    assert "expired" in summary


def test_hostname_mismatch_is_critical():
    certificate = make_certificate(alt_names=["other.example.com"])
    handshake = _Handshake(protocol="TLSv1.3", certificate=certificate, verified=False)

    status, severity, _, _ = _assess(handshake, certificate.not_valid_after_utc, False, ())
    assert (status, severity) == ("fail", "critical")


def test_untrusted_certificate_fails_high():
    certificate = make_certificate()
    handshake = _Handshake(protocol="TLSv1.3", certificate=certificate, verified=False)

    status, severity, _, _ = _assess(handshake, certificate.not_valid_after_utc, True, ())
    assert (status, severity) == ("fail", "high")


def test_imminent_expiry_outranks_legacy_protocols():
    certificate = make_certificate(days_until_expiry=5)
    status, severity, summary, _ = _assess(
        trusted(certificate), certificate.not_valid_after_utc, True, ("TLS 1.0",)
    )
    assert (status, severity) == ("fail", "high")
    assert "expires in 4 days" in summary


def test_legacy_protocols_fail_medium():
    certificate = make_certificate(days_until_expiry=200)
    status, severity, summary, fix = _assess(
        trusted(certificate), certificate.not_valid_after_utc, True, ("TLS 1.0", "TLS 1.1")
    )
    assert (status, severity) == ("fail", "medium")
    assert "TLS 1.0 and TLS 1.1" in summary
    assert "TLS 1.2" in fix


def test_approaching_expiry_only_warns():
    certificate = make_certificate(days_until_expiry=21)
    status, severity, _, _ = _assess(
        trusted(certificate), certificate.not_valid_after_utc, True, ()
    )
    assert (status, severity) == ("warn", "low")


def test_healthy_configuration_passes():
    certificate = make_certificate(days_until_expiry=200)
    status, severity, summary, _ = _assess(
        trusted(certificate), certificate.not_valid_after_utc, True, ()
    )
    assert (status, severity) == ("pass", "info")
    assert "TLSv1.3" in summary
    assert "199 days remaining" in summary
