"""Unit tests for domain canonicalisation and the outbound address policy.

The rejection cases matter more than the acceptance cases. This module is the
boundary between user input and outbound requests, so anything that slips
through it is a request the scanner makes on an attacker's behalf.
"""

import pytest

from netgrade.domains import (
    InvalidDomainError,
    is_public_address,
    normalise_domain,
    organisational_domain,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "example.com"),
        ("  EXAMPLE.com  ", "example.com"),
        ("https://example.com/pricing?plan=pro#top", "example.com"),
        ("http://example.com", "example.com"),
        ("example.com.", "example.com"),
        ("example.com:8443", "example.com"),
        ("user:secret@example.com", "example.com"),
        ("shop.example.co.uk", "shop.example.co.uk"),
        ("3com.com", "3com.com"),
    ],
)
def test_accepts_what_people_actually_paste(raw, expected):
    assert normalise_domain(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("bücher.de", "xn--bcher-kva.de"),
        ("BÜCHER.de", "xn--bcher-kva.de"),
        ("xn--bcher-kva.de", "xn--bcher-kva.de"),
    ],
)
def test_internationalised_names_become_punycode(raw, expected):
    """Reports must show the A-label.

    Rendering the Unicode form would let a homograph domain display as the
    name it is imitating, inside a report the reader is trusting.
    """
    assert normalise_domain(raw) == expected


def test_homograph_domain_is_visibly_distinct_once_normalised():
    """A Cyrillic lookalike must not render as its ASCII target."""
    cyrillic = normalise_domain("аpple.com")  # noqa: RUF001 - leading char is U+0430
    assert cyrillic != "apple.com"
    assert cyrillic.startswith("xn--")


@pytest.mark.parametrize(
    "raw",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "http://192.168.1.1/admin",
        "127.0.0.1:8080",
        "::1",
        "[::1]",
        "[::1]:8443",
        "http://[fd00::1]/admin",
        "[2001:4860:4860::8888]",
    ],
)
def test_ip_literals_are_refused(raw):
    """Scanning by address is out of scope and is the main SSRF vector."""
    with pytest.raises(InvalidDomainError, match="IP address"):
        normalise_domain(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "localhost",
        "example",
        "test.internal",
        "server.local",
        "-bad.com",
        "exa mple.com",
    ],
)
def test_non_public_and_malformed_names_are_refused(raw):
    with pytest.raises(InvalidDomainError):
        normalise_domain(raw)


def test_overlong_name_is_refused():
    with pytest.raises(InvalidDomainError, match="too long"):
        normalise_domain("a" * 250 + ".com")


@pytest.mark.parametrize(
    ("domain", "expected"),
    [
        ("example.com", "example.com"),
        ("shop.example.com", "example.com"),
        ("shop.example.co.uk", "example.co.uk"),
        ("a.b.c.example.com", "example.com"),
    ],
)
def test_organisational_domain_handles_multi_part_suffixes(domain, expected):
    """DMARC falls back to this name; co.uk is where a naive split goes wrong."""
    assert organisational_domain(domain) == expected


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111"])
def test_public_addresses_are_allowed(address):
    assert is_public_address(address) is True


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",  # cloud instance metadata
        "100.64.0.1",  # carrier-grade NAT
        "203.0.113.10",  # TEST-NET-3, reserved for documentation
        "0.0.0.0",  # noqa: S104 - an address under test, not a bind address
        "::1",
        "fd00::1",
        "fe80::1",
        "not-an-address",
    ],
)
def test_non_routable_addresses_are_refused(address):
    assert is_public_address(address) is False
