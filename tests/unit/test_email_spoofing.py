"""Unit tests for the email spoofing check.

Two of these pin bugs that survived code review and were only caught by
running the check against live DNS: an empty DKIM p= tag read as a key, and a
non-existent domain graded as having no DMARC policy.
"""

import pytest

from netgrade.checks.base import execute
from netgrade.checks.email_spoofing import CHECK, run
from tests.conftest import PUBLIC_IP

APEX = {"A": [PUBLIC_IP]}
SPF_STRICT = "v=spf1 include:_spf.google.com -all"
DMARC_REJECT = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"


async def test_full_protection_passes(dns_context):
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT]},
            "_dmarc.example.com": {"TXT": [DMARC_REJECT]},
        }
    )
    result = await run("example.com", ctx)

    assert result.status == "pass"
    assert result.severity == "info"
    assert result.evidence["dmarc_policy"] == "reject"


async def test_missing_dmarc_fails(dns_context):
    ctx = dns_context({"example.com": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT]}})
    result = await run("example.com", ctx)

    assert result.status == "fail"
    assert result.severity == "high"
    assert result.evidence["dmarc_record"] is None
    assert "though SPF is published" in result.summary


async def test_spf_pass_all_is_critical(dns_context):
    """+all authorises the whole internet, which is worse than no SPF at all."""
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP], "TXT": ["v=spf1 +all"]},
            "_dmarc.example.com": {"TXT": [DMARC_REJECT]},
        }
    )
    result = await run("example.com", ctx)

    assert result.status == "fail"
    assert result.severity == "critical"


async def test_duplicate_spf_records_fail(dns_context):
    """RFC 7208 permits one SPF record; more makes receivers ignore SPF entirely."""
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT, "v=spf1 ~all"]},
            "_dmarc.example.com": {"TXT": [DMARC_REJECT]},
        }
    )
    result = await run("example.com", ctx)

    assert result.status == "fail"
    assert result.evidence["spf_record_count"] == 2


@pytest.mark.parametrize(
    ("policy", "expected_severity"),
    [("none", "medium"), ("quarantine", "low")],
)
async def test_weak_dmarc_policies_warn(dns_context, policy, expected_severity):
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT]},
            "_dmarc.example.com": {"TXT": [f"v=DMARC1; p={policy}"]},
        }
    )
    result = await run("example.com", ctx)

    assert result.status == "warn"
    assert result.severity == expected_severity


async def test_partial_enforcement_warns(dns_context):
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT]},
            "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; pct=20"]},
        }
    )
    result = await run("example.com", ctx)

    assert result.status == "warn"
    assert result.evidence["dmarc_percentage"] == 20


async def test_subdomain_inherits_organisational_dmarc(dns_context):
    """A subdomain with no record of its own is covered by the parent policy."""
    ctx = dns_context(
        {
            "shop.example.com": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT]},
            "_dmarc.example.com": {"TXT": [DMARC_REJECT]},
        }
    )
    result = await run("shop.example.com", ctx)

    assert result.status == "pass"
    assert result.evidence["dmarc_inherited_from"] == "example.com"


async def test_multi_part_suffix_resolves_correct_parent(dns_context):
    """example.co.uk, not co.uk -- getting this wrong invents a missing policy."""
    ctx = dns_context(
        {
            "shop.example.co.uk": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT]},
            "_dmarc.example.co.uk": {"TXT": [DMARC_REJECT]},
        }
    )
    result = await run("shop.example.co.uk", ctx)

    assert result.status == "pass"
    assert result.evidence["organisational_domain"] == "example.co.uk"


async def test_revoked_dkim_key_is_not_a_key(dns_context):
    """An empty p= publishes a withdrawn selector, not a signing key.

    Regression: a substring test for "p=" reported six keys on a domain that
    had none.
    """
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT]},
            "_dmarc.example.com": {"TXT": [DMARC_REJECT]},
            "google._domainkey.example.com": {"TXT": ["v=DKIM1; p="]},
        }
    )
    result = await run("example.com", ctx)

    assert result.evidence["dkim_selectors_found"] == []
    assert result.evidence["dkim_wildcarded"] is False


async def test_real_dkim_key_is_reported(dns_context):
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT]},
            "_dmarc.example.com": {"TXT": [DMARC_REJECT]},
            "google._domainkey.example.com": {"TXT": ["v=DKIM1; k=rsa; p=MIGfMA0GCSq"]},
        }
    )
    result = await run("example.com", ctx)

    assert result.evidence["dkim_selectors_found"] == ["google"]


async def test_wildcard_domainkey_is_reported_as_inconclusive(dns_context):
    """A domain answering every selector name makes the probe meaningless.

    The control selector resolves against the wildcard, so the check must
    decline to draw a conclusion rather than claiming six keys.
    """

    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP], "TXT": [SPF_STRICT]},
            "_dmarc.example.com": {"TXT": [DMARC_REJECT]},
            "*._domainkey.example.com": {"TXT": ["v=DKIM1; k=rsa; p=MIGfMA0GCSq"]},
        }
    )
    result = await run("example.com", ctx)

    assert result.evidence["dkim_wildcarded"] is True
    assert result.evidence["dkim_selectors_found"] == []
    assert "could not be established" in result.explanation


async def test_nonexistent_domain_errors_rather_than_failing(dns_context):
    """A typo is not a security failure.

    Regression: this graded fail/high with "no DMARC policy is published".
    """
    ctx = dns_context({})
    result = await execute(CHECK, "no-such-domain.example", ctx)

    assert result.status == "error"
    assert result.severity == "info"
    assert "does not exist" in result.summary


async def test_long_txt_record_is_rejoined(dns_context):
    """Values over 255 bytes arrive in chunks and must be reassembled."""
    long_spf = "v=spf1 " + " ".join(f"ip4:203.0.113.{n}" for n in range(1, 40)) + " -all"
    assert len(long_spf) > 255

    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP], "TXT": [long_spf]},
            "_dmarc.example.com": {"TXT": [DMARC_REJECT]},
        }
    )
    result = await run("example.com", ctx)

    assert result.evidence["spf_record"] == long_spf
    assert result.evidence["spf_qualifier"] == "-all"


async def test_result_conforms_to_contract(dns_context):
    """Whatever the finding, the shape the frontend receives is the same."""
    ctx = dns_context({"example.com": APEX})
    result = await execute(CHECK, "example.com", ctx)

    assert result.id == "email_spoofing"
    assert result.status in {"pass", "warn", "fail", "error"}
    assert result.severity in {"critical", "high", "medium", "low", "info"}
    assert result.summary and result.explanation and result.fix
    assert result.duration_ms is not None
