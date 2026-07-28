"""Unit tests for the DNS hygiene check."""

from netgrade.checks.dns_hygiene import _assess, _find_dangling, _Findings, _nameservers
from tests.conftest import PUBLIC_IP

TWO_PROVIDERS = _Findings(
    nameservers=("ns1.provider-a.com", "ns1.provider-b.net"),
    providers=("provider-a.com", "provider-b.net"),
    transfer_results={"ns1.provider-a.com": "refused", "ns1.provider-b.net": "refused"},
)


def test_healthy_dns_passes():
    status, severity, summary, _ = _assess(TWO_PROVIDERS)
    assert (status, severity) == ("pass", "info")
    assert "2 providers" in summary


def test_open_zone_transfer_outranks_everything():
    """One request returns every hostname the business owns."""
    findings = _Findings(
        nameservers=("ns1.example.com",),
        providers=("example.com",),
        transfers_open=("ns1.example.com",),
        dangling=("www.example.com",),
    )
    status, severity, summary, fix = _assess(findings)

    assert (status, severity) == ("fail", "high")
    assert "entire DNS zone" in summary
    assert "Restrict zone transfers" in fix


def test_one_open_secondary_among_several_is_still_a_finding():
    """An aggregate verdict would hide a single misconfigured nameserver."""
    findings = _Findings(
        nameservers=("ns1.a.com", "ns2.a.com", "ns3.a.com"),
        providers=("a.com",),
        transfers_open=("ns2.a.com",),
        transfer_results={"ns1.a.com": "refused", "ns2.a.com": "open", "ns3.a.com": "refused"},
    )
    status, _, summary, _ = _assess(findings)

    assert status == "fail"
    assert "ns2.a.com" in summary


def test_dangling_record_fails_high():
    findings = _Findings(
        nameservers=("ns1.a.com", "ns1.b.com"),
        providers=("a.com", "b.com"),
        dangling=("www.example.com",),
    )
    status, severity, summary, fix = _assess(findings)

    assert (status, severity) == ("fail", "high")
    assert "no longer exists" in summary
    assert "point it somewhere you control" in fix


def test_single_provider_only_warns():
    """An availability concern, not a break-in route."""
    findings = _Findings(
        nameservers=("ns1.a.com", "ns2.a.com"),
        providers=("a.com",),
    )
    status, severity, _, _ = _assess(findings)
    assert (status, severity) == ("warn", "low")


def test_no_nameservers_warns_rather_than_passing():
    status, severity, _, _ = _assess(_Findings())
    assert (status, severity) == ("warn", "low")


async def test_nameservers_are_read_from_the_organisational_domain(dns_context):
    """NS records live on the registrable domain, not on a subdomain."""
    ctx = dns_context(
        {
            "shop.example.com": {"A": [PUBLIC_IP]},
            "example.com": {"NS": ["ns1.provider.com.", "ns2.provider.com."]},
        }
    )
    assert await _nameservers("shop.example.com", ctx) == (
        "ns1.provider.com",
        "ns2.provider.com",
    )


async def test_missing_ns_records_are_not_an_error(dns_context):
    ctx = dns_context({"example.com": {"A": [PUBLIC_IP]}})
    assert await _nameservers("example.com", ctx) == ()


async def test_cname_to_missing_target_is_dangling(dns_context):
    """The target name does not exist, so anyone can register it and claim it."""
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP]},
            "www.example.com": {"CNAME": ["deleted-bucket.s3.amazonaws.com."]},
        }
    )
    assert await _find_dangling("example.com", ctx) == ("www.example.com",)


async def test_cname_to_live_target_is_not_dangling(dns_context):
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP]},
            "www.example.com": {"CNAME": ["cdn.provider.com."]},
            "cdn.provider.com": {"A": [PUBLIC_IP]},
        }
    )
    assert await _find_dangling("example.com", ctx) == ()


async def test_cname_target_without_an_address_is_not_dangling(dns_context):
    """The name exists but has no A record. Ordinary, not abandoned."""
    ctx = dns_context(
        {
            "example.com": {"A": [PUBLIC_IP]},
            "www.example.com": {"CNAME": ["intermediate.provider.com."]},
            "intermediate.provider.com": {"TXT": ["placeholder"]},
        }
    )
    assert await _find_dangling("example.com", ctx) == ()


async def test_no_cname_means_nothing_can_dangle(dns_context):
    ctx = dns_context(
        {"example.com": {"A": [PUBLIC_IP]}, "www.example.com": {"A": [PUBLIC_IP]}}
    )
    assert await _find_dangling("example.com", ctx) == ()
