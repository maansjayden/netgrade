"""Shared test fixtures.

Checks are tested against a stubbed resolver rather than live DNS. Real
lookups would make the suite depend on the internet, on someone else's
records not changing, and on a network round trip per assertion. The stub
raises the same exceptions dnspython raises and returns real rdata objects,
so the parsing under test is the parsing that runs in production.
"""

import asyncio
from collections.abc import Mapping, Sequence

import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import httpx
import pytest

from netgrade.context import ScanContext, Timeouts

#: name -> record type -> values. A name absent from the mapping does not
#: exist (NXDOMAIN). A name present without the requested type exists but has
#: no such record (NoAnswer). Keeping those distinct matters: for _dmarc.x the
#: first means "no DMARC policy", for the apex it means "no such domain".
DnsRecords = Mapping[str, Mapping[str, Sequence[str]]]


class StubResolver:
    """A dnspython resolver that answers from a dict."""

    def __init__(self, records: DnsRecords) -> None:
        self._records = {name.rstrip("."): types for name, types in records.items()}
        self.queries: list[tuple[str, str]] = []

    async def resolve(self, qname: str, rdtype: str = "A", *args: object, **kwargs: object):
        name = str(qname).rstrip(".")
        record_type = str(rdtype).upper()
        self.queries.append((name, record_type))

        types = self._records.get(name) or self._wildcard_match(name)
        if types is None:
            raise dns.resolver.NXDOMAIN(qnames=[dns.name.from_text(name)])

        values = types.get(record_type)
        if not values:
            raise dns.resolver.NoAnswer()

        if record_type == "TXT":
            values = [_quote_txt(value) for value in values]

        return dns.rrset.from_text_list(name, 300, "IN", record_type, list(values))

    def _wildcard_match(self, name: str) -> Mapping[str, Sequence[str]] | None:
        """Resolve a name against a ``*.`` entry, as a real zone would.

        Wildcards are not a test convenience. A domain that publishes
        ``*._domainkey`` answers for every selector, which is precisely the
        configuration that makes DKIM selector probing meaningless, so the
        stub has to be able to reproduce it.
        """
        _, separator, parent = name.partition(".")
        if not separator:
            return None
        return self._records.get(f"*.{parent}")


def _quote_txt(value: str) -> str:
    """Render a TXT value as dnspython's text form, split as the wire is.

    Values longer than 255 bytes arrive as several strings and have to be
    rejoined by the code under test, so the stub splits them the same way.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    chunks = [escaped[i : i + 255] for i in range(0, len(escaped), 255)] or [""]
    return " ".join(f'"{chunk}"' for chunk in chunks)


def make_context(records: DnsRecords, *, timeouts: Timeouts | None = None) -> ScanContext:
    """Build a ScanContext wired to a stubbed resolver.

    The HTTP client is real but unused by DNS-only checks; tests that exercise
    HTTP mount a respx transport onto it instead.
    """
    return ScanContext(
        http=httpx.AsyncClient(),
        resolver=StubResolver(records),  # type: ignore[arg-type]
        limiter=asyncio.Semaphore(8),
        timeouts=timeouts or Timeouts(),
    )


#: A globally routable address. Documentation ranges such as 203.0.113.0/24
#: are correctly refused by the outbound address policy, so any stub whose
#: records feed an HTTP check has to use an address that is actually public.
PUBLIC_IP = "93.184.216.34"

#: A domain that exists, so assert_domain_exists passes, with nothing else.
BARE_DOMAIN: DnsRecords = {"example.com": {"A": [PUBLIC_IP]}}


@pytest.fixture
async def dns_context():
    """Factory for contexts backed by stubbed DNS, closed when the test ends."""
    contexts: list[ScanContext] = []

    def _build(records: DnsRecords, **kwargs: object) -> ScanContext:
        context = make_context(records, **kwargs)  # type: ignore[arg-type]
        contexts.append(context)
        return context

    yield _build

    for context in contexts:
        await context.aclose()
