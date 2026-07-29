"""Client identification and request pricing.

The client key tests are the important ones. A spoofable implementation and a
correct one behave identically when every request comes from one address, so
this is the part that has to be pinned by tests rather than by hitting the URL
and seeing a 429.
"""

import pytest
from starlette.requests import Request

from netgrade.config import Settings
from netgrade.middleware import RateLimitMiddleware, client_key


def request_with(
    forwarded: str | None,
    peer: str = "10.0.0.1",
    *,
    path: str = "/scan",
    query: str = "",
) -> Request:
    """A request as it would arrive behind a proxy."""
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "https",
            "path": path,
            "raw_path": path.encode(),
            "query_string": query.encode(),
            "headers": headers,
            "client": (peer, 54321),
            "server": ("netgrade", 8080),
            "app": None,
        }
    )


class TestClientKeyBehindOneProxy:
    """Railway and Fly both terminate at a single edge proxy."""

    def test_the_rightmost_entry_is_the_real_client(self) -> None:
        """The address our proxy actually received the request from."""
        assert client_key(request_with("203.0.113.7"), 1) == "203.0.113.7"

    def test_a_spoofed_prefix_is_ignored(self) -> None:
        """The attack the leftmost reading is vulnerable to.

        A caller who sets the header themselves has their value appear on the
        left. Taking the leftmost entry would hand them a fresh bucket per
        request; taking the rightmost pins them to the address the proxy saw.
        """
        spoofed = request_with("1.2.3.4, 203.0.113.7")
        assert client_key(spoofed, 1) == "203.0.113.7"

    def test_varying_the_spoofed_prefix_does_not_change_the_key(self) -> None:
        first = client_key(request_with("9.9.9.9, 203.0.113.7"), 1)
        second = client_key(request_with("8.8.8.8, 203.0.113.7"), 1)
        assert first == second == "203.0.113.7"

    def test_different_real_clients_get_different_keys(self) -> None:
        """Isolation: the property the six-request test cannot demonstrate."""
        laptop = client_key(request_with("203.0.113.7"), 1)
        phone = client_key(request_with("198.51.100.22"), 1)
        assert laptop != phone


class TestClientKeyWithOtherTopologies:
    def test_two_hops_reads_the_second_from_the_right(self) -> None:
        chain = request_with("1.2.3.4, 203.0.113.7, 172.16.0.1")
        assert client_key(chain, 2) == "203.0.113.7"

    def test_no_proxy_ignores_the_header_entirely(self) -> None:
        """Directly exposed, the header is pure user input and worth nothing."""
        assert client_key(request_with("1.2.3.4"), 0) == "10.0.0.1"

    def test_a_missing_header_falls_back_to_the_peer(self) -> None:
        assert client_key(request_with(None), 1) == "10.0.0.1"

    def test_a_shorter_chain_than_expected_falls_back_to_the_peer(self) -> None:
        """Rather than guessing at an index into a chain we were misinformed about."""
        assert client_key(request_with("1.2.3.4"), 3) == "10.0.0.1"

    def test_whitespace_and_empty_entries_are_tolerated(self) -> None:
        assert client_key(request_with("1.2.3.4 , , 203.0.113.7 "), 1) == "203.0.113.7"


BOTH_DOMAINS = "domain1=a.com&domain2=b.com"


class TestRequestPricing:
    @pytest.mark.parametrize(
        ("path", "query", "expected"),
        [
            ("/api/v1/scan", "domain=a.com", 1),
            ("/scan", "domain=a.com", 1),
            ("/api/v1/compare", BOTH_DOMAINS, 2),
            ("/api/v1/compare/", BOTH_DOMAINS, 2),
            ("/compare", BOTH_DOMAINS, 2),
        ],
    )
    def test_a_comparison_that_scans_two_domains_costs_double(
        self, path: str, query: str, expected: int
    ) -> None:
        middleware = RateLimitMiddleware(app=None, settings=Settings())  # type: ignore[arg-type]
        assert middleware._cost_of(request_with(None, path=path, query=query)) == expected

    @pytest.mark.parametrize("query", ["", "domain1=a.com", "domain2=b.com", "domain1=&domain2="])
    def test_the_empty_comparison_form_is_priced_as_an_ordinary_request(
        self, query: str
    ) -> None:
        """Opening a page that scans nothing must not spend the price of work."""
        middleware = RateLimitMiddleware(app=None, settings=Settings())  # type: ignore[arg-type]
        assert middleware._cost_of(request_with(None, path="/compare", query=query)) == 1

    def test_the_comparison_price_is_configurable(self) -> None:
        middleware = RateLimitMiddleware(
            app=None,  # type: ignore[arg-type]
            settings=Settings(compare_cost=3, rate_burst=6),
        )
        request = request_with(None, path="/api/v1/compare", query=BOTH_DOMAINS)
        assert middleware._cost_of(request) == 3
