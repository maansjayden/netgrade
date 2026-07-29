"""Bad input reaches every route, and none of it may become a 500.

The HTML pages and the JSON API are two front doors onto the same engine, and
they have to agree about what a bad request is. They did not: the engine gained
DomainNotFoundError, the JSON routes were taught to answer 404, and the HTML
routes were not -- so a typed-in typo returned "Internal Server Error" on the
page a person actually uses.

Parametrised across both front doors deliberately. A test that only covered the
one that was updated would have stayed green through exactly that bug.
"""

import itertools

import pytest
from fastapi.testclient import TestClient
from httpx import Response

from netgrade.main import app

#: A domain that is syntactically fine and does not exist. Registered names
#: could be bought by somebody; this one is noise.
NONEXISTENT = "awsdexcfvgbhnjm-9f3a2b.com"

#: Rejected before any lookup: no public suffix, so there is nothing to scan.
MALFORMED = "a"


@pytest.fixture(scope="module")
def client():
    """A client with the real engine started, as the lifespan handler builds it."""
    with TestClient(app) as started:
        yield started


_addresses = itertools.count(1)


def get(client: TestClient, path: str, **params: str) -> Response:
    """Request a path as a client nobody else in this module shares.

    Every route here is rate limited, and these tests make far more requests
    than one client is allowed. Rather than switch the limiter off -- which
    would stop these tests covering the middleware at all -- each request
    arrives from its own address, which is also a small demonstration that
    separate clients really do get separate buckets.
    """
    # One entry, because the default topology trusts a single proxy hop and
    # therefore reads the rightmost. Putting the varying octet on the left --
    # the first thing I wrote -- left every request sharing the rightmost
    # address, which is the same reading mistake the limiter itself once made.
    counter = next(_addresses)
    forwarded = f"198.51.{counter // 256 % 256}.{counter % 256}"
    return client.get(path, params=params, headers={"x-forwarded-for": forwarded})


class TestNonexistentDomain:
    """A typo is a fault in the request, not a posture worth reporting."""

    @pytest.mark.parametrize("path", ["/scan", "/api/v1/scan"])
    def test_both_front_doors_answer_404(self, client: TestClient, path: str) -> None:
        response = get(client, path, domain=NONEXISTENT)
        assert response.status_code == 404

    @pytest.mark.parametrize(
        "path", ["/compare", "/api/v1/compare"]
    )
    def test_comparison_answers_404_too(self, client: TestClient, path: str) -> None:
        response = get(client, path, domain1=NONEXISTENT, domain2="example.com")
        assert response.status_code == 404

    def test_the_reason_reaches_the_user(self, client: TestClient) -> None:
        response = get(client, "/api/v1/scan", domain=NONEXISTENT)
        assert "does not exist" in response.json()["detail"]


class TestMalformedInput:
    @pytest.mark.parametrize("path", ["/scan", "/api/v1/scan"])
    def test_both_front_doors_answer_400(self, client: TestClient, path: str) -> None:
        response = get(client, path, domain=MALFORMED)
        assert response.status_code == 400

    def test_the_message_is_written_for_a_person(self, client: TestClient) -> None:
        response = get(client, "/api/v1/scan", domain=MALFORMED)
        detail = response.json()["detail"]
        assert "example.com" in detail
        assert "Traceback" not in detail


class TestNothingBecomesAServerError:
    """The catch-all. A 500 means an exception nobody expected got out."""

    @pytest.mark.parametrize(
        "domain",
        [
            NONEXISTENT,
            MALFORMED,
            "",
            "   ",
            "not a domain",
            "http://",
            "..",
            "-leading-hyphen.com",
            "192.168.1.1",
            "localhost",
            "a" * 300 + ".com",
        ],
    )
    @pytest.mark.parametrize("path", ["/scan", "/api/v1/scan"])
    def test_bad_input_never_returns_500(
        self, client: TestClient, path: str, domain: str
    ) -> None:
        response = get(client, path, domain=domain)
        assert response.status_code != 500, (
            f"{path} returned a server error for {domain!r}; "
            "an exception escaped the route"
        )
        assert response.status_code < 500
