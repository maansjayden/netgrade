"""JSON API routes.

The engine's public surface. The HTML routes in main.py are one consumer of
this contract; the teammate's frontend and the integration tests are others.

Routes are versioned from the start. When the contract has to change after
the freeze, /api/v2 can exist alongside /api/v1 rather than breaking whatever
is already built against it.
"""

import json
import logging
from pathlib import Path
from typing import Annotated, Final

from fastapi import APIRouter, HTTPException, Query, Request

from netgrade.context import DomainNotFoundError
from netgrade.domains import InvalidDomainError
from netgrade.models import ScanResult
from netgrade.service import ScanService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["engine"])

_REPO_ROOT: Final = Path(__file__).resolve().parent.parent
_FIXTURE_PATH: Final = _REPO_ROOT / "tests" / "fixtures" / "mock_scan.json"

#: The longest a fully-qualified domain name can be, per RFC 1035.
_MAX_DOMAIN_LENGTH: Final = 253


def _load_fixture() -> ScanResult:
    """Parse the mock fixture at import time.

    Deliberately eager. The fixture is also the integration test fixture, so
    validating it once at startup means a fixture that has drifted out of the
    contract fails the application loudly instead of rotting unnoticed until
    a test happens to touch it.
    """
    with _FIXTURE_PATH.open(encoding="utf-8") as handle:
        return ScanResult.model_validate(json.load(handle))


_MOCK_SCAN: Final = _load_fixture()


@router.get(
    "/mock-scan",
    response_model=ScanResult,
    summary="Fixed example scan result",
    description=(
        "Returns a representative scan result with a mix of pass, warn, fail "
        "and error findings. The data is illustrative and describes no real "
        "domain. Build against this while the engine is being written; the "
        "shape is identical to the live scan endpoint."
    ),
)
async def mock_scan(
    domain: str | None = Query(
        default=None,
        max_length=_MAX_DOMAIN_LENGTH,
        description="Optional. Substitutes the domain name in the response.",
    ),
) -> ScanResult:
    """Serve the mock scan, optionally restamped with a caller-chosen domain.

    The timestamp is intentionally fixed rather than set to now(), so the
    response is byte-identical on every call and can be asserted against.
    """
    if domain is None:
        return _MOCK_SCAN

    # model_copy rather than assignment: _MOCK_SCAN is module-level state
    # shared by every request, and mutating it would leak one caller's
    # domain into the next caller's response.
    return _MOCK_SCAN.model_copy(update={"domain": domain.strip().lower()})


def _service(request: Request) -> ScanService:
    """The shared engine, attached to the app at startup.

    Read off application state rather than constructed here, so that every
    route shares one connection pool, one concurrency bound and one cache.
    """
    service = getattr(request.app.state, "service", None)
    if not isinstance(service, ScanService):
        raise HTTPException(
            status_code=503,
            detail="The scanning engine is not available in this build.",
        )
    return service


DomainParam = Annotated[
    str,
    Query(
        min_length=1,
        max_length=_MAX_DOMAIN_LENGTH,
        description="Domain to scan. A pasted URL is accepted and reduced to its host.",
    ),
]


@router.get(
    "/scan",
    response_model=ScanResult,
    summary="Scan a domain",
    responses={
        400: {"description": "The input is not a domain this tool will scan."},
        404: {"description": "The domain does not exist in DNS."},
        429: {"description": "Rate limited. Retry-After says when to return."},
    },
)
async def scan_domain(
    request: Request,
    domain: DomainParam,
    force: bool = Query(default=False, description="Bypass and replace any cached result."),
) -> ScanResult:
    """Run all seven checks and return a scored report.

    A domain that cannot be reached is not an error here: the checks that could
    not run come back with status "error" inside an otherwise normal report.
    Only malformed input produces a 4xx, because that is a fault in the request
    rather than a finding about a domain.
    """
    try:
        return await _service(request).scan(domain, force=force)
    except InvalidDomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DomainNotFoundError as exc:
        # A typo, not a posture. Reporting on a domain that does not exist
        # would mean scoring seven "could not check" findings as a clean
        # result, which reads as reassurance about nothing.
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get(
    "/compare",
    response_model=list[ScanResult],
    summary="Scan two domains concurrently",
    responses={
        400: {"description": "One of the inputs is not a domain this tool will scan."},
        404: {"description": "One of the domains does not exist in DNS."},
        429: {"description": "Rate limited. Retry-After says when to return."},
    },
)
async def compare_domains(
    request: Request,
    domain1: DomainParam,
    domain2: DomainParam,
    force: bool = Query(default=False, description="Bypass and replace any cached results."),
) -> list[ScanResult]:
    """Scan two domains at once and return both reports, in the order given.

    A list rather than an object with named sides, so the frontend can render
    it with the same loop it uses for one report and so a future three-way
    comparison does not need a new shape.
    """
    try:
        first, second = await _service(request).compare(domain1, domain2, force=force)
    except InvalidDomainError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except DomainNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return [first, second]
