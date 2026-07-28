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
from typing import Final

from fastapi import APIRouter, Query

from netgrade.models import ScanResult

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
