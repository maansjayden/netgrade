"""The canonical list of checks the orchestrator runs.

Registration is explicit rather than discovered by scanning the package.
Import-time auto-discovery would mean a half-finished module dropped into the
directory silently joins a live scan, and it hides the answer to "what does
this tool actually do?" behind a runtime behaviour instead of a readable list.
"""

from typing import Final

from netgrade.checks import (
    cert_history,
    cookie_flags,
    dns_hygiene,
    email_spoofing,
    exposed_artefacts,
    security_headers,
    tls_config,
)
from netgrade.checks.base import Check
from netgrade.models import CHECK_IDS

#: Declaration order only. The report is ordered by remediation priority,
#: which scoring works out from the findings themselves.
REGISTRY: Final[tuple[Check, ...]] = (
    email_spoofing.CHECK,
    tls_config.CHECK,
    security_headers.CHECK,
    cookie_flags.CHECK,
    exposed_artefacts.CHECK,
    dns_hygiene.CHECK,
    cert_history.CHECK,
)


def _assert_registry_matches_contract() -> None:
    """Fail at import if the registry and the contract have drifted apart.

    CHECK_IDS is what the frontend, the fixture and the scoring weights are all
    written against. A check registered under an id nobody else knows about
    would score as an unknown and render as an unstyled badge, so the mismatch
    is caught here rather than in whichever of those surfaces notices first.
    """
    registered = tuple(check.id for check in REGISTRY)

    duplicates = {check_id for check_id in registered if registered.count(check_id) > 1}
    if duplicates:
        raise RuntimeError(f"checks registered more than once: {sorted(duplicates)}")

    if set(registered) != set(CHECK_IDS):
        missing = sorted(set(CHECK_IDS) - set(registered))
        unexpected = sorted(set(registered) - set(CHECK_IDS))
        raise RuntimeError(
            f"registry does not match the contract; missing={missing} unexpected={unexpected}"
        )


_assert_registry_matches_contract()
