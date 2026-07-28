"""The registry is the answer to "what does this tool actually do?"."""

import inspect

from netgrade.checks.base import Check
from netgrade.checks.registry import REGISTRY
from netgrade.models import CHECK_IDS


def test_every_contract_check_is_registered() -> None:
    assert {check.id for check in REGISTRY} == set(CHECK_IDS)


def test_nothing_extra_is_registered() -> None:
    assert len(REGISTRY) == len(CHECK_IDS)


def test_no_check_is_registered_twice() -> None:
    registered = [check.id for check in REGISTRY]
    assert len(registered) == len(set(registered))


def test_every_entry_is_a_check() -> None:
    assert all(isinstance(check, Check) for check in REGISTRY)


def test_every_check_has_a_human_readable_title() -> None:
    for check in REGISTRY:
        assert check.title
        assert check.title != check.id


def test_every_run_is_a_coroutine_taking_domain_and_context() -> None:
    """The uniform interface, asserted rather than assumed."""
    for check in REGISTRY:
        assert inspect.iscoroutinefunction(check.run), check.id
        assert list(inspect.signature(check.run).parameters) == ["domain", "ctx"], check.id


def test_only_certificate_history_overrides_the_shared_time_budget() -> None:
    """A per-check timeout is an exception that should need justifying."""
    overridden = {check.id for check in REGISTRY if check.timeout is not None}
    assert overridden == {"cert_history"}
