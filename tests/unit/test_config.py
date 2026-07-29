"""Environment-driven settings."""

import pytest

from netgrade.config import (
    ENV_COMPARE_COST,
    ENV_DEBUG_CLIENT_KEY,
    ENV_RATE_BURST,
    ENV_RATE_PER_MINUTE,
    ENV_TRUSTED_PROXY_HOPS,
    Settings,
)


class TestDefaults:
    def test_an_unconfigured_instance_uses_the_published_defaults(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """What the README documents must be what an empty environment does."""
        for name in (
            ENV_RATE_PER_MINUTE,
            ENV_RATE_BURST,
            ENV_COMPARE_COST,
            ENV_TRUSTED_PROXY_HOPS,
            ENV_DEBUG_CLIENT_KEY,
        ):
            monkeypatch.delenv(name, raising=False)

        assert Settings.from_env() == Settings()

    def test_the_defaults_are_the_conservative_ones(self) -> None:
        defaults = Settings()
        assert (defaults.rate_per_minute, defaults.rate_burst) == (5.0, 5)
        assert defaults.compare_cost == 2
        assert defaults.trusted_proxy_hops == 1
        assert defaults.debug_client_key is False


class TestOverrides:
    def test_the_rate_can_be_raised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_RATE_PER_MINUTE, "60")
        monkeypatch.setenv(ENV_RATE_BURST, "20")
        settings = Settings.from_env()
        assert (settings.rate_per_minute, settings.rate_burst) == (60.0, 20)

    def test_proxy_hops_can_be_changed_for_another_host(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(ENV_TRUSTED_PROXY_HOPS, "2")
        assert Settings.from_env().trusted_proxy_hops == 2

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_debug_logging_accepts_the_usual_truthy_spellings(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv(ENV_DEBUG_CLIENT_KEY, value)
        assert Settings.from_env().debug_client_key is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "", "  ", "maybe"])
    def test_anything_else_leaves_debug_logging_off(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv(ENV_DEBUG_CLIENT_KEY, value)
        assert Settings.from_env().debug_client_key is False


class TestBadInput:
    def test_a_nonsense_number_keeps_the_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A typo in a platform variable must not take the service down."""
        monkeypatch.setenv(ENV_RATE_PER_MINUTE, "fast please")
        assert Settings.from_env().rate_per_minute == Settings().rate_per_minute

    def test_a_comparison_that_could_never_be_served_is_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Fails at startup rather than 429ing every comparison forever."""
        monkeypatch.setenv(ENV_COMPARE_COST, "10")
        monkeypatch.setenv(ENV_RATE_BURST, "5")
        with pytest.raises(ValueError, match="could never be served"):
            Settings.from_env()

    def test_negative_proxy_hops_are_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(ENV_TRUSTED_PROXY_HOPS, "-1")
        with pytest.raises(ValueError, match="cannot be negative"):
            Settings.from_env()
