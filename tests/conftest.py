from pathlib import Path

import pytest

from phishlens.config import Settings

SAMPLES = Path(__file__).resolve().parent.parent / "phishlens" / "samples"


@pytest.fixture
def phishing_raw() -> str:
    return (SAMPLES / "phishing.eml").read_text(encoding="utf-8")


@pytest.fixture
def legit_raw() -> str:
    return (SAMPLES / "legitimate.eml").read_text(encoding="utf-8")


@pytest.fixture
def no_keys() -> Settings:
    return Settings(
        safe_browsing_key=None,
        urlhaus_key=None,
        anthropic_key=None,
        llm_model="test-model",
        max_email_bytes=2_000_000,
        rate_limit_per_minute=1000,
        intel_timeout_seconds=1,
    )


@pytest.fixture(autouse=True)
def _clear_api_keys(monkeypatch):
    """Tests never call real external services."""
    for var in ("SAFE_BROWSING_API_KEY", "URLHAUS_AUTH_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("PHISHLENS_RATE_LIMIT", "1000")
