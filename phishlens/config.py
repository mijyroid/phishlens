"""Runtime settings, read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    safe_browsing_key: str | None
    urlhaus_key: str | None
    anthropic_key: str | None
    llm_model: str
    max_email_bytes: int
    rate_limit_per_minute: int
    intel_timeout_seconds: float


def get_settings() -> Settings:
    return Settings(
        safe_browsing_key=os.environ.get("SAFE_BROWSING_API_KEY") or None,
        urlhaus_key=os.environ.get("URLHAUS_AUTH_KEY") or None,
        anthropic_key=os.environ.get("ANTHROPIC_API_KEY") or None,
        llm_model=os.environ.get("PHISHLENS_LLM_MODEL", "claude-haiku-5-5"),
        max_email_bytes=_int("PHISHLENS_MAX_EMAIL_BYTES", 2_000_000),
        rate_limit_per_minute=_int("PHISHLENS_RATE_LIMIT", 20),
        intel_timeout_seconds=float(os.environ.get("PHISHLENS_INTEL_TIMEOUT", "5")),
    )
