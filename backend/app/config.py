"""Runtime configuration.

All settings come from environment variables (prefix ``TW_``) or an env file.
Secrets (AI API key, session secret) are never logged; see ``Settings.safe_dict``.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TW_", env_file=None, extra="ignore")

    # Storage
    data_dir: Path = Path("./data")
    db_filename: str = "threatwatch.db"

    # Web
    static_dir: Path | None = None  # built frontend assets; served by the API when set
    cookie_secure: bool = True  # set False only for local http development
    session_days: int = 30
    trusted_hosts: str = "*"  # comma separated, e.g. "watch.thefish.nz,threatwatch.tailnet.ts.net"
    login_max_attempts: int = 8  # per 15 minutes, per client
    timezone: str = "Pacific/Auckland"

    # Ingestion
    ingest_interval_minutes: int = 30
    briefing_hour: int = 7
    briefing_minute: int = 0
    http_timeout_seconds: float = 20.0
    http_max_bytes: int = 15 * 1024 * 1024  # KEV JSON is ~2 MB; Google TI RSS ~1.5 MB
    user_agent: str = "ThreatWatch/1.0 (+personal security news reader)"
    ingest_max_age_days: int = 60  # ignore feed items older than this (initial backlog)
    ingest_max_items_per_fetch: int = 60
    retention_days: int = 365  # articles older than this (and not saved/linked) are pruned

    # AI (optional; app works without it)
    ai_provider: str = "anthropic"  # "anthropic" or "none"
    anthropic_api_key: SecretStr | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    ai_model: str = "claude-opus-5-5"
    ai_effort: str = "low"  # low effort is ample for summarisation / extraction
    ai_daily_budget_usd: float = 2.00
    ai_max_requests_per_run: int = 40
    ai_input_usd_per_mtok: float = 4.00
    ai_output_usd_per_mtok: float = 20.00
    ai_server_fallback: bool = True  # server-side refusal fallback (beta)

    # Web push (optional; requires HTTPS deployment)
    vapid_public_key: str | None = None
    vapid_private_key: SecretStr | None = None
    vapid_subject: str = "mailto:admin@localhost"

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_filename

    @property
    def ai_enabled(self) -> bool:
        return self.ai_provider == "anthropic" and self.anthropic_api_key is not None and bool(
            self.anthropic_api_key.get_secret_value().strip()
        )

    def safe_dict(self) -> dict:
        d = self.model_dump()
        for k in ("anthropic_api_key", "vapid_private_key"):
            d[k] = "***set***" if d.get(k) else None
        d["data_dir"] = str(self.data_dir)
        d["static_dir"] = str(self.static_dir) if self.static_dir else None
        return d


@lru_cache
def get_settings() -> Settings:
    return Settings()
