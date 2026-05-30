"""
config.py — Centralised configuration for auth-audit.

All settings are loaded from environment variables (or a .env file via
python-dotenv).  No secrets or environment-specific values are hardcoded here.

Usage:
    from config import settings
    print(settings.llm_base_url)

Every field is typed and validated by Pydantic's BaseSettings so that
configuration errors surface at startup, not at runtime deep inside a tier.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Runtime configuration for the auth-audit pipeline.

    Values are sourced from (in priority order):
      1. Real environment variables
      2. A .env file in the working directory
      3. Defaults defined below
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -------------------------------------------------------------------------
    # Input / Output paths
    # -------------------------------------------------------------------------

    proxy_hosts_file: Path = Field(
        default=Path("data/proxy_hosts.json"),
        description="Path to the proxy host JSON input file.",
    )
    output_dir: Path = Field(
        default=Path("output"),
        description="Root directory for all pipeline output artifacts.",
    )
    results_json: Path = Field(
        default=Path("output/results.json"),
        description="Path where the final JSON results file is written.",
    )
    results_jsonl: Path = Field(
        default=Path("output/results.jsonl"),
        description="Path where the final JSONL results file is written.",
    )
    results_html: Path = Field(
        default=Path("output/results.html"),
        description="Path where the HTML report is written.",
    )
    screenshots_dir: Path = Field(
        default=Path("output/screenshots"),
        description="Directory for browser screenshots from Tier 3 escalation.",
    )

    # -------------------------------------------------------------------------
    # Active Discovery — API route discovery (pre-probe wordlist / kiterunner)
    # -------------------------------------------------------------------------

    discovery_enabled: bool = Field(
        default=True,
        description="Enable Phase 0 route discovery for all-404 domains.",
    )
    discovery_trigger_404_ratio: Annotated[float, Field(ge=0.0, le=1.0)] = Field(
        default=0.9,
        description=(
            "Minimum ratio of 404 responses in initial probes that triggers "
            "Phase 0 route discovery."
        ),
    )
    kiterunner_enabled: bool = Field(
        default=False,
        description="If true, invoke kiterunner binary for route discovery (requires 'kr' on PATH).",
    )
    kiterunner_binary: str = Field(
        default="kr",
        description="Path or name of the kiterunner binary.",
    )
    kiterunner_wordlist: Path | None = Field(
        default=None,
        description="Path to kiterunner .kite wordlist file. Defaults to routes.kite in CWD.",
    )
    kiterunner_concurrency: Annotated[int, Field(ge=1, le=50)] = Field(
        default=3,
        description="Concurrent threads for kiterunner scanning.",
    )
    kiterunner_timeout: Annotated[float, Field(gt=0)] = Field(
        default=120.0,
        description="Timeout in seconds for kiterunner subprocess execution.",
    )

    # -------------------------------------------------------------------------
    # Tier 1 — Async HTTP probing
    # -------------------------------------------------------------------------

    prober_concurrency: Annotated[int, Field(ge=1, le=200)] = Field(
        default=10,
        description="Maximum number of concurrent HTTP probe workers.",
    )
    http_timeout: Annotated[float, Field(gt=0)] = Field(
        default=15.0,
        description="HTTP request timeout in seconds (connect + read combined).",
    )
    http_max_redirects: Annotated[int, Field(ge=0, le=30)] = Field(
        default=10,
        description="Maximum number of redirects followed per probe request.",
    )
    body_preview_bytes: Annotated[int, Field(ge=256, le=65536)] = Field(
        default=8192,
        description="Maximum body bytes captured as a preview per probe response.",
    )
    http_user_agent: str = Field(
        default="auth-audit/0.1 (security audit pipeline)",
        description="User-Agent header sent with all HTTP probe requests.",
    )

    # -------------------------------------------------------------------------
    # Tier 2 — Local LLM / LLM reasoning
    # -------------------------------------------------------------------------

    llm_base_url: AnyHttpUrl = Field(
        default="http://localhost:8000/v1",  # type: ignore[assignment]
        description="Base URL of the Local LLM-compatible OpenAI API endpoint.",
    )
    llm_api_key: str | None = Field(
        default=None,
        description="API key for the Local LLM endpoint (None if no auth required).",
    )
    llm_model: str = Field(
        default="qwen3.6-27b",
        description="Model identifier passed to the Local LLM API.",
    )
    llm_max_tokens: Annotated[int, Field(ge=128, le=32768)] = Field(
        default=2048,
        description="Maximum tokens the LLM may generate per completion.",
    )
    llm_temperature: Annotated[float, Field(ge=0.0, le=2.0)] = Field(
        default=0.1,
        description="Sampling temperature for LLM calls (0 = deterministic).",
    )
    llm_max_html_chars: Annotated[int, Field(ge=500, le=32000)] = Field(
        default=4000,
        description="Maximum characters of summarised HTML sent to the LLM per domain.",
    )
    tier2_escalation_threshold: Annotated[int, Field(ge=0, le=100)] = Field(
        default=60,
        description=(
            "Minimum rule_score below which Tier 2 LLM analysis is always invoked. "
            "Domains with rule_score < this value are sent to Tier 2."
        ),
    )
    llm_concurrency: Annotated[int, Field(ge=1, le=50)] = Field(
        default=5,
        description="Maximum number of concurrent Local LLM analysis tasks.",
    )

    # Retry settings for Local LLM API calls
    llm_retry_attempts: Annotated[int, Field(ge=1, le=10)] = Field(
        default=2,
        description="Maximum retry attempts for transient Local LLM API errors.",
    )

    # -------------------------------------------------------------------------
    # Tier 3 — Hermes browser automation
    # -------------------------------------------------------------------------

    hermes_base_url: AnyHttpUrl = Field(
        default="http://localhost:8080",  # type: ignore[assignment]
        description="Base URL of the Hermes Agent API.",
    )
    hermes_api_key: str | None = Field(
        default=None,
        description="API key for the Hermes Agent (None if no auth required).",
    )
    hermes_task_timeout: Annotated[float, Field(gt=0)] = Field(
        default=120.0,
        description="Timeout in seconds for a single Hermes browser task.",
    )
    hermes_concurrency: Annotated[int, Field(ge=1, le=20)] = Field(
        default=5,
        description="Maximum number of concurrent Hermes browser automation tasks.",
    )

    # -------------------------------------------------------------------------
    # Screenshot storage — Ceph / S3-compatible object store
    # -------------------------------------------------------------------------

    s3_endpoint: str | None = Field(
        default=None,
        description=(
            "S3-compatible endpoint URL (e.g. http://s3.amazonaws.com or http://localhost:9000). "
            "Leave unset to skip screenshot upload entirely."
        ),
    )
    s3_bucket: str = Field(
        default="auth-audit-screenshots",
        description="S3 bucket name for screenshot storage.",
    )
    s3_access_key: str | None = Field(
        default=None,
        description="S3 access key (AWS_ACCESS_KEY_ID equivalent).",
    )
    s3_secret_key: str | None = Field(
        default=None,
        description="S3 secret key (AWS_SECRET_ACCESS_KEY equivalent).",
    )
    s3_screenshot_prefix: str = Field(
        default="auth-audit/screenshots",
        description="Key prefix inside the bucket for all screenshot objects.",
    )
    s3_report_prefix: str = Field(
        default="auth-audit/reports",
        description="Key prefix inside the bucket for HTML reports.",
    )
    s3_public_base_url: str | None = Field(
        default=None,
        description=(
            "Override for the public base URL used to construct screenshot URLs. "
            "Defaults to {s3_endpoint}/{s3_bucket}. Useful for CDN or path-style access."
        ),
    )

    @property
    def s3_enabled(self) -> bool:
        """True when all required S3 fields are configured."""
        return bool(self.s3_endpoint and self.s3_access_key and self.s3_secret_key)

    def s3_screenshot_url(self, key: str) -> str:
        """Build the public URL for a given S3 object key."""
        base = (self.s3_public_base_url or f"{self.s3_endpoint}/{self.s3_bucket}").rstrip("/")
        return f"{base}/{key}"


    http_retry_attempts: Annotated[int, Field(ge=1, le=10)] = Field(
        default=3,
        description="Maximum retry attempts for transient Tier 1 network errors.",
    )
    http_retry_wait: Annotated[float, Field(ge=0.1, le=60.0)] = Field(
        default=1.0,
        description="Base wait time in seconds between HTTP retries (exponential backoff).",
    )

    # -------------------------------------------------------------------------
    # Logging
    # -------------------------------------------------------------------------

    log_level: str = Field(
        default="INFO",
        description="Logging verbosity: DEBUG | INFO | WARNING | ERROR.",
    )
    log_rich: bool = Field(
        default=True,
        description="Enable Rich console output for prettier logs.",
    )
    log_file: Path | None = Field(
        default=None,
        description="Optional file path to tee log output. None means stdout only.",
    )

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}, got {v!r}")
        return upper

    @model_validator(mode="after")
    def _ensure_output_dirs_consistent(self) -> "Settings":
        """
        Warn (but do not fail) if results_json / results_html sit outside
        output_dir — callers may use absolute paths intentionally.
        """
        return self


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------

def get_settings() -> Settings:
    """
    Return the global Settings instance, loading from .env on first call.

    Import this function (not the ``settings`` singleton directly) in modules
    that need to support swapping settings during testing.
    """
    return _settings


# Module-level singleton — instantiated once at import time.
# Tests can override individual fields via environment variables or by
# monkey-patching ``config._settings`` before importing dependent modules.
_settings: Settings = Settings()

#: Convenience alias — ``from config import settings`` for normal usage.
settings: Settings = _settings
