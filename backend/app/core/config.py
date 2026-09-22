"""Application settings.

Every value comes from the environment with the ``DIOPTRA_`` prefix. There is no
default for any secret: the process MUST refuse to boot rather than run with a
guessable key (see tasks/phase0-survey.md, risk 2).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

MIN_JWT_SECRET_LENGTH = 32


class Settings(BaseSettings):
    """Runtime configuration, validated at import of the app factory."""

    model_config = SettingsConfigDict(
        env_prefix="DIOPTRA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    env: Literal["dev", "test", "prod"] = "prod"
    database_url: str = "postgresql+psycopg://dioptra:dioptra@localhost:5432/dioptra"

    jwt_secret: SecretStr
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    jwt_issuer: str = "dioptra"

    access_token_ttl_seconds: int = Field(default=900, ge=60, le=3600)
    refresh_token_ttl_seconds: int = Field(default=28_800, ge=300, le=604_800)

    # Lockout: the Nth consecutive failure (1-based, past the threshold) picks
    # the Nth backoff step; the last step repeats for further failures.
    lockout_threshold: int = Field(default=5, ge=3, le=20)
    lockout_backoff_seconds: tuple[int, ...] = (60, 120, 240, 480, 900)

    # Browsers only: the refresh token lives in an HttpOnly cookie so no script
    # in the audited-code-rendering UI can read it.
    refresh_cookie_name: str = "dioptra_refresh"
    refresh_cookie_secure: bool = True

    # The frontend is served from the same origin in production; this list only
    # exists for the split dev servers (Vite on 5173).
    cors_origins: tuple[str, ...] = ()

    # --- Phase 1: ingest + analysis pipeline (tasks/phase1-survey.md) ---
    #: Root of every per-analysis jail. Audited code is extracted under
    #: ``<root>/<project_id>/<analysis_id>/src`` and never anywhere else.
    workspace_root: Path = Path("/var/lib/dioptra/workspaces")
    max_zip_bytes: int = Field(default=200 * 1024 * 1024, ge=1024)
    max_unpacked_bytes: int = Field(default=1024 * 1024 * 1024, ge=1024)
    max_zip_entries: int = Field(default=50_000, ge=1)
    max_zip_ratio: int = Field(default=100, ge=2)
    git_clone_timeout_seconds: int = Field(default=300, ge=10)

    #: RQ broker. ``queue_inline`` runs every job synchronously in the calling
    #: process — the test suite and single-process development need no broker.
    redis_url: str = "redis://valkey:6379/0"
    queue_inline: bool = False

    #: ``docker`` runs each tool in an ephemeral container with no network;
    #: ``local`` runs the same argv on the host (development, CI fixtures).
    runner_mode: Literal["docker", "local"] = "docker"
    analysis_image: str = "dioptra-analysis:latest"
    runner_timeout_seconds: int = Field(default=600, ge=30)
    runner_memory: str = "2g"
    runner_cpus: str = "2"
    runner_pids_limit: int = Field(default=512, ge=16)
    #: uid:gid the analysis containers run as. Never root. It must own the
    #: jails the API/worker create (mode 0700), i.e. match the process that
    #: writes DIOPTRA_DATA_DIR — 10001 in the shipped images; a developer
    #: running the API on the host sets their own uid here.
    runner_user: str = Field(default="10001:10001", pattern=r"^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$")
    #: Local OSV database directory (offline mode). Empty → OSV-Scanner is
    #: recorded as a coverage gap, never queried live.
    osv_db_dir: Path | None = None
    #: Our own analysis policy: Semgrep rules (``semgrep/``), the vendored
    #: gitleaks rule set (``gitleaks/``) and the OSV-Scanner config
    #: (``osv-scanner/``). Every scanner is pointed at THIS tree so a config
    #: file shipped inside the audited code is never honoured.
    rules_dir: Path = Path("/srv/app/rules")
    #: Findings persisted per analysis, worst first; the rest is a recorded
    #: coverage gap. Bounds report rendering against a tree built to hit a
    #: rule on every line.
    max_findings_per_analysis: int = Field(default=2000, ge=100)
    #: Caps on what is read back from a tool: hostile output must not fill the DB.
    max_tool_output_bytes: int = Field(default=32 * 1024 * 1024, ge=1024)

    @model_validator(mode="after")
    def _prod_requires_a_secure_refresh_cookie(self) -> Settings:
        """Refuse to boot a production instance that would leak the refresh token.

        Compose publishes plain HTTP, so an operator whose refresh silently
        breaks off localhost has one obvious "fix": turn this flag off. That puts
        a long-lived session token in cleartext on the factory LAN. Failing at
        startup makes the real fix (terminate TLS in front) the only way forward.
        """
        if self.env == "prod" and not self.refresh_cookie_secure:
            message = (
                "DIOPTRA_REFRESH_COOKIE_SECURE must stay true when DIOPTRA_ENV=prod: "
                "serve the app over HTTPS instead of weakening the cookie"
            )
            raise ValueError(message)
        return self

    @field_validator("jwt_secret")
    @classmethod
    def _secret_must_be_long_enough(cls, value: SecretStr) -> SecretStr:
        if len(value.get_secret_value()) < MIN_JWT_SECRET_LENGTH:
            message = f"DIOPTRA_JWT_SECRET must be at least {MIN_JWT_SECRET_LENGTH} characters"
            raise ValueError(message)
        return value

    @field_validator("lockout_backoff_seconds")
    @classmethod
    def _backoff_must_be_non_empty(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if not value:
            message = "DIOPTRA_LOCKOUT_BACKOFF_SECONDS must contain at least one step"
            raise ValueError(message)
        return value

    def backoff_for(self, consecutive_failures: int) -> int:
        """Seconds to lock the account after ``consecutive_failures`` failures."""
        steps_past_threshold = consecutive_failures - self.lockout_threshold
        index = min(max(steps_past_threshold, 0), len(self.lockout_backoff_seconds) - 1)
        return self.lockout_backoff_seconds[index]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton (cache cleared by tests)."""
    return Settings()  # type: ignore[call-arg]  # values arrive from the environment
