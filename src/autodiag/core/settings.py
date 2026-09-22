"""Runtime settings.

Precedence (highest first): explicit kwargs, ``AUTODIAG_*`` environment variables,
``.env`` file, the TOML file named by ``AUTODIAG_CONFIG`` (default
``~/.config/autodiag/config.toml``), then the generic defaults below.

Defaults are deliberately loopback-only and environment-neutral; real hosts, models and
targets belong in the git-ignored TOML file.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource,
)

DEFAULT_CONFIG_PATH = "~/.config/autodiag/config.toml"
CONFIG_ENV_VAR = "AUTODIAG_CONFIG"


def config_file_path() -> Path:
    return Path(os.path.expanduser(os.environ.get(CONFIG_ENV_VAR, DEFAULT_CONFIG_PATH)))


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AUTODIAG_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Storage
    data_dir: Path = Field(default=Path("~/.local/share/autodiag"))
    targets_file: Path = Field(default=Path("~/.config/autodiag/targets.yaml"))

    # Service
    listen_host: str = "127.0.0.1"
    listen_port: int = 8790
    mcp_token: str | None = Field(default=None, description="Bearer token for /mcp and /api")

    # LLM (optional; the core never needs it)
    ollama_primary_url: str = "http://127.0.0.1:11434"
    ollama_fallback_url: str | None = None
    ollama_advisor_model: str = "qwen3:27b"
    ollama_embedding_model: str = "nomic-embed-text:latest"
    ollama_num_ctx: int = 32768
    ollama_request_timeout: float = 300.0
    ollama_health_cache_seconds: float = 30.0

    # Tool output discipline (MCP boundary)
    redact_for_llm: bool = True
    tool_max_lines: int = 200
    tool_max_lines_hard_cap: int = 1000
    tool_max_bytes: int = 16384

    # Transports
    ssh_config: Path | None = Field(default=None, description="ssh_config file passed with -F")
    ssh_connect_timeout: int = 10
    ssh_command_timeout: int = 120
    sql_timeout: int = 60

    # Housekeeping
    retention_days: int = 90
    scan_interval_minutes: int = 30

    @field_validator("data_dir", "targets_file", "ssh_config", mode="after")
    @classmethod
    def _expand_user(cls, value: Path | None) -> Path | None:
        if value is None:
            return None
        return Path(os.path.expanduser(str(value))).resolve()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        sources: list[PydanticBaseSettingsSource] = [init_settings, env_settings, dotenv_settings]
        toml_path = config_file_path()
        if toml_path.is_file():
            sources.append(TomlConfigSettingsSource(settings_cls, toml_file=toml_path))
        sources.append(file_secret_settings)
        return tuple(sources)


def load_settings(env_file: str | None = ".env", **overrides: object) -> Settings:
    """Build settings; ``env_file=None`` disables ``.env`` loading (used by tests)."""
    return Settings(_env_file=env_file, **overrides)  # type: ignore[call-arg]
