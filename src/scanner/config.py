"""Scanner configuration management.

Handles loading settings from environment variables, .env files,
and CLI flags. Uses Pydantic for validation.
"""

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings


class ScannerConfig(BaseSettings):
    """Global configuration for the scanner."""

    model_config = {"env_prefix": "SCANNER_", "env_file": ".env", "extra": "ignore"}

    solc_version: str = Field(default="0.8.28", description="Solidity compiler version to use.")
    solc_binary: str | None = Field(
        default=None, description="Path to a local solc binary. Overrides managed version."
    )
    output_dir: Path = Field(
        default=Path("reports"), description="Directory for analysis output."
    )
    log_level: str = Field(default="INFO", description="Logging verbosity.")


def load_config(**overrides: object) -> ScannerConfig:
    """Load scanner configuration with optional overrides.

    Returns a validated ScannerConfig instance. Environment variables
    prefixed with SCANNER_ take precedence over defaults.
    """
    return ScannerConfig(**overrides)  # type: ignore[arg-type]
