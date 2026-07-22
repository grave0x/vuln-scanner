"""Configuration data model and YAML loader."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised on configuration validation failure."""


@dataclass
class Settings:
    """Global scanner settings."""
    work_dir: str = "/tmp/vuln-scanner"
    max_concurrent_scanners: int = 4
    timeout_per_scanner: int = 600
    shallow_clone: bool = True
    cleanup_after_scan: bool = True


@dataclass
class RepoConfig:
    """Configuration for a single repository to scan."""
    url: str = ""
    branch: str = "main"
    depth: int = 50
    schedule: str = "daily"
    scanners: dict = field(default_factory=lambda: {
        "semgrep": True,
        "gitleaks": True,
        "trufflehog": False,
        "checkov": True,
        "dependency": True,
    })
    semgrep_rules: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)


@dataclass
class ScannerDefaults:
    """Default configuration for individual scanners."""
    semgrep_config: str = "auto"
    semgrep_metrics: str = "off"
    gitleaks_config_path: str = ""
    gitleaks_redact: bool = True
    checkov_framework: str = "all"
    checkov_skip_frameworks: list[str] = field(default_factory=list)
    dependency_primary_tool: str = "osv-scanner"
    dependency_ecosystem_tools: bool = False


@dataclass
class Reporting:
    """Reporting output configuration."""
    sarif_path: str = "results.sarif"
    summary_path: str = "summary.md"


@dataclass
class Config:
    """Top-level configuration for vuln-scanner."""
    version: int = 1
    settings: Settings = field(default_factory=Settings)
    repositories: list[RepoConfig] = field(default_factory=list)
    scanners: ScannerDefaults = field(default_factory=ScannerDefaults)
    reporting: Reporting = field(default_factory=Reporting)

    @classmethod
    def load(cls, path: str) -> "Config":
        """Load and validate configuration from a YAML file.

        Args:
            path: Path to the YAML configuration file.

        Returns:
            A validated Config instance.

        Raises:
            ConfigError: On any validation failure.
            FileNotFoundError: If the config file does not exist.
        """
        config_path = Path(path)
        if not config_path.is_file():
            raise ConfigError(f"Config file not found: {path}")

        raw = config_path.read_text()
        try:
            data = yaml.safe_load(raw) or {}
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in config file: {e}") from e

        # Validate version
        version = data.get("version")
        if version is None:
            raise ConfigError("Config is missing required field 'version'")
        if version != 1:
            raise ConfigError(f"Unsupported config version: {version}. "
                              f"Only version 1 is supported.")

        # Validate repositories
        repos_data = data.get("repositories", [])
        if not isinstance(repos_data, list):
            raise ConfigError("'repositories' must be a list")

        repositories: list[RepoConfig] = []
        for i, repo in enumerate(repos_data):
            if not isinstance(repo, dict):
                raise ConfigError(
                    f"Repository at index {i} must be a mapping, "
                    f"got {type(repo).__name__}"
                )
            if "url" not in repo or not repo["url"]:
                raise ConfigError(
                    f"Repository at index {i} is missing required field 'url'"
                )
            repositories.append(cls._build_repo_config(repo))

        # Build settings
        settings = cls._build_settings(data.get("settings", {}))

        # Build scanner defaults
        scanner_defaults = cls._build_scanner_defaults(
            data.get("scanners", {})
        )

        # Build reporting
        reporting = cls._build_reporting(data.get("reporting", {}))

        config = cls(
            version=version,
            settings=settings,
            repositories=repositories,
            scanners=scanner_defaults,
            reporting=reporting,
        )
        logger.info("Loaded config from %s with %d repositories",
                     path, len(repositories))
        return config

    @staticmethod
    def _build_settings(data: dict) -> Settings:
        kwargs: dict = {}
        for field_name in ("work_dir", "max_concurrent_scanners",
                           "timeout_per_scanner", "shallow_clone",
                           "cleanup_after_scan"):
            if field_name in data:
                kwargs[field_name] = data[field_name]
        return Settings(**kwargs)

    @staticmethod
    def _build_repo_config(data: dict) -> RepoConfig:
        kwargs: dict = {"url": data["url"]}
        for field_name in ("branch", "depth", "schedule", "scanners",
                           "semgrep_rules", "exclude_paths"):
            if field_name in data:
                kwargs[field_name] = data[field_name]
        return RepoConfig(**kwargs)

    @staticmethod
    def _build_scanner_defaults(data: dict) -> ScannerDefaults:
        kwargs: dict = {}
        for field_name in ("semgrep_config", "semgrep_metrics",
                           "gitleaks_config_path", "gitleaks_redact",
                           "checkov_framework", "checkov_skip_frameworks",
                           "dependency_primary_tool",
                           "dependency_ecosystem_tools"):
            if field_name in data:
                kwargs[field_name] = data[field_name]
        return ScannerDefaults(**kwargs)

    @staticmethod
    def _build_reporting(data: dict) -> Reporting:
        kwargs: dict = {}
        for field_name in ("sarif_path", "summary_path"):
            if field_name in data:
                kwargs[field_name] = data[field_name]
        return Reporting(**kwargs)
