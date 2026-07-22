"""Scanner registry for discovery and selection."""

import logging
from pathlib import Path
from typing import Type

from .base import AbstractScanner
from .semgrep import SemgrepScanner
from .gitleaks import GitleaksScanner
from .checkov import CheckovScanner
from .dependency import DependencyScanner
from .trufflehog import TrufflehogScanner

logger = logging.getLogger(__name__)

SCANNER_REGISTRY: dict[str, Type[AbstractScanner]] = {
    "semgrep": SemgrepScanner,
    "gitleaks": GitleaksScanner,
    "trufflehog": TrufflehogScanner,
    "checkov": CheckovScanner,
    "dependency": DependencyScanner,
}


def select_scanners(toggles: dict[str, bool]) -> list[AbstractScanner]:
    """Select and instantiate enabled scanners that are installed.

    Args:
        toggles: Dict mapping scanner names to boolean enable/disable flags.

    Returns:
        List of instantiated scanner objects (only those enabled AND installed).
    """
    selected = []
    for name, enabled in toggles.items():
        if not enabled:
            continue
        cls = SCANNER_REGISTRY.get(name)
        if cls is None:
            logger.warning(f"Unknown scanner: {name}")
            continue
        scanner = cls()
        if not scanner.check_installed():
            logger.warning(
                f"Scanner '{name}' is enabled but the CLI tool is not installed. Skipping."
            )
            continue
        selected.append(scanner)
    return selected


def list_scanners() -> None:
    """Print all registered scanners and their install status."""
    print(f"{'Scanner':<15} {'Installed':<12} {'Version'}")
    print("-" * 50)
    for name, cls in SCANNER_REGISTRY.items():
        scanner = cls()
        installed = "\u2713" if scanner.check_installed() else "\u2717"
        version = scanner.version() or "N/A"
        print(f"{name:<15} {installed:<12} {version}")
