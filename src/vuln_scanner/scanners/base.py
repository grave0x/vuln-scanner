"""Abstract base scanner and Finding dataclass."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Finding:
    """A single vulnerability finding from any scanner."""
    rule_id: str
    message: str
    severity: str  # "error", "warning", or "note"
    file_path: str  # relative to repo root
    line_start: int | None = None
    line_end: int | None = None
    column_start: int | None = None
    column_end: int | None = None
    scanner: str = ""
    confidence: str = "medium"  # "high", "medium", "low"
    suggestion: str | None = None
    raw: dict = field(default_factory=dict)


class AbstractScanner(ABC):
    """Base class for all vulnerability scanners."""

    name: str = "abstract"

    def check_installed(self) -> bool:
        """Check if the CLI tool is available on PATH."""
        import shutil
        return shutil.which(self.name) is not None

    def version(self) -> str | None:
        """Get the scanner tool version string."""
        return None

    @abstractmethod
    def run(self, repo_path: Path) -> list[Finding]:
        """Execute the scan and return findings."""
        ...
