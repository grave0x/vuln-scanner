"""Semgrep scanner integration."""

import json
import logging
import subprocess
from pathlib import Path

from .base import AbstractScanner, Finding

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "ERROR": "error",
    "WARNING": "warning",
    "INFO": "note",
}

_CONFIDENCE_MAP: dict[str, str] = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


class SemgrepScanner(AbstractScanner):
    """Scanner wrapping the semgrep CLI tool."""

    name = "semgrep"

    def run(self, repo_path: Path) -> list[Finding]:
        if not self.check_installed():
            logger.warning(
                "semgrep is not installed. Skipping semgrep scan."
            )
            return []

        cmd = [
            "semgrep", "scan",
            "--config=p/default",
            "--json",
            "--quiet",
            "--no-git-ignore",
            str(repo_path),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError:
            logger.warning("semgrep not found on PATH. Skipping.")
            return []
        except subprocess.TimeoutExpired:
            logger.error("semgrep scan timed out for %s", repo_path)
            return []

        if proc.returncode != 0 and not proc.stdout.strip():
            logger.error("semgrep failed: %s", proc.stderr)
            return []

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.error("Failed to parse semgrep JSON output")
            return []

        findings: list[Finding] = []
        repo_path_str = str(repo_path)
        for result in data.get("results", []):
            check_id = result.get("check_id", "")
            extra = result.get("extra", {})
            raw_severity = extra.get("severity", "WARNING")
            severity = _SEVERITY_MAP.get(raw_severity, "warning")
            confidence = _CONFIDENCE_MAP.get(raw_severity, "medium")

            file_path = result.get("path", "")
            if file_path.startswith(repo_path_str):
                file_path = file_path[len(repo_path_str):].lstrip("/")

            start = result.get("start", {})
            end = result.get("end", {})

            finding = Finding(
                rule_id=check_id,
                message=extra.get("message", ""),
                severity=severity,
                file_path=file_path,
                line_start=start.get("line"),
                line_end=end.get("line"),
                column_start=start.get("col"),
                column_end=end.get("col"),
                scanner="semgrep",
                confidence=confidence,
            )
            findings.append(finding)

        logger.info("semgrep found %d finding(s)", len(findings))
        return findings
