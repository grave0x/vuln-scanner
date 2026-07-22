"""Checkov scanner integration (IaC security)."""

import json
import logging
import subprocess
from pathlib import Path

from .base import AbstractScanner, Finding

logger = logging.getLogger(__name__)

_SEVERITY_MAP: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "UNKNOWN": "note",
}


class CheckovScanner(AbstractScanner):
    """Scanner wrapping the checkov CLI tool for IaC scanning."""

    name = "checkov"

    def run(self, repo_path: Path) -> list[Finding]:
        if not self.check_installed():
            logger.warning(
                "checkov is not installed. Skipping checkov scan."
            )
            return []

        cmd = [
            "checkov",
            f"--directory={repo_path}",
            "--output", "json",
            "--quiet",
            "--skip-framework", "secrets",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError:
            logger.warning("checkov not found on PATH. Skipping.")
            return []
        except subprocess.TimeoutExpired:
            logger.error("checkov scan timed out for %s", repo_path)
            return []

        if proc.returncode != 0 and not proc.stdout.strip():
            logger.error("checkov failed: %s", proc.stderr)
            return []

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.error("Failed to parse checkov JSON output")
            return []

        # checkov can return a dict with "results" key or a list
        if isinstance(data, list):
            results = data
        elif isinstance(data, dict):
            # Try common keys: results, failed_checks
            results = []
            for key in ("results", "failed_checks"):
                val = data.get(key)
                if isinstance(val, list):
                    results.extend(val)
        else:
            logger.error("Unexpected checkov output format: %s", type(data))
            return []

        repo_path_str = str(repo_path)
        findings: list[Finding] = []
        for item in results:
            if not isinstance(item, dict):
                continue

            file_path = item.get("file_path", "")
            if file_path.startswith(repo_path_str):
                file_path = file_path[len(repo_path_str):].lstrip("/")

            line_range = item.get("file_line_range", [])
            line_start = line_range[0] if line_range else None

            raw_severity = item.get("severity", "MEDIUM")
            severity = _SEVERITY_MAP.get(raw_severity, "warning")

            finding = Finding(
                rule_id=item.get("check_id", ""),
                message=item.get("check_name", ""),
                severity=severity,
                file_path=file_path,
                line_start=line_start,
                scanner="checkov",
                confidence="medium",
            )
            findings.append(finding)

        logger.info("checkov found %d finding(s)", len(findings))
        return findings
