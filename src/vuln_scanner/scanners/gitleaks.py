"""Gitleaks scanner integration."""

import json
import logging
import subprocess
from pathlib import Path

from .base import AbstractScanner, Finding

logger = logging.getLogger(__name__)


class GitleaksScanner(AbstractScanner):
    """Scanner wrapping the gitleaks CLI tool."""

    name = "gitleaks"

    def run(self, repo_path: Path) -> list[Finding]:
        if not self.check_installed():
            logger.warning(
                "gitleaks is not installed. Skipping gitleaks scan."
            )
            return []

        cmd = [
            "gitleaks", "detect",
            f"--source={repo_path}",
            "--no-git",
            "--report-format=json",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError:
            logger.warning("gitleaks not found on PATH. Skipping.")
            return []
        except subprocess.TimeoutExpired:
            logger.error("gitleaks scan timed out for %s", repo_path)
            return []

        # gitleaks exits 1 when leaks are found (expected)
        if proc.returncode not in (0, 1):
            logger.error("gitleaks failed: %s", proc.stderr)
            return []

        if not proc.stdout.strip():
            logger.info("gitleaks found nothing")
            return []

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.error("Failed to parse gitleaks JSON output")
            return []

        # Handle both list and dict-with-results formats
        if isinstance(data, dict):
            leaks = data.get("results", data.get("leaks", []))
        elif isinstance(data, list):
            leaks = data
        else:
            logger.error("Unexpected gitleaks output format: %s", type(data))
            return []

        repo_path_str = str(repo_path)
        findings: list[Finding] = []
        for leak in leaks:
            file_path = leak.get("File", "")
            if file_path.startswith(repo_path_str):
                file_path = file_path[len(repo_path_str):].lstrip("/")

            finding = Finding(
                rule_id=leak.get("RuleID", ""),
                message=leak.get("Description", ""),
                severity="error",
                file_path=file_path,
                line_start=leak.get("StartLine"),
                line_end=leak.get("EndLine"),
                scanner="gitleaks",
                confidence="high",
            )
            findings.append(finding)

        logger.info("gitleaks found %d finding(s)", len(findings))
        return findings
