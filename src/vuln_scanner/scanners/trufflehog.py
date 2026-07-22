"""TruffleHog scanner integration."""

import json
import logging
import subprocess
from pathlib import Path

from .base import AbstractScanner, Finding

logger = logging.getLogger(__name__)


class TrufflehogScanner(AbstractScanner):
    """Scanner wrapping the trufflehog CLI tool."""

    name = "trufflehog"

    def run(self, repo_path: Path) -> list[Finding]:
        if not self.check_installed():
            logger.warning(
                "trufflehog is not installed. Skipping trufflehog scan."
            )
            return []

        cmd = [
            "trufflehog", "filesystem",
            str(repo_path),
            "--json",
            "--no-update",
            "--no-verification",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError:
            logger.warning("trufflehog not found on PATH. Skipping.")
            return []
        except subprocess.TimeoutExpired:
            logger.error("trufflehog scan timed out for %s", repo_path)
            return []

        if proc.returncode != 0:
            logger.error("trufflehog failed: %s", proc.stderr)
            return []

        if not proc.stdout.strip():
            logger.info("trufflehog found nothing")
            return []

        repo_path_str = str(repo_path)
        findings: list[Finding] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Failed to parse trufflehog JSON line: %s", line[:200])
                continue

            file_path = (
                obj.get("SourceMetadata", {})
                .get("Data", {})
                .get("Filesystem", {})
                .get("file", "")
            )
            if file_path.startswith(repo_path_str):
                file_path = file_path[len(repo_path_str):].lstrip("/")

            finding = Finding(
                rule_id=obj.get("DetectorName", ""),
                message=obj.get("DetectorName", ""),
                severity="error",
                file_path=file_path,
                scanner="trufflehog",
                confidence="high",
                raw={
                    "raw": obj.get("Raw", ""),
                    "redacted": obj.get("Redacted", ""),
                    "source_id": obj.get("SourceID"),
                    "verified": obj.get("Verified", False),
                },
            )
            findings.append(finding)

        logger.info("trufflehog found %d finding(s)", len(findings))
        return findings
