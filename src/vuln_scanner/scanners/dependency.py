"""Dependency vulnerability scanner using osv-scanner."""

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
}


class DependencyScanner(AbstractScanner):
    """Scanner wrapping osv-scanner for dependency vulnerability scanning."""

    name = "osv-scanner"

    def run(self, repo_path: Path) -> list[Finding]:
        if not self.check_installed():
            logger.warning(
                "osv-scanner is not installed. Skipping dependency scan."
            )
            return []

        cmd = [
            "osv-scanner", "scan", "source",
            "--format", "json",
            "-r", str(repo_path),
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except FileNotFoundError:
            logger.warning("osv-scanner not found on PATH. Skipping.")
            return []
        except subprocess.TimeoutExpired:
            logger.error("osv-scanner scan timed out for %s", repo_path)
            return []

        if proc.returncode != 0 and not proc.stdout.strip():
            # osv-scanner exits 128 when no lockfile/package sources exist — not an error
            if "No package sources found" in (proc.stderr or ""):
                logger.info("osv-scanner: no package sources found (skipping)")
                return []
            logger.error("osv-scanner failed: %s", proc.stderr)
            return []

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            logger.error("Failed to parse osv-scanner JSON output")
            return []

        repo_path_str = str(repo_path)
        findings: list[Finding] = []
        for result in data.get("results", []):
            source = result.get("source", {})
            source_path = source.get("path", "")
            if source_path.startswith(repo_path_str):
                source_path = source_path[len(repo_path_str):].lstrip("/")

            for pkg in result.get("packages", []):
                pkg_info = pkg.get("package", {})
                for vuln in pkg.get("vulnerabilities", []):
                    vuln_id = vuln.get("id", "")
                    severity = self._extract_severity(vuln)

                    finding = Finding(
                        rule_id=vuln_id,
                        message=vuln.get("summary", ""),
                        severity=severity,
                        file_path=source_path,
                        scanner="osv-scanner",
                        confidence="medium",
                        suggestion=vuln.get("details", ""),
                    )
                    findings.append(finding)

        logger.info("osv-scanner found %d finding(s)", len(findings))
        return findings

    @staticmethod
    def _extract_severity(vuln: dict) -> str:
        """Extract the highest severity from an osv-scanner vulnerability entry."""
        severities = vuln.get("severity", [])
        if not severities:
            return "warning"

        best = "note"
        for sev in severities:
            if isinstance(sev, dict):
                sev_type = sev.get("type", "").upper()
                score = sev.get("score", "")
                sev_level = _SEVERITY_MAP.get(sev_type)
                if sev_level is None and score:
                    # CVSS score-based mapping
                    try:
                        cvss = float(score.split(":")[-1])
                    except (ValueError, IndexError):
                        continue
                    if cvss >= 9.0:
                        sev_level = "error"
                    elif cvss >= 7.0:
                        sev_level = "error"
                    elif cvss >= 4.0:
                        sev_level = "warning"
                    else:
                        sev_level = "note"
                if sev_level == "error":
                    return "error"
                if sev_level == "warning" and best != "error":
                    best = "warning"
            elif isinstance(sev, str):
                sev_level = _SEVERITY_MAP.get(sev.upper())
                if sev_level == "error":
                    return "error"
                if sev_level == "warning" and best != "error":
                    best = "warning"

        return best
