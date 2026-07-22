"""SARIF 2.1.0 report builder."""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from ..scanners.base import Finding
from ..config import Reporting

logger = logging.getLogger(__name__)

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"


class SARIFBuilder:
    """Builds SARIF 2.1.0 documents from scanner findings."""

    @staticmethod
    def build(
        findings: list[Finding],
        repo_url: str,
        repo_branch: str,
        reporting: Reporting,
    ) -> dict:
        """Build a SARIF document for a single repository scan.

        Groups findings by scanner name into separate runs.
        """
        # Group findings by scanner
        by_scanner: dict[str, list[Finding]] = {}
        for f in findings:
            by_scanner.setdefault(f.scanner, []).append(f)

        runs = []
        for scanner_name, scanner_findings in by_scanner.items():
            run = SARIFBuilder._build_run(
                scanner_name, scanner_findings, repo_url, repo_branch
            )
            runs.append(run)

        # If no findings, still produce a valid document
        if not runs:
            runs.append({
                "tool": {
                    "driver": {
                        "name": "vuln-scanner",
                        "version": "0.1.0",
                    }
                },
                "results": [],
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    ),
                }],
            })

        return {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": runs,
        }

    @staticmethod
    def _build_run(
        scanner_name: str,
        findings: list[Finding],
        repo_url: str,
        repo_branch: str,
    ) -> dict:
        """Build a single SARIF run for one scanner."""
        results = []
        rules: dict[str, dict] = {}

        for f in findings:
            # Register the rule
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "shortDescription": {"text": f.rule_id},
                    "help": {"text": f.message},
                }

            result = {
                "ruleId": f.rule_id,
                "level": f.severity,
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                    }
                }],
            }

            # Add region if line info available
            if f.line_start is not None:
                region = {"startLine": f.line_start}
                if f.line_end is not None:
                    region["endLine"] = f.line_end
                if f.column_start is not None:
                    region["startColumn"] = f.column_start
                if f.column_end is not None:
                    region["endColumn"] = f.column_end
                result["locations"][0]["physicalLocation"]["region"] = region

            # Add properties
            result["properties"] = {
                "confidence": f.confidence,
                "scanner": f.scanner,
            }
            if f.suggestion:
                result["properties"]["suggestion"] = f.suggestion

            results.append(result)

        return {
            "tool": {
                "driver": {
                    "name": scanner_name,
                    "version": "0.1.0",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "versionControlProvenance": [{
                "repositoryUri": repo_url,
                "revisionId": repo_branch,
            }],
            "invocations": [{
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
            }],
        }

    @staticmethod
    def write(document: dict, path: str) -> None:
        """Write SARIF document to a file."""
        with open(path, "w") as f:
            json.dump(document, f, indent=2)
