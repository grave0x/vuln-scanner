"""Tests for SARIF report builder."""

import json
import tempfile
from pathlib import Path

from vuln_scanner.reporters.sarif import SARIFBuilder, SARIF_SCHEMA, SARIF_VERSION
from vuln_scanner.scanners.base import Finding
from vuln_scanner.config import Reporting


def _make_reporting() -> Reporting:
    """Create a default Reporting config for tests."""
    return Reporting()


class TestSARIFBuilder:
    """Tests for SARIFBuilder document generation."""

    def test_build_empty(self):
        """SARIF document with no findings should still be valid."""
        doc = SARIFBuilder.build(
            [], "https://github.com/test/repo", "main", _make_reporting()
        )
        assert doc["version"] == SARIF_VERSION
        assert doc["$schema"] == SARIF_SCHEMA
        assert len(doc["runs"]) >= 1
        # The empty run should have no results
        assert doc["runs"][0]["results"] == []

    def test_build_with_findings(self):
        """SARIF document should group findings by scanner into runs."""
        findings = [
            Finding(
                rule_id="test-rule-1",
                message="Test finding 1",
                severity="error",
                file_path="src/main.py",
                line_start=10,
                scanner="semgrep",
            ),
            Finding(
                rule_id="test-rule-2",
                message="Test finding 2",
                severity="warning",
                file_path="config.yaml",
                line_start=5,
                scanner="gitleaks",
            ),
        ]
        doc = SARIFBuilder.build(
            findings, "https://github.com/test/repo", "main", _make_reporting()
        )
        assert len(doc["runs"]) == 2  # Two scanners

        # Find the semgrep run
        semgrep_run = [
            r for r in doc["runs"] if r["tool"]["driver"]["name"] == "semgrep"
        ][0]
        assert len(semgrep_run["results"]) == 1
        assert semgrep_run["results"][0]["ruleId"] == "test-rule-1"
        assert semgrep_run["results"][0]["level"] == "error"

        # Check location
        loc = semgrep_run["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uri"] == "src/main.py"
        assert loc["physicalLocation"]["region"]["startLine"] == 10

    def test_finding_with_full_region(self):
        """Findings with column info should include full region."""
        finding = Finding(
            rule_id="r1",
            message="msg",
            severity="warning",
            file_path="a.py",
            line_start=5,
            line_end=7,
            column_start=2,
            column_end=10,
            scanner="semgrep",
        )
        doc = SARIFBuilder.build(
            [finding], "https://github.com/r", "main", _make_reporting()
        )
        region = doc["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["region"]
        assert region["startLine"] == 5
        assert region["endLine"] == 7
        assert region["startColumn"] == 2
        assert region["endColumn"] == 10

    def test_finding_without_line_info(self):
        """Findings without line info should not have a region."""
        finding = Finding(
            rule_id="r1",
            message="msg",
            severity="note",
            file_path="a.py",
            scanner="gitleaks",
        )
        doc = SARIFBuilder.build(
            [finding], "https://github.com/r", "main", _make_reporting()
        )
        loc = doc["runs"][0]["results"][0]["locations"][0]
        assert "region" not in loc["physicalLocation"]

    def test_properties_include_confidence_and_scanner(self):
        """Results should carry confidence and scanner in properties."""
        finding = Finding(
            rule_id="r1",
            message="msg",
            severity="warning",
            file_path="x.py",
            scanner="checkov",
            confidence="high",
            suggestion="Fix it",
        )
        doc = SARIFBuilder.build(
            [finding], "https://github.com/r", "main", _make_reporting()
        )
        props = doc["runs"][0]["results"][0]["properties"]
        assert props["confidence"] == "high"
        assert props["scanner"] == "checkov"
        assert props["suggestion"] == "Fix it"

    def test_single_scanner_multiple_findings(self):
        """Findings from the same scanner go into one run."""
        findings = [
            Finding(
                rule_id="r1",
                message="m1",
                severity="error",
                file_path="a.py",
                scanner="semgrep",
            ),
            Finding(
                rule_id="r2",
                message="m2",
                severity="warning",
                file_path="b.py",
                scanner="semgrep",
            ),
        ]
        doc = SARIFBuilder.build(
            findings, "https://github.com/r", "main", _make_reporting()
        )
        assert len(doc["runs"]) == 1
        assert len(doc["runs"][0]["results"]) == 2

    def test_rules_are_registered(self):
        """Each unique rule_id should be listed in the driver rules."""
        findings = [
            Finding(
                rule_id="rule-a",
                message="msg",
                severity="error",
                file_path="f.py",
                scanner="semgrep",
            ),
            Finding(
                rule_id="rule-b",
                message="msg",
                severity="warning",
                file_path="g.py",
                scanner="semgrep",
            ),
        ]
        doc = SARIFBuilder.build(
            findings, "https://github.com/r", "main", _make_reporting()
        )
        rules = doc["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        assert rule_ids == {"rule-a", "rule-b"}

    def test_finding_without_suggestion(self):
        """Properties should not include suggestion key when None."""
        finding = Finding(
            rule_id="r1",
            message="msg",
            severity="warning",
            file_path="f.py",
            scanner="gitleaks",
            suggestion=None,
        )
        doc = SARIFBuilder.build(
            [finding], "https://github.com/r", "main", _make_reporting()
        )
        props = doc["runs"][0]["results"][0]["properties"]
        assert "suggestion" not in props


class TestSARIFWrite:
    """Tests for SARIFBuilder.write()."""

    def test_write_creates_valid_json(self):
        """SARIF document should be written as valid JSON to a file."""
        doc = SARIFBuilder.build(
            [], "https://github.com/test/repo", "main", _make_reporting()
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False
        ) as f:
            path = f.name
        try:
            SARIFBuilder.write(doc, path)
            with open(path) as f:
                parsed = json.load(f)
            assert parsed == doc
            assert parsed["version"] == SARIF_VERSION
        finally:
            Path(path).unlink(missing_ok=True)

    def test_write_with_findings(self):
        """Written SARIF with findings should be valid JSON."""
        findings = [
            Finding(
                rule_id="r1",
                message="msg",
                severity="error",
                file_path="f.py",
                line_start=1,
                scanner="semgrep",
            ),
        ]
        doc = SARIFBuilder.build(
            findings, "https://github.com/r", "main", _make_reporting()
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sarif", delete=False
        ) as f:
            path = f.name
        try:
            SARIFBuilder.write(doc, path)
            with open(path) as f:
                parsed = json.load(f)
            assert len(parsed["runs"]) == 1
            assert len(parsed["runs"][0]["results"]) == 1
        finally:
            Path(path).unlink(missing_ok=True)
