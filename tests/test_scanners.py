"""Tests for scanner modules."""

import json
import subprocess
from pathlib import Path

import pytest

from vuln_scanner.scanners.base import Finding
from vuln_scanner.scanners.semgrep import SemgrepScanner
from vuln_scanner.scanners.gitleaks import GitleaksScanner
from vuln_scanner.scanners.checkov import CheckovScanner
from vuln_scanner.scanners.registry import (
    SCANNER_REGISTRY,
    select_scanners,
    list_scanners,
)


FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(name: str) -> str:
    return (FIXTURES_DIR / name).read_text()


def _mock_subprocess_run(mocker, stdout: str, returncode: int = 0):
    """Helper to mock subprocess.run with given stdout/returncode."""
    proc = mocker.MagicMock(spec=subprocess.CompletedProcess)
    proc.stdout = stdout
    proc.stderr = ""
    proc.returncode = returncode
    mock_run = mocker.patch("subprocess.run", return_value=proc)
    return mock_run


class TestSemgrepScanner:
    """Tests for SemgrepScanner."""

    def test_parse(self, mocker):
        """Feed mock JSON and verify Finding fields are parsed correctly."""
        repo_path = Path("/tmp/repo")
        fixture = _load_fixture("semgrep_output.json")

        mocker.patch.object(SemgrepScanner, "check_installed", return_value=True)
        _mock_subprocess_run(mocker, fixture)

        scanner = SemgrepScanner()
        findings = scanner.run(repo_path)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "python.lang.security.audit.dangerous-subprocess-use"
        assert f.message == "Detected subprocess function without proper sanitization"
        assert f.severity == "warning"
        assert f.file_path == "src/app.py"
        assert f.line_start == 42
        assert f.line_end == 42
        assert f.column_start == 5
        assert f.column_end == 20
        assert f.scanner == "semgrep"
        assert f.confidence == "medium"

    def test_not_installed(self, mocker):
        """Return empty list when semgrep is not installed."""
        mocker.patch.object(SemgrepScanner, "check_installed", return_value=False)
        mock_run = mocker.patch("subprocess.run")

        scanner = SemgrepScanner()
        findings = scanner.run(Path("/tmp/repo"))

        assert findings == []
        mock_run.assert_not_called()


class TestGitleaksScanner:
    """Tests for GitleaksScanner."""

    def test_parse(self, mocker):
        """Feed mock JSON and verify Finding fields are parsed correctly."""
        repo_path = Path("/tmp/repo")
        fixture = _load_fixture("gitleaks_output.json")

        mocker.patch.object(GitleaksScanner, "check_installed", return_value=True)
        _mock_subprocess_run(mocker, fixture, returncode=1)

        scanner = GitleaksScanner()
        findings = scanner.run(repo_path)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws-access-key"
        assert f.message == "AWS Access Key"
        assert f.severity == "error"
        assert f.file_path == "config/secrets.yaml"
        assert f.line_start == 15
        assert f.line_end == 15
        assert f.scanner == "gitleaks"
        assert f.confidence == "high"

    def test_not_installed(self, mocker):
        """Return empty list when gitleaks is not installed."""
        mocker.patch.object(GitleaksScanner, "check_installed", return_value=False)
        mock_run = mocker.patch("subprocess.run")

        scanner = GitleaksScanner()
        findings = scanner.run(Path("/tmp/repo"))

        assert findings == []
        mock_run.assert_not_called()


class TestCheckovScanner:
    """Tests for CheckovScanner."""

    def test_parse_list_format(self, mocker):
        """Feed mock JSON list and verify Finding fields."""
        repo_path = Path("/infra")
        fixture = _load_fixture("checkov_output.json")

        mocker.patch.object(CheckovScanner, "check_installed", return_value=True)
        _mock_subprocess_run(mocker, fixture)

        scanner = CheckovScanner()
        findings = scanner.run(repo_path)

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "CKV_AWS_1"
        assert f.message == "Ensure IAM policies are attached only to groups or roles"
        assert f.severity == "warning"
        assert f.file_path == "main.tf"
        assert f.line_start == 10
        assert f.scanner == "checkov"
        assert f.confidence == "medium"

    def test_not_installed(self, mocker):
        """Return empty list when checkov is not installed."""
        mocker.patch.object(CheckovScanner, "check_installed", return_value=False)
        mock_run = mocker.patch("subprocess.run")

        scanner = CheckovScanner()
        findings = scanner.run(Path("/tmp/repo"))

        assert findings == []
        mock_run.assert_not_called()


class TestRegistry:
    """Tests for scanner registry."""

    def test_select_scanners_enabled(self, mocker):
        """Enabled and installed scanners are returned."""
        mocker.patch(
            "vuln_scanner.scanners.registry.SemgrepScanner.check_installed",
            return_value=True,
        )
        mocker.patch(
            "vuln_scanner.scanners.registry.GitleaksScanner.check_installed",
            return_value=True,
        )
        mocker.patch(
            "vuln_scanner.scanners.registry.CheckovScanner.check_installed",
            return_value=True,
        )
        mocker.patch(
            "vuln_scanner.scanners.registry.DependencyScanner.check_installed",
            return_value=True,
        )

        toggles = {
            "semgrep": True,
            "gitleaks": True,
            "checkov": False,
            "dependency": False,
        }
        scanners = select_scanners(toggles)
        assert len(scanners) == 2
        names = {s.name for s in scanners}
        assert names == {"semgrep", "gitleaks"}

    def test_select_scanners_not_installed_skipped(self, mocker):
        """Enabled but not installed scanners are skipped."""
        mocker.patch(
            "vuln_scanner.scanners.registry.SemgrepScanner.check_installed",
            return_value=False,
        )

        toggles = {"semgrep": True}
        scanners = select_scanners(toggles)
        assert len(scanners) == 0

    def test_select_scanners_disabled(self, mocker):
        """Disabled scanners are never returned."""
        toggles = {"semgrep": False}
        scanners = select_scanners(toggles)
        assert len(scanners) == 0

    def test_select_scanners_unknown_name(self, mocker):
        """Unknown scanner names are ignored."""
        toggles = {"nonexistent": True}
        scanners = select_scanners(toggles)
        assert len(scanners) == 0

    def test_list_scanners_output(self, mocker, capsys):
        """list_scanners prints expected scanner names."""
        mocker.patch(
            "vuln_scanner.scanners.registry.SemgrepScanner.check_installed",
            return_value=True,
        )
        mocker.patch(
            "vuln_scanner.scanners.registry.GitleaksScanner.check_installed",
            return_value=False,
        )
        mocker.patch(
            "vuln_scanner.scanners.registry.CheckovScanner.check_installed",
            return_value=False,
        )
        mocker.patch(
            "vuln_scanner.scanners.registry.DependencyScanner.check_installed",
            return_value=False,
        )

        list_scanners()
        captured = capsys.readouterr()

        assert "semgrep" in captured.out
        assert "gitleaks" in captured.out
        assert "checkov" in captured.out
        assert "dependency" in captured.out

    def test_registry_coverage(self):
        """All expected scanners are registered."""
        assert "semgrep" in SCANNER_REGISTRY
        assert "gitleaks" in SCANNER_REGISTRY
        assert "checkov" in SCANNER_REGISTRY
        assert "dependency" in SCANNER_REGISTRY
