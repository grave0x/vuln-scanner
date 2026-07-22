"""Tests for scan orchestrator."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from vuln_scanner.orchestrator import Orchestrator


def _make_config_yaml(work_dir: str, repositories: list[dict] | None = None) -> str:
    """Create a minimal valid config YAML string."""
    data = {
        "version": 1,
        "settings": {
            "work_dir": work_dir,
            "cleanup_after_scan": False,
        },
        "repositories": repositories or [],
    }
    config_dir = Path(work_dir)
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.yaml"
    config_path.write_text(yaml.dump(data))
    return str(config_path)


class TestOrchestratorDryRun:
    """Tests for Orchestrator in dry-run mode."""

    def test_dry_run_no_clone(self):
        """With dry_run=True, no cloning or scanning happens."""
        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                },
            ])

            with patch(
                "vuln_scanner.orchestrator.RepoManager"
            ) as mock_rm_cls:
                orch = Orchestrator(config_path, dry_run=True)
                result = orch.run()

                assert result == 0
                # RepoManager should not be called for ensure_cloned
                mock_rm_cls.return_value.ensure_cloned.assert_not_called()

    def test_dry_run_logs_repos(self, caplog):
        """Dry run should log which repos would be scanned."""
        import logging

        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                },
            ])

            with patch("vuln_scanner.orchestrator.RepoManager"), \
                 patch("vuln_scanner.orchestrator.setup_logging"):
                with caplog.at_level(logging.INFO):
                    orch = Orchestrator(config_path, dry_run=True)
                    orch.run()

            log_text = caplog.text
            assert "[DRY RUN] Would scan:" in log_text
            assert "test/repo" in log_text


class TestOrchestratorFiltering:
    """Tests for repository filtering."""

    def test_no_matching_repos_returns_zero(self, caplog):
        """When filter produces empty list, return 0 and log appropriately."""
        import logging

        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                    "schedule": "weekly",
                },
            ])

            with patch("vuln_scanner.orchestrator.RepoManager"), \
                 patch("vuln_scanner.orchestrator.setup_logging"):
                with caplog.at_level(logging.INFO):
                    orch = Orchestrator(
                        config_path, schedule_filter="hourly"
                    )
                    result = orch.run()

            assert result == 0
            assert "No repositories match" in caplog.text

    def test_schedule_filter_matches_daily(self):
        """daily-schedule repos should always be included regardless of filter."""
        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                    "schedule": "daily",
                },
            ])

            with patch("vuln_scanner.orchestrator.RepoManager"), \
                 patch("vuln_scanner.orchestrator.select_scanners") as mock_select, \
                 patch("vuln_scanner.orchestrator.SARIFBuilder"), \
                 patch("vuln_scanner.orchestrator.SummaryWriter"):
                mock_select.return_value = []
                orch = Orchestrator(
                    config_path, schedule_filter="weekly"
                )
                result = orch.run()
                # daily repos are always included
                assert result == 0  # No findings, but repo was scanned

    def test_repo_filter_regex(self):
        """repo_filter should match against repo URLs."""
        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/org/alpha",
                    "branch": "main",
                },
                {
                    "url": "https://github.com/org/beta",
                    "branch": "main",
                },
            ])

            with patch("vuln_scanner.orchestrator.RepoManager"), \
                 patch("vuln_scanner.orchestrator.select_scanners") as mock_select, \
                 patch("vuln_scanner.orchestrator.SARIFBuilder"), \
                 patch("vuln_scanner.orchestrator.SummaryWriter"):
                mock_select.return_value = []
                orch = Orchestrator(
                    config_path, repo_filter="alpha"
                )
                result = orch.run()
                assert result == 0  # Only alpha matched


class TestOrchestratorScan:
    """Tests for orchestrator scan pipeline."""

    def test_scanners_called_for_each_repo(self):
        """Each repo should trigger scanner selection and execution."""
        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                },
            ])

            with patch(
                "vuln_scanner.orchestrator.RepoManager"
            ) as mock_rm_cls, \
                 patch(
                "vuln_scanner.orchestrator.select_scanners"
            ) as mock_select, \
                 patch(
                "vuln_scanner.orchestrator.SARIFBuilder"
            ) as mock_sarif, \
                 patch(
                "vuln_scanner.orchestrator.SummaryWriter"
            ) as mock_summary:
                mock_rm = mock_rm_cls.return_value
                mock_rm.ensure_cloned.return_value = Path(tmp) / "cloned"

                mock_scanner = MagicMock()
                mock_scanner.name = "semgrep"
                mock_scanner.run.return_value = []
                mock_select.return_value = [mock_scanner]

                orch = Orchestrator(config_path)
                result = orch.run()

                assert result == 0  # No errors
                mock_rm.ensure_cloned.assert_called_once()
                mock_select.assert_called_once()
                mock_scanner.run.assert_called_once()
                mock_sarif.build.assert_called_once()
                mock_summary.generate.assert_called_once()

    def test_scanner_exception_is_caught(self, caplog):
        """When a scanner raises, the error is logged and scan continues."""
        import logging

        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                },
            ])

            with patch(
                "vuln_scanner.orchestrator.RepoManager"
            ) as mock_rm_cls, \
                 patch(
                "vuln_scanner.orchestrator.select_scanners"
            ) as mock_select, \
                 patch(
                "vuln_scanner.orchestrator.SARIFBuilder"
            ), \
                 patch(
                "vuln_scanner.orchestrator.SummaryWriter"
            ), \
                 patch(
                "vuln_scanner.orchestrator.setup_logging"
            ):
                mock_rm = mock_rm_cls.return_value
                mock_rm.ensure_cloned.return_value = Path(tmp) / "cloned"

                failing_scanner = MagicMock()
                failing_scanner.name = "semgrep"
                failing_scanner.run.side_effect = RuntimeError("boom")
                mock_select.return_value = [failing_scanner]

                with caplog.at_level(logging.ERROR):
                    orch = Orchestrator(config_path)
                    result = orch.run()

                assert result == 0  # No errors in findings
                assert "semgrep failed" in caplog.text

    def test_returns_2_when_errors_present_and_fail_on_error(self):
        """Return code is 2 when fail_on=error and there are error findings."""
        from vuln_scanner.scanners.base import Finding

        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                },
            ])

            with patch(
                "vuln_scanner.orchestrator.RepoManager"
            ) as mock_rm_cls, \
                 patch(
                "vuln_scanner.orchestrator.select_scanners"
            ) as mock_select, \
                 patch(
                "vuln_scanner.orchestrator.SARIFBuilder"
            ), \
                 patch(
                "vuln_scanner.orchestrator.SummaryWriter"
            ):
                mock_rm = mock_rm_cls.return_value
                mock_rm.ensure_cloned.return_value = Path(tmp) / "cloned"

                scanner = MagicMock()
                scanner.name = "semgrep"
                scanner.run.return_value = [
                    Finding(
                        rule_id="r1", message="e", severity="error",
                        file_path="a.py", scanner="semgrep",
                    ),
                ]
                mock_select.return_value = [scanner]

                orch = Orchestrator(config_path, fail_on="error")
                result = orch.run()

                assert result == 2

    def test_returns_1_when_warnings_present_and_fail_on_warning(self):
        """Return code is 1 when fail_on=warning and only warnings present."""
        from vuln_scanner.scanners.base import Finding

        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                },
            ])

            with patch(
                "vuln_scanner.orchestrator.RepoManager"
            ) as mock_rm_cls, \
                 patch(
                "vuln_scanner.orchestrator.select_scanners"
            ) as mock_select, \
                 patch(
                "vuln_scanner.orchestrator.SARIFBuilder"
            ), \
                 patch(
                "vuln_scanner.orchestrator.SummaryWriter"
            ):
                mock_rm = mock_rm_cls.return_value
                mock_rm.ensure_cloned.return_value = Path(tmp) / "cloned"

                scanner = MagicMock()
                scanner.name = "semgrep"
                scanner.run.return_value = [
                    Finding(
                        rule_id="r1", message="w", severity="warning",
                        file_path="a.py", scanner="semgrep",
                    ),
                ]
                mock_select.return_value = [scanner]

                orch = Orchestrator(config_path, fail_on="warning")
                result = orch.run()

                assert result == 1

    def test_returns_0_when_errors_present_and_fail_on_never(self):
        """Return code is 0 when fail_on=never regardless of findings."""
        from vuln_scanner.scanners.base import Finding

        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                },
            ])

            with patch(
                "vuln_scanner.orchestrator.RepoManager"
            ) as mock_rm_cls, \
                 patch(
                "vuln_scanner.orchestrator.select_scanners"
            ) as mock_select, \
                 patch(
                "vuln_scanner.orchestrator.SARIFBuilder"
            ), \
                 patch(
                "vuln_scanner.orchestrator.SummaryWriter"
            ):
                mock_rm = mock_rm_cls.return_value
                mock_rm.ensure_cloned.return_value = Path(tmp) / "cloned"

                scanner = MagicMock()
                scanner.name = "semgrep"
                scanner.run.return_value = [
                    Finding(
                        rule_id="r1", message="e", severity="error",
                        file_path="a.py", scanner="semgrep",
                    ),
                ]
                mock_select.return_value = [scanner]

                orch = Orchestrator(config_path)
                result = orch.run()

                assert result == 0

    def test_returns_0_for_warnings_only_with_fail_on_error(self):
        """Return code is 0 when fail_on=error and only warnings are present."""
        from vuln_scanner.scanners.base import Finding

        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/test/repo",
                    "branch": "main",
                },
            ])

            with patch(
                "vuln_scanner.orchestrator.RepoManager"
            ) as mock_rm_cls, \
                 patch(
                "vuln_scanner.orchestrator.select_scanners"
            ) as mock_select, \
                 patch(
                "vuln_scanner.orchestrator.SARIFBuilder"
            ), \
                 patch(
                "vuln_scanner.orchestrator.SummaryWriter"
            ):
                mock_rm = mock_rm_cls.return_value
                mock_rm.ensure_cloned.return_value = Path(tmp) / "cloned"

                scanner = MagicMock()
                scanner.name = "semgrep"
                scanner.run.return_value = [
                    Finding(
                        rule_id="r1", message="w", severity="warning",
                        file_path="a.py", scanner="semgrep",
                    ),
                ]
                mock_select.return_value = [scanner]

                orch = Orchestrator(config_path, fail_on="error")
                result = orch.run()

                assert result == 0

    def test_reports_use_first_repo_info(self):
        """SARIF and summary should use the first repo URL/branch from config."""
        with tempfile.TemporaryDirectory() as tmp:
            config_path = _make_config_yaml(tmp, [
                {
                    "url": "https://github.com/first/repo",
                    "branch": "develop",
                },
            ])

            with patch(
                "vuln_scanner.orchestrator.RepoManager"
            ) as mock_rm_cls, \
                 patch(
                "vuln_scanner.orchestrator.select_scanners"
            ) as mock_select, \
                 patch(
                "vuln_scanner.orchestrator.SARIFBuilder"
            ) as mock_sarif, \
                 patch(
                "vuln_scanner.orchestrator.SummaryWriter"
            ) as mock_summary:
                mock_rm = mock_rm_cls.return_value
                mock_rm.ensure_cloned.return_value = Path(tmp) / "cloned"
                mock_select.return_value = []

                orch = Orchestrator(config_path)
                orch.run()

                call_args = mock_sarif.build.call_args
                assert call_args[0][1] == "https://github.com/first/repo"
                assert call_args[0][2] == "develop"

                call_args = mock_summary.generate.call_args
                assert call_args[0][0] == "https://github.com/first/repo"
                assert call_args[0][1] == "develop"

    def test_cleanup_after_scan(self):
        """When cleanup_after_scan is True, cleanup is called."""
        with tempfile.TemporaryDirectory() as tmp:
            data = {
                "version": 1,
                "settings": {
                    "work_dir": tmp,
                    "cleanup_after_scan": True,
                },
                "repositories": [
                    {
                        "url": "https://github.com/test/repo",
                        "branch": "main",
                    },
                ],
            }
            config_path = Path(tmp) / "config.yaml"
            config_path.write_text(yaml.dump(data))

            with patch(
                "vuln_scanner.orchestrator.RepoManager"
            ) as mock_rm_cls, \
                 patch(
                "vuln_scanner.orchestrator.select_scanners"
            ) as mock_select, \
                 patch(
                "vuln_scanner.orchestrator.SARIFBuilder"
            ), \
                 patch(
                "vuln_scanner.orchestrator.SummaryWriter"
            ):
                mock_rm = mock_rm_cls.return_value
                mock_rm.ensure_cloned.return_value = Path(tmp) / "cloned"
                mock_select.return_value = []

                orch = Orchestrator(str(config_path))
                orch.run()

                mock_rm.cleanup.assert_called_once()
