"""Scan orchestrator: ties together repo management, scanning, and reporting."""

import logging
import re
import time
from pathlib import Path

from .config import Config
from .repo_manager import RepoManager
from .scanners.registry import select_scanners
from .scanners.base import Finding
from .reporters.sarif import SARIFBuilder
from .reporters.summary import SummaryWriter
from .utils import setup_logging

logger = logging.getLogger(__name__)


class Orchestrator:
    """Orchestrates the full vulnerability scan pipeline."""

    def __init__(
        self,
        config_path: str,
        schedule_filter: str | None = None,
        repo_filter: str | None = None,
        dry_run: bool = False,
    ):
        self.config = Config.load(config_path)
        self.schedule_filter = schedule_filter
        self.repo_filter = repo_filter
        self.dry_run = dry_run
        self.repo_manager = RepoManager()

    def run(self) -> int:
        """Execute the scan pipeline. Returns exit code (0 = clean, 1 = findings)."""
        setup_logging()

        # Filter repositories by schedule
        repos = self._filter_repos()

        if not repos:
            logger.info("No repositories match the filter criteria. Nothing to scan.")
            return 0

        logger.info(f"Scanning {len(repos)} repositories")

        if self.dry_run:
            for repo in repos:
                logger.info(f"  [DRY RUN] Would scan: {repo.url} ({repo.branch})")
            return 0

        all_findings: list[Finding] = []

        for repo in repos:
            findings = self._scan_repo(repo)
            all_findings.extend(findings)

            # Cleanup if configured
            if self.config.settings.cleanup_after_scan:
                repo_name = RepoManager._sanitize_name(repo.url)
                self.repo_manager.cleanup(
                    Path(self.config.settings.work_dir) / repo_name
                )

        # Generate reports
        self._generate_reports(all_findings)

        # Summary
        errors = sum(1 for f in all_findings if f.severity == "error")
        warnings = sum(1 for f in all_findings if f.severity == "warning")
        logger.info(
            f"Scan complete: {len(all_findings)} findings "
            f"({errors} errors, {warnings} warnings)"
        )

        return 1 if errors > 0 else 0

    def _filter_repos(self) -> list:
        """Filter repositories by schedule and repo URL filter."""
        repos = self.config.repositories

        if self.schedule_filter:
            repos = [
                r for r in repos
                if r.schedule == self.schedule_filter or r.schedule == "daily"
            ]

        if self.repo_filter:
            pattern = re.compile(self.repo_filter)
            repos = [r for r in repos if pattern.search(r.url)]

        return repos

    def _scan_repo(self, repo) -> list[Finding]:
        """Scan a single repository with all enabled scanners."""
        logger.info(f"Scanning: {repo.url} ({repo.branch})")

        start_time = time.time()

        # Clone/update repo
        repo_path = self.repo_manager.ensure_cloned(repo, self.config.settings)

        # Select scanners
        scanners = select_scanners(repo.scanners)
        logger.info(f"  Scanners: {[s.name for s in scanners]}")

        all_findings: list[Finding] = []

        for scanner in scanners:
            try:
                logger.info(f"  Running {scanner.name}...")
                findings = scanner.run(repo_path)
                all_findings.extend(findings)
                logger.info(f"  {scanner.name}: {len(findings)} findings")
            except Exception as e:
                logger.error(f"  {scanner.name} failed: {e}")

        elapsed = time.time() - start_time
        logger.info(
            f"  Completed {repo.url} in {elapsed:.1f}s: "
            f"{len(all_findings)} total findings"
        )

        return all_findings

    def _generate_reports(self, findings: list[Finding]) -> None:
        """Generate SARIF and summary reports."""
        rep = self.config.reporting

        repo_url = "unknown"
        repo_branch = "unknown"
        if self.config.repositories:
            first_repo = self.config.repositories[0]
            repo_url = first_repo.url
            repo_branch = first_repo.branch

        sarif_doc = SARIFBuilder.build(findings, repo_url, repo_branch, rep)
        SARIFBuilder.write(sarif_doc, rep.sarif_path)
        logger.info(f"SARIF report written to {rep.sarif_path}")

        summary = SummaryWriter.generate(repo_url, repo_branch, findings)
        SummaryWriter.write(summary, rep.summary_path)
        logger.info(f"Summary written to {rep.summary_path}")
