"""Tests for repo_manager."""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

from vuln_scanner.config import RepoConfig, Settings
from vuln_scanner.repo_manager import RepoManager


def _git(args, cwd):
    """Run a git command, raise on failure."""
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@test.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@test.com",
    }
    subprocess.run(
        ["git"] + args,
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )


class TestSanitizeName:
    """Tests for _sanitize_name URL-to-name conversion."""

    def test_standard_github_url(self):
        assert RepoManager._sanitize_name(
            "https://github.com/user/repo.git"
        ) == "user-repo"

    def test_without_git_suffix(self):
        assert RepoManager._sanitize_name(
            "https://github.com/user/repo"
        ) == "user-repo"

    def test_git_protocol_url(self):
        assert RepoManager._sanitize_name(
            "git@github.com:user/repo.git"
        ) == "user-repo"

    def test_nested_path(self):
        assert RepoManager._sanitize_name(
            "https://github.com/org/team/repo.git"
        ) == "org-team-repo"

    def test_no_trailing_slash_matters(self):
        assert RepoManager._sanitize_name(
            "https://example.com/project"
        ) == "project"

    def test_trailing_slash(self):
        assert RepoManager._sanitize_name(
            "https://example.com/project/"
        ) == "project"


class TestCloneAndUpdate:
    """Integration tests using real git operations with bare repos."""

    @staticmethod
    def _make_bare_repo(path: Path, branch: str = "main") -> Path:
        """Create a bare git repo with an initial commit on the given branch."""
        bare_dir = path / "upstream.git"
        bare_dir.mkdir()
        _git(["init", "--bare", "--initial-branch", branch], bare_dir)

        # Clone bare -> temp working copy to add files
        work = path / "work"
        _git(["clone", str(bare_dir), str(work)], path)
        _git(["checkout", "-b", branch], work)

        (work / "README.md").write_text("# Test Repo\n")
        _git(["add", "README.md"], work)
        _git(["commit", "-m", "initial commit"], work)
        _git(["push", "origin", branch], work)

        return bare_dir

    @staticmethod
    def _make_settings(work_dir: str) -> Settings:
        """Create Settings with a custom work_dir."""
        return Settings(
            work_dir=work_dir,
            shallow_clone=True,
            cleanup_after_scan=False,
        )

    @staticmethod
    def _make_repo_config(bare_url: str, branch: str = "main") -> RepoConfig:
        return RepoConfig(url=bare_url, branch=branch, depth=1)

    def test_clone_new_repo(self):
        """Clone a bare repo via RepoManager and verify files exist."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            bare = self._make_bare_repo(tmp)

            work_dir = tmp / "scanner-work"
            settings = self._make_settings(str(work_dir))
            repo_cfg = self._make_repo_config(str(bare))

            result = RepoManager.ensure_cloned(repo_cfg, settings)

            assert result.exists()
            assert (result / "README.md").exists()
            assert (result / "README.md").read_text() == "# Test Repo\n"
            expected_name = RepoManager._sanitize_name(str(bare))
            assert result == work_dir / expected_name

    def test_clone_update_existing(self):
        """Clone, push new commit, re-clone, verify update."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            bare = self._make_bare_repo(tmp)

            work_dir = tmp / "scanner-work"
            settings = self._make_settings(str(work_dir))
            repo_cfg = self._make_repo_config(str(bare))

            # First clone
            result = RepoManager.ensure_cloned(repo_cfg, settings)
            assert (result / "README.md").read_text() == "# Test Repo\n"

            # Push a new commit to bare via work clone
            work_clone = tmp / "work2"
            _git(["clone", str(bare), str(work_clone)], tmp)
            (work_clone / "CHANGES.md").write_text("v2 changes\n")
            _git(["add", "CHANGES.md"], work_clone)
            _git(["commit", "-m", "second commit"], work_clone)
            _git(["push", "origin", "main"], work_clone)

            # Re-clone (should update)
            result = RepoManager.ensure_cloned(repo_cfg, settings)
            assert (result / "CHANGES.md").exists()
            assert (result / "CHANGES.md").read_text() == "v2 changes\n"

    def test_cleanup(self):
        """Clone, verify existence, cleanup, verify gone."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            bare = self._make_bare_repo(tmp)

            work_dir = tmp / "scanner-work"
            settings = self._make_settings(str(work_dir))
            repo_cfg = self._make_repo_config(str(bare))

            result = RepoManager.ensure_cloned(repo_cfg, settings)
            assert result.exists()

            RepoManager.cleanup(result)
            assert not result.exists()

    def test_clone_specific_branch(self):
        """Clone a non-main branch from a bare repo."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            branch = "develop"

            # Create bare repo with develop branch
            bare_dir = tmp / "upstream.git"
            bare_dir.mkdir()
            _git(["init", "--bare", "--initial-branch", branch], bare_dir)

            work = tmp / "work"
            _git(["clone", str(bare_dir), str(work)], tmp)
            _git(["checkout", "-b", branch], work)

            (work / "README.md").write_text("# Develop branch\n")
            _git(["add", "README.md"], work)
            _git(["commit", "-m", "initial on develop"], work)
            _git(["push", "origin", branch], work)

            work_dir = tmp / "scanner-work"
            settings = self._make_settings(str(work_dir))
            repo_cfg = self._make_repo_config(str(bare_dir), branch=branch)

            result = RepoManager.ensure_cloned(repo_cfg, settings)

            assert result.exists()
            assert (result / "README.md").exists()
            assert (result / "README.md").read_text() == "# Develop branch\n"
