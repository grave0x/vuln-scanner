"""Git repository management: clone, fetch, cleanup."""

import logging
import os
import re
import shutil
from pathlib import Path
from urllib.parse import urlparse

from .config import RepoConfig, Settings
from .utils import run, ScannerError

logger = logging.getLogger(__name__)


def _inject_token(url: str) -> str:
    """Inject GIT_TOKEN into HTTPS GitHub URLs for private repo access."""
    token = os.environ.get("GIT_TOKEN", "")
    if not token:
        return url
    # Only rewrite HTTPS GitHub URLs
    if url.startswith("https://github.com/"):
        # Insert token before host: https://<token>@github.com/...
        return url.replace("https://", f"https://{token}@", 1)
    return url


class RepoManager:
    """Manages cloning, updating, and cleaning up git repositories."""

    @staticmethod
    def _sanitize_name(url: str) -> str:
        """Extract owner-repo from a git URL for directory naming."""
        parsed = urlparse(url)
        if parsed.scheme:
            # Standard URL: https://host/path or git://host/path
            path = parsed.path.strip("/")
        else:
            # SCP-style: git@host:path
            path = url.split(":", 1)[-1].strip("/")
        # Remove .git suffix if present
        path = re.sub(r"\.git$", "", path)
        # Replace slashes with dashes
        return path.replace("/", "-")

    @staticmethod
    def ensure_cloned(repo: RepoConfig, settings: Settings) -> Path:
        """
        Ensure the repository is cloned and up-to-date at the right branch.

        If the directory exists: fetch origin and reset hard to origin/{branch}.
        If not: shallow clone with --depth and --single-branch.

        Returns the absolute path to the local clone.
        """
        work_dir = Path(settings.work_dir)
        repo_name = RepoManager._sanitize_name(repo.url)
        target_path = work_dir / repo_name

        work_dir.mkdir(parents=True, exist_ok=True)

        if target_path.exists():
            logger.info("Updating existing clone: %s", target_path)
            try:
                # Fetch the specific branch
                run(
                    ["git", "fetch", "origin", repo.branch,
                     "--depth", str(repo.depth)],
                    timeout=120,
                    cwd=str(target_path),
                )
                # Reset to the fetched commit
                run(
                    ["git", "reset", "--hard", f"origin/{repo.branch}"],
                    timeout=60,
                    cwd=str(target_path),
                )
                # Clean untracked files
                run(
                    ["git", "clean", "-fd"],
                    timeout=60,
                    cwd=str(target_path),
                )
                logger.info("Repository updated to origin/%s", repo.branch)
            except ScannerError as e:
                logger.warning("Fetch failed (%s), re-cloning from scratch", e)
                RepoManager.cleanup(target_path)
                return RepoManager._clone(repo, settings, target_path)
        else:
            logger.info("Cloning fresh: %s -> %s", repo.url, target_path)
            return RepoManager._clone(repo, settings, target_path)

        return target_path

    @staticmethod
    def _clone(repo: RepoConfig, settings: Settings, target_path: Path) -> Path:
        """Perform a shallow or full clone."""
        url = _inject_token(repo.url)
        if settings.shallow_clone:
            cmd = [
                "git", "clone",
                "--branch", repo.branch,
                "--single-branch",
                "--depth", str(repo.depth),
                url,
                str(target_path),
            ]
        else:
            cmd = [
                "git", "clone",
                "--branch", repo.branch,
                url,
                str(target_path),
            ]

        run(cmd, timeout=300)
        return target_path

    @staticmethod
    def cleanup(path: Path) -> None:
        """Remove the cloned repository directory."""
        if path.exists():
            logger.info("Cleaning up: %s", path)
            shutil.rmtree(path, ignore_errors=True)
