"""Utility functions and exception classes for vuln-scanner."""

import logging
import os
import subprocess

logger = logging.getLogger(__name__)


class ScannerError(Exception):
    """Raised when a scanner subprocess fails."""

    def __init__(self, message: str, command: list[str] | None = None,
                 returncode: int | None = None, stderr: str | None = None):
        super().__init__(message)
        self.command = command or []
        self.returncode = returncode
        self.stderr = stderr or ""


def run(cmd: list[str], timeout: int = 300, cwd: str | None = None,
        env: dict | None = None) -> subprocess.CompletedProcess:
    """Run a subprocess command with logging and error handling.

    Args:
        cmd: Command as list of strings.
        timeout: Timeout in seconds.
        cwd: Working directory for the command.
        env: Environment variables to pass.

    Returns:
        The completed process.

    Raises:
        ScannerError: On non-zero exit code or timeout.
    """
    logger.info("Running command: %s", " ".join(cmd))
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        if proc.returncode != 0:
            raise ScannerError(
                f"Command exited with code {proc.returncode}: {' '.join(cmd)}",
                command=cmd,
                returncode=proc.returncode,
                stderr=proc.stderr,
            )
        return proc
    except subprocess.TimeoutExpired as e:
        raise ScannerError(
            f"Command timed out after {timeout}s: {' '.join(cmd)}",
            command=cmd,
        ) from e


def setup_logging(level: str = "INFO") -> None:
    """Configure root logger with a console handler.

    Args:
        level: Log level as string (e.g. "DEBUG", "INFO", "WARNING").
    """
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    root.addHandler(handler)


_LANG_LOCKFILE_MAP: dict[str, str] = {
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "yarn.lock": "javascript",
    "Pipfile": "python",
    "Pipfile.lock": "python",
    "pyproject.toml": "python",
    "Cargo.toml": "rust",
    "Cargo.lock": "rust",
    "go.mod": "go",
    "go.sum": "go",
    "pom.xml": "java",
    "Gemfile": "ruby",
    "Gemfile.lock": "ruby",
    "Dockerfile": "docker",
}


def detect_languages(repo_path: str) -> set[str]:
    """Detect programming languages used in a repository.

    Scans for lockfiles, build manifests, and other language indicators.

    Args:
        repo_path: Path to the repository root.

    Returns:
        Set of detected language names.
    """
    languages: set[str] = set()

    # Check for lockfile/manifest indicators
    for filename, lang in _LANG_LOCKFILE_MAP.items():
        if os.path.isfile(os.path.join(repo_path, filename)):
            languages.add(lang)

    # Dockerfile with any suffix (e.g. Dockerfile.prod)
    if any(f.startswith("Dockerfile") for f in os.listdir(repo_path)
           if os.path.isfile(os.path.join(repo_path, f))):
        languages.add("docker")

    # requirements*.txt patterns
    for f in os.listdir(repo_path):
        if f.startswith("requirements") and f.endswith(".txt"):
            languages.add("python")
            break

    # Terraform: *.tf or *.tfvars anywhere in repo
    for root, _dirs, files in os.walk(repo_path):
        for f in files:
            if f.endswith(".tf") or f.endswith(".tfvars"):
                languages.add("terraform")
                break
        else:
            continue
        break

    # Kubernetes: *.yaml/*.yml in k8s-related paths
    k8s_path_patterns = {"kubernetes", "k8s", "deploy", "manifests", "helm",
                         ".github/workflows"}
    for root, _dirs, files in os.walk(repo_path):
        dirname = os.path.basename(root).lower()
        if dirname in k8s_path_patterns or any(
            p in root for p in k8s_path_patterns
        ):
            for f in files:
                if f.endswith(".yaml") or f.endswith(".yml"):
                    languages.add("kubernetes")
                    break
        else:
            continue
        break

    if not languages:
        logger.debug("No languages detected in %s", repo_path)

    return languages
