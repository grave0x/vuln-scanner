"""CLI entry point for vuln-scanner."""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(prog="vuln-scanner")
    sub = parser.add_subparsers(dest="command")

    # --- run subcommand ---
    run_p = sub.add_parser("run", help="Run vulnerability scan")
    run_p.add_argument("--config", default=None, help="Config file path")
    run_p.add_argument("--schedule", default=None,
                       help="Filter repos by schedule tag")
    run_p.add_argument("--repo-filter", default=None,
                       help="Regex filter for repo URLs")
    run_p.add_argument("--dry-run", action="store_true",
                       help="Validate config and list repos, skip scanning")
    run_p.add_argument("--fail-on", default="never",
                       choices=["never", "note", "warning", "error"],
                       help="Severity threshold for non-zero exit "
                            "(default: never)")
    run_p.add_argument("--output-dir", default=None,
                       help="Directory for output reports")

    # --- scan subcommand ---
    scan_p = sub.add_parser("scan", help="Scan a single repository")
    scan_p.add_argument("--repo", required=True,
                        help="Repository URL to scan")
    scan_p.add_argument("--branch", default="main",
                        help="Branch to scan (default: main)")
    scan_p.add_argument("--output-dir", default=None,
                        help="Directory for output reports")
    scan_p.add_argument("--fail-on", default="never",
                        choices=["never", "note", "warning", "error"],
                        help="Severity threshold for non-zero exit "
                             "(default: never)")

    # --- validate subcommand ---
    val_p = sub.add_parser("validate", help="Validate config file only")
    val_p.add_argument("--config", default=None, help="Config file path")

    # --- list-scanners subcommand ---
    sub.add_parser("list-scanners",
                   help="List available scanners and their install status")

    # --- install-tools subcommand ---
    sub.add_parser("install-tools",
                   help="Check and install scanner CLI tools")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "list-scanners":
        from .scanners.registry import list_scanners
        list_scanners()
        return

    if args.command == "install-tools":
        _install_tools()
        return

    if args.command == "scan":
        _run_scan(args)
        return

    config_path = args.config or os.environ.get(
        "VULN_SCANNER_CONFIG", "config.yaml"
    )

    if args.command == "validate":
        from .config import Config
        try:
            Config.load(config_path)
            print(f"\u2713 Config at {config_path} is valid")
        except Exception as e:
            print(f"\u2717 Config error: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.command == "run":
        from .orchestrator import Orchestrator
        orch = Orchestrator(config_path, args.schedule,
                            args.repo_filter, args.dry_run,
                            fail_on=args.fail_on,
                            output_dir=args.output_dir)
        sys.exit(orch.run())


def _run_scan(args) -> None:
    """Handle the 'scan' subcommand: create temp config and run."""
    from .orchestrator import Orchestrator

    # Build a temporary config with a single repo
    config_data = {
        "version": 1,
        "settings": {
            "work_dir": tempfile.mkdtemp(prefix="vuln-scan-"),
            "cleanup_after_scan": True,
        },
        "repositories": [
            {
                "url": args.repo,
                "branch": args.branch,
            },
        ],
    }

    import yaml
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        yaml.dump(config_data, f)
        config_path = f.name

    try:
        orch = Orchestrator(
            config_path,
            fail_on=args.fail_on,
            output_dir=args.output_dir,
        )
        sys.exit(orch.run())
    finally:
        try:
            os.unlink(config_path)
        except OSError:
            pass


def _install_tools() -> None:
    """Check and install scanner CLI tools."""
    tools = {
        "semgrep": {
            "type": "pip",
            "binary": "semgrep",
            "package": "semgrep",
        },
        "gitleaks": {
            "type": "curl",
            "binary": "gitleaks",
            "url": "https://github.com/gitleaks/gitleaks/releases/latest/"
                   "download/gitleaks_8.18.0_linux_x64.tar.gz",
        },
        "checkov": {
            "type": "pip",
            "binary": "checkov",
            "package": "checkov",
        },
        "osv-scanner": {
            "type": "curl",
            "binary": "osv-scanner",
            "url": "https://github.com/google/osv-scanner/releases/latest/"
                   "download/osv-scanner_linux_amd64",
        },
        "trufflehog": {
            "type": "curl",
            "binary": "trufflehog",
            "url": "https://github.com/trufflesecurity/trufflehog/releases/"
                   "latest/download/trufflehog_3.82.0_linux_amd64.tar.gz",
        },
    }

    for name, info in tools.items():
        binary = info["binary"]
        if shutil.which(binary):
            print(f"\u2713 {name:<15} already installed ({binary})")
            continue

        print(f"\u25cb {name:<15} installing...", end=" ", flush=True)
        try:
            if info["type"] == "pip":
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", info["package"]],
                    check=True, capture_output=True, text=True,
                )
            elif info["type"] == "curl":
                _install_curl_binary(name, binary, info["url"])

            if shutil.which(binary):
                print("\u2713 done")
            else:
                print("\u2717 installed but not on PATH")
        except Exception as e:
            print(f"\u2717 failed: {e}")


def _install_curl_binary(name: str, binary: str, url: str) -> None:
    """Download and install a binary from a URL."""
    install_dir = Path.home() / ".local" / "bin"
    install_dir.mkdir(parents=True, exist_ok=True)

    if url.endswith(".tar.gz"):
        import tarfile
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / f"{name}.tar.gz"
            subprocess.run(
                ["curl", "-fsSL", "-o", str(archive), url],
                check=True, capture_output=True, text=True,
            )
            with tarfile.open(archive, "r:gz") as tar:
                # Extract the binary
                for member in tar.getmembers():
                    if member.name == binary:
                        member.name = binary
                        tar.extract(member, str(install_dir))
                        break
    else:
        dest = install_dir / binary
        subprocess.run(
            ["curl", "-fsSL", "-o", str(dest), url],
            check=True, capture_output=True, text=True,
        )
        dest.chmod(0o755)

    # Add to PATH for this session
    os.environ["PATH"] = str(install_dir) + os.pathsep + os.environ.get("PATH", "")
