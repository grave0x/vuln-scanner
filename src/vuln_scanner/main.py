"""CLI entry point for vuln-scanner."""

import argparse
import os
import sys


def main():
    parser = argparse.ArgumentParser(prog="vuln-scanner")
    sub = parser.add_subparsers(dest="command")

    run_p = sub.add_parser("run", help="Run vulnerability scan")
    run_p.add_argument("--config", default=None, help="Config file path")
    run_p.add_argument("--schedule", default=None,
                       help="Filter repos by schedule tag")
    run_p.add_argument("--repo-filter", default=None,
                       help="Regex filter for repo URLs")
    run_p.add_argument("--dry-run", action="store_true",
                       help="Validate config and list repos, skip scanning")

    val_p = sub.add_parser("validate", help="Validate config file only")
    val_p.add_argument("--config", default=None, help="Config file path")

    sub.add_parser("list-scanners",
                   help="List available scanners and their install status")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "list-scanners":
        from .scanners.registry import list_scanners
        list_scanners()
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
                            args.repo_filter, args.dry_run)
        orch.run()
