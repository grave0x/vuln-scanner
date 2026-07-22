# vuln-scanner Architecture Plan

## Project Overview

`vuln-scanner` is an autonomous git repository vulnerability scanner that
clones target repositories, runs multiple security scanners against them,
and uploads results as SARIF to GitHub's Security tab.

## Directory Structure

```
vuln-scanner/
├── .github/workflows/          # GitHub Actions CI/CD
│   ├── scan.yml                # Scheduled + on-demand vulnerability scans
│   ├── validate-config.yml     # PR gate: validate config.example.yaml
│   └── ci.yml                  # Standard CI: test + lint across py3.11-3.13
├── src/vuln_scanner/
│   ├── main.py                 # CLI entry point (argparse)
│   ├── config.py               # YAML config loader (Config, RepoConfig, Settings)
│   ├── orchestrator.py         # Orchestrator: clone → scan → report pipeline
│   ├── repo_manager.py         # Git clone, cleanup, schedule filtering
│   ├── utils.py                # Shared utilities
│   ├── scanners/               # Scanner plugins (AbstractScanner base)
│   │   ├── base.py             # AbstractScanner + Finding dataclass
│   │   ├── registry.py         # Scanner registry + list-scanners CLI
│   │   ├── semgrep.py          # Semgrep SAST scanner
│   │   ├── gitleaks.py         # Gitleaks secret scanner
│   │   ├── checkov.py          # Checkov IaC scanner
│   │   └── dependency.py       # osv-scanner dependency scanner
│   └── reporters/              # Output formatters
│       ├── sarif.py            # SARIF 2.1.0 builder + writer
│       └── summary.py          # Markdown summary writer
├── tests/                      # Pytest test suite
│   ├── test_orchestrator.py
│   ├── test_repo_manager.py
│   ├── test_sarif.py
│   ├── test_scanners.py
│   └── test_summary.py
├── config.example.yaml         # Annotated configuration reference
├── pyproject.toml              # Build config (setuptools, py3.11+)
└── README.md                   # Project documentation
```

## Architecture Decisions

- **CLI**: argparse-based with subcommands (`run`, `validate`, `list-scanners`)
- **Scanner pattern**: AbstractScanner base class with `check_installed()`,
  `version()`, `scan()` interface; each scanner wraps a CLI tool subprocess
- **Config**: YAML with Pydantic-like dataclass validation in `config.py`
- **Reporting**: SARIF 2.1.0 (GitHub Code Scanning compatible) + Markdown summary
- **Orchestration**: Sequential clone → scan → report pipeline with per-repo
  schedule filtering and optional `--dry-run` mode

## CI/CD Pipeline

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `scan.yml` | Cron daily, manual dispatch, push to config/src | Clone repos, run scanners, upload SARIF |
| `validate-config.yml` | PR touching config files | Validate config syntax |
| `ci.yml` | Push/PR to main | Run tests on py3.11-3.13, verify CLI |

## Key Dependencies

- **Runtime**: pyyaml (YAML config parsing)
- **Dev**: pytest, pytest-mock
- **External tools** (installed by scan workflow): semgrep, gitleaks, checkov, osv-scanner
