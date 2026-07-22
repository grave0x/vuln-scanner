# vuln-scanner

Autonomous git repository vulnerability scanner powered by GitHub Actions.

Clones your repositories on a schedule, runs a multi-tool security scan
(SAST, secrets, IaC, dependencies), and uploads results as SARIF to
GitHub's Security tab.

## How it works

1. **Schedule**: GitHub Actions cron triggers daily (configurable)
2. **Clone**: Shallow-clone target repos from your config
3. **Scan**: Run semgrep (SAST), gitleaks (secrets), checkov (IaC), osv-scanner (dependencies)
4. **Report**: Generate SARIF 2.1.0 → upload to Security tab + Markdown summary

## Quick start

### 1. Fork or create from this repo

### 2. Configure your repos

```bash
cp config.example.yaml config.yaml
```

Edit `config.yaml` — add the repos you want to scan:

```yaml
repositories:
  - url: https://github.com/your-org/your-repo.git
    branch: main
    schedule: daily
    scanners:
      semgrep: true
      gitleaks: true
      checkov: true
      dependency: true
```

### 3. Enable GitHub Actions

Go to your repo → Actions → enable workflows.
The scan runs daily at 6am UTC, or trigger manually from the Actions tab.

### 4. View results

Findings appear in your repo's **Security tab → Code scanning**.
A Markdown summary is uploaded as a workflow artifact.

## Scanners

| Scanner | Tool | What it finds |
|---------|------|---------------|
| **semgrep** | [semgrep](https://semgrep.dev) | SAST — SQL injection, XSS, unsafe functions, hardcoded secrets in code |
| **gitleaks** | [gitleaks](https://gitleaks.io) | Secrets — API keys, tokens, credentials, private keys |
| **checkov** | [checkov](https://checkov.io) | IaC — Terraform, CloudFormation, Kubernetes, Dockerfile misconfigs |
| **dependency** | [osv-scanner](https://google.github.io/osv-scanner/) | CVEs in npm, PyPI, Cargo, Go, Maven, Ruby dependencies |

## Configuration

See `config.example.yaml` for the full annotated reference.
Key options:

- `repositories[].url` — git clone URL (HTTPS or SSH)
- `repositories[].schedule` — `daily`, `weekly`, `monthly`, or `manual`
- `repositories[].scanners` — enable/disable per-scanner per-repo
- `repositories[].exclude_paths` — glob patterns to skip
- `scanners.<name>.*` — global scanner defaults

## CLI

```bash
# Run a scan
vuln-scanner run --config config.yaml

# Dry run (list repos, skip scanning)
vuln-scanner run --config config.yaml --dry-run

# Validate config
vuln-scanner validate --config config.yaml

# List available scanners
vuln-scanner list-scanners
```

## Requirements

- Python >= 3.11
- Git
- Scanner CLI tools (installed automatically by the workflow):
  - semgrep, gitleaks, checkov, osv-scanner

## License

MIT
