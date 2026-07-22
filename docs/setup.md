# Setup Guide

## Quick start

1. **Fork or clone** this repo
2. **Configure** your target repos in `config.yaml` (see `config.example.yaml` for reference)
3. **Enable Actions** in repo Settings → Actions → Allow all actions
4. **Done** — the daily scan runs at 6:07am UTC

Trigger manually from the **Actions tab → Vulnerability Scan → Run workflow**.

---

## Private repository access

If the repos listed in `config.yaml` are private, the scan runner needs auth to clone them.

### Option A: Classic PAT (simplest)

1. Go to [github.com/settings/tokens](https://github.com/settings/tokens)
2. **Generate new token (classic)**
3. Scope: tick **`repo`** (full control of private repositories)
4. Copy the token
5. Go to your repo → **Settings → Secrets and variables → Actions**
6. **New repository secret** → Name: `GIT_TOKEN`, Value: paste token → **Add secret**

### Option B: Fine-grained token (least privilege)

1. Go to [github.com/settings/tokens?type=beta](https://github.com/settings/tokens?type=beta)
2. **Generate new token**
3. Resource owner: your user/org
4. Repository access: **All repositories** (or select the target repos individually)
5. Permissions: **Contents → Read-only**
6. Create, copy, add as `GIT_TOKEN` secret (same steps as Option A)

The workflow injects `GIT_TOKEN` into clone URLs as `https://<token>@github.com/...`.

---

## Configuration

Copy and edit the example config:

```bash
cp config.example.yaml config.yaml
```

Key fields:

| Field | Description |
|-------|-------------|
| `repositories[].url` | Git clone URL (HTTPS or SSH) |
| `repositories[].branch` | Branch to scan |
| `repositories[].schedule` | `daily`, `weekly`, `monthly`, or `manual` |
| `repositories[].scanners` | Enable/disable per-scanner per-repo |
| `repositories[].exclude_paths` | Glob patterns to skip |
| `scanners.semgrep_config` | SAST ruleset: `p/default`, `auto`, or custom path |
| `reporting.sarif_path` | SARIF output path (uploaded to Security tab) |
| `reporting.summary_path` | Markdown summary path |

---

## Scanners

| Scanner | Tool | What it finds |
|---------|------|---------------|
| **semgrep** | [semgrep](https://semgrep.dev) | SAST — SQL injection, XSS, unsafe functions, hardcoded secrets |
| **gitleaks** | [gitleaks](https://gitleaks.io) | Secrets — API keys, tokens, credentials, private keys |
| **checkov** | [checkov](https://checkov.io) | IaC — Terraform, CloudFormation, Kubernetes, Dockerfile misconfigs |
| **dependency** | [osv-scanner](https://google.github.io/osv-scanner/) | CVEs in npm, PyPI, Cargo, Go, Maven, Ruby dependencies |

---

## Local usage

```bash
pip install -e ".[dev]"

# Validate config
vuln-scanner validate --config config.yaml

# List available scanners
vuln-scanner list-scanners

# Dry run (list repos, skip scanning)
vuln-scanner run --config config.yaml --dry-run

# Full scan
vuln-scanner run --config config.yaml

# Filter by schedule tag
vuln-scanner run --config config.yaml --schedule daily

# Filter by repo URL regex
vuln-scanner run --config config.yaml --repo-filter "my-org"
```

---

## Viewing results

- **GitHub Security tab → Code scanning** — SARIF findings with file/line annotations
- **Actions tab → workflow run → Artifacts** — `results.sarif` + `summary.md` (90-day retention)

---

## Workflows

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `ci.yml` | Push/PR to main | Tests on Python 3.11–3.13 + CLI verification |
| `scan.yml` | Daily cron, manual dispatch, push to config/src | Clone repos, run scanners, upload SARIF |
| `validate-config.yml` | PR touching config files | Validate YAML config syntax |
