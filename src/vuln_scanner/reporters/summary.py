"""Markdown summary report generator."""

from datetime import datetime, timezone
from pathlib import Path

from ..scanners.base import Finding


class SummaryWriter:
    """Generates a human-readable Markdown summary of scan results."""

    @staticmethod
    def generate(
        repo_url: str,
        repo_branch: str,
        findings: list[Finding],
        scan_duration_seconds: float = 0,
    ) -> str:
        """Generate a Markdown summary string."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Count by scanner and severity
        by_scanner: dict[str, dict[str, int]] = {}
        total = len(findings)
        errors = sum(1 for f in findings if f.severity == "error")
        warnings = sum(1 for f in findings if f.severity == "warning")
        notes = sum(1 for f in findings if f.severity == "note")

        for f in findings:
            by_scanner.setdefault(f.scanner, {"error": 0, "warning": 0, "note": 0})
            by_scanner[f.scanner][f.severity] += 1

        lines = [
            "# \U0001f512 Vulnerability Scan Report",
            "",
            f"**Repository:** `{repo_url}`  ",
            f"**Branch:** `{repo_branch}`  ",
            f"**Scan time:** {now}  ",
            f"**Duration:** {scan_duration_seconds:.1f}s",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| \U0001f534 Error  | {errors} |",
            f"| \U0001f7e1 Warning | {warnings} |",
            f"| \U0001f535 Note   | {notes} |",
            f"| **Total** | **{total}** |",
            "",
        ]

        if by_scanner:
            lines.append("## By Scanner")
            lines.append("")
            lines.append("| Scanner | Errors | Warnings | Notes | Total |")
            lines.append("|---------|--------|----------|-------|-------|")
            for scanner, counts in sorted(by_scanner.items()):
                total_scanner = sum(counts.values())
                lines.append(
                    f"| {scanner} | {counts['error']} | "
                    f"{counts['warning']} | {counts['note']} | {total_scanner} |"
                )
            lines.append("")

        # Top findings
        if findings:
            severity_order = {"error": 0, "warning": 1, "note": 2}
            sorted_findings = sorted(
                findings,
                key=lambda f: (severity_order.get(f.severity, 99), f.file_path),
            )
            top_n = min(10, len(sorted_findings))

            lines.append(f"## Top {top_n} Findings")
            lines.append("")
            lines.append(
                "| Severity | File | Line | Scanner | Description |"
            )
            lines.append(
                "|----------|------|------|---------|-------------|"
            )
            for f in sorted_findings[:top_n]:
                line_info = str(f.line_start) if f.line_start else "-"
                desc = f.message[:80] + ("..." if len(f.message) > 80 else "")
                lines.append(
                    f"| {f.severity} | `{f.file_path}` | {line_info} | "
                    f"{f.scanner} | {desc} |"
                )
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def write(summary: str, path: str) -> None:
        """Write summary to a file."""
        with open(path, "w") as f:
            f.write(summary)
