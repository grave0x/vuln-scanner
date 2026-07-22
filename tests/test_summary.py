"""Tests for Markdown summary report generator."""

from vuln_scanner.reporters.summary import SummaryWriter
from vuln_scanner.scanners.base import Finding


class TestSummaryGenerate:
    """Tests for SummaryWriter.generate()."""

    def test_empty_findings(self):
        """Summary with no findings should still produce valid Markdown."""
        summary = SummaryWriter.generate(
            "https://github.com/r/repo", "main", []
        )
        assert "# " in summary
        assert "Repository:" in summary
        assert "Branch:" in summary
        assert "Summary" in summary
        assert "Total" in summary
        assert "0" in summary
        assert "Error" in summary
        assert "Warning" in summary
        assert "Note" in summary

    def test_counts_by_severity(self):
        """Summary should count errors, warnings, and notes correctly."""
        findings = [
            Finding(
                rule_id="r1", message="e", severity="error",
                file_path="a.py", scanner="semgrep",
            ),
            Finding(
                rule_id="r2", message="e2", severity="error",
                file_path="b.py", scanner="semgrep",
            ),
            Finding(
                rule_id="r3", message="w", severity="warning",
                file_path="c.py", scanner="gitleaks",
            ),
            Finding(
                rule_id="r4", message="n", severity="note",
                file_path="d.py", scanner="checkov",
            ),
        ]
        summary = SummaryWriter.generate(
            "https://github.com/r/repo", "main", findings
        )
        assert "2" in summary  # Two errors somewhere
        # Check the table has correct counts
        assert "| **Total** | **4** |" in summary

    def test_by_scanner_breakdown(self):
        """Summary should include a per-scanner breakdown table."""
        findings = [
            Finding(
                rule_id="r1", message="e", severity="error",
                file_path="a.py", scanner="semgrep",
            ),
            Finding(
                rule_id="r2", message="w", severity="warning",
                file_path="b.py", scanner="gitleaks",
            ),
        ]
        summary = SummaryWriter.generate(
            "https://github.com/r/repo", "main", findings
        )
        assert "By Scanner" in summary
        assert "semgrep" in summary
        assert "gitleaks" in summary

    def test_top_findings_section(self):
        """Summary should include a top findings section."""
        findings = [
            Finding(
                rule_id="r1", message="something bad happened here",
                severity="error", file_path="a.py", line_start=42,
                scanner="semgrep",
            ),
        ]
        summary = SummaryWriter.generate(
            "https://github.com/r/repo", "main", findings
        )
        assert "Top 1 Findings" in summary
        assert "a.py" in summary
        assert "42" in summary
        assert "something bad happened here" in summary

    def test_top_findings_capped_at_10(self):
        """Only top 10 findings should be shown."""
        findings = [
            Finding(
                rule_id=f"r{i}", message=f"msg {i}", severity="warning",
                file_path=f"f{i}.py", scanner="semgrep",
            )
            for i in range(15)
        ]
        summary = SummaryWriter.generate(
            "https://github.com/r/repo", "main", findings
        )
        assert "Top 10 Findings" in summary

    def test_finding_without_line_number(self):
        """Findings without line_start should show '-' in the table."""
        findings = [
            Finding(
                rule_id="r1", message="msg", severity="error",
                file_path="a.py", scanner="semgrep",
            ),
        ]
        summary = SummaryWriter.generate(
            "https://github.com/r/repo", "main", findings
        )
        # Should contain '-' for line number
        lines_with_table_row = [
            l for l in summary.split("\n") if "a.py" in l
        ]
        assert len(lines_with_table_row) >= 1
        assert "-" in lines_with_table_row[0]

    def test_long_message_is_truncated(self):
        """Messages longer than 80 chars should be truncated with ..."""
        long_msg = "x" * 120
        findings = [
            Finding(
                rule_id="r1", message=long_msg, severity="error",
                file_path="a.py", line_start=1, scanner="semgrep",
            ),
        ]
        summary = SummaryWriter.generate(
            "https://github.com/r/repo", "main", findings
        )
        # The displayed message should be truncated
        assert long_msg not in summary
        assert "..." in summary

    def test_scan_duration_is_displayed(self):
        """Summary should include scan duration."""
        findings = [
            Finding(
                rule_id="r1", message="msg", severity="error",
                file_path="a.py", scanner="semgrep",
            ),
        ]
        summary = SummaryWriter.generate(
            "https://github.com/r/repo", "main", findings,
            scan_duration_seconds=42.5,
        )
        assert "42.5s" in summary

    def test_errors_sorted_first(self):
        """Errors should appear before warnings in top findings."""
        findings = [
            Finding(
                rule_id="r2", message="warning msg", severity="warning",
                file_path="b.py", scanner="gitleaks",
            ),
            Finding(
                rule_id="r1", message="error msg", severity="error",
                file_path="a.py", scanner="semgrep",
            ),
        ]
        summary = SummaryWriter.generate(
            "https://github.com/r/repo", "main", findings
        )
        # "error msg" should appear before "warning msg"
        error_pos = summary.index("error msg")
        warning_pos = summary.index("warning msg")
        assert error_pos < warning_pos


class TestSummaryWrite:
    """Tests for SummaryWriter.write()."""

    def test_write_to_file(self, tmp_path):
        """Summary should be written to a file."""
        summary_text = "# Test Summary\n\nHello world"
        path = tmp_path / "summary.md"
        SummaryWriter.write(summary_text, str(path))
        assert path.exists()
        assert path.read_text() == summary_text
