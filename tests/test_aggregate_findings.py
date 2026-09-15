"""Runs scripts/aggregate_findings.py against fixtures/ and checks its output."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "aggregate_findings.py"
FIXTURES = REPO_ROOT / "fixtures"


class AggregateFindingsTest(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)
        self.output_path = Path(self.tmp_dir.name) / "report.md"

    def run_script(self):
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--codeql-sarif",
                str(FIXTURES / "codeql" / "javascript.sarif"),
                "--semgrep-sarif",
                str(FIXTURES / "semgrep" / "semgrep-results.sarif"),
                "--zap-json",
                str(FIXTURES / "zap" / "report_json.json"),
                "--output",
                str(self.output_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def test_exits_1_and_writes_expected_report(self):
        result = self.run_script()

        self.assertEqual(
            result.returncode, 1, msg=f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        self.assertTrue(self.output_path.exists())

        report = self.output_path.read_text(encoding="utf-8")

        # Summary counts: 1 CodeQL finding, 5 Semgrep findings, 10 ZAP alerts (16 total).
        # High = 1 CodeQL (security-severity 7.8) + 2 Semgrep "error"-level rules
        # (hardcoded Stripe key, Dockerfile missing USER).
        self.assertIn("| Critical | 0 |", report)
        self.assertIn("| High | 3 |", report)
        self.assertIn("| Medium | 5 |", report)
        self.assertIn("| Low | 7 |", report)
        self.assertIn("| Info | 1 |", report)
        self.assertIn("| **Total** | **16** |", report)

        # Each tool's planted/real finding should be traceable in the report.
        self.assertIn("target-app/server.js", report)  # CodeQL reflected XSS location
        self.assertIn("Cross-site scripting", report)
        self.assertIn("target-app/config.js", report)  # Semgrep hardcoded secret location
        self.assertIn("Stripe API Key detected", report)
        self.assertIn("ZAP", report)
        self.assertIn("Content Security Policy (CSP) Header Not Set", report)

    def test_report_has_no_findings_section_when_empty(self):
        empty_dir = Path(self.tmp_dir.name)
        empty_sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "x", "rules": []}}, "results": []}],
        }
        empty_zap = {"site": []}

        import json

        codeql_path = empty_dir / "empty_codeql.sarif"
        semgrep_path = empty_dir / "empty_semgrep.sarif"
        zap_path = empty_dir / "empty_zap.json"
        codeql_path.write_text(json.dumps(empty_sarif), encoding="utf-8")
        semgrep_path.write_text(json.dumps(empty_sarif), encoding="utf-8")
        zap_path.write_text(json.dumps(empty_zap), encoding="utf-8")

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--codeql-sarif",
                str(codeql_path),
                "--semgrep-sarif",
                str(semgrep_path),
                "--zap-json",
                str(zap_path),
                "--output",
                str(self.output_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

        self.assertEqual(result.returncode, 0)
        report = self.output_path.read_text(encoding="utf-8")
        self.assertIn("No findings reported.", report)
        self.assertIn("| **Total** | **0** |", report)


if __name__ == "__main__":
    unittest.main()
