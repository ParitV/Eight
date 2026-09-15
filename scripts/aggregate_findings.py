#!/usr/bin/env python3
"""Aggregate CodeQL, Semgrep, and ZAP output into one Markdown security report."""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
FAIL_SEVERITIES = {"Critical", "High"}

SARIF_LEVEL_TO_SEVERITY = {"error": "High", "warning": "Medium", "note": "Low"}
ZAP_RISKCODE_TO_SEVERITY = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}

_ACTIONABLE_VERBS = (
    "Ensure|Consider|Use|Avoid|Validate|Rotate|Set|Enable|Sanitize|Implement|Replace|Instead"
)
_ACTIONABLE_SENTENCE = re.compile(
    rf"(?:(?<=^)|(?<=[.!?]\s))\b(?:{_ACTIONABLE_VERBS})\b.*?[.!?](?=\s|$)"
)


@dataclass
class Finding:
    tool: str
    file: str
    line: str
    severity: str
    message: str
    fix_hint: str


def _strip_html(text: str) -> str:
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _first_line(text: str) -> str:
    text = (text or "").strip()
    return text.splitlines()[0] if text else ""


def _severity_from_security_severity(score) -> str | None:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return "Critical"
    if value >= 7.0:
        return "High"
    if value >= 4.0:
        return "Medium"
    return "Low"


def _severity_from_sarif_level(level: str) -> str:
    return SARIF_LEVEL_TO_SEVERITY.get(level, "Info")


def _codeql_fix_hint(rule: dict) -> str:
    help_text = rule.get("help", {}).get("text", "")
    marker = "## Recommendation"
    if marker in help_text:
        after = help_text.split(marker, 1)[1].split("##", 1)[0].strip()
        if after:
            return _first_line(after)
    return rule.get("shortDescription", {}).get("text", "")


def parse_codeql(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for run in data.get("runs", []):
        rules_by_id: dict[str, dict] = {}
        for ext in run.get("tool", {}).get("extensions", []):
            for rule in ext.get("rules", []):
                rules_by_id[rule["id"]] = rule
        for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
            rules_by_id.setdefault(rule["id"], rule)

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules_by_id.get(rule_id, {})
            props = rule.get("properties", {})

            severity = _severity_from_security_severity(props.get("security-severity"))
            if severity is None:
                level = rule.get("defaultConfiguration", {}).get("level", "warning")
                severity = _severity_from_sarif_level(level)

            location = (result.get("locations") or [{}])[0]
            phys = location.get("physicalLocation", {})
            uri = phys.get("artifactLocation", {}).get("uri", "unknown")
            file_path = uri if uri.startswith("target-app/") else f"target-app/{uri}"
            line = phys.get("region", {}).get("startLine", "")

            findings.append(
                Finding(
                    tool="CodeQL",
                    file=file_path,
                    line=str(line) if line != "" else "",
                    severity=severity,
                    message=_first_line(result.get("message", {}).get("text", "")) or rule_id,
                    fix_hint=_codeql_fix_hint(rule) or "See CodeQL query documentation.",
                )
            )
    return findings


def _semgrep_fix_hint(message: str, rule: dict) -> str:
    for text in (message, rule.get("fullDescription", {}).get("text", "")):
        actionable = " ".join(m.strip() for m in _ACTIONABLE_SENTENCE.findall(text or ""))
        if actionable:
            return actionable
    help_uri = rule.get("helpUri", "")
    return f"See rule documentation: {help_uri}" if help_uri else "See Semgrep rule documentation."


def parse_semgrep(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for run in data.get("runs", []):
        rules_by_id = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules_by_id.get(rule_id, {})
            level = rule.get("defaultConfiguration", {}).get("level", "warning")
            severity = _severity_from_sarif_level(level)

            location = (result.get("locations") or [{}])[0]
            phys = location.get("physicalLocation", {})
            file_path = phys.get("artifactLocation", {}).get("uri", "unknown")
            line = phys.get("region", {}).get("startLine", "")

            message = _first_line(result.get("message", {}).get("text", "")) or rule_id
            fix_hint = _semgrep_fix_hint(message, rule)

            findings.append(
                Finding(
                    tool="Semgrep",
                    file=file_path,
                    line=str(line) if line != "" else "",
                    severity=severity,
                    message=message,
                    fix_hint=fix_hint,
                )
            )
    return findings


def parse_zap(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            severity = ZAP_RISKCODE_TO_SEVERITY.get(alert.get("riskcode", ""), "Info")

            instances = alert.get("instances", [])
            urls = [i.get("uri", "") for i in instances if i.get("uri")]
            file_ref = urls[0] if urls else site.get("@name", "unknown")
            if len(urls) > 1:
                file_ref += f" (+{len(urls) - 1} more)"

            findings.append(
                Finding(
                    tool="ZAP",
                    file=file_ref,
                    line="",
                    severity=severity,
                    message=alert.get("alert", "Unknown alert"),
                    fix_hint=_strip_html(alert.get("solution", "")) or "See ZAP alert reference.",
                )
            )
    return findings


def _escape_md(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def build_report(findings: list[Finding]) -> str:
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    lines = [
        "# Security Findings Report",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|---|---|",
    ]
    lines += [f"| {sev} | {counts[sev]} |" for sev in SEVERITY_ORDER]
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")

    if not findings:
        lines.append("No findings reported.")
        lines.append("")
        return "\n".join(lines)

    lines += [
        "## Findings",
        "",
        "| Tool | Severity | File | Line | Message | Fix Hint |",
        "|---|---|---|---|---|---|",
    ]

    order_index = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    for finding in sorted(
        findings,
        key=lambda f: (order_index.get(f.severity, len(SEVERITY_ORDER)), f.tool, f.file, f.line),
    ):
        lines.append(
            "| {tool} | {severity} | {file} | {line} | {message} | {fix_hint} |".format(
                tool=finding.tool,
                severity=finding.severity,
                file=_escape_md(finding.file),
                line=finding.line or "-",
                message=_escape_md(finding.message),
                fix_hint=_escape_md(finding.fix_hint),
            )
        )
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codeql-sarif", required=True, type=Path)
    parser.add_argument("--semgrep-sarif", required=True, type=Path)
    parser.add_argument("--zap-json", required=True, type=Path)
    parser.add_argument("--output", default=Path("report.md"), type=Path)
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    findings += parse_codeql(args.codeql_sarif)
    findings += parse_semgrep(args.semgrep_sarif)
    findings += parse_zap(args.zap_json)

    args.output.write_text(build_report(findings), encoding="utf-8")

    high_or_critical = [f for f in findings if f.severity in FAIL_SEVERITIES]
    print(
        f"Wrote {len(findings)} finding(s) to {args.output} "
        f"({len(high_or_critical)} High/Critical)."
    )

    return 1 if high_or_critical else 0


if __name__ == "__main__":
    sys.exit(main())
