# Project: SAST/DAST Security Pipeline Wrapper

## Goal
A GitHub Actions pipeline that:
1. Runs CodeQL + Semgrep (SAST) on every push/PR
2. Builds the app in Docker and runs OWASP ZAP baseline scan (DAST) against it
3. Aggregates all three tools' output (SARIF/JSON) into one Markdown report
4. Fails the build (exit 1) on any High/Critical finding
5. Posts the report as a PR comment

## Stack
- Target app: [Node/Express OR Python/FastAPI — pick one]
- Aggregator script: Python
- CI: GitHub Actions only, must stay free (public repo)

## Conventions
- Keep all workflow files under .github/workflows/
- Aggregator script lives in scripts/aggregate_findings.py
- Never hardcode secrets — flag it if you see one added