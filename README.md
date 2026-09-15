# SAST/DAST Security Pipeline Wrapper

A GitHub Actions pipeline that runs static and dynamic security scans against `target-app/` and reports the results on every pull request.

## What it does

1. **CodeQL** and **Semgrep** run SAST against `target-app/`, each producing a SARIF report.
2. `target-app` is built into a Docker image, run, and scanned with an **OWASP ZAP** baseline (DAST) scan, producing an HTML/Markdown/JSON report.
3. On pull requests, a final job downloads all three reports, runs `scripts/aggregate_findings.py` to normalize them into one Markdown report, and posts it as a PR comment.
4. The workflow fails if any finding is High or Critical severity.

## Layout

- `.github/workflows/security.yml` — the pipeline
- `target-app/` — the Node/Express app under test (contains a few intentionally planted vulnerabilities for the scanners to catch)
- `scripts/aggregate_findings.py` — normalizes CodeQL/Semgrep/ZAP output into `report.md`
- `fixtures/` — sample SARIF/JSON output used by `tests/test_aggregate_findings.py`
- `tests/` — tests for the aggregator script

## Running the aggregator locally

```
python scripts/aggregate_findings.py \
  --codeql-sarif <path-to-codeql-sarif> \
  --semgrep-sarif <path-to-semgrep-sarif> \
  --zap-json <path-to-zap-report-json> \
  --output report.md
```

Exits non-zero if any finding is High or Critical.
