# SAST/DAST Security Pipeline

A GitHub Actions pipeline that runs static and dynamic security scans on every pull request, aggregates the results into one Markdown report, posts it as a PR comment, and fails the build on High/Critical findings.

This repo is both a working demo (`target-app/` is an intentionally vulnerable Node/Express app for the scanners to catch) and a reusable component: the aggregation step is published as a composite GitHub Action (`ParitV/Eight@v1`) that any other repo can call directly.

## What it does

1. **CodeQL** and **Semgrep** run SAST against the app, each producing a SARIF report.
2. The app is built into a Docker image, run, and scanned with an **OWASP ZAP** baseline scan (DAST), producing an HTML/Markdown/JSON report.
3. All three reports are uploaded as workflow artifacts.
4. On pull requests, a final job downloads those three artifacts and runs the **Aggregate Security Findings** action, which:
   - normalizes CodeQL/Semgrep/ZAP output into one `report.md`
   - posts it as a comment on the PR
   - fails the job if any finding is High or Critical severity

## How it works

`.github/workflows/security.yml` defines four jobs:

| Job | Trigger | Produces |
|---|---|---|
| `codeql` | push to `main`, every PR | `codeql-sarif` artifact |
| `semgrep` | push to `main`, every PR | `semgrep-sarif` artifact |
| `zap-dast` | push to `main`, every PR | `zap-report` artifact |
| `report` | **PR only** | downloads the three artifacts above, runs the aggregator, comments, gates on severity |

The `report` job doesn't reimplement the aggregation logic — it calls this same repo's own composite action (`uses: ./`), which wraps `scripts/aggregate_findings.py`. That's the exact same action published as `ParitV/Eight@v1` for external use (see below).

## Repo layout

- `.github/workflows/security.yml` — the pipeline
- `action.yml` — the composite action (CodeQL/Semgrep/ZAP → `report.md` → PR comment → pass/fail)
- `target-app/` — the Node/Express app under test (contains a few intentionally planted vulnerabilities for the scanners to catch — see the comments in `target-app/config.js` and `target-app/server.js`)
- `scripts/aggregate_findings.py` — normalizes CodeQL/Semgrep/ZAP output into a Markdown report; the logic behind the action
- `fixtures/` — sample SARIF/JSON output used by `tests/test_aggregate_findings.py`
- `tests/` — tests for the aggregator script

## Using this on your own code

You don't need to fork or copy this repo. There are two ways to adopt it, depending on how much you want to reuse.

### Option A: You already run CodeQL/Semgrep/ZAP — just add the report step

If your repo already produces a CodeQL SARIF file, a Semgrep SARIF file, and a ZAP JSON report (as workflow artifacts, or just as files on disk in the same job), add one step that calls the published action:

```yaml
- name: Aggregate findings & comment on PR
  uses: ParitV/Eight@v1
  with:
    codeql-sarif: path/to/codeql.sarif
    semgrep-sarif: path/to/semgrep.sarif
    zap-json: path/to/zap-report.json
    # optional, all default as shown:
    report-path: report.md
    post-comment: 'true'      # only actually posts on pull_request events
    fail-on-findings: 'true'  # fail the job if any High/Critical finding exists
    # github-token: ${{ github.token }}  # override only if you need a different token
```

Requirements for this step's job:
- Triggered on `pull_request` if you want the comment to post (it silently skips commenting on other events)
- `permissions: pull-requests: write` on the job (or workflow), so the action can post the comment

That's the entire integration — no need to touch your existing scan jobs.

### Option B: You're starting from scratch — copy the whole pipeline

1. **Copy the workflow file.** Copy `.github/workflows/security.yml` into your repo at the same path.

2. **Point the jobs at your app instead of `target-app/`.**
   - `codeql`: change `source-root: target-app` to your app's directory (or remove `source-root` if your app is at the repo root), and change `languages: javascript` to whatever your app's language is.
   - `semgrep`: change `target-app/` in the `semgrep scan ... target-app/` command to your app's path.
   - `zap-dast`: change `docker build -t target-app:ci ./target-app` and the container run/port lines to match your app's Dockerfile location and port. If your app isn't containerized, you'll need to adjust how it gets started before the ZAP step — ZAP just needs a running HTTP target to scan.

3. **Leave the `report` job as-is**, or simplify it to use the published action directly instead of `uses: ./`:
   ```yaml
   - name: Aggregate findings & comment on PR
     uses: ParitV/Eight@v1
     with:
       codeql-sarif: artifacts/codeql/<your-codeql-file>.sarif
       semgrep-sarif: artifacts/semgrep/semgrep-results.sarif
       zap-json: artifacts/zap/report_json.json
   ```
   (This is exactly what this repo's own `report` job does, just referencing the action by tag instead of by local path.)

4. **Push and open a pull request.** Watch the Actions tab — you should see `CodeQL (SAST)`, `Semgrep (SAST)`, `OWASP ZAP Baseline (DAST)`, then `Aggregate Findings & Comment on PR` run in that order, and a report comment appear on the PR.

5. **(Optional) Require the checks.** In your repo's Settings → Branches → branch protection rule for your default branch, add the three scan job names as required status checks. If you also want the aggregation job to block merges on High/Critical findings, add it too — but note it will block *every* PR for as long as any High/Critical finding exists anywhere in your app, so most teams treat it as informational (comment-only) rather than required.

## Running the aggregator locally

```
python scripts/aggregate_findings.py \
  --codeql-sarif <path-to-codeql-sarif> \
  --semgrep-sarif <path-to-semgrep-sarif> \
  --zap-json <path-to-zap-report-json> \
  --output report.md
```

Exits non-zero if any finding is High or Critical.

## License

[MIT](LICENSE)
