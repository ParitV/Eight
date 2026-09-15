# SAST/DAST Security Pipeline

A GitHub Actions pipeline that runs static and dynamic security scans on every pull request, aggregates the results into one Markdown report, posts it as a PR comment, and fails the build on High/Critical findings.

This repo is both a working demo (`target-app/` is an intentionally vulnerable Node/Express app for the scanners to catch) and a reusable component. The aggregation step is published as a composite GitHub Action (`ParitV/Eight@v1`) that any other repo can call directly.

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
| `report` | PR only | downloads the three artifacts above, runs the aggregator, comments, gates on severity |

The `report` job doesn't reimplement the aggregation logic. It calls this same repo's own composite action (`uses: ./`), which wraps `scripts/aggregate_findings.py`. That's the exact same action published as `ParitV/Eight@v1` for external use (see below).

## Repo layout

- `.github/workflows/security.yml`: the pipeline
- `action.yml`: the composite action (takes CodeQL/Semgrep/ZAP output, writes `report.md`, comments on the PR, passes or fails)
- `target-app/`: the Node/Express app under test. It has a few intentionally planted vulnerabilities for the scanners to catch, see the comments in `target-app/config.js` and `target-app/server.js`
- `scripts/aggregate_findings.py`: normalizes CodeQL/Semgrep/ZAP output into a Markdown report. This is the logic behind the action
- `fixtures/`: sample SARIF/JSON output used by `tests/test_aggregate_findings.py`
- `tests/`: tests for the aggregator script

## Using this on your own code

You don't need to fork or copy this repo. There are two ways to adopt it, depending on how much you want to reuse.

### Option A: You already run CodeQL/Semgrep/ZAP, just add the report step

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
- It needs to be triggered on `pull_request` if you want the comment to post (it silently skips commenting on other events)
- The job (or workflow) needs `permissions: pull-requests: write`, so the action can post the comment

That's the whole integration. No need to touch your existing scan jobs.

### Option B: You're starting from scratch, copy the whole pipeline

1. **Copy the workflow file.** Copy `.github/workflows/security.yml` into your repo at the same path.

2. **Point the CodeQL and Semgrep jobs at your app instead of `target-app/`.**
   - `codeql`: change `source-root: target-app` to your app's directory (or remove `source-root` if your app is at the repo root), and change `languages: javascript` to whatever your app's language is.
   - `semgrep`: change `target-app/` in the `semgrep scan ... target-app/` command to your app's path.

3. **Point the `zap-dast` job at your app.** ZAP just needs a running HTTP server to scan. How you get there depends on whether your app runs in Docker.

   If your app has a Dockerfile, swap the image name, port, and target URL for yours. For example, if your app is a Node app on port 3000 living in `my-app/`:

   ```yaml
   - name: Build my-app Docker image
     run: docker build -t my-app:ci ./my-app

   - name: Run my-app container
     run: docker run -d --name my-app -p 3000:3000 my-app:ci

   - name: Wait for my-app to be ready
     run: |
       for i in $(seq 1 30); do
         if curl -sSf http://localhost:3000/ > /dev/null; then
           echo "my-app is up"
           exit 0
         fi
         sleep 2
       done
       exit 1

   - name: ZAP Baseline Scan
     uses: zaproxy/action-baseline@v0.15.0
     with:
       target: 'http://localhost:3000'
   ```

   If your app isn't containerized, skip the Docker steps and just start it directly on the runner in the background, then wait for it the same way. For example, a Python app started with `python app.py` on port 5000:

   ```yaml
   - name: Install dependencies
     run: pip install -r my-app/requirements.txt

   - name: Start my-app in the background
     run: |
       cd my-app
       nohup python app.py &

   - name: Wait for my-app to be ready
     run: |
       for i in $(seq 1 30); do
         if curl -sSf http://localhost:5000/ > /dev/null; then
           echo "my-app is up"
           exit 0
         fi
         sleep 2
       done
       exit 1

   - name: ZAP Baseline Scan
     uses: zaproxy/action-baseline@v0.15.0
     with:
       target: 'http://localhost:5000'
   ```

   The pattern is always the same: start the app, poll it with `curl` in a loop until it responds, then point ZAP's `target` at that same URL.

4. **Leave the `report` job as-is**, or simplify it to use the published action directly instead of `uses: ./`:
   ```yaml
   - name: Aggregate findings & comment on PR
     uses: ParitV/Eight@v1
     with:
       codeql-sarif: artifacts/codeql/<your-codeql-file>.sarif
       semgrep-sarif: artifacts/semgrep/semgrep-results.sarif
       zap-json: artifacts/zap/report_json.json
   ```
   This is exactly what this repo's own `report` job does, just referencing the action by tag instead of by local path.

5. **Push and open a pull request.** Watch the Actions tab. You should see `CodeQL (SAST)`, `Semgrep (SAST)`, `OWASP ZAP Baseline (DAST)`, then `Aggregate Findings & Comment on PR` run in that order, and a report comment appear on the PR.

6. **(Optional) Require the checks.** In your repo's Settings, under Branches, edit the branch protection rule for your default branch and add the three scan job names as required status checks. If you also want the aggregation job to block merges on High/Critical findings, add it too, but keep in mind it will block every PR for as long as any High/Critical finding exists anywhere in your app. Most teams end up treating it as informational (comment-only) rather than required, for that reason.

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
