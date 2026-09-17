# Eight

A GitHub Actions pipeline that scans your code (SAST), attacks your running app (DAST), merges the results into one report, and blocks the merge if anything High or Critical turns up.

- **CodeQL** and **Semgrep** scan the source for known-unsafe patterns and data-flow bugs.
- **OWASP ZAP** attacks a live, running copy of the app over HTTP, with no source access, exactly like a real attacker.
- A Python script merges all three tools' output into one Markdown report, posts it as a PR comment, and fails the check if anything is High/Critical severity.

> **This is free, as long as your repo is public.** CodeQL's free tier only applies to public repositories on GitHub's Free plan; on a private repo, it requires a paid GitHub Advanced Security license. Semgrep, OWASP ZAP, and GitHub Actions minutes are all free regardless of visibility, but **CodeQL specifically is the one thing that isn't** unless the repo is public. If you're replicating this to try it out, keep the repo public.

---

## Try it yourself (no setup required)

This repo's own `target-app/` is an intentionally vulnerable Node/Express app: the vulnerabilities are already there, so you don't need to write any bugs yourself to see the pipeline catch something.

1. **Fork this repo** (or clone it and push to a new repo of your own; either works).
2. **Open a pull request against `main`**, even a trivial one, like editing a comment in the README. You don't need to touch `target-app/` at all.
3. **Watch the Actions tab.** You'll see four jobs run in this order: `CodeQL (SAST)` → `Semgrep (SAST)` → `OWASP ZAP Baseline (DAST)` → `Aggregate Findings & Comment on PR`.
4. **Check the PR.** A comment appears listing the vulnerabilities already planted in `target-app/` (see `target-app/config.js` and `target-app/server.js` for what's in there), with severity, file/line, and a suggested fix for each.

That's the whole pipeline, working, with zero configuration, and it's the fastest way to see what it actually does before deciding whether to adopt it in your own project.

---

## Branch protection (to actually enforce it)

Running the pipeline is separate from it *blocking* anything. That second part is a branch protection rule you set up yourself, in **Settings → Branches → Add branch protection rule**:

1. **Branch name pattern**: `main`
2. Check **Require a pull request before merging**
3. Check **Require status checks to pass before merging**, then search for and add:
   - `CodeQL (SAST)`
   - `Semgrep (SAST)`
   - `OWASP ZAP Baseline (DAST)`

**Important nuance:** adding those three checks only guarantees the scans *ran*; it doesn't block on severity. The three scan jobs themselves don't fail just because they found something; they just produce reports. The job that actually fails when something is High/Critical is `Aggregate Findings & Comment on PR`. If you want merges genuinely blocked on real findings, add that job as a required check too.

**One thing to know before you do that on this specific repo:** `target-app/` is *permanently* vulnerable by design, and that's the point of it as a demo. If you require the aggregator job as blocking on this repo (rather than a fork where you've fixed the findings), every PR will be blocked forever, since the findings never go away. For learning/demo purposes, leave the aggregator as informational (comment-only, not required) unless you've actually resolved `target-app`'s planted issues first. Save the "required and blocking" setup for your own real application, once it's clean.

---

## Repo layout

```
.
├── .github/workflows/security.yml   # the pipeline itself
├── action.yml                       # the composite action: takes CodeQL/Semgrep/ZAP
│                                     #   output, writes report.md, comments on the PR
├── target-app/                      # intentionally vulnerable demo app,
│                                     #   see config.js and server.js for what's planted
├── scripts/aggregate_findings.py    # the aggregation logic behind the action
├── fixtures/                        # sample SARIF/JSON used by the tests below
└── tests/test_aggregate_findings.py
```

---

## Adding this to your own project

There are two paths, depending on your starting point.

### You already run CodeQL, Semgrep, and ZAP, and just want the report/gate step

Add one step, as the last step in whichever job produces all three output files:

```yaml
- name: Aggregate findings & comment on PR
  uses: ParitV/Eight@v1
  with:
    codeql-sarif: path/to/codeql.sarif
    semgrep-sarif: path/to/semgrep.sarif
    zap-json: path/to/zap-report.json
```

Two requirements for that job: it needs to run **on `pull_request`** (the comment step silently skips on other event types), and needs `permissions: pull-requests: write` so it's actually allowed to post. That's the entire integration; nothing else in your existing scan setup needs to change.

### You're starting from scratch

Copy one file, then change exactly three things in it.

**1. Copy the file:** `.github/workflows/security.yml` from this repo → the same path in yours: `your-repo/.github/workflows/security.yml`.

**2. Make these three edits:**

| In this job | Find | Change to |
|---|---|---|
| `codeql` | `source-root: target-app` | your app's folder (or delete this line if your app lives at the repo root) |
| `codeql` | `languages: javascript` | your app's language, e.g. `python`, `java` |
| `semgrep` | `target-app/` in the scan command | your app's folder path |

**3. Point the `zap-dast` job at your running app.** ZAP just needs a live HTTP server to attack, and the exact steps depend on whether your app runs in Docker.

*If it's Dockerized* (example: a Node app on port 3000, living in `my-app/`):
```yaml
- name: Build my-app image
  run: docker build -t my-app:ci ./my-app
- name: Run my-app container
  run: docker run -d --name my-app -p 3000:3000 my-app:ci
- name: Wait for my-app
  run: |
    for i in $(seq 1 30); do
      curl -sSf http://localhost:3000/ > /dev/null && exit 0
      sleep 2
    done
    exit 1
- name: ZAP Baseline Scan
  uses: zaproxy/action-baseline@v0.15.0
  with:
    target: 'http://localhost:3000'
```

*If it isn't Dockerized* (example: a Python app started with `python app.py` on port 5000):
```yaml
- run: pip install -r my-app/requirements.txt
- name: Start my-app in the background
  run: cd my-app && nohup python app.py &
- name: Wait for my-app
  run: |
    for i in $(seq 1 30); do
      curl -sSf http://localhost:5000/ > /dev/null && exit 0
      sleep 2
    done
    exit 1
- name: ZAP Baseline Scan
  uses: zaproxy/action-baseline@v0.15.0
  with:
    target: 'http://localhost:5000'
```
The pattern is always the same regardless of language: start the app in the background, poll it with `curl` until it responds, then point ZAP's `target` at that same URL.

**4. Leave the `report` job as-is.** It already calls this same repo's own action (`uses: ./`), so no change is needed there.

**5. Push and open a pull request.** Same four jobs you saw in "Try it yourself" above should now run against your own app, and a report comment should appear on your PR.

---

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
