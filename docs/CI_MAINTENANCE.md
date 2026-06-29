# CI Maintenance Notes

Operational notes for maintaining the GitHub Actions workflow(s) in this
repository. This concerns the CI pipeline only — it does not affect MCC-Core
runtime behavior, governance semantics, tests, evidence, or security posture.

## Workflows

| File | Purpose |
|------|---------|
| `.github/workflows/mcc-runtime-ci.yml` | The single CI workflow: tests, smoke, invariants, Redis cross-instance smoke, consensus challenge/enforcement/evidence. |

## Node.js runtime migration (Node 20 → Node 24)

GitHub is retiring the Node.js 20 runtime for JavaScript-based actions. Actions
that still ship a Node 20 entrypoint emit a deprecation warning in the run logs.
To clear those warnings from repository-controlled actions, the official actions
are pinned to their current Node 24-based major versions:

| Action | Before | After | Runtime |
|--------|--------|-------|---------|
| `actions/checkout` | `v4` | `v5` | Node 24 |
| `actions/setup-python` | `v5` | `v6` | Node 24 |

No other official actions (`upload-artifact`, `download-artifact`, `cache`,
`github/codeql-action`, `docker/setup-buildx-action`, `docker/login-action`,
`docker/build-push-action`) are used by this repository. Docker is exercised
through the `docker compose` CLI inside a `run:` step, not via a Docker action,
so there is no Docker action to upgrade.

The version bumps are runtime-only for our usage: we use `checkout` with default
settings and `setup-python` pinned to `python-version: "3.11"`. No behavioral
flags changed, so CI results remain deterministic.

## Runner requirements

- **GitHub-hosted `ubuntu-latest` is the supported default** and provides a Node
  24-capable runner. No workflow change requires a runner newer than the
  GitHub-hosted environment provides.
- The Node 24-based action majors above require the GitHub Actions runner
  release that bundles Node 24 (shipped well before this change). GitHub-hosted
  runners always satisfy this.
- **Self-hosted runners** (not used by this repository by default) must run a
  runner version recent enough to provide Node 24. If you add a self-hosted
  runner, keep the runner agent updated; an outdated agent without Node 24 will
  fail these actions. We do **not** install Node manually or set
  `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` to mask an outdated runner — the correct
  fix is to update the runner agent.

## Security posture of the workflow

- A top-level `permissions: { contents: read }` block applies least privilege;
  every job inherits read-only access. No job writes to the repository,
  comments, or publishes artifacts, so no write scope is granted.
- Every `actions/checkout` step sets `persist-credentials: false`: no job
  performs git operations after checkout, so the automatic token is not left in
  the local git config.
- No elevated-trust triggers (`pull_request_target`, etc.) are used; the
  workflow runs on `push` and `pull_request` only.
- Official, first-party actions only — no third-party actions are introduced.

## Diagnosing future deprecated-action warnings

1. Open a recent workflow run and look in the **Annotations** / step logs for a
   message like *"This action uses Node.js 20 which is deprecated"* or a
   `save-state`/`set-output` command deprecation.
2. The warning names the offending action. Find every reference:

   ```bash
   grep -rEn 'uses:\s' .github/workflows/
   ```
3. Check the action's release notes / migration guide for the latest major that
   ships the supported Node runtime, and read its breaking-change notes before
   bumping — do not upgrade blindly.
4. Bump the major (e.g. `@v5` → `@v6`) and re-run CI. Confirm the warning is gone
   and all jobs still pass.
5. If the offending action is a **third-party** action with no Node 24-compatible
   release yet, document the specific action and the blocker here rather than
   suppressing the warning. Never silence a warning by disabling checks or
   installing Node manually purely to quiet the log.

## Local validation

Before pushing a workflow change:

```bash
# YAML well-formedness for every workflow file
python -c "import glob,yaml; [yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]; print('YAML OK')"

# Optional: actionlint (not vendored in this repo). If you choose to run it,
# install the official binary from https://github.com/rhysd/actionlint and run:
#   actionlint .github/workflows/*.yml
```

CI itself remains the source of truth for the full test/smoke/invariant matrix.
