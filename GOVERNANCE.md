# Repository Governance Note

**Date:** 2026-06-12  
**Repository:** mcc-prior-art/mcc-layer  
**Subject:** v1.11.0 release process and main branch protection

During the v1.11.0 release process, a temporary workflow was committed directly to `main` under explicit owner authorization because tag creation was unavailable through the standard release path.

The episode was time-limited, fully auditable in git history, and left repository content unchanged after the workflow was removed.

Relevant commits:

- `2a15d82` — temporary release workflow added
- `1a64f27` — temporary release workflow removed

The v1.11.0 release remains anchored to the PR #4 merge commit:

- Release: `v1.11.0`
- Target commit: `32d4d3a`
- PR: `https://github.com/mcc-prior-art/mcc-layer/pull/4`
- CI: `4/4 checks passed`

This episode demonstrated the exact repository-governance gap that branch protection closes.

Following v1.11.0, `main` branch protection was enabled with:

- Required pull request before merge
- Required status checks before merge
- Required up-to-date branch before merge
- Required checks: `tests`, `invariants`
- Blocked force pushes
- Restricted branch deletions
- Empty bypass list

Repository changes must now follow the same execution-governance doctrine expressed by MCC-Core:

> No verified path — no trusted execution.  
> No green checks — no merge.

This note is intended as a public governance record, not as a security certification, formal audit, or production-safety claim.
