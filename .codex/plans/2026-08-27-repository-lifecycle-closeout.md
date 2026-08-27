# Repository lifecycle closeout

## Objective

Drive every live pull request, local branch, remote branch, and worktree to an
evidence-backed terminal state while preserving the Mail.app zero-write gate.

## Live baseline

- Default head: `6d88f2bdacc95d9cd8c459fa2dbe40f146e131b3`.
- Open PRs at intake: `#192`, `#190`, and `#158`.
- Worktrees at intake: main plus the clean `feat/mailapp-seven-state-flags`
  worktree.
- Local branches at intake: main, the #192 head, merged #189 residue, and merged
  #174 residue.
- Remote refs at intake: 306 total, including 233 automated capture refs.
- Required main checks: Python 3.11 and Python 3.12.
- GitHub admission blocker: jobs start with zero steps and annotate the account
  as locked because of a billing issue.

## Execution

1. Independently audit each open PR and every live review thread.
2. Repair or terminally close superseded PRs; never disable required checks.
3. Remove generated, private-runtime, and merge-residue files from source.
4. Add an executable tracked-file hygiene predicate to prevent recurrence.
5. Record every remote ref and its disposition before deleting terminal refs.
6. Enable automatic head-branch deletion after future merges.
7. Remove clean merged/local worktree residue.
8. Re-query exact remote and local state and record remaining external gates.

## Safety boundary

No Mail.app read, AppleScript, flag mutation, canary, send, credential change,
or billing/account action is part of this closeout. PR #192 stays mutation
disabled and draft unless its own published admission contract is satisfied.
