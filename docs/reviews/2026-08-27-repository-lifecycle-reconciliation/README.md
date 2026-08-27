# Repository lifecycle reconciliation

This packet records the 2026-08-27 repository closeout at exact remote state.
It is an evidence ledger, not a claim that GitHub admission or live Mail.app
mutation occurred.

## Intake census

| Surface | Intake state |
| --- | ---: |
| Open PRs | 3 |
| Local worktrees | 2 |
| Local branches | 4 |
| Remote-tracking refs, including symbolic `origin/HEAD` | 306 |
| Live remote branch heads | 305 |
| Manifested non-main branch heads | 304 |
| Automated `capture/*` refs | 233 |
| Remote branches with a terminal PR | 65 |
| Remote branches with an open PR | 3 |
| Remote branches without a PR | 236 |
| Remote refs admitted for reaping | 301 |

The 233 `capture/*` commits reduce to three repeated diff signatures: 199
copies of one generated-build snapshot, 33 copies of an earlier generated-build
snapshot, and one broad deferred snapshot. The repeated snapshots contain
package output, coverage/runtime state, conflict residue, or stale source trees;
they are not review lanes. Their exact ref/SHA inventory and dispositions are
stored in `remote-ref-manifest.json` before deletion. One representative of each
content group remains reachable through an annotated `archive/uma-capture-*`
tag; the 233 working-branch refs themselves can therefore be reaped without
discarding the three distinct snapshots.

## Executed ref lifecycle

The manifest was committed and pushed at
`39adcc39eff2b0d2b690763dc1455bd95f45b497` before deletion. A fresh
`git ls-remote --heads` comparison then found zero SHA mismatches across all
301 deletion candidates. Git accepted the 301 explicit deletions as one atomic
push. A post-delete query showed only `main` and the four active PR heads.
The fourth active head was this lifecycle PR branch, created after the manifest
captured its 304-entry non-main intake partition; the manifest itself retained
the three pre-existing open-PR heads.

The three annotated archive tags resolve to the recorded representative
commits:

- `archive/uma-capture-snapshot-a-20260702` -> `c3e47625164b0eaf6dba2881032a62d89246db90`
- `archive/uma-capture-snapshot-b-20260718` -> `418dc90339eb9c85dbf168aa365a687fa1ad6fcb`
- `archive/uma-capture-main-deferred-20260721` -> `7306a0b9655d16dcba0730e7e71716dd44b3e980`

Review found one branch whose tip postdated its linked merged PR:
`codex/uma-literal-mail-union-154` at
`16b62e50e4f7e2341ecebac4e07ceec87d941694`. Its stable patch ID exactly
matches main commit `375932548bbe87348ed140c2a782f259fb7dedc9`, so the content was
already landed; the distinct historical tip is additionally preserved by
`archive/uma-postmerge-vox3b-20260710`.

Repository setting `delete_branch_on_merge` is now enabled so merged PR heads
are reaped automatically in future.

## Local validation

- Repository hygiene predicate: PASS.
- Hygiene regressions: 56 passed.
- Full Python suite: 845 passed, 5 skipped.
- Ruff and Actionlint: PASS.
- `uv lock --check`: PASS.
- Source distribution and wheel build: PASS.
- Twine validation of both distributions: PASS.
- Web zero-warning lint and static production build: PASS; the clean-checkout
  export renders the normal zero-count dashboard and no state-load error.
- Staged-diff whitespace/error check: PASS.

Repository hygiene runs inside the required Python matrix, including the
protected Python 3.11 and Python 3.12 contexts; the packaging job repeats the
same predicate before building distributions. The predicate rejects tracked
virtual environments, compiled Python output, and Outlook token caches, and it
also requires the Docker build context to exclude credentials, private runtime
data, mailbox state, environment-secret files, and local agent/session
material. Public `*.env.example` templates remain source; the generated
`mail_report.md` mailbox report does not. Ignored Next.js exports, build state,
and frontend dependency trees are rejected from Git and the Docker context.

## Admission truth

Current CI and CodeQL jobs were not started because the account is locked.
GitHub's check-run annotation is: `The job was not started because your account
is locked due to a billing issue.` The required Python 3.11 and Python 3.12
contexts therefore cannot become executable receipts until the account owner
clears that gate. The repository keeps those checks and does not use an
administrator bypass.

The package metadata is also migrated from the deprecated license table and
license classifier to the PEP 639 SPDX expression plus an explicit license-file
declaration. The build backend floor is Setuptools 77, the first release line
that supports those fields. The contributing guide now records the tracked
`uv.lock` policy and its relationship to the independently resolved CI matrix,
completing the repository-side acceptance criteria from issue `#150` without
claiming that billing-blocked CI executed.

## Mail safety truth

This reconciliation performs repository-only operations. It invokes no Mail.app
process, AppleScript, mailbox inventory, flag canary, apply, rollback, draft,
send, credential read, or provider mutation.
