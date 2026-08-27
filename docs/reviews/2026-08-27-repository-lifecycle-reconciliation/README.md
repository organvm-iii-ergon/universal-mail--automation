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
| Remote refs, including `origin/main` | 306 |
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

## Admission truth

Current CI and CodeQL jobs fail before executing any step. GitHub's check-run
annotation is: `The job was not started because your account is locked due to a
billing issue.` The required Python 3.11 and Python 3.12 contexts therefore
cannot become executable receipts until the account owner clears that gate.
The repository keeps those checks and does not use an administrator bypass.

The package metadata is also migrated from the deprecated license table and
license classifier to the PEP 639 SPDX expression plus an explicit license-file
declaration. The build backend floor is Setuptools 77, the first release line
that supports those fields.

## Mail safety truth

This reconciliation performs repository-only operations. It invokes no Mail.app
process, AppleScript, mailbox inventory, flag canary, apply, rollback, draft,
send, credential read, or provider mutation.
