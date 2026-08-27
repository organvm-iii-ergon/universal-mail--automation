# PR #192 — adversarial verification packet

## Purpose

This self-contained packet lets an external reviewer verify or falsify the Mail.app seven-state flag workflow claims. It distinguishes completed code phases from unresolved release-admission gates. It does not authorize merge, ready-for-review, Mail.app launch, AppleScript, canary, or live provider mutation.

## Exact identity

| Item | Value |
| --- | --- |
| Repository | `organvm/universal-mail--automation` |
| Pull request | [#192](https://github.com/organvm/universal-mail--automation/pull/192) |
| Branch | `feat/mailapp-seven-state-flags` |
| Implementation-evidence head | `36e83db60255bb639f9190ce58afc616f0003db4` |
| PR state at final census | Open, draft |
| Merge state at final census | Blocked |

Confirm that the implementation-evidence SHA is an ancestor of the current PR head, then inspect the intervening diff. Any code-affecting change after that SHA requires a new exact-head census. This packet itself is a documentation-only review aid and may be a descendant of the evidence head.

```bash
gh pr view 192 --repo organvm/universal-mail--automation --json state,isDraft,headRefOid,mergeStateStatus
git ls-remote origin refs/heads/feat/mailapp-seven-state-flags
git merge-base --is-ancestor 36e83db60255bb639f9190ce58afc616f0003db4 HEAD
git diff --name-status 36e83db60255bb639f9190ce58afc616f0003db4..HEAD
```

## Eight-phase delivery reconciliation

All eight logical implementation phases are present. Commit 6 was intentionally split to make transaction trust boundaries independently reviewable.

| Logical phase | Status | Commit evidence | Audit focus |
| --- | --- | --- | --- |
| Commits 1–5 | Complete | ancestry through `8061822` | provider-neutral flags, scoped workflow, artifact-only planning |
| Commit 5b | Complete | `70c7e73` | native mapping, canonical status, marketing gate, digest coverage |
| Commit 6 | Complete, split | `de1f8db` | transaction engine; CLI remains `NOT_READY` |
| Commit 6b | Complete | `5b6da35` | RED/0 preflight, ledger authority, private-file hardening |
| Commit 6c | Complete | `4f1c31a` | approval binding and lineage-bound rollback |
| Commit 6d | Complete | `4d2f468` | executable mutations from a validated plan |
| Commit 7 | Complete | `b9d777c` | adversarial suite, Groups A–P |
| Commit 8 | Complete | `b484f04` | type correction and quality-gate evidence |

Two later commits correct the independent final audit and review findings: `9d469279a8952b69a505906f3ec5bda5a0fe52b2` (audit/review correction) and `36e83db60255bb639f9190ce58afc616f0003db4` (quality/documentation closeout).

```bash
git log --oneline --decorate 70c7e73..36e83db
git merge-base --is-ancestor 70c7e73 36e83db
git merge-base --is-ancestor b484f04 36e83db
```

## Implemented contract

### Seven-state model and scope

| Native index | Flag value | Queue label |
| ---: | --- | --- |
| -1 | `no_flag` | `UNFLAGGED` |
| 0 | `red` | `NOW` |
| 1 | `orange` | `ACTION` |
| 2 | `yellow` | `WAITING` |
| 3 | `green` | `SCHEDULED` |
| 4 | `blue` | `REFERENCE` |
| 5 | `purple` | `REVIEW` |
| 6 | `gray` | `LATER` |

`FlagColor` is a string enum. Unknown or malformed native indices remain `UNKNOWN`, not a coerced known color. Reads and writes use `MessageReference`, not bare global IDs, and `LabelAction.message_id` must equal the scoped reference's provider ID.

### Artifact and private-state security

The code rejects hostile type coercion (`bool`, `str`, and similar values), incoherent snapshot counts, stale scoped digests, missing safety declarations, malformed timestamps, invalid approval timing, and corrupt private state. Private plans, receipts, and overrides use atomic mode-0600 writes. The override store uses a process-wide lock, exact mapping validation, unique temporaries, and safe special-file/symlink refusal. Public output only projects allowlisted error codes.

### Transaction honesty

`ProviderWriteAmbiguous` denotes that a write may have crossed a provider boundary. Apply and rollback preserve that state through readback, ledger, and override errors, conservatively report nonzero `writes_performed`, freeze remaining work, and enumerate unattempted actions. A malformed authoritative ledger blocks zero further writes; it is never skipped because that could erase idempotency state. Rollback receipts must match authoritative ledger lineage.

### Discovery, CLI, policy, and provider restrictions

Single-surface Mail.app audit, queue, overrides, and explain require explicit account scope. Estate audit may omit account scope but records completeness. Nested mailbox paths and control delimiters are preserved; missing dates stay missing; invalid native indices remain `UNKNOWN`; timestamps are awareness-normalized. Incomplete queue/override results are refused. Queue JSON preserves queue-label keys with structured rows; bare `flags` prints usage and exits 2; the unsupported CSV `is_read` column is absent; provider options parse on either side of `flags`; explain uses numeric and scoped validation.

Operator-action evidence outranks scheduled-event evidence. Standalone active references become BLUE, independent axes are counted independently, conflicts yield `RC_AMBIGUOUS_PURPLE`, and the policy version/digest invalidates older plans. STAR creation requires `ProviderCapabilities.STAR`; Gmail validates actions before normalization and rejects unsupported colors before API dispatch.

## Intentional non-operational boundary

- Valid `flags apply --plan ...` exits 89 before provider construction.
- Valid `flags rollback --receipt ...` exits 89 before provider construction.
- There is no force flag or implicit bypass.
- This tranche launched no Mail.app process, AppleScript, live provider read/write, canary, apply, or rollback.

Passing tests are not authorization for a live mailbox change.

## Test and quality evidence

| Gate | Recorded result |
| --- | --- |
| Prescribed focused suite | 606 passed |
| Full Python suite | 1,441 passed; 4 skipped; 1 existing warning |
| Diff validation | `git diff --check` passed |
| Strict Ruff | passed across 25 Python files changed from `main` |
| Prescribed mypy subset | passed across 9 production files |
| Dependency consistency | `python -m pip check` passed |
| Package build | isolated sdist/wheel build and `twine check` passed |
| Wheel smoke | wheel outside source with `--no-deps`; `umail` and `core` reported `0.2.0` |
| Web | zero-warning lint and production build passed |
| Cloudflare Worker | 15 passed |
| Mutation CLI safety | apply/rollback returned 89; bare flags returned 2 |

The full-suite warning is pre-existing: Pydantic field `schema` shadows a parent attribute in `api/schemas.py:102`. A dependency-resolved wheel install was abandoned when the remote Google API client download stalled; do not report that network-dependent smoke as passing. This does not alter the separate `pip check`, build, metadata, or `--no-deps` entry-point evidence.

```bash
python -m pytest -q tests/test_pr192_audit_regressions.py tests/test_flag_workflow.py tests/test_commit6_transactions.py tests/test_commit6d_plan_derived_mutations.py tests/test_commit7_adversarial_a.py tests/test_commit7_adversarial_b.py tests/test_flags_cli.py tests/test_mailapp.py tests/test_flag_policy.py tests/test_models.py tests/test_base_provider.py tests/test_protected_enforcement.py
python -m pytest -q
git diff --check main...HEAD
python -m ruff check cli.py core providers tests
python -m mypy --follow-imports=skip --ignore-missing-imports cli.py core/flag_policy.py core/flag_transactions.py core/flag_workflow.py core/models.py providers/base.py providers/flag_codecs.py providers/gmail.py providers/mailapp.py
python -m pip check
```

Use isolated fakes to test valid apply/rollback subprocess invocations, asserting exit 89 without provider construction. Never point them at a real plan, receipt, or Mail.app account.

## Review and CI evidence

The corrective ledger contained 49 current threads. Every one received an evidence-backed reply and was resolved, including duplicates and threads made outdated by the repair diff.

| Thread state | Count |
| --- | ---: |
| Unresolved, current/non-outdated | 0 |
| Resolved | 53 of 62 total |
| Unresolved, historical/outdated | 9 |

At the final exact-head query, ten CI, Worker, and CodeQL jobs failed before execution. Python 3.10 job `98552157515` had no runner and `steps: []`; its annotation stated: "The job was not started because your account is locked due to a billing issue." Classification is `CI_NOT_ADMITTED`, not an executed test failure or passing CI. CodeRabbit succeeded; deploy was skipped. The PR must remain draft until billing is cleared, the jobs execute at one exact head, and an independent exact-head audit passes.

```bash
gh pr view 192 --repo organvm/universal-mail--automation --json state,isDraft,headRefOid,mergeStateStatus,statusCheckRollup
gh api repos/organvm/universal-mail--automation/actions/jobs/98552157515
gh api repos/organvm/universal-mail--automation/check-runs/98552157515/annotations
```

## Suggested adversarial probes

1. Inject `bool`, `str`, malformed timestamps, incoherent counts, altered digests, missing safety declarations, invalid approvals, and mismatched provider IDs into artifacts; require typed rejection before a write boundary.
2. Race override reads/writes and substitute symlink/FIFO paths; require safe refusal without permissive fallback or descriptor leak.
3. Raise `ProviderWriteAmbiguous` after dispatch, during readback, ledger persistence, and override persistence; require conservative nonzero accounting and frozen remaining work.
4. Corrupt ledger history or receipt lineage; require zero further writes and no skipped malformed row.
5. Use nested mailbox paths, delimiters, absent dates, unknown indices, incomplete estate scans, and account-less single-surface commands; require truthful output or refusal.
6. Test policy precedence, active references, conflicts, unsupported Gmail colors, and STAR operations; require rejection before API dispatch.
7. Test provider-option placement, missing subcommands, malformed snapshot JSON, scoped explain input, and stderr-only receipts.
8. Confirm every mutation-like CLI path still exits 89 before provider creation.

## Decision rubric

- **Implementation phases 1–8 complete:** supported by commit ancestry and code/test inspection.
- **Local quality evidence complete:** supported by reproducing the listed gates.
- **Operational mutation readiness:** explicitly unsupported and out of scope.
- **Merge/ready status:** unsupported until billing clears, CI/CodeQL are admitted and green at one exact head, and an independent audit is recorded.

Report any defect with exact SHA, command, fixture/input, observed result, expected safety property, and whether provider dispatch was attempted.
