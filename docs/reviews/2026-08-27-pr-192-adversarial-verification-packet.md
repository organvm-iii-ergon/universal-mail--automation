# PR #192 — adversarial verification packet

## Purpose

This self-contained packet lets an external reviewer verify or falsify the Mail.app seven-state flag workflow claims. It distinguishes completed code phases from unresolved release-admission gates. It does not authorize merge, ready-for-review, Mail.app launch, AppleScript, canary, or live provider mutation.

## Exact identity

| Item | Value |
| --- | --- |
| Repository | `organvm/universal-mail--automation` |
| Pull request | [#192](https://github.com/organvm/universal-mail--automation/pull/192) |
| Branch | `feat/mailapp-seven-state-flags` |
| Corrective implementation-evidence head | `95caa460e0f0286bdfefa1dadc7782ba203cc949` |
| PR state at final census | Open, draft |
| Merge state at final census | Blocked |

Confirm that the implementation-evidence SHA is an ancestor of the current PR head, then inspect the intervening diff. Any code-affecting change after that SHA requires a new exact-head census. This packet itself is a documentation-only review aid and may be a descendant of the evidence head.

```bash
gh pr view 192 --repo organvm/universal-mail--automation --json state,isDraft,headRefOid,mergeStateStatus
git ls-remote origin refs/heads/feat/mailapp-seven-state-flags
git merge-base --is-ancestor 95caa460e0f0286bdfefa1dadc7782ba203cc949 HEAD
git diff --name-status 95caa460e0f0286bdfefa1dadc7782ba203cc949..HEAD
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

Three later commits correct independent audit and review findings: `9d469279a8952b69a505906f3ec5bda5a0fe52b2` (audit/review correction), `36e83db60255bb639f9190ce58afc616f0003db4` (quality/documentation closeout), and `95caa460e0f0286bdfefa1dadc7782ba203cc949` (same-request native compare-and-set plus digest-bound PURPLE review-only enforcement).

```bash
git log --oneline --decorate 70c7e73..36e83db
git merge-base --is-ancestor 70c7e73 36e83db
git merge-base --is-ancestor b484f04 36e83db
git merge-base --is-ancestor 36e83db 95caa460
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

`ProviderWriteAmbiguous` denotes that a write may have crossed a provider boundary. `ProviderNativeStateDrift` denotes a proven zero-write compare-and-set refusal. Mail.app rechecks the plan-bound expected native index inside the same AppleScript request that would perform the set and returns before the set on drift. Apply and rollback persist that dispatch-gap drift as a human override, report zero writes for the refused operation, freeze remaining work, and never overwrite the intervening state. Apply and rollback preserve ambiguous states through readback, ledger, and override errors, conservatively report nonzero `writes_performed`, and enumerate unattempted actions. A malformed authoritative ledger blocks zero further writes; it is never skipped because that could erase idempotency state. Rollback receipts must match authoritative ledger lineage.

### Discovery, CLI, policy, and provider restrictions

Single-surface Mail.app audit, queue, overrides, and explain require explicit account scope. Estate audit may omit account scope but records completeness. Nested mailbox paths and control delimiters are preserved; missing dates stay missing; invalid native indices remain `UNKNOWN`; timestamps are awareness-normalized. Incomplete queue/override results are refused. Queue JSON preserves queue-label keys with structured rows; bare `flags` prints usage and exits 2; the unsupported CSV `is_read` column is absent; provider options parse on either side of `flags`; explain uses numeric and scoped validation.

Operator-action evidence outranks scheduled-event evidence. Standalone active references become BLUE, independent axes are counted independently, and conflicts yield `RC_AMBIGUOUS_PURPLE`. PURPLE and conflicting semantic types are now digest-bound review-only invariants: no confidence or future weight change can make them auto-eligible, and forged hash-valid plans that violate the invariant are rejected by both private and public validation. The policy version is `1.evidence-classifier.3`, so older plans are invalidated. STAR creation requires `ProviderCapabilities.STAR`; Gmail validates actions before normalization and rejects unsupported colors before API dispatch.

## Intentional non-operational boundary

- Valid `flags apply --plan ...` exits 89 before provider construction.
- Valid `flags rollback --receipt ...` exits 89 before provider construction.
- There is no force flag or implicit bypass.
- This tranche launched no Mail.app process, AppleScript, live provider read/write, canary, apply, or rollback.

Passing tests are not authorization for a live mailbox change.

## Test and quality evidence

| Gate | Recorded result |
| --- | --- |
| Corrective focused suite | 581 passed |
| Full Python suite | 1,447 passed; 4 skipped; 1 existing warning |
| Diff validation | `git diff --check` passed |
| Strict Ruff | passed across all 10 corrective Python files |
| Prescribed mypy subset | passed across 9 production files |
| Dependency consistency | `python -m pip check` passed |
| Package build | isolated sdist/wheel build and `twine check` passed; existing setuptools license deprecations emitted |
| Mutation CLI safety | covered by the focused suite; apply/rollback remain hard-return 89 before provider construction |

These results were recorded at implementation-evidence head `95caa460e0f0286bdfefa1dadc7782ba203cc949`. The full-suite warning is pre-existing: Pydantic field `schema` shadows a parent attribute in `api/schemas.py:102`. Web and Worker checks were not rerun in the corrective batch because no web or Worker file changed; earlier results are historical evidence only, not exact-head receipts. A dependency-resolved wheel install was not rerun; do not infer one from the package-build result.

```bash
python -m pytest -q tests/test_base_provider.py tests/test_mailapp.py tests/test_flag_policy.py tests/test_flag_workflow.py tests/test_commit6_transactions.py tests/test_commit6b_p0_regressions.py tests/test_commit6c_trust_boundaries.py tests/test_commit6d_plan_derived_mutations.py tests/test_commit7_adversarial_a.py tests/test_commit7_adversarial_b.py tests/test_flags_cli.py tests/test_pr192_audit_regressions.py
python -m pytest -q
git diff --check
python -m ruff check cli.py core/flag_policy.py core/flag_transactions.py core/flag_workflow.py providers/base.py providers/mailapp.py tests/test_commit6_transactions.py tests/test_flag_policy.py tests/test_flag_workflow.py tests/test_mailapp.py
python -m mypy --follow-imports=skip --ignore-missing-imports cli.py core/flag_policy.py core/flag_transactions.py core/flag_workflow.py core/models.py providers/base.py providers/flag_codecs.py providers/gmail.py providers/mailapp.py
python -m pip check
uvx --from build pyproject-build --outdir /tmp/uma-pr192-build
uvx --from twine twine check /tmp/uma-pr192-build/*
```

Use isolated fakes to test valid apply/rollback subprocess invocations, asserting exit 89 without provider construction. Never point them at a real plan, receipt, or Mail.app account.

## Review and CI evidence

The corrective ledger contained 49 current threads. Every one received an evidence-backed reply and was resolved, including duplicates and threads made outdated by the repair diff.

| Thread state | Count |
| --- | ---: |
| Unresolved, current/non-outdated | 0 |
| Resolved | 53 of 62 total |
| Unresolved, historical/outdated | 9 |

At corrective implementation head `95caa460e0f0286bdfefa1dadc7782ba203cc949`, CI run `33090253731` and CodeQL run `33090248436` completed as failures, but all ten executable jobs had `steps: []`. The Python 3.11 annotation states: "The job was not started because your account is locked due to a billing issue." Deploy was skipped. Classification is `CI_NOT_ADMITTED`, not an executed test failure or passing CI. A later packet-publication commit is documentation-only, but it still requires its own exact-head admission query. CodeRabbit success on a draft means review was skipped, not approval. The PR must remain draft until billing is cleared, all required jobs execute at one exact head, and an independent exact-head audit passes.

```bash
gh pr view 192 --repo organvm/universal-mail--automation --json state,isDraft,headRefOid,mergeStateStatus,statusCheckRollup
gh pr checks 192 --repo organvm/universal-mail--automation
gh run list --repo organvm/universal-mail--automation --branch feat/mailapp-seven-state-flags --commit "$(gh pr view 192 --repo organvm/universal-mail--automation --json headRefOid --jq .headRefOid)" --json databaseId,workflowName,status,conclusion,headSha,url
gh api "repos/organvm/universal-mail--automation/commits/$(gh pr view 192 --repo organvm/universal-mail--automation --json headRefOid --jq .headRefOid)/check-runs"
```

## Artifact availability and operational evidence

- GitHub reported `total_count: 0` downloadable Actions artifacts for corrective implementation run `33090253731`; a zero-step run is not an artifact receipt.
- No tracked Mail.app doctor report, read-only inventory, immutable migration plan, canary receipt, apply receipt, or rollback receipt exists for this corrective head.
- The corrective validation used only isolated fakes and local source/package tooling. It did not invoke `osascript`, launch or query Mail.app, construct a live provider, or mutate a mailbox/provider.
- Doctor and inventory commands remain deliberately unrun under this batch's zero-Mail.app boundary. Their absence blocks operational-readiness claims; it is not silently treated as a pass.

## Suggested adversarial probes

1. Inject `bool`, `str`, malformed timestamps, incoherent counts, altered digests, missing safety declarations, invalid approvals, and mismatched provider IDs into artifacts; require typed rejection before a write boundary.
2. Race override reads/writes and substitute symlink/FIFO paths; require safe refusal without permissive fallback or descriptor leak.
3. Change the native flag after transaction preflight but before apply or rollback dispatch; require same-request compare-and-set refusal, zero writes, durable override suppression, and frozen remaining work. Separately raise `ProviderWriteAmbiguous` after dispatch, during readback, ledger persistence, and override persistence; require conservative nonzero accounting.
4. Corrupt ledger history or receipt lineage; require zero further writes and no skipped malformed row.
5. Use nested mailbox paths, delimiters, absent dates, unknown indices, incomplete estate scans, and account-less single-surface commands; require truthful output or refusal.
6. Force a conflicting classification's confidence above the automatic threshold and forge a hash-valid auto-eligible PURPLE plan; require review-only classification and schema rejection before provider dispatch. Also test policy precedence, active references, unsupported Gmail colors, and STAR operations.
7. Test provider-option placement, missing subcommands, malformed snapshot JSON, scoped explain input, and stderr-only receipts.
8. Confirm every mutation-like CLI path still exits 89 before provider creation.

## Decision rubric

- **Implementation phases 1–8 complete:** supported by commit ancestry and code/test inspection.
- **Local quality evidence complete:** supported by reproducing the listed gates.
- **Operational mutation readiness:** explicitly unsupported and out of scope.
- **Merge/ready status:** unsupported until billing clears, CI/CodeQL are admitted and green at one exact head, and an independent audit is recorded.

Report any defect with exact SHA, command, fixture/input, observed result, expected safety property, and whether provider dispatch was attempted.
