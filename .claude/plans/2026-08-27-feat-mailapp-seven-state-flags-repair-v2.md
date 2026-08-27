# Plan: Mail.app Seven-State Flags Corrective Repair V2

**Date:** 2026-08-27
**Branch:** `feat/mailapp-seven-state-flags`
**PR:** `organvm/universal-mail--automation#192`
**Supersedes:** `2026-08-23-feat-mailapp-seven-state-flags.md`

## Status and authority

`REVIEW_REQUIRED` at the repair baseline
`b484f047145604e329c5f6a10c15a1b3b15d8f3e`.

At that exact head the PR was open and draft, all ten GitHub CI/CodeQL jobs
were rejected before execution by the account billing lock, and 49 current,
non-outdated review threads were unresolved. Local tests did not supersede
those admission and review gates.

This repair authorizes code, test, documentation, ordinary commits, a normal
push, PR-description correction, and evidence-backed review-thread
disposition. It does not authorize merge, ready-for-review promotion, Mail.app
launch or reads, AppleScript execution, canary execution, apply, rollback, or
mutation enablement.

## Truthful flag contract

`FlagColor` is a string-valued enum. Native Mail.app indices remain a provider
codec detail.

| Native index | Enum value | Queue label | Meaning |
| ---: | --- | --- | --- |
| -1 | `no_flag` | `UNFLAGGED` | no active colored-flag queue |
| 0 | `red` | `NOW` | critical action now |
| 1 | `orange` | `ACTION` | operator action owed |
| 2 | `yellow` | `WAITING` | waiting or follow-up |
| 3 | `green` | `SCHEDULED` | scheduled or committed |
| 4 | `blue` | `REFERENCE` | active reference |
| 5 | `purple` | `REVIEW` | human judgment required |
| 6 | `gray` | `LATER` | deliberately deferred |

Unknown or malformed native indices map to `UNKNOWN`; they are evidence of an
incomplete decision surface and are never silently coerced into a known state.

## Scoped provider interfaces

Colored-flag reads and writes are bound to `MessageReference`:

- `get_flag_color_ref(message_ref)`
- `set_flag_color_ref(message_ref, color)`
- `clear_flag_ref(message_ref)`
- Mail.app details lookup by the same scoped reference

The legacy bare-ID `get_flag_color(message_id)` contract is unsupported and
raises `NotImplementedError`. An action ID must equal the provider ID embedded
in its scoped reference. Scoped reference digests are recomputed during
artifact validation.

## Mutation gates

The transaction engine is library code under adversarial tests, but operator
mutation commands are not wired:

- a syntactically valid `flags apply --plan ...` returns 89 before provider
  construction;
- a syntactically valid `flags rollback --receipt ...` returns 89 before
  provider construction;
- there is no force flag or implicit bypass;
- `ProviderWriteAmbiguous` records that a provider write may have crossed the
  boundary and forces conservative, nonzero write accounting.

These commands are exercised only with isolated subprocess fakes during this
tranche. They are not operational workflow steps.

## Corrective scope

- Fail closed on hostile artifact types, incoherent counts, unsafe plan
  declarations, stale digests, malformed timestamps, and corrupt private
  state.
- Serialize private-state reads and read-modify-writes; write private artifacts
  atomically with mode 0600; project public errors through an allowlist.
- Preserve honest apply and rollback outcomes after a possible write,
  including ambiguous, failed, and unattempted work.
- Preserve the fail-closed ledger corruption doctrine. Malformed history must
  block with zero further writes because skipping authoritative rows can erase
  idempotency state.
- Require an explicit account for every single-surface Mail.app audit, queue,
  override, and explain operation. Account omission is reserved for estate
  audit, whose nested mailbox discovery and completeness are explicit.
- Repair structured queue output, CLI parsing, policy precedence, provider
  capability gates, Gmail action validation, and strict quality findings.

## Verification and closeout gates

Evidence must be recorded at one final exact head:

1. prescribed focused regression suite;
2. full pytest with exact pass, skip, and warning counts;
3. `git diff --check` and strict Ruff on every Python file changed from main;
4. the prescribed focused mypy invocation;
5. dependency consistency, package build/metadata/wheel smoke;
6. web lint/build and Cloudflare Worker tests;
7. valid apply and rollback subprocesses returning 89 without constructing a
   provider;
8. clean synchronized local/remote/PR SHA;
9. zero unresolved, current review threads and PR still draft;
10. executing GitHub CI and CodeQL at that same head.

If billing still blocks job admission, the truthful state is
`CI_NOT_ADMITTED`. The PR remains draft, and an independent exact-head audit is
still required. No local result authorizes merge, canary, or live mutation.

## Corrective local evidence

Recorded on 2026-08-27 before the two corrective commits:

- prescribed focused regression batch: 606 passed;
- final full suite: 1,441 passed, 4 skipped, 1 existing warning;
- strict Ruff: pass across all 25 Python files touched by the PR;
- prescribed mypy command: pass across all 9 production files;
- dependency consistency: `python -m pip check` passed;
- package: isolated no-build-environment build passed, both distributions
  passed `twine check`, and the wheel-installed `umail` and `core` entry
  points both reported version 0.2.0 outside the source tree;
- web: zero-warning lint and production build passed;
- Cloudflare Worker: 15 passed;
- syntactically valid apply and rollback commands each returned 89 before
  provider construction; a missing flags subcommand returned 2 with usage.

The active Python lacked the `build` module, so package construction used an
ephemeral `uv` tool environment. A separate dependency-resolved wheel install
was abandoned when the remote Google API client download stalled; this did not
invalidate the built-wheel entry-point smoke or the independent dependency
consistency gate. GitHub review and CI facts must be re-censused after the
normal push and are not represented by these local results.
