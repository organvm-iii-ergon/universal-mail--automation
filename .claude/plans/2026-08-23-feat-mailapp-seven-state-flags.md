# Plan: Mail.app Seven-State Colored Flags (feat/mailapp-seven-state-flags)

**Date**: 2026-08-23
**Branch**: feat/mailapp-seven-state-flags
**Base**: main@6d88f2b

## Objective

Implement a seven-color workflow state system for macOS Mail.app using native flag indices (-1 through 6), mapping each color to an operator posture for triage discipline.

## Flag Color Mapping

| Index | Color | Queue Label | Operator Posture |
|-------|-------|-------------|------------------|
| -1 | No Flag | DONE | CLOSED / COMPLETED / NO OPEN LOOP |
| 0 | Red | NOW | CRITICAL / ACT NOW |
| 1 | Orange | ACTION | ACTION OWED |
| 2 | Yellow | WAITING | WAITING / FOLLOW-UP |
| 3 | Green | SCHEDULED | SCHEDULED / COMMITTED |
| 4 | Blue | REFERENCE | ACTIVE REFERENCE |
| 5 | Purple | REVIEW | HUMAN JUDGMENT REQUIRED |
| 6 | Gray | LATER | DELIBERATELY DEFERRED |

## Scope

### Phase A: Read-Only Snapshot (Audit)
- [x] `flags audit` — enumerate flagged messages with color, posture, sender, subject
- [x] `flags doctor` — diagnose Mail.app colored flag capability
- [x] `flags overrides` — detect human flag overrides vs. automation proposals

### Phase B: Proposed Reclassification (Plan)
- [x] `flags plan` — generate migration plan from legacy Red-only flags to seven-state
- [x] Heuristic content analysis for reclassification proposals
- [x] Immutable plan with SHA256 hash for drift detection

### Phase C: Approval-Bound Execution (Apply)
- [x] `flags apply` — apply plan with `--limit` canary batch (default 10)
- [x] Plan hash verification on apply (drift detection)
- [x] Dry-run mode for safe preview
- [x] Rollback receipt generation on success

### Phase D: Rollback & Safety
- [x] `flags rollback` — restore previous flag states from receipt
- [x] Idempotent reapplication (hash gate prevents double-apply)
- [x] Canary-first workflow documented

### CLI Command Group
- [x] `flags doctor` — capability diagnostic
- [x] `flags audit [--flagged-only] [--csv] [--json]` — inventory
- [x] `flags plan [--legacy-migration] --output <file>` — generate plan
- [x] `flags queue [--json]` — working surface view
- [x] `flags apply --plan <file> [--limit N] [--dry-run] [--force]` — execute
- [x] `flags rollback --receipt <file> [--dry-run]` — undo
- [x] `flags overrides` — detect human overrides
- [x] `flags explain <message_ref>` — classification reasoning

### Core Model Extensions
- [x] `FlagColor(IntEnum)` with name_str, operator_posture, queue_label properties
- [x] `StateSource` enum (HUMAN, DETERMINISTIC_RULE, MODEL, MIGRATION, LEGACY_UNKNOWN)
- [x] `FlagMutation` dataclass for batch planning
- [x] `EmailMessage.flag_color`, `flag_color_source`, `flag_updated_at`, `categories` (separate axis)
- [x] `LabelAction.flag_color`, `clear_flag`, `ActionType.SET_FLAG`, `ActionType.CLEAR_FLAG`

### Provider Interface Extensions
- [x] `ProviderCapabilities.COLORED_FLAGS` capability flag
- [x] `get_flag_color(message_id) -> FlagColor` (base: returns NO_FLAG)
- [x] `set_flag_color(message_id, FlagColor) -> bool` (base: returns False)
- [x] `clear_flag(message_id) -> bool` (base: returns False)
- [x] `apply_actions()` handles SET_FLAG/CLEAR_FLAG

### Mail.app Provider Implementation
- [x] AppleScript `flag index` read/write (-1 through 6)
- [x] Backward-compatible boolean `star()`/`unstar()` preserved
- [x] `list_messages()` and `get_message_details()` capture flag index
- [x] `capabilities` includes `COLORED_FLAGS | STAR | FOLDERS | ARCHIVE`

### Testing
- [x] Unit tests for FlagColor enum (from_index, from_string, properties)
- [x] Unit tests for FlagMutation, StateSource
- [x] Mail.app provider colored flag tests (get/set/clear, capabilities)
- [x] All 788 existing tests pass
- [x] Lint (ruff) and type-check (mypy for changed files) pass

## Files Changed

- `core/models.py` — FlagColor, StateSource, FlagMutation, EmailMessage, LabelAction, ActionType
- `providers/base.py` — COLORED_FLAGS capability, get/set/clear_flag, apply_actions
- `providers/mailapp.py` — AppleScript implementation, capability flag
- `cli.py` — flags command group (8 subcommands)
- `tests/test_models.py` — FlagColor, FlagMutation, StateSource tests
- `tests/test_mailapp.py` — Colored flag provider tests

## Validation Commands

```bash
# Run tests
python -m pytest tests/ -q

# Lint
python -m ruff check core/models.py providers/base.py providers/mailapp.py cli.py

# Type-check (changed files only)
python -m mypy core/models.py providers/base.py providers/mailapp.py cli.py

# Manual CLI verification
python cli.py flags doctor --provider mailapp --account "padavano.anthony@gmail"
python cli.py flags audit --provider mailapp --account "padavano.anthony@gmail" --flagged-only
python cli.py flags plan --provider mailapp --account "padavano.anthony@gmail" --legacy-migration --output /tmp/plan.json
python cli.py flags apply --provider mailapp --account "padavano.anthony@gmail" --plan /tmp/plan.json --dry-run --limit 5
```

## Migration Workflow (Operational)

```bash
# 1. Audit current flagged backlog
uma flags audit --provider mailapp --account "padavano.anthony@gmail" --flagged-only

# 2. Generate migration plan (read-only)
uma flags plan --provider mailapp --account "padavano.anthony@gmail" --legacy-migration --output plan.json

# 3. Review plan.json (inspect mutations, hash)

# 4. Canary apply (first 10 messages)
uma flags apply --provider mailapp --account "padavano.anthony@gmail" --plan plan.json --limit 10

# 5. Verify in Mail.app, then full apply
uma flags apply --provider mailapp --account "padavano.anthony@gmail" --plan plan.json

# 6. If issues, rollback
uma flags rollback --provider mailapp --account "padavano.anthony@gmail" --receipt plan-rollback-*.json
```

## Rollback Receipt Schema

```json
{
  "schema": "uma.flags.rollback.receipt.v1",
  "plan_hash": "<sha256>",
  "applied_at": "2026-08-23T...",
  "applied": [{"message_id": "...", "observed_flag": "Red", "proposed_flag": "Orange", ...}],
  "failed": [],
  "rollback_data": [{"message_id": "...", "previous_flag": "Red"}]
}
```

## Blockers / Open Items

- None — implementation complete and tested
- Branch not yet pushed to origin (requires push authority)
- No plan file existed for this work prior to this closeout

## Closeout Status

**Complete** — All phases implemented, tested, and verified. Ready for commit and push.