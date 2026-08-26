"""Flag migration TRANSACTION ENGINE (Commit 6).

Turns the immutable plan + cryptographically bound approval into
transaction semantics — while every production entry point stays behind
the CLI NOT_READY gate.

DOCTRINE
--------
- ALL-OR-ZERO PREFLIGHT: every selected mutation is fully preflighted
  BEFORE the first write. One drifted item freezes the entire batch;
  writes performed = 0.
- SCOPED WRITES ONLY: the engine calls ONLY set_flag_color_ref /
  clear_flag_ref / resolve_scoped on the provider. The generic
  apply_actions path is never reachable from here.
- READ-AFTER-WRITE PROOF: a provider returning True is not success. The
  engine re-resolves the qualified message and verifies evidence still
  bound + exact native index + semantic mapping before recording
  ``verified``. Write-done-but-verification-failed => AMBIGUOUS, frozen.
- HONEST PARTIAL FAILURE: a mid-batch failure records exactly which
  mutations verified, which failed, which were unattempted; status is
  partially_failed — NEVER "applied". No silent automatic compensation:
  rollback requires an explicit transaction-bound receipt.
- IDEMPOTENCY: replaying an already-verified mutation performs ZERO
  provider writes and reports already_applied.
- UNLOCK-ONLY OVERRIDES: a persisted human override suppresses the ref;
  preflight refuses suppressed messages.
- CONCURRENCY: one advisory lock per plan serializes approval validation,
  ledger checks, preflight, claim, writes, and receipt append. A second
  contender performs zero writes and reports already_claimed.

Every artifact (ledger lines, receipts, lock files) lives under the
private UMA state directory: directories 0700, files 0600, fsync'd
appends, atomic replacement for rewritten JSON.
"""

from __future__ import annotations

import fcntl
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.flag_workflow import (
    ApprovalReceipt,
    FlagWorkflowError,
    PlannedMutation,
    compute_plan_hash,
    require_hex256,
    sha256_hex,
)
from core.models import FlagColor, MessageReference

TX_LEDGER_SCHEMA = "uma.flags.transactions.v1"
ROLLBACK_TX_SCHEMA = "uma.flags.rollback.tx.v1"

# Ledger states — explicit, ordered lifecycle.
ST_PREPARED = "prepared"
ST_PREFLIGHT_PASSED = "preflight_passed"
ST_APPLYING = "applying"
ST_VERIFIED = "verified"
ST_PARTIALLY_FAILED = "partially_failed"
ST_BLOCKED = "blocked"
ST_AMBIGUOUS = "ambiguous"
ST_FROZEN_UNATTEMPTED = "frozen_unattempted"
ST_ALREADY_VERIFIED = "already_verified"          # EVENT ONLY (see below)
ST_ROLLBACK_PENDING = "rollback_pending"
ST_ROLLED_BACK = "rolled_back"
ST_ROLLBACK_BLOCKED = "rollback_blocked"

# AUTHORITATIVE mutation states vs EVENT records.
#
# `already_verified` is an informational REPLAY EVENT. It must NEVER
# supersede the authoritative `verified` state: treating last-row-wins over
# a mixed stream let a third apply re-execute (P0 6b), and dropped verified
# mutations from rollback candidacy. Authority is computed from the LAST
# authoritative row; event rows are skipped entirely.
AUTHORITATIVE_STATUSES = frozenset({ST_VERIFIED, ST_ROLLED_BACK})


class TransactionLocked(FlagWorkflowError):
    """Another process holds the advisory lock for this plan."""


class LedgerCorrupted(FlagWorkflowError):
    """The transaction ledger cannot be trusted for authority
    reconstruction (malformed line, unparsable JSON, wrong shape).

    DOCTRINE (Commit 7, Group H): a corrupt ledger MUST NOT be interpreted
    as 'nothing previously happened'. Corruption blocks transactions with
    ZERO provider writes; it never resets idempotency or rollback safety.
    An EMPTY/blank-lines-only file IS a legitimate fresh ledger (our
    writers never create blank files, but touch(1)-style pre-creation is
    benign — there is provably no history to lose).
    """


class PrivateStateUnusable(FlagWorkflowError):
    """A private-state artifact (ledger/lock/store) is structurally
    unusable — e.g. a SYMLINK where a regular file is required. We refuse
    to follow attacker-controlled links out of the managed tree."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- Advisory lock -------------------------------------------------------------


class AdvisoryFileLock:
    """Non-blocking exclusive advisory lock around the whole transaction.

    Avoids the check-then-write race on ledger.has(): claim happens INSIDE
    the lock together with validation, preflight, writes, and receipt.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._fd: Optional[int] = None

    def __enter__(self) -> "AdvisoryFileLock":
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)   # re-harden pre-existing dirs
        try:
            # O_NOFOLLOW: refuse to acquire a lock through an
            # attacker-controlled symlink (Commit 7 Group O).
            fd = os.open(self.path,
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        except OSError as e:
            raise PrivateStateUnusable(
                f"lock path unusable ({self.path}): {e}") from e
        try:
            os.fchmod(fd, 0o600)            # EVERY open — pre-existing
            # 0644 lock files must be hardened too (P0 6b FIX 3).
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            os.close(fd)
            raise TransactionLocked(
                f"another process holds {self.path.name}") from e
        except Exception as e:
            os.close(fd)
            raise PrivateStateUnusable(
                f"lock acquisition failed ({self.path}): {e}") from e
        self._fd = fd
        return self

    def __exit__(self, *exc) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


# --- Transaction ledger ----------------------------------------------------------


@dataclass
class TransactionRecord:
    """One durable ledger line for ONE mutation's lifecycle step."""
    transaction_id: str
    plan_sha256: str
    approval_sha256: str
    mutation_id: str
    ref_digest: str
    pre_state: Optional[str]
    intended_state: str
    verified_post_state: Optional[str]
    timestamp: str
    status: str
    error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": TX_LEDGER_SCHEMA,
            "transaction_id": self.transaction_id,
            "plan_sha256": self.plan_sha256,
            "approval_sha256": self.approval_sha256,
            "mutation_id": self.mutation_id,
            "ref_digest": self.ref_digest,
            "pre_state": self.pre_state,
            "intended_state": self.intended_state,
            "verified_post_state": self.verified_post_state,
            "timestamp": self.timestamp,
            "status": self.status,
            "error_code": self.error_code,
        }


class TransactionLedger:
    """Append-only JSONL with EXPLICIT transaction states.

    Durability: each line is written + flushed + fsync'd before the next
    action. File/dir permissions enforced on every open (0600/0700).
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    def _append(self, record: TransactionRecord) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)   # re-harden pre-existing dirs
        line = json.dumps(record.to_dict(), sort_keys=True) + "\n"
        try:
            fd = os.open(self.path,
                         os.O_WRONLY | os.O_CREAT | os.O_APPEND |
                         os.O_NOFOLLOW,       # never write through symlinks
                         0o600)
        except OSError as e:
            raise LedgerCorrupted(
                f"ledger not appendable ({self.path}): {e}") from e
        try:
            os.fchmod(fd, 0o600)            # EVERY open — pre-existing
            # 0644 ledgers must be hardened too (P0 6b FIX 3).
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        except OSError as e:
            raise LedgerCorrupted(
                f"ledger durability failure ({self.path}): {e}") from e
        finally:
            os.close(fd)

    def entries(self) -> List[Dict[str, Any]]:
        """Parse the ledger, FAILING CLOSED on any malformed line.

        Blank lines are skipped (benign). A non-blank line that is not
        valid JSON, or a JSON object missing the minimal authoritative
        shape (plan_sha256/mutation_id/status), raises LedgerCorrupted —
        corruption must block, never masquerade as empty history.
        """
        if not self.path.exists():
            return []
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise LedgerCorrupted(
                f"ledger unreadable ({self.path}): {exc}") from exc
        out: List[Dict[str, Any]] = []
        for lineno, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue                    # benign blank line
            try:
                e = json.loads(line)
            except json.JSONDecodeError as ex:
                raise LedgerCorrupted(
                    f"ledger line {lineno} malformed JSON") from ex
            if not isinstance(e, dict) or not all(
                    k in e for k in ("plan_sha256", "mutation_id", "status")):
                raise LedgerCorrupted(
                    f"ledger line {lineno} lacks authoritative shape")
            out.append(e)
        return out

    def latest_status(self, plan_hash: str, mutation_id: str) -> Optional[str]:
        """Most recent EVENT row for this plan+mutation (raw stream view).

        NEVER use for authority decisions — replay events would poison it.
        Use :meth:`authoritative_state`.
        """
        found = None
        for e in self.entries():
            if e.get("plan_sha256") == plan_hash \
                    and e.get("mutation_id") == mutation_id:
                found = e.get("status")
        return found

    def authoritative_state(self, plan_hash: str,
                            mutation_id: str) -> Optional[str]:
        """The authoritative applied-state: last AUTHORITATIVE row wins.

        Event rows (already_verified replays, preflight noise) are skipped.
        verified → rolled_back transitions are honored; a replay event
        between them changes nothing.
        """
        state = None
        for e in self.entries():
            if e.get("plan_sha256") != plan_hash \
                    or e.get("mutation_id") != mutation_id:
                continue
            if e.get("status") in AUTHORITATIVE_STATUSES:
                state = e["status"]
        return state

    def has_verified(self, plan_hash: str, mutation_id: str) -> bool:
        return self.authoritative_state(
            plan_hash, mutation_id) == ST_VERIFIED

    def is_rolled_back(self, plan_hash: str, mutation_id: str) -> bool:
        return self.authoritative_state(
            plan_hash, mutation_id) == ST_ROLLED_BACK

    def latest_authoritative_record(self, plan_hash: str,
                                    mutation_id: str) -> Optional[Dict[str, Any]]:
        """The last AUTHORITATIVE row for this plan+mutation (dict or None).

        This is the provenance anchor for rollback: receipt fields must
        match THIS record, never merely themselves.
        """
        found = None
        for e in self.entries():
            if e.get("plan_sha256") != plan_hash \
                    or e.get("mutation_id") != mutation_id:
                continue
            if e.get("status") in AUTHORITATIVE_STATUSES:
                found = e
        return found

    def verified_transactions(self, plan_hash: str) -> List[Dict[str, Any]]:
        """Mutations whose AUTHORITATIVE state is verified (rollback pool).

        Replay events never remove a mutation from this set; an explicit
        rolled_back transition does.
        """
        out = []
        seen_mids = set()
        for e in self.entries():
            if e.get("plan_sha256") != plan_hash:
                continue
            mid = str(e.get("mutation_id"))
            if mid in seen_mids:
                continue
            if self.authoritative_state(plan_hash, mid) == ST_VERIFIED \
                    and e.get("status") == ST_VERIFIED:
                out.append(e)
                seen_mids.add(mid)
        return out

    def record(self, rec: TransactionRecord) -> None:
        self._append(rec)


# --- Rollback receipt (transaction-bound, own integrity hash) ---------------------


@dataclass
class TransactionRollbackReceipt:
    """Immutable rollback intent for ONE verified transaction.

    Binds the exact applied state so a later human change forces refusal:
    rollback only ever runs when current == verified_applied_state.
    """
    schema: str
    rollback_id: str
    transaction_id: str
    plan_sha256: str
    approval_sha256: str
    mutation_id: str
    ref_digest: str
    pre_native_flag: int
    pre_semantic_flag: str
    applied_native_flag: int
    applied_semantic_flag: str
    created_at: str
    content_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "schema": self.schema,
            "rollback_id": self.rollback_id,
            "transaction_id": self.transaction_id,
            "plan_sha256": self.plan_sha256,
            "approval_sha256": self.approval_sha256,
            "mutation_id": self.mutation_id,
            "ref_digest": self.ref_digest,
            "pre_native_flag": self.pre_native_flag,
            "pre_semantic_flag": self.pre_semantic_flag,
            "applied_native_flag": self.applied_native_flag,
            "applied_semantic_flag": self.applied_semantic_flag,
            "created_at": self.created_at,
        }
        d["content_hash"] = sha256_hex(d)
        return d

    def validate(self) -> None:
        if self.schema != ROLLBACK_TX_SCHEMA:
            raise FlagWorkflowError(
                f"rollback schema must be {ROLLBACK_TX_SCHEMA}")
        require_hex256(self.plan_sha256, "rollback.plan_sha256")
        require_hex256(self.approval_sha256, "rollback.approval_sha256")
        stored = require_hex256(self.content_hash, "rollback.content_hash")
        body = self.to_dict()
        body.pop("content_hash")
        if sha256_hex(body) != stored:
            raise FlagWorkflowError(
                "rollback content_hash mismatch (tampered)")

    @classmethod
    def create(cls, *, transaction_id: str, plan_sha256: str,
               approval_sha256: str, mutation_id: str, ref_digest: str,
               pre_native_flag: int, pre_semantic_flag: str,
               applied_native_flag: int,
               applied_semantic_flag: str) -> "TransactionRollbackReceipt":
        receipt = cls(
            schema=ROLLBACK_TX_SCHEMA,
            rollback_id="rbx-" + sha256_hex({
                "transaction_id": transaction_id,
                "mutation_id": mutation_id,
                "hint": _now(),
            })[:32],
            transaction_id=transaction_id,
            plan_sha256=plan_sha256,
            approval_sha256=approval_sha256,
            mutation_id=mutation_id,
            ref_digest=ref_digest,
            pre_native_flag=int(pre_native_flag),
            pre_semantic_flag=pre_semantic_flag,
            applied_native_flag=int(applied_native_flag),
            applied_semantic_flag=applied_semantic_flag,
            created_at=_now(),
        )
        receipt.content_hash = receipt.to_dict()["content_hash"]
        return receipt


# --- Results -----------------------------------------------------------------------


@dataclass
class ApplyResult:
    status: str                      # applied|partially_failed|blocked|already_applied|already_claimed
    writes_performed: int = 0
    verified: List[Dict[str, Any]] = field(default_factory=list)
    failed: List[Dict[str, Any]] = field(default_factory=list)
    unattempted: List[Dict[str, Any]] = field(default_factory=list)
    already_applied: List[Dict[str, Any]] = field(default_factory=list)
    blocked_reason: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class RollbackResult:
    status: str                      # rolled_back|already_rolled_back|rollback_blocked_by_override|blocked
    writes_performed: int = 0
    restored_native_flag: Optional[int] = None
    error_code: Optional[str] = None


# --- Engine -------------------------------------------------------------------------


class TransactionEngine:
    """Executes approved flag migrations as verifiable transactions."""

    def __init__(self, state_dir: Path, ledger: TransactionLedger,
                 overrides: Any):
        self.state_dir = Path(state_dir)
        self.ledger = ledger
        self.overrides = overrides       # flag_workflow.OverrideStore

    # -- helpers ------------------------------------------------------------------

    @staticmethod
    def _ref_for(mutation: PlannedMutation) -> MessageReference:
        return MessageReference(
            provider=mutation.provider,
            account=mutation.account,
            mailbox=mutation.mailbox,
            provider_id=mutation.provider_id,
            observed_native_flag=mutation.observed_native_flag,
            evidence_digest=mutation.evidence_digest,
            message_id_digest=mutation.message_id_digest,
            snapshot_id=mutation.snapshot_id,
        )

    @staticmethod
    def _semantic_for_native(provider: str, native_index: int) -> FlagColor:
        from core.flag_workflow import _native_validator_for
        return _native_validator_for(provider)(native_index)

    @staticmethod
    def _native_for_semantic(provider: str, color: FlagColor) -> int:
        if provider != "mailapp":
            raise FlagWorkflowError(
                f"no native writer for provider {provider!r}")
        from providers.flag_codecs import mailapp_index_from_flag
        return mailapp_index_from_flag(color)   # KeyError for UNKNOWN

    def _txid(self, plan_hash: str, mutation: PlannedMutation,
              approval: ApprovalReceipt) -> str:
        return "tx-" + sha256_hex({
            "plan": plan_hash,
            "approval": approval.content_hash,
            "mutation": mutation.mutation_id,
        })[:24]

    def _resolve_live(self, provider: Any,
                      ref: MessageReference) -> MessageReference:
        """Fresh qualified read: evidence + native + semantic in one shot."""
        return provider.resolve_scoped(ref)

    # -- preflight ------------------------------------------------------------------

    def preflight_one(self, provider: Any, plan: Dict[str, Any],
                      mutation: PlannedMutation,
                      approval: ApprovalReceipt) -> Optional[str]:
        """Return None when the target is clear to write, else an error code.

        Checks (review order): bindings -> live state -> structural gates.
        """
        # Structural gates FIRST — no provider contact needed to refuse.
        if mutation.auto_eligible is not True:
            return "not_auto_eligible"
        if mutation.review_required is not False:
            return "review_required"
        if mutation.proposed_flag == FlagColor.UNKNOWN:
            return "proposed_unknown_not_writable"
        if mutation.snapshot_id != plan.get("snapshot_id"):
            return "snapshot_binding_mismatch"
        if plan.get("policy_sha256") and \
                approval.policy_sha256 != plan["policy_sha256"]:
            return "policy_mismatch"
        if self.overrides.is_suppressed(mutation.ref_digest):
            return "human_override_suppressed"
        if mutation.evidence_digest is None:
            return "no_durable_evidence"

        # Durable reference validity + exact live-state verification.
        try:
            ref = self._ref_for(mutation)
            ref.validate_scoped()
        except Exception:
            return "invalid_reference_scope"

        try:
            live = self._resolve_live(provider, ref)
        except Exception:
            return "resolve_failed"

        if live.evidence_digest != mutation.evidence_digest:
            return "evidence_drift"
        # NATIVE INDEX COMPARISON — explicit None checks ONLY. Mail.app RED
        # is native index 0; truthiness (`x or -999`) would treat a live or
        # bound RED as "missing" and structurally block every legacy red.
        expected_native = mutation.observed_native_flag
        if expected_native is None:
            return "missing_observed_native_flag"
        if live.observed_native_flag is None:
            return "native_flag_unavailable"
        if int(live.observed_native_flag) != int(expected_native):
            return "native_flag_drift"
        live_semantic = self._semantic_for_native(
            mutation.provider, int(live.observed_native_flag))
        if live_semantic != mutation.observed_flag:
            return "semantic_flag_drift"
        return None

    # -- apply ------------------------------------------------------------------------

    def apply_transaction(self, *, plan: Dict[str, Any],
                          approval: ApprovalReceipt,
                          provider: Any) -> ApplyResult:
        """Execute the approved subset as one all-or-zero-preflight batch.

        EXECUTABLE MUTATIONS ARE DERIVED FROM THE PLAN ITSELF (Commit 6d):
        callers cannot supply detached PlannedMutation objects — everything
        the engine touches is parsed from the hash-committed artifact, so
        execution data is always exactly what ``plan_hash`` commits.
        """
        plan_hash = plan.get("plan_hash")
        require_hex256(plan_hash, "plan.plan_hash")
        # Plan integrity re-check inside the engine (defense vs callers that
        # skipped schema validation).
        if compute_plan_hash(plan) != plan_hash:
            raise FlagWorkflowError("plan_hash mismatch — plan was tampered")

        lock_path = (self.state_dir / "locks" /
                     f"apply-{plan_hash[:16]}.lock")
        try:
            with AdvisoryFileLock(lock_path):
                return self._apply_locked(plan, plan_hash, approval,
                                          provider)
        except TransactionLocked:
            return ApplyResult(status="already_claimed", writes_performed=0,
                               error_code="lock_held_elsewhere")
        except (LedgerCorrupted, PrivateStateUnusable) as e:
            # Corrupt local state must BLOCK — never masquerade as fresh
            # history. Any write already attempted before the failure is
            # counted honestly.
            return ApplyResult(status="blocked", writes_performed=0,
                               error_code=f"private_state_failure:{e}")

    def _apply_locked(self, plan: Dict[str, Any], plan_hash: str,
                      approval: ApprovalReceipt,
                      provider: Any) -> ApplyResult:
        # APPROVAL VALIDATION FIRST — inside the lock, before ledger
        # authority checks, preflight, claims, or ANY provider contact.
        # The canonical validator (ApprovalReceipt.validate) is the single
        # authority for approval rules; the engine never re-implements them.
        #
        # EXECUTABLE MUTATIONS come from the validated plan itself: parsing
        # re-runs every schema/invariant rule against hash-committed bytes,
        # so detached caller objects can never become execution authority.
        from core.flag_workflow import validate_plan_schema
        try:
            mutations = validate_plan_schema(plan)
        except FlagWorkflowError as e:
            return ApplyResult(
                status="blocked", writes_performed=0,
                blocked_reason="plan_validation_failed",
                error_code=f"plan_invalid:{e}")
        try:
            approval.validate(plan=dict(plan), plan_mutations=mutations)
        except FlagWorkflowError as e:
            # A rejected approval creates NO lifecycle records — a bad
            # approval must never leave misleading prepared/verified state.
            return ApplyResult(
                status="blocked", writes_performed=0,
                blocked_reason="approval_validation_failed",
                error_code=f"approval_invalid:{e}")

        # Validation passed: every approved id provably exists.
        by_id = {m.mutation_id: m for m in mutations}
        approved = [by_id[i] for i in approval.approved_mutation_ids]

        result = ApplyResult(status="applied")
        approval_sha = approval.content_hash
        by_id = {m.mutation_id: m for m in approved}

        # IDEMPOTENCY PASS (authority-based) + POST-ROLLBACK DOCTRINE.
        # Replay events appended here are EVENT records; they never erase
        # the authoritative verified state (P0 6b fix).
        pending: List[PlannedMutation] = []
        rolled_back_ids: List[str] = []
        for m in approved:
            state = self.ledger.authoritative_state(plan_hash, m.mutation_id)
            if state == ST_VERIFIED:
                txid = self._txid(plan_hash, m, approval)
                self.ledger.record(TransactionRecord(
                    transaction_id=txid, plan_sha256=plan_hash,
                    approval_sha256=approval_sha,
                    mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                    pre_state=None, intended_state=m.proposed_flag.value,
                    verified_post_state=None,
                    timestamp=_now(), status=ST_ALREADY_VERIFIED))
                result.already_applied.append({"mutation_id": m.mutation_id})
            elif state == ST_ROLLED_BACK:
                # A rolled-back mutation is NOT currently applied. Re-running
                # an undone migration requires a NEW plan/approval cycle —
                # deterministic refusal, zero writes.
                rolled_back_ids.append(m.mutation_id)
            else:
                pending.append(m)
        if rolled_back_ids:
            for mid in rolled_back_ids:
                self.ledger.record(TransactionRecord(
                    transaction_id=self._txid(
                        plan_hash, by_id[mid], approval),
                    plan_sha256=plan_hash, approval_sha256=approval_sha,
                    mutation_id=mid,
                    ref_digest=by_id[mid].ref_digest,
                    pre_state=None,
                    intended_state=by_id[mid].proposed_flag.value,
                    verified_post_state=None, timestamp=_now(),
                    status=ST_BLOCKED, error_code="previously_rolled_back"))
            result.status = "blocked"
            result.blocked_reason = "mutation_previously_rolled_back"
            result.error_code = "previously_rolled_back"
            result.failed.extend({"mutation_id": i,
                                  "error_code": "previously_rolled_back"}
                                 for i in rolled_back_ids)
            return result
        if not pending:
            result.status = "already_applied"
            return result

        # FULL-BATCH PREFLIGHT — all-or-zero.
        failures: List[Dict[str, Any]] = []
        pre_states: Dict[str, Optional[str]] = {}
        for m in pending:
            code = self.preflight_one(provider, plan, m, approval)
            pre_states[m.mutation_id] = code
            if code is not None:
                failures.append({"mutation_id": m.mutation_id,
                                 "error_code": code})
        if failures:
            for m in pending:
                code = pre_states[m.mutation_id]
                self.ledger.record(TransactionRecord(
                    transaction_id=self._txid(plan_hash, m, approval),
                    plan_sha256=plan_hash, approval_sha256=approval_sha,
                    mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                    pre_state=None, intended_state=m.proposed_flag.value,
                    verified_post_state=None, timestamp=_now(),
                    status=ST_BLOCKED,
                    error_code=code or "preflight_failed"))
            result.status = "blocked"
            result.blocked_reason = "batch_preflight_failed"
            result.failed = failures
            result.unattempted = [
                {"mutation_id": m.mutation_id} for m in pending
                if pre_states[m.mutation_id] is None
            ]
            return result           # writes_performed stays 0

        for m in pending:
            self.ledger.record(TransactionRecord(
                transaction_id=self._txid(plan_hash, m, approval),
                plan_sha256=plan_hash, approval_sha256=approval_sha,
                mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                pre_state=m.observed_flag.value,
                intended_state=m.proposed_flag.value,
                verified_post_state=None, timestamp=_now(),
                status=ST_PREFLIGHT_PASSED))

        # WRITE PHASE — scoped methods ONLY; freeze on first non-verified.
        remaining = list(pending)
        while remaining:
            m = remaining.pop(0)
            txid = self._txid(plan_hash, m, approval)
            ref = self._ref_for(m)
            expected_native = self._native_for_semantic(
                m.provider, m.proposed_flag)
            self.ledger.record(TransactionRecord(
                transaction_id=txid, plan_sha256=plan_hash,
                approval_sha256=approval_sha, mutation_id=m.mutation_id,
                ref_digest=m.ref_digest,
                pre_state=m.observed_flag.value,
                intended_state=m.proposed_flag.value,
                verified_post_state=None, timestamp=_now(),
                status=ST_APPLYING))
            write_done = False
            try:
                if m.proposed_flag == FlagColor.NO_FLAG:
                    ok = provider.clear_flag_ref(ref)
                else:
                    ok = provider.set_flag_color_ref(ref, m.proposed_flag)
                if ok is not True:
                    # Provider explicitly reports NOTHING happened.
                    raise ProviderRefused("provider returned non-True")
                write_done = True
                # MANDATORY read-after-write proof — provider True is NOT
                # success.
                live = self._resolve_live(provider, ref)
                post_native_raw = live.observed_native_flag
                if live.evidence_digest != m.evidence_digest:
                    raise FlagStateAmbiguous("evidence changed during write")
                if post_native_raw is None or \
                        int(post_native_raw) != expected_native:
                    raise FlagStateAmbiguous(
                        f"post-write native {post_native_raw!r} != "
                        f"{expected_native}")
                post_semantic = self._semantic_for_native(
                    m.provider, int(post_native_raw))
                if post_semantic != m.proposed_flag:
                    raise FlagStateAmbiguous("post-write semantic mismatch")
            except ProviderRefused as e:
                self.ledger.record(TransactionRecord(
                    transaction_id=txid, plan_sha256=plan_hash,
                    approval_sha256=approval_sha,
                    mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                    pre_state=m.observed_flag.value,
                    intended_state=m.proposed_flag.value,
                    verified_post_state=None, timestamp=_now(),
                    status=ST_BLOCKED, error_code=f"provider_refused:{e}"))
                result.failed.append({"mutation_id": m.mutation_id,
                                      "status": ST_BLOCKED,
                                      "error_code": f"provider_refused:{e}"})
                result.status = "partially_failed"
                break
            except FlagStateAmbiguous as e:
                self.ledger.record(TransactionRecord(
                    transaction_id=txid, plan_sha256=plan_hash,
                    approval_sha256=approval_sha,
                    mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                    pre_state=m.observed_flag.value,
                    intended_state=m.proposed_flag.value,
                    verified_post_state=None, timestamp=_now(),
                    status=ST_AMBIGUOUS, error_code=str(e)))
                result.writes_performed += 1 if write_done else 0
                result.failed.append({"mutation_id": m.mutation_id,
                                      "status": ST_AMBIGUOUS,
                                      "error_code": str(e)})
                result.status = "partially_failed"
                break
            except Exception as e:                       # provider failure
                self.ledger.record(TransactionRecord(
                    transaction_id=txid, plan_sha256=plan_hash,
                    approval_sha256=approval_sha,
                    mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                    pre_state=m.observed_flag.value,
                    intended_state=m.proposed_flag.value,
                    verified_post_state=None, timestamp=_now(),
                    status=(ST_PARTIALLY_FAILED if write_done
                            else ST_BLOCKED),
                    error_code=f"provider_error:{e}"))
                result.writes_performed += 1 if write_done else 0
                result.failed.append({
                    "mutation_id": m.mutation_id,
                    "status": (ST_PARTIALLY_FAILED if write_done
                               else ST_BLOCKED),
                    "error_code": f"provider_error:{e}"})
                result.status = "partially_failed"
                break
            # Verified!
            self.ledger.record(TransactionRecord(
                transaction_id=txid, plan_sha256=plan_hash,
                approval_sha256=approval_sha, mutation_id=m.mutation_id,
                ref_digest=m.ref_digest,
                pre_state=m.observed_flag.value,
                intended_state=m.proposed_flag.value,
                verified_post_state=m.proposed_flag.value,
                timestamp=_now(), status=ST_VERIFIED))
            # Record automation post-state WITHOUT ever clearing overrides
            # (unlock-only contract lives inside OverrideStore).
            self.overrides.record_automation_state(
                m.ref_digest, m.proposed_flag.value, True)
            result.writes_performed += 1
            result.verified.append({
                "mutation_id": m.mutation_id,
                "transaction_id": txid,
                "verified_post_state": m.proposed_flag.value,
            })

        # Honest remainder accounting after any mid-batch freeze.
        if result.status == "partially_failed":
            result.unattempted.extend(
                {"mutation_id": m.mutation_id} for m in remaining)
            for m in remaining:
                self.ledger.record(TransactionRecord(
                    transaction_id=self._txid(plan_hash, m, approval),
                    plan_sha256=plan_hash, approval_sha256=approval_sha,
                    mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                    pre_state=None, intended_state=m.proposed_flag.value,
                    verified_post_state=None, timestamp=_now(),
                    status=ST_FROZEN_UNATTEMPTED,
                    error_code="batch_frozen_after_failure"))
        return result

    # -- rollback -----------------------------------------------------------------
    # Rollback lives in ScopedRollbackEngine: receipts store ONLY digests +
    # native/semantic states (PII-free), so scope recovery requires the
    # private plan's durable bindings, supplied at engine construction.


class ScopedRollbackEngine(TransactionEngine):
    """Rollback bound to the IMMUTABLE PLAN (Commit 6d).

    The receipt intentionally stores only digests + native/semantic states
    (PII-free). Scope reconstruction parses executable mutations FROM the
    hash-committed plan on every rollback — never from a free-standing
    caller-supplied mutation list. Plan integrity is re-verified under the
    lock before anything else.
    """

    def __init__(self, state_dir: Path, ledger: TransactionLedger,
                 overrides: Any, plan: Dict[str, Any]):
        super().__init__(state_dir, ledger, overrides)
        self._plan = dict(plan)

    def _mutations_by_id(self) -> Dict[str, PlannedMutation]:
        from core.flag_workflow import validate_plan_schema
        if compute_plan_hash(self._plan) != self._plan.get("plan_hash"):
            raise FlagWorkflowError(
                "rollback plan_hash mismatch — plan artifact tampered")
        return {m.mutation_id: m for m in validate_plan_schema(self._plan)}

    def rollback_transaction(self, *, receipt: TransactionRollbackReceipt,
                             provider: Any) -> RollbackResult:
        receipt.validate()
        # MUTUAL EXCLUSION (Commit 7, Group I): rollback must never race an
        # active apply on the same plan. Take the APPLY lock for the plan
        # FIRST; only then the rollback-specific lock.
        apply_lock_path = (self.state_dir / "locks" /
                           f"apply-{receipt.plan_sha256[:16]}.lock")
        rb_lock_path = (self.state_dir / "locks" /
                        f"rb-{receipt.transaction_id[:16]}.lock")
        try:
            with AdvisoryFileLock(apply_lock_path), \
                    AdvisoryFileLock(rb_lock_path):
                return self._scoped_rollback_locked(receipt, provider)
        except TransactionLocked:
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code="apply_in_progress_or_locked")
        except (LedgerCorrupted, PrivateStateUnusable) as e:
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code=f"private_state_failure:{e}")
        except (LedgerCorrupted, PrivateStateUnusable) as e:
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code=f"private_state_failure:{e}")

    def _scoped_rollback_locked(
            self, receipt: TransactionRollbackReceipt,
            provider: Any) -> RollbackResult:
        # Idempotency on AUTHORITATIVE state: already rolled back →
        # ZERO-write no-op. Replay/event rows can never flip this.
        state = self.ledger.authoritative_state(receipt.plan_sha256,
                                                receipt.mutation_id)
        if state == ST_ROLLED_BACK:
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=receipt.pre_semantic_flag,
                intended_state=receipt.pre_semantic_flag,
                verified_post_state=receipt.pre_semantic_flag,
                timestamp=_now(), status=ST_ROLLED_BACK,
                error_code="idempotent_noop"))
            return RollbackResult(status="already_rolled_back",
                                  writes_performed=0)
        if state != ST_VERIFIED:
            return RollbackResult(
                status="blocked", writes_performed=0,
                error_code=f"transaction_not_verified({state})")

        # ---------------------------------------------------------------
        # LINEAGE BINDING: the receipt is SELF-integrity only (SHA-256 is
        # integrity, NOT authentication — anyone can recompute a hash).
        # Authoritative truth is reconstructed from the immutable
        # PlannedMutation + the ledger's VERIFIED record; every receipt
        # field must MATCH that record or rollback refuses with ZERO
        # writes. Receipt fields are informational from here on.
        # ---------------------------------------------------------------
        rec = self.ledger.latest_authoritative_record(
            receipt.plan_sha256, receipt.mutation_id)
        try:
            by_id = self._mutations_by_id()
        except FlagWorkflowError as e:
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code=f"rollback_plan_invalid:{e}")
        mutation = by_id.get(receipt.mutation_id)
        expected_applied_native = self._native_for_semantic(
            mutation.provider, mutation.proposed_flag) \
            if mutation else None
        lineage_expectations = {
            "transaction_id": (receipt.transaction_id,
                               rec.get("transaction_id") if rec else None),
            "plan_sha256": (receipt.plan_sha256, receipt.plan_sha256),
            "approval_sha256": (receipt.approval_sha256,
                                rec.get("approval_sha256") if rec else None),
            "mutation_id": (receipt.mutation_id,
                            receipt.mutation_id),
            "ref_digest": (receipt.ref_digest,
                           mutation.ref_digest if mutation else None),
            "pre_semantic_flag": (receipt.pre_semantic_flag,
                                  mutation.observed_flag.value
                                  if mutation else None),
            "pre_native_flag": (
                receipt.pre_native_flag,
                mutation.observed_native_flag if mutation else None),
            "applied_semantic_flag": (
                receipt.applied_semantic_flag,
                mutation.proposed_flag.value if mutation else None),
            "applied_native_flag": (
                receipt.applied_native_flag, expected_applied_native),
        }
        for field_name, (got, expected) in lineage_expectations.items():
            if got != expected:
                self.ledger.record(TransactionRecord(
                    transaction_id=receipt.transaction_id,
                    plan_sha256=receipt.plan_sha256,
                    approval_sha256=receipt.approval_sha256,
                    mutation_id=receipt.mutation_id,
                    ref_digest=receipt.ref_digest,
                    pre_state=None,
                    intended_state=receipt.pre_semantic_flag,
                    verified_post_state=None, timestamp=_now(),
                    status=ST_ROLLBACK_BLOCKED,
                    error_code=f"receipt_lineage_mismatch:{field_name}"))
                return RollbackResult(
                    status="blocked", writes_performed=0,
                    error_code=f"receipt_lineage_mismatch:{field_name}")
        # Narrow for mypy: a None mutation would have failed ref_digest
        # lineage above.
        if mutation is None:  # pragma: no cover
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code="receipt_lineage_mismatch:mutation")

        # DERIVED truth (never receipt fields) drives the write target and
        # the current-state gate:
        prior_color = mutation.observed_flag
        expected_applied_native = self._native_for_semantic(
            mutation.provider, mutation.proposed_flag)

        ref = self._ref_for(mutation)
        try:
            live = self._resolve_live(provider, ref)
        except Exception as e:
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=receipt.pre_semantic_flag,
                intended_state=receipt.pre_semantic_flag,
                verified_post_state=None, timestamp=_now(),
                status=ST_ROLLBACK_BLOCKED,
                error_code=f"resolve_failed:{e}"))
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code="resolve_failed")

        current_native = live.observed_native_flag
        # OVERRIDE-SAFETY: current MUST equal the DERIVED applied state
        # (mutation.proposed_flag via provider codec) — never the receipt's
        # self-asserted applied state. A human having touched the message
        # since means we must NOT clobber their choice with the old color.
        if current_native is None or \
                int(current_native) != int(expected_applied_native):
            applied_semantic_derived = self._semantic_for_native(
                mutation.provider, int(expected_applied_native)).value
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=applied_semantic_derived,
                intended_state=prior_color.value,
                verified_post_state=(
                    self._semantic_for_native(
                        mutation.provider, int(current_native)).value
                    if current_native is not None else None),
                timestamp=_now(), status=ST_ROLLBACK_BLOCKED,
                error_code="human_intervention_detected"))
            # Persist detection as a suppression so future preflight refuses.
            observed_semantic = (
                self._semantic_for_native(
                    mutation.provider, int(current_native)).value
                if current_native is not None else "unknown_unknown")
            self.overrides.detect_override(
                mutation.ref_digest,
                automation_expected_state=applied_semantic_derived,
                human_observed_state=observed_semantic)
            return RollbackResult(
                status="rollback_blocked_by_override", writes_performed=0,
                error_code="human_intervention_detected")

        try:
            if prior_color == FlagColor.NO_FLAG:
                ok = provider.clear_flag_ref(ref)
            else:
                ok = provider.set_flag_color_ref(ref, prior_color)
            if ok is not True:
                raise FlagWorkflowError("provider returned non-True")
            live2 = self._resolve_live(provider, ref)
            expected_prior_native = self._native_for_semantic(
                mutation.provider, prior_color)
            if live2.evidence_digest != mutation.evidence_digest:
                raise FlagStateAmbiguous("evidence changed during rollback")
            if live2.observed_native_flag is None or \
                    int(live2.observed_native_flag) != expected_prior_native:
                raise FlagStateAmbiguous("post-rollback native mismatch")
        except FlagStateAmbiguous as e:
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=receipt.pre_semantic_flag,
                intended_state=receipt.pre_semantic_flag,
                verified_post_state=None, timestamp=_now(),
                status=ST_ROLLBACK_BLOCKED, error_code=str(e)))
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code=str(e))
        except Exception as e:
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=receipt.pre_semantic_flag,
                intended_state=receipt.pre_semantic_flag,
                verified_post_state=None, timestamp=_now(),
                status=ST_ROLLBACK_PENDING,
                error_code=f"provider_error:{e}"))
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code=f"provider_error:{e}")

        self.ledger.record(TransactionRecord(
            transaction_id=receipt.transaction_id,
            plan_sha256=receipt.plan_sha256,
            approval_sha256=receipt.approval_sha256,
            mutation_id=receipt.mutation_id,
            ref_digest=receipt.ref_digest,
            pre_state=receipt.applied_semantic_flag,
            intended_state=receipt.pre_semantic_flag,
            verified_post_state=receipt.pre_semantic_flag,
            timestamp=_now(), status=ST_ROLLED_BACK))
        return RollbackResult(status="rolled_back", writes_performed=1,
                              restored_native_flag=expected_prior_native)


class FlagStateAmbiguous(Exception):
    """Write executed but post-write verification could not prove success."""


class ProviderRefused(Exception):
    """Provider explicitly reports the mutation did NOT happen (False)."""
