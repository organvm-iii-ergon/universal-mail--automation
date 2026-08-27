"""Commit 6 acceptance: transaction semantics on top of immutable plans.

Covers: structural auto_eligible gate, v2 approval binding, ALL-OR-ZERO
batch preflight, scoped-writes-only enforcement, mandatory read-after-write
verification, honest partial failure, idempotency, advisory-lock
concurrency, unlock-only overrides, transaction-bound override-safe
rollback, private-state permissions, PII-free projections, and CLI gates
that MUST remain NOT_READY exit 89.
"""

import json
import os
import stat
from types import SimpleNamespace

import pytest

import cli
from core import flag_workflow as fw
from core.flag_transactions import (
    AdvisoryFileLock,
    LedgerCorrupted,
    ROLLBACK_TX_SCHEMA,
    ST_ALREADY_VERIFIED,
    ST_AMBIGUOUS,
    ST_APPLYING,
    ST_BLOCKED,
    ST_FROZEN_UNATTEMPTED,
    ST_ROLLED_BACK,
    ST_ROLLBACK_BLOCKED,
    ST_ROLLBACK_PENDING,
    ST_VERIFIED,
    ST_VERIFIED_PENDING_PRIVATE_STATE,
    ScopedRollbackEngine,
    TransactionLedger,
    TransactionRecord,
    TransactionRollbackReceipt,
    TransactionEngine,
)
from core.models import FlagColor, MessageReference
from providers.base import ProviderNativeStateDrift, ProviderWriteAmbiguous
from providers.mailapp import mailapp_index_from_flag

ELIG_SENDER = "billing@corp.example"
ELIG_SUBJECT = "Payment due tomorrow — account suspension otherwise"
OBSERVED_COLOR = FlagColor.ORANGE          # ≠ RED proposal target


def _row(pid, color=OBSERVED_COLOR, sender=ELIG_SENDER, subject=ELIG_SUBJECT,
         account="acct", mailbox="INBOX", received="2026-07-01T00:00:00"):
    return SimpleNamespace(
        provider_id=pid, account=account, mailbox=mailbox,
        sender=sender, subject=subject,
        native_index=None if color == FlagColor.UNKNOWN
        else mailapp_index_from_flag(color),
        flag_color=color, received_iso=received)


def _digest(received, sender, subject):
    return MessageReference.compute_evidence_digest(received, sender, subject)


class FakeMessage:
    def __init__(self, pid, native, received="2026-07-01T00:00:00",
                 sender=ELIG_SENDER, subject=ELIG_SUBJECT):
        self.pid, self.native = pid, native
        self.received, self.sender, self.subject = received, sender, subject


class FakeScopedProvider:
    """Duck-typed Mail.app scoped surface. Generic action methods EXPLODE —
    the engine must never reach them."""

    name = "mailapp"

    def __init__(self, messages):
        self.messages = {m.pid: m for m in messages}
        self.calls = []

    # -- scoped surface (the ONLY thing the engine may touch) ---------------
    def _live_ref(self, ref):
        m = self.messages[ref.provider_id]
        return MessageReference(
            provider=ref.provider, account=ref.account, mailbox=ref.mailbox,
            provider_id=m.pid, received_iso=m.received,
            sender_digest=None, subject_digest=None,
            observed_native_flag=m.native,
            evidence_digest=_digest(m.received, m.sender, m.subject),
            snapshot_id=ref.snapshot_id)

    def resolve_scoped(self, ref):
        self.calls.append(("resolve_scoped", ref.provider_id))
        if ref.provider_id not in self.messages:
            raise RuntimeError("NOT_FOUND")
        return self._live_ref(ref)

    def set_flag_color_ref(self, ref, color):
        self.calls.append(("set_flag_color_ref", ref.provider_id,
                           color.value))
        m = self.messages[ref.provider_id]
        live = _digest(m.received, m.sender, m.subject)
        if live != ref.evidence_digest:
            raise RuntimeError("evidence drifted at provider boundary")
        expected_native = ref.observed_native_flag
        if expected_native is None:
            raise RuntimeError("missing compare-and-set precondition")
        if m.native != expected_native:
            raise ProviderNativeStateDrift(expected_native, m.native)
        m.native = mailapp_index_from_flag(color)
        return True

    def clear_flag_ref(self, ref):
        self.calls.append(("clear_flag_ref", ref.provider_id))
        return self.set_flag_color_ref(ref, FlagColor.NO_FLAG)

    # -- generic mail-action surface (MUST be unreachable) --------------------
    def _forbidden(self, *a, **k):
        raise AssertionError("generic mail-action path reached!")

    apply_label = _forbidden
    remove_label = _forbidden
    archive = _forbidden
    move = _forbidden
    delete = _forbidden
    create_draft = _forbidden
    send = _forbidden
    star = _forbidden
    unstar = _forbidden
    apply_actions = _forbidden


class Harness:
    """Plan + approval + engine wired against a FakeScopedProvider."""

    def __init__(self, tmp_path, pids=("1", "2", "3")):
        self.tmp = tmp_path
        snap = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=[_row(p) for p in pids],
            complete=True, scope_complete=True, status="complete",
            errors=[], inaccessible_count=0, timeout_count=0,
            unknown_index_count=0, limit=500, since_days=None,
            total_matched=len(pids), returned_count=len(pids),
            hidden_by_limit=0)
        self.snapshot = snap
        self.plan = fw.build_plan(snap)
        self.mutations = fw.validate_plan_schema(self.plan)
        self.approval = fw.ApprovalReceipt.create(
            plan_hash=self.plan["plan_hash"],
            snapshot_sha256=self.plan["snapshot_sha256"],
            policy_sha256=self.plan["policy_sha256"],
            approved_mutation_ids=[m.mutation_id for m in self.mutations],
            approving_operator="operator",
            canary_limit=max(1, len(self.mutations)))
        self.state_dir = tmp_path / "state"
        self.ledger = TransactionLedger(
            self.state_dir / "ledger" / "transactions.jsonl")
        self.overrides = fw.OverrideStore(
            self.state_dir / "overrides.json")
        self.provider = FakeScopedProvider([
            FakeMessage(m.provider_id, m.observed_native_flag or -1)
            for m in self.mutations])
        self.engine = TransactionEngine(
            self.state_dir, self.ledger, self.overrides)
        self.rb_engine = ScopedRollbackEngine(
            self.state_dir, self.ledger, self.overrides, self.plan)

    def by_pid(self, pid):
        return next(m for m in self.mutations
                    if m.provider_id == pid)

    def apply(self):
        return self.engine.apply_transaction(
            plan=dict(self.plan),
            approval=self.approval, provider=self.provider)


# --- auto_eligible persistence ---------------------------------------------------


class TestAutoEligiblePersistence:
    def test_auto_eligible_in_serialization_mutation_id_and_hash(self,
                                                                  tmp_path):
        h = Harness(tmp_path)
        m = h.mutations[0]
        d = m.to_dict()
        assert d["auto_eligible"] is True
        assert "auto_eligible" in json.dumps(h.plan["mutations"])
        # Flipping eligibility WITHOUT recomputing the hash = tamper.
        flipped = dict(h.plan)
        flipped["mutations"] = [dict(d, auto_eligible=False)] + \
            [mm.to_dict() for mm in h.mutations[1:]]
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.validate_plan_schema(flipped)
        # Even an attacker who ALSO fixes the hash gains nothing: classifier
        # proof makes eligibility a derived semantic invariant.
        flipped2 = dict(h.plan)
        flipped2["mutations"] = [dict(d, auto_eligible=False)] + [
            mm.to_dict() for mm in h.mutations[1:]]
        flipped2["auto_eligible_count"] -= 1
        flipped2.pop("plan_hash")
        flipped2["plan_hash"] = fw.compute_plan_hash(flipped2)
        with pytest.raises(fw.FlagWorkflowError, match="mutation_id mismatch"):
            fw.validate_plan_schema(flipped2)

    @staticmethod
    def _state(tmp_path):
        return tmp_path / "state"

    @pytest.mark.parametrize("field,value", [
        ("review_required", True),
        ("auto_eligible", False),
    ])
    def test_detached_ineligibility_tamper_is_ignored(
            self, tmp_path, field, value):
        """Commit 6d doctrine: the engine parses mutations from the plan,
        so tampering a DETACHED object has no effect at all — execution
        follows the hash-committed artifact (full matrix lives in
        test_commit6d_plan_derived_mutations.py; forging the PLAN BYTES
        with ineligibility is refused at parse/approval boundaries there
        and in test_commit6c_trust_boundaries.py)."""
        h = Harness(tmp_path, pids=("1",))
        object.__setattr__(h.by_pid("1"), field, value)
        result = h.apply()
        assert result.status == "applied"
        assert result.writes_performed == 1

    def test_parse_time_rejects_review_required_with_auto_true(self,
                                                                tmp_path):
        h = Harness(tmp_path, pids=("1",))
        raw = dict(h.plan["mutations"][0],
                   review_required=True, auto_eligible=True)
        bad = dict(h.plan)
        bad["mutations"] = [raw]
        bad.pop("plan_hash")
        bad["plan_hash"] = fw.compute_plan_hash(bad)
        with pytest.raises(fw.FlagWorkflowError,
                           match="incompatible with.*review_required"):
            fw.validate_plan_schema(bad)

    def test_parse_time_rejects_unknown_observed_auto_eligible(self,
                                                                tmp_path):
        h = Harness(tmp_path, pids=("1",))
        raw = dict(h.plan["mutations"][0],
                   observed_flag="unknown",
                   observed_native_flag=None)
        bad = dict(h.plan)
        bad["mutations"] = [raw]
        bad.pop("plan_hash")
        bad["plan_hash"] = fw.compute_plan_hash(bad)
        with pytest.raises(fw.FlagWorkflowError,
                           match="UNKNOWN observations"):
            fw.validate_plan_schema(bad)


# --- Full-batch preflight: ALL-OR-ZERO ----------------------------------------------


class TestAllOrZeroPreflight:
    def test_full_batch_success_writes_everything_verified(self, tmp_path):
        h = Harness(tmp_path)
        result = h.apply()
        assert result.status == "applied"
        assert result.writes_performed == len(h.mutations)
        assert len(result.verified) == len(h.mutations)
        for m in h.mutations:
            assert h.ledger.has_verified(h.plan["plan_hash"],
                                         m.mutation_id)

    def test_one_native_drift_freezes_entire_batch(self, tmp_path):
        h = Harness(tmp_path)
        drift_pid = h.mutations[1].provider_id
        h.provider.messages[drift_pid].native = 4     # someone touched BLUE
        result = h.apply()
        assert result.status == "blocked"
        assert result.writes_performed == 0           # THE property
        assert result.failed[0]["error_code"] == "native_flag_drift"
        statuses = [e["status"] for e in h.ledger.entries()]
        assert ST_VERIFIED not in statuses
        assert ST_BLOCKED in statuses

    def test_human_change_after_preflight_is_compare_and_set_refusal(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        mutation = h.mutations[0]
        real_set = h.provider.set_flag_color_ref

        def change_then_dispatch(ref, color):
            # Both transaction preflight reads have already passed when the
            # provider write entry point is reached. Simulate a human choosing
            # YELLOW in that gap; provider CAS must preserve it.
            h.provider.messages[mutation.provider_id].native = 2
            return real_set(ref, color)

        h.provider.set_flag_color_ref = change_then_dispatch
        result = h.apply()

        assert result.status == "blocked"
        assert result.writes_performed == 0
        assert result.error_code == "native_flag_drift_at_dispatch"
        assert h.provider.messages[mutation.provider_id].native == 2
        assert h.overrides.is_suppressed(mutation.ref_digest) is True
        assert h.ledger.latest_status(
            h.plan["plan_hash"], mutation.mutation_id
        ) == ST_BLOCKED

    def test_one_evidence_mismatch_zero_writes_entire_batch(self, tmp_path):
        h = Harness(tmp_path)
        drift_pid = h.mutations[1].provider_id
        h.provider.messages[drift_pid].subject = "EDITED BY HUMAN"
        result = h.apply()
        assert result.status == "blocked"
        assert result.writes_performed == 0
        assert result.failed[0]["error_code"] == "evidence_drift"

    def test_one_human_override_zero_writes_entire_batch(self, tmp_path):
        h = Harness(tmp_path)
        suppressed = h.mutations[1].ref_digest
        h.overrides.detect_override(suppressed,
                                    automation_expected_state="orange",
                                    human_observed_state="yellow")
        result = h.apply()
        assert result.status == "blocked"
        assert result.writes_performed == 0
        assert any(f["error_code"] == "human_override_suppressed"
                   for f in result.failed)

    def test_corrupt_override_state_blocks_before_provider_contact(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        h.overrides.path.parent.mkdir(parents=True, exist_ok=True)
        h.overrides.path.write_text("[]", encoding="utf-8")

        result = h.apply()

        assert result.status == "blocked"
        assert result.writes_performed == 0
        assert result.blocked_reason == "override_state_unusable"
        assert result.error_code.startswith("override_state_failure:")
        assert result.failed == []
        assert result.unattempted == [{
            "mutation_id": h.mutations[0].mutation_id,
        }]
        assert h.provider.calls == []

    def test_already_consumed_mutation_is_deterministic_skip(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        first = h.apply()
        assert first.status == "applied"
        writes_after_first = len(h.provider.calls)
        second = h.apply()
        assert second.status == "already_applied"
        assert second.writes_performed == 0
        assert len(h.provider.calls) == writes_after_first   # ZERO new calls
        assert any(e["status"] == ST_ALREADY_VERIFIED
                   for e in h.ledger.entries())

    def test_concurrent_claim_only_one_process_permitted(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        plan_hash = h.plan["plan_hash"]
        lock_path = (h.state_dir / "locks" /
                     f"apply-{plan_hash[:16]}.lock")
        with AdvisoryFileLock(lock_path):             # process A holds it
            result = h.apply()                        # process B attempts
        assert result.status == "already_claimed"
        assert result.writes_performed == 0
        assert h.ledger.entries() == []

    def test_malformed_authoritative_history_blocks_without_further_writes(
            self, tmp_path):
        """Corruption cannot be skipped as if verified history never existed."""
        h = Harness(tmp_path, pids=("1",))
        first = h.apply()
        assert first.status == "applied"

        # Replace the authoritative history with a torn row.  A permissive
        # skip-row parser would now reconstruct an empty ledger and repeat the
        # provider write; fail-closed parsing must stop before any provider
        # contact instead.
        h.ledger.path.write_text("{\"schema\":", encoding="utf-8")
        calls_before = list(h.provider.calls)

        result = h.apply()

        assert result.status == "blocked"
        assert result.writes_performed == 0
        assert result.error_code.startswith("private_state_failure")
        assert h.provider.calls == calls_before


# --- Write phase honesty ---------------------------------------------------------------


class TestWritePhaseVerification:
    def test_provider_true_but_wrong_readback_is_ambiguous(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))

        def lying_set(ref, color):
            h.provider.calls.append(("set_flag_color_ref",
                                     ref.provider_id, color.value))
            return True                               # lies: nothing changed

        h.provider.set_flag_color_ref = lying_set
        result = h.apply()
        assert result.status == "ambiguous"
        # A write MAY have happened at the provider — counted honestly.
        assert result.writes_performed == 1
        assert result.failed[0]["status"] == ST_AMBIGUOUS
        assert any(e["status"] == ST_AMBIGUOUS
                   for e in h.ledger.entries())
        assert not h.ledger.has_verified(h.plan["plan_hash"],
                                         h.mutations[0].mutation_id)

    def test_typed_provider_ambiguity_counts_possible_write_and_freezes(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1", "2"))

        def write_then_lose_proof(ref, color):
            h.provider.messages[ref.provider_id].native = \
                mailapp_index_from_flag(color)
            raise ProviderWriteAmbiguous("connection lost after dispatch")

        h.provider.set_flag_color_ref = write_then_lose_proof
        result = h.apply()

        assert result.status == "ambiguous"
        assert result.writes_performed == 1
        assert result.failed[0]["status"] == ST_AMBIGUOUS
        assert result.unattempted == [
            {"mutation_id": h.by_pid("2").mutation_id}
        ]
        assert h.provider.messages["1"].native == mailapp_index_from_flag(
            FlagColor.RED
        )

    def test_verified_ledger_failure_cannot_reset_write_count(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        original_record = h.ledger.record

        def fail_verified_record(record):
            if record.status == ST_VERIFIED:
                raise LedgerCorrupted(
                    "simulated fsync failure after provider write"
                )
            original_record(record)

        h.ledger.record = fail_verified_record
        result = h.apply()

        assert result.status == "ambiguous"
        assert result.writes_performed == 1
        assert result.failed[0]["status"] == ST_AMBIGUOUS
        assert h.provider.messages["1"].native == mailapp_index_from_flag(
            FlagColor.RED
        )
        assert h.ledger.latest_status(
            h.plan["plan_hash"], h.mutations[0].mutation_id
        ) == ST_VERIFIED_PENDING_PRIVATE_STATE

        h.provider.calls.clear()
        replay = h.apply()
        assert replay.status == "blocked"
        assert replay.writes_performed == 0
        assert h.provider.calls == []

    def test_post_write_ledger_parent_chmod_failure_is_ambiguous(
            self, tmp_path, monkeypatch):
        h = Harness(tmp_path, pids=("1",))
        real_set = h.provider.set_flag_color_ref
        real_fchmod = os.fchmod
        write_crossed = False

        def set_and_mark(ref, color):
            nonlocal write_crossed
            result = real_set(ref, color)
            write_crossed = True
            return result

        def fail_chmod_after_write(fd, mode):
            if write_crossed:
                raise PermissionError("simulated post-write chmod failure")
            return real_fchmod(fd, mode)

        h.provider.set_flag_color_ref = set_and_mark
        monkeypatch.setattr(
            "core.flag_transactions.os.fchmod", fail_chmod_after_write
        )

        result = h.apply()

        assert result.status == "ambiguous"
        assert result.writes_performed == 1
        assert result.failed[0]["status"] == ST_AMBIGUOUS
        assert "private_state_failure" in result.error_code

    def test_override_persistence_failure_cannot_reset_write_count(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))

        def fail_override_state(*_args, **_kwargs):
            raise fw.FlagWorkflowError("override store unavailable")

        h.overrides.record_automation_state = fail_override_state
        result = h.apply()

        assert result.status == "ambiguous"
        assert result.writes_performed == 1
        assert result.failed[0]["status"] == ST_AMBIGUOUS
        assert result.failed[0]["error_code"].startswith(
            "override_state_failure"
        )
        assert h.ledger.has_verified(
            h.plan["plan_hash"], h.mutations[0].mutation_id
        )
        assert h.ledger.latest_status(
            h.plan["plan_hash"], h.mutations[0].mutation_id
        ) == ST_AMBIGUOUS

        h.provider.calls.clear()
        replay = h.apply()
        assert replay.status == "blocked"
        assert replay.error_code == "transaction_recovery_required"
        assert replay.writes_performed == 0
        assert h.provider.calls == []

    def test_private_state_failure_after_first_write_enumerates_remainder(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1", "2", "3"))
        original_record = h.ledger.record
        blocked_mid = h.by_pid("2").mutation_id

        def fail_second_applying(record):
            if record.status == ST_APPLYING and \
                    record.mutation_id == blocked_mid:
                raise LedgerCorrupted("cannot persist second applying row")
            original_record(record)

        h.ledger.record = fail_second_applying
        result = h.apply()

        assert result.status == "ambiguous"
        assert result.writes_performed == 1
        assert [item["mutation_id"] for item in result.verified] == [
            h.by_pid("1").mutation_id
        ]
        assert result.unattempted == [
            {"mutation_id": h.by_pid("2").mutation_id},
            {"mutation_id": h.by_pid("3").mutation_id},
        ]

    def test_mid_batch_failure_records_exact_partial_state(self, tmp_path):
        h = Harness(tmp_path, pids=("1", "2", "3"))
        boom_pid = h.mutations[1].provider_id
        real_set = FakeScopedProvider.set_flag_color_ref

        def raising_set(ref, color):
            if ref.provider_id == boom_pid:
                h.provider.calls.append(("explode", ref.provider_id))
                raise RuntimeError("AppleScript connection lost")
            return real_set(h.provider, ref, color)

        h.provider.set_flag_color_ref = raising_set
        result = h.apply()
        assert result.status == "partially_failed"
        # Mutation 1 verified BEFORE the failure; 2 failed; 3 untouched.
        assert [v["mutation_id"] for v in result.verified] == \
            [h.by_pid("1").mutation_id]
        assert result.failed[0]["mutation_id"] == h.by_pid("2").mutation_id
        assert result.unattempted == [
            {"mutation_id": h.by_pid("3").mutation_id}]
        statuses = {e["mutation_id"]: e["status"]
                    for e in h.ledger.entries()}
        assert statuses[h.by_pid("3").mutation_id] == ST_FROZEN_UNATTEMPTED
        # The receipt must NOT claim "applied".
        assert result.status != "applied"

    def test_generic_action_surface_never_reached(self, tmp_path):
        h = Harness(tmp_path, pids=("1", "2"))
        result = h.apply()                            # would explode if hit
        assert result.status == "applied"
        kinds = {c[0] for c in h.provider.calls}
        assert kinds <= {"resolve_scoped", "set_flag_color_ref",
                         "clear_flag_ref"}
        # And an explicit probe: every forbidden method still explodes.
        for name in ("apply_label", "archive", "delete", "create_draft",
                     "send", "move"):
            with pytest.raises(AssertionError):
                getattr(h.provider, name)()


# --- Overrides lifecycle inside transactions ---------------------------------------------


class TestOverrideLifecycleInTransactions:
    def test_automation_records_state_without_clearing_suppression(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        ref_digest = h.mutations[0].ref_digest
        h.overrides.detect_override(ref_digest, "orange", "gray")
        # Even a successful-looking apply cannot resurrect authority...
        h.overrides.record_automation_state(ref_digest, "red", True)
        assert h.overrides.is_suppressed(ref_digest) is True

    def test_explicit_unlock_clears_and_preflight_resumes(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        ref_digest = h.mutations[0].ref_digest
        h.overrides.detect_override(ref_digest, "orange", "yellow")
        assert h.apply().status == "blocked"
        h.overrides.unlock(ref_digest, actor="human-operator")
        result = h.apply()
        assert result.status == "applied"
        history = h.overrides.list_overrides()[ref_digest]
        assert history["unlock_actor"] == "human-operator"


# --- Rollback: transaction-bound, override-safe, idempotent --------------------------


class TestTransactionBoundRollback:
    def _applied(self, tmp_path, pids=("1",)):
        h = Harness(tmp_path, pids=pids)
        result = h.apply()
        assert result.status == "applied"
        m = h.mutations[0]
        receipt = TransactionRollbackReceipt.create(
            transaction_id=result.verified[0]["transaction_id"],
            plan_sha256=h.plan["plan_hash"],
            approval_sha256=h.approval.content_hash,
            mutation_id=m.mutation_id,
            ref_digest=m.ref_digest,
            pre_native_flag=m.observed_native_flag,
            pre_semantic_flag=m.observed_flag.value,
            applied_native_flag=mailapp_index_from_flag(m.proposed_flag),
            applied_semantic_flag=m.proposed_flag.value,
        )
        return h, m, receipt

    def test_valid_rollback_restores_exact_prior_state(self, tmp_path):
        h, m, receipt = self._applied(tmp_path)
        result = h.rb_engine.rollback_transaction(receipt=receipt,
                                                  provider=h.provider)
        assert result.status == "rolled_back"
        assert result.restored_native_flag == m.observed_native_flag
        live = h.provider.resolve_scoped(
            TransactionEngine._ref_for(m))
        assert int(live.observed_native_flag) == m.observed_native_flag
        latest = h.ledger.latest_status(h.plan["plan_hash"], m.mutation_id)
        assert latest == ST_ROLLED_BACK

    def test_post_rollback_read_failure_is_ambiguous_and_counted(
            self, tmp_path):
        h, m, receipt = self._applied(tmp_path)
        real_resolve = h.provider.resolve_scoped
        resolve_count = 0

        def fail_final_read(ref):
            nonlocal resolve_count
            resolve_count += 1
            if resolve_count == 2:
                raise RuntimeError("readback unavailable")
            return real_resolve(ref)

        h.provider.resolve_scoped = fail_final_read
        result = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )

        assert result.status == "ambiguous"
        assert result.writes_performed == 1
        assert h.provider.messages[m.provider_id].native == \
            m.observed_native_flag
        assert h.ledger.latest_status(
            h.plan["plan_hash"], m.mutation_id
        ) == ST_ROLLBACK_PENDING

        calls_before_retry = len(h.provider.calls)
        retry = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )
        assert retry.status == "blocked"
        assert retry.error_code == "transaction_frozen(rollback_pending)"
        assert retry.writes_performed == 0
        assert len(h.provider.calls) == calls_before_retry

    def test_typed_provider_ambiguity_during_rollback_is_counted(
            self, tmp_path):
        h, m, receipt = self._applied(tmp_path)

        def write_then_lose_proof(ref, color):
            h.provider.messages[ref.provider_id].native = \
                mailapp_index_from_flag(color)
            raise ProviderWriteAmbiguous("verification transport failed")

        h.provider.set_flag_color_ref = write_then_lose_proof
        result = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )

        assert result.status == "ambiguous"
        assert result.writes_performed == 1
        assert h.provider.messages[m.provider_id].native == \
            m.observed_native_flag

    def test_crash_after_rollback_claim_freezes_retry_before_write(
            self, tmp_path):
        h, m, receipt = self._applied(tmp_path)
        dispatches = 0

        def crash_after_dispatch_claim(ref, color):
            nonlocal dispatches
            dispatches += 1
            raise SystemExit("simulated process death")

        h.provider.set_flag_color_ref = crash_after_dispatch_claim
        with pytest.raises(SystemExit, match="simulated process death"):
            h.rb_engine.rollback_transaction(
                receipt=receipt, provider=h.provider
            )
        assert dispatches == 1
        assert h.ledger.latest_status(
            h.plan["plan_hash"], m.mutation_id
        ) == ST_ROLLBACK_PENDING

        retry = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )
        assert retry.status == "blocked"
        assert retry.error_code == "transaction_frozen(rollback_pending)"
        assert retry.writes_performed == 0
        assert dispatches == 1

    def test_post_rollback_ledger_failure_is_ambiguous_and_counted(
            self, tmp_path):
        h, m, receipt = self._applied(tmp_path)
        original_record = h.ledger.record

        def fail_rolled_back_record(record):
            if record.status == ST_ROLLED_BACK:
                raise LedgerCorrupted("simulated rollback fsync failure")
            original_record(record)

        h.ledger.record = fail_rolled_back_record
        result = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )

        assert result.status == "ambiguous"
        assert result.writes_performed == 1
        assert h.provider.messages[m.provider_id].native == \
            m.observed_native_flag
        assert h.ledger.latest_status(
            h.plan["plan_hash"], m.mutation_id
        ) == ST_ROLLBACK_PENDING

    def test_second_rollback_is_zero_write_noop(self, tmp_path):
        h, m, receipt = self._applied(tmp_path)
        first = h.rb_engine.rollback_transaction(receipt=receipt,
                                                 provider=h.provider)
        assert first.status == "rolled_back"
        calls_before = len(h.provider.calls)
        second = h.rb_engine.rollback_transaction(receipt=receipt,
                                                  provider=h.provider)
        assert second.status == "already_rolled_back"
        assert second.writes_performed == 0
        assert len(h.provider.calls) == calls_before

    def test_human_change_after_apply_blocks_rollback(self, tmp_path):
        h, m, receipt = self._applied(tmp_path)
        # Human overrides automation: RED -> YELLOW by hand.
        h.provider.messages[m.provider_id].native = 2      # YELLOW
        result = h.rb_engine.rollback_transaction(receipt=receipt,
                                                  provider=h.provider)
        assert result.status == "rollback_blocked_by_override"
        assert result.writes_performed == 0
        # YELLOW REMAINS — never clobbered back to pre-state.
        live = h.provider.resolve_scoped(TransactionEngine._ref_for(m))
        assert int(live.observed_native_flag) == 2
        assert h.ledger.latest_status(
            h.plan["plan_hash"], m.mutation_id) == ST_ROLLBACK_BLOCKED
        # Detection persisted as suppression.
        assert h.overrides.is_suppressed(m.ref_digest) is True

        # Returning the live color to the automation-applied value does not
        # clear human authority. A retry stays zero-write until explicit
        # unlock.
        h.provider.messages[m.provider_id].native = \
            mailapp_index_from_flag(m.proposed_flag)
        writes_before = len([
            call for call in h.provider.calls
            if call[0] in ("set_flag_color_ref", "clear_flag_ref")
        ])
        suppressed_retry = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )
        assert suppressed_retry.status == "rollback_blocked_by_override"
        assert suppressed_retry.error_code == "human_override_suppressed"
        assert suppressed_retry.writes_performed == 0
        assert len([
            call for call in h.provider.calls
            if call[0] in ("set_flag_color_ref", "clear_flag_ref")
        ]) == writes_before

        h.overrides.unlock(m.ref_digest, actor="human-operator")
        unlocked_retry = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )
        assert unlocked_retry.status == "rolled_back"
        assert unlocked_retry.writes_performed == 1

    def test_human_change_after_rollback_preflight_is_cas_refusal(
            self, tmp_path):
        h, m, receipt = self._applied(tmp_path)
        real_set = h.provider.set_flag_color_ref

        def change_then_dispatch(ref, color):
            # Rollback's live-state gate has passed. A human chooses YELLOW
            # immediately before dispatch; provider CAS must not restore the
            # original ORANGE over that choice.
            h.provider.messages[m.provider_id].native = 2
            return real_set(ref, color)

        h.provider.set_flag_color_ref = change_then_dispatch
        result = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )

        assert result.status == "rollback_blocked_by_override"
        assert result.writes_performed == 0
        assert result.error_code == \
            "human_intervention_detected_at_dispatch"
        assert h.provider.messages[m.provider_id].native == 2
        assert h.overrides.is_suppressed(m.ref_digest) is True
        assert h.ledger.latest_status(
            h.plan["plan_hash"], m.mutation_id
        ) == ST_ROLLBACK_BLOCKED

    def test_tampered_rollback_receipt_rejected(self, tmp_path):
        h, m, receipt = self._applied(tmp_path)
        receipt.applied_native_flag = 9               # mutate AFTER hashing
        with pytest.raises(fw.FlagWorkflowError,
                           match="content_hash mismatch"):
            h.rb_engine.rollback_transaction(receipt=receipt,
                                             provider=h.provider)

    @pytest.mark.parametrize("field,value,error", [
        ("pre_native_flag", True, "must be an integer"),
        ("applied_native_flag", "0", "must be an integer"),
        ("created_at", "not-a-timestamp", "must be an ISO timestamp"),
        ("pre_semantic_flag", "orange-ish", "canonical FlagColor"),
    ])
    def test_rehashed_malformed_rollback_receipt_is_rejected(
            self, tmp_path, field, value, error):
        _, _, receipt = self._applied(tmp_path)
        setattr(receipt, field, value)
        receipt.content_hash = receipt.to_dict()["content_hash"]

        with pytest.raises(fw.FlagWorkflowError, match=error):
            receipt.validate()

    def test_rollback_receipt_create_does_not_coerce_native_flags(
            self, tmp_path):
        h, mutation, _ = self._applied(tmp_path)
        with pytest.raises(fw.FlagWorkflowError, match="must be an integer"):
            TransactionRollbackReceipt.create(
                transaction_id="tx-strict",
                plan_sha256=h.plan["plan_hash"],
                approval_sha256=h.approval.content_hash,
                mutation_id=mutation.mutation_id,
                ref_digest=mutation.ref_digest,
                pre_native_flag=True,
                pre_semantic_flag=mutation.observed_flag.value,
                applied_native_flag=mailapp_index_from_flag(
                    mutation.proposed_flag),
                applied_semantic_flag=mutation.proposed_flag.value,
            )

    def test_transaction_id_path_traversal_is_rejected_before_state_touch(
            self, tmp_path):
        state_dir = tmp_path / "private-state"
        receipt = TransactionRollbackReceipt(
            schema=ROLLBACK_TX_SCHEMA,
            rollback_id="rbx-" + "a" * 32,
            transaction_id="x/../../../escape",
            plan_sha256="b" * 64,
            approval_sha256="c" * 64,
            mutation_id="mut-1",
            ref_digest="d" * 64,
            pre_native_flag=1,
            pre_semantic_flag="orange",
            applied_native_flag=0,
            applied_semantic_flag="red",
            created_at="2026-08-27T12:00:00+00:00",
        )
        receipt.content_hash = receipt.to_dict()["content_hash"]
        engine = ScopedRollbackEngine(
            state_dir,
            TransactionLedger(state_dir / "ledger" / "transactions.jsonl"),
            overrides=None,
            plan={},
        )

        with pytest.raises(fw.FlagWorkflowError, match="transaction_id"):
            engine.rollback_transaction(receipt=receipt, provider=object())

        assert not state_dir.exists()
        assert not (tmp_path / "escap.lock").exists()

    def test_forged_verified_ledger_lineage_cannot_authorize_rollback(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        mutation = h.mutations[0]
        transaction_id = h.engine._txid(
            h.plan["plan_hash"], mutation, h.approval
        )
        h.ledger.record(TransactionRecord(
            transaction_id=transaction_id,
            plan_sha256=h.plan["plan_hash"],
            approval_sha256=h.approval.content_hash,
            mutation_id=mutation.mutation_id,
            ref_digest="f" * 64,
            pre_state=mutation.observed_flag.value,
            intended_state=mutation.proposed_flag.value,
            verified_post_state=mutation.proposed_flag.value,
            timestamp="2026-08-27T12:00:00+00:00",
            status=ST_VERIFIED,
        ))
        h.provider.messages[mutation.provider_id].native = \
            mailapp_index_from_flag(mutation.proposed_flag)
        receipt = TransactionRollbackReceipt.create(
            transaction_id=transaction_id,
            plan_sha256=h.plan["plan_hash"],
            approval_sha256=h.approval.content_hash,
            mutation_id=mutation.mutation_id,
            ref_digest=mutation.ref_digest,
            pre_native_flag=mutation.observed_native_flag,
            pre_semantic_flag=mutation.observed_flag.value,
            applied_native_flag=mailapp_index_from_flag(
                mutation.proposed_flag
            ),
            applied_semantic_flag=mutation.proposed_flag.value,
        )
        h.provider.calls.clear()

        result = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )

        assert result.status == "blocked"
        assert result.error_code == \
            "receipt_lineage_mismatch:ledger_ref_digest"
        assert result.writes_performed == 0
        assert h.provider.calls == []

    def test_rollback_on_unverified_transaction_refused(self, tmp_path):
        h, m, receipt = self._applied(tmp_path)
        # Forge ledger state: pretend this was never verified.
        entries = h.ledger.entries()
        h.ledger.path.write_text("".join(
            json.dumps(dict(e, status="blocked"), sort_keys=True) + "\n"
            for e in entries))
        result = h.rb_engine.rollback_transaction(receipt=receipt,
                                                  provider=h.provider)
        assert result.status == "blocked"
        assert result.writes_performed == 0

    def test_rolled_back_item_blocks_and_enumerates_pending_sibling(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1", "2"))
        second_pid = h.by_pid("2").provider_id
        real_set = FakeScopedProvider.set_flag_color_ref

        def fail_second(ref, color):
            if ref.provider_id == second_pid:
                raise RuntimeError("pre-dispatch refusal")
            return real_set(h.provider, ref, color)

        h.provider.set_flag_color_ref = fail_second
        applied = h.apply()
        assert len(applied.verified) == 1
        first = h.by_pid("1")
        receipt = TransactionRollbackReceipt.create(
            transaction_id=applied.verified[0]["transaction_id"],
            plan_sha256=h.plan["plan_hash"],
            approval_sha256=h.approval.content_hash,
            mutation_id=first.mutation_id,
            ref_digest=first.ref_digest,
            pre_native_flag=first.observed_native_flag,
            pre_semantic_flag=first.observed_flag.value,
            applied_native_flag=mailapp_index_from_flag(
                first.proposed_flag
            ),
            applied_semantic_flag=first.proposed_flag.value,
        )
        h.provider.set_flag_color_ref = lambda ref, color: real_set(
            h.provider, ref, color
        )
        rolled_back = h.rb_engine.rollback_transaction(
            receipt=receipt, provider=h.provider
        )
        assert rolled_back.status == "rolled_back"

        result = h.apply()

        assert result.status == "blocked"
        assert result.writes_performed == 0
        assert result.failed == [{
            "mutation_id": first.mutation_id,
            "error_code": "previously_rolled_back",
        }]
        assert result.unattempted == [{
            "mutation_id": h.by_pid("2").mutation_id,
        }]
        assert h.ledger.latest_status(
            h.plan["plan_hash"], h.by_pid("2").mutation_id
        ) == ST_FROZEN_UNATTEMPTED


# --- Private-state hygiene + gates ------------------------------------------------------


class TestPrivateStateAndGates:
    def test_private_material_permissions_enforced(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        h.apply()

        def mode(p):
            return stat.S_IMODE(os.stat(p).st_mode)

        assert mode(h.ledger.path) == 0o600
        assert mode(h.ledger.path.parent) == 0o700
        locks_dir = h.state_dir / "locks"
        assert mode(locks_dir) == 0o700
        assert mode(h.overrides.path) == 0o600

    def test_public_plan_projection_stays_pii_free_with_new_field(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        pub = fw.to_public_safe_plan(h.plan)
        blob = json.dumps(pub)
        for secret in ('"acct"', '"INBOX"', '"provider_id"',
                       '"evidence_digest"', 'billing@'):
            assert secret not in blob
        assert pub["mutations"][0]["auto_eligible"] is True
        fw.validate_public_plan(pub)

    def test_cli_apply_and_rollback_remain_not_ready_89(self, capsys):
        for handler, attr in (("cmd_flags_apply", "plan"),
                              ("cmd_flags_rollback", "receipt")):
            args = SimpleNamespace(provider="mailapp")
            setattr(args, attr, "/nonexistent")
            rc = getattr(cli, handler)(args)
            assert rc == 89, handler
            assert "NOT_READY" in capsys.readouterr().err
