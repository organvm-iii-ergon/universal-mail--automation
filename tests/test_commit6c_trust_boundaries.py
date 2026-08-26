"""Commit 6c acceptance: transaction trust boundaries.

FIX 1 — the engine itself invokes the canonical ApprovalReceipt.validate()
        against the actual plan/mutations INSIDE the lock, before ledger
        checks, preflight, claims, or any provider contact.
FIX 2 — rollback receipts are LINEAGE-BOUND: correctly re-hashed forgeries
        are refused because every field must match the authoritative
        verified ledger record + immutable PlannedMutation. The write
        target and current-state gate are DERIVED from plan truth, never
        from receipt assertions.
"""

import pytest

from core.flag_transactions import (
    TransactionRollbackReceipt,
)
from providers.mailapp import mailapp_index_from_flag

from tests.test_commit6_transactions import (
    Harness,
)
import core.flag_workflow as fw


def _provider_calls(h):
    return len(h.provider.calls)


# --- FIX 1: invalid approvals die at the engine, before ANY provider call ------


class TestEngineValidatesApproval:
    def _attempt(self, tmp_path, mutate=None, build_other_plan=False):
        h = Harness(tmp_path, pids=("1",))
        approval = h.approval
        if mutate is not None:
            mutate(h, approval)
        calls_before = _provider_calls(h)          # always 0 here
        result = h.engine.apply_transaction(
            plan=dict(h.plan), approval=approval, provider=h.provider)
        assert result.status == "blocked"
        assert result.error_code.startswith("approval_invalid")
        assert result.writes_performed == 0
        # ZERO provider interaction of ANY kind (not even resolves).
        assert len(h.provider.calls) == calls_before == 0
        # NO misleading lifecycle rows — a rejected approval leaves the
        # ledger EMPTY.
        assert h.ledger.entries() == [], \
            "invalid approval must not create transaction state"
        return h, result

    def test_tampered_content_hash(self, tmp_path):
        def mutate(h, a):
            a.canary_limit = 9                      # after hashing
        self._attempt(tmp_path, mutate)

    def test_expired(self, tmp_path):
        from datetime import datetime, timedelta, timezone
        now = datetime.now(timezone.utc)

        def mutate(h, a):
            a.issued_at = (now - timedelta(hours=2)).isoformat()
            a.expires_at = (now - timedelta(seconds=1)).isoformat()
            a.content_hash = a.to_dict()["content_hash"]
        self._attempt(tmp_path, mutate)

    def test_wrong_plan_hash(self, tmp_path):
        def mutate(h, a):
            other = fw.build_plan(h.snapshot)       # different snapshot_id →
            a.plan_hash = "f" * 64                  # simulate cross-plan use
            a.content_hash = a.to_dict()["content_hash"]
            del other
        self._attempt(tmp_path, mutate)

    def test_wrong_snapshot_sha256(self, tmp_path):
        def mutate(h, a):
            a.snapshot_sha256 = "e" * 64
            a.content_hash = a.to_dict()["content_hash"]
        self._attempt(tmp_path, mutate)

    def test_wrong_policy_sha256(self, tmp_path):
        def mutate(h, a):
            a.policy_sha256 = "0" * 64
            a.content_hash = a.to_dict()["content_hash"]
        self._attempt(tmp_path, mutate)

    def test_duplicate_approved_ids(self, tmp_path):
        def mutate(h, a):
            mid = a.approved_mutation_ids[0]
            a.approved_mutation_ids = [mid, mid]
            a.content_hash = a.to_dict()["content_hash"]
        self._attempt(tmp_path, mutate)

    def test_absent_approved_id(self, tmp_path):
        def mutate(h, a):
            a.approved_mutation_ids = ["mut-doesnotexist"]
            a.content_hash = a.to_dict()["content_hash"]
        self._attempt(tmp_path, mutate)

    @pytest.mark.parametrize("bad_limit", [0, 11])
    def test_canary_bounds(self, tmp_path, bad_limit):
        def mutate(h, a):
            object.__setattr__(a, "canary_limit", bad_limit)
            a.content_hash = a.to_dict()["content_hash"]
        self._attempt(tmp_path, mutate)

    def test_ineligible_target_review_required(self, tmp_path):
        """Commit 6d: ineligibility must live in the PLAN BYTES. A detached
        mutated object is simply ignored — so forge the artifact instead
        (serialized review_required=True + recomputed hash); the canonical
        validator refuses at the approval boundary."""
        h = Harness(tmp_path, pids=("1",))
        muts = [dict(m, review_required=True)
                for m in h.plan["mutations"]]
        forged = dict(h.plan, mutations=muts)
        forged.pop("plan_hash")
        forged["plan_hash"] = fw.compute_plan_hash(forged)
        approval = fw.ApprovalReceipt.create(
            plan_hash=forged["plan_hash"],
            snapshot_sha256=forged["snapshot_sha256"],
            policy_sha256=forged["policy_sha256"],
            approved_mutation_ids=[
                m["mutation_id"] for m in forged["mutations"]],
            approving_operator="attacker", canary_limit=1)
        result = h.engine.apply_transaction(
            plan=dict(forged), approval=approval, provider=h.provider)
        assert result.status == "blocked"
        # Refused at one of the two pre-provider boundaries: parse-time
        # structural invariant OR canonical approval validation.
        assert result.error_code.startswith(
            ("approval_invalid", "plan_invalid")), result.error_code
        assert "review_required" in result.error_code
        assert result.writes_performed == 0
        assert h.provider.calls == []
        assert h.ledger.entries() == []

    def test_valid_approval_still_applies_after_matrix(self, tmp_path):
        """Guard: the validation gate didn't over-refuse legit artifacts."""
        h = Harness(tmp_path, pids=("1",))
        result = h.apply()
        assert result.status == "applied"
        assert _provider_calls(h) > 0


# --- FIX 2: forged-but-correctly-hashed receipts are lineage-refused ------------


class TestRollbackLineageBinding:
    def _applied_harness(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
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
            applied_semantic_flag=m.proposed_flag.value)
        calls_before = _provider_calls(h)
        return h, m, receipt, calls_before

    def _forged(self, tmp_path, field, value):
        """Freshly created receipt with ONE field replaced and its hash
        RECOMPUTED CORRECTLY — pure provenance forgery, no byte tampering."""
        h, m, receipt, calls_before = self._applied_harness(tmp_path)
        setattr(receipt, field, value)
        receipt.content_hash = receipt.to_dict()["content_hash"]   # valid!
        result = h.rb_engine.rollback_transaction(receipt=receipt,
                                                  provider=h.provider)
        assert result.status == "blocked", field
        assert result.error_code.startswith("receipt_lineage_mismatch"), field
        assert result.error_code.endswith(field)
        assert result.writes_performed == 0
        assert _provider_calls(h) == calls_before, field   # ZERO provider calls
        return h

    def test_forged_pre_native_with_valid_hash_refused(self, tmp_path):
        self._forged(tmp_path, "pre_native_flag", 4)          # claims BLUE pre-state

    def test_forged_pre_semantic_with_valid_hash_refused(self, tmp_path):
        self._forged(tmp_path, "pre_semantic_flag", "blue")

    def test_forged_applied_native_with_valid_hash_refused(self, tmp_path):
        self._forged(tmp_path, "applied_native_flag", 5)

    def test_forged_applied_semantic_with_valid_hash_refused(self, tmp_path):
        self._forged(tmp_path, "applied_semantic_flag", "purple")

    def test_forged_transaction_id_with_valid_hash_refused(self, tmp_path):
        self._forged(tmp_path, "transaction_id", "tx-forged-000000000000")

    def test_forged_approval_sha256_with_valid_hash_refused(self, tmp_path):
        self._forged(tmp_path, "approval_sha256", "a" * 64)

    def test_forged_ref_digest_with_valid_hash_refused(self, tmp_path):
        self._forged(tmp_path, "ref_digest", "b" * 64)

    def test_legitimate_receipt_rolls_back_exactly_once(self, tmp_path):
        h, m, receipt, _ = self._applied_harness(tmp_path)
        rb1 = h.rb_engine.rollback_transaction(receipt=receipt,
                                               provider=h.provider)
        assert rb1.status == "rolled_back"
        assert rb1.restored_native_flag == m.observed_native_flag
        rb2 = h.rb_engine.rollback_transaction(receipt=receipt,
                                               provider=h.provider)
        assert rb2.status == "already_rolled_back"
        assert rb2.writes_performed == 0

    def test_rollback_write_target_derived_not_asserted(self, tmp_path):
        """Even for a LEGIT receipt, the restored color comes from the
        plan's observed_flag — prove by succeeding and checking native."""
        h, m, receipt, _ = self._applied_harness(tmp_path)
        rb = h.rb_engine.rollback_transaction(receipt=receipt,
                                              provider=h.provider)
        live = h.provider.resolve_scoped(
            __import__("core.flag_transactions",
                       fromlist=["TransactionEngine"]).TransactionEngine
            ._ref_for(m))
        assert int(live.observed_native_flag) == m.observed_native_flag
        assert rb.status == "rolled_back"

    def test_lineage_mismatch_records_blocked_row_only(self, tmp_path):
        """Audit trail: exactly one rollback_blocked row, nothing else new."""
        h = self._forged(tmp_path, "pre_native_flag", 6)
        rows = [e for e in h.ledger.entries()
                if e["status"] == "rollback_blocked"]
        assert len(rows) == 1
        assert rows[0]["error_code"] == \
            "receipt_lineage_mismatch:pre_native_flag"
