"""Commit 6d acceptance: executable mutations are DERIVED from the
validated plan inside the engine — detached objects cannot become
execution authority.

The preferred design is implemented: apply_transaction() and
ScopedRollbackEngine take NO authoritative mutation list. Parsing happens
from the hash-committed artifact under the lock, so a caller-supplied
PlannedMutation with an altered field is not merely refused — it is
STRUCTURALLY IGNORED.
"""

import pytest

import core.flag_workflow as fw
from core.flag_transactions import (
    ScopedRollbackEngine,
    TransactionEngine,
    TransactionRollbackReceipt,
)
from core.models import FlagColor
from providers.mailapp import mailapp_index_from_flag

from tests.test_commit6_transactions import (
    Harness,
)

# Every execution-relevant field a detached object could lie about.
DETACHED_FIELDS = [
    "proposed_flag", "observed_flag", "account", "mailbox", "provider_id",
    "evidence_digest", "observed_native_flag", "snapshot_id", "ref_digest",
    "auto_eligible", "review_required",
]


def _gross_tamper(m, field):
    """Set a blatantly different value for any detachable field."""
    if field == "proposed_flag":
        object.__setattr__(m, field, FlagColor.GREEN)
    elif field == "observed_flag":
        object.__setattr__(m, field, FlagColor.PURPLE)
    elif field in ("account",):
        object.__setattr__(m, field, "evil-account")
    elif field == "mailbox":
        object.__setattr__(m, field, "evil-mailbox")
    elif field == "provider_id":
        object.__setattr__(m, field, "999999")
    elif field == "evidence_digest":
        object.__setattr__(m, field, "c" * 64)
    elif field == "observed_native_flag":
        object.__setattr__(m, field, 6)
    elif field == "snapshot_id":
        object.__setattr__(m, field, "snap-forged")
    elif field == "ref_digest":
        object.__setattr__(m, field, "d" * 64)
    elif field == "auto_eligible":
        object.__setattr__(m, field, False)
    elif field == "review_required":
        object.__setattr__(m, field, True)


class TestMutationsDerivedFromPlan:
    def test_engine_signature_has_no_mutations_parameter(self):
        """API closure: there is no authoritative mutations= argument to
        abuse."""
        import inspect
        sig = inspect.signature(
            TransactionEngine.apply_transaction)
        assert "mutations" not in sig.parameters
        assert "plan" in sig.parameters and "approval" in sig.parameters
        rb_sig = inspect.signature(ScopedRollbackEngine.__init__)
        assert "mutations" not in rb_sig.parameters
        assert "plan" in rb_sig.parameters

    @pytest.mark.parametrize("field", DETACHED_FIELDS)
    def test_detached_object_fields_are_structurally_ignored(
            self, tmp_path, field):
        """Tamper EVERY listed field on the caller-held parsed objects;
        the engine re-parses from plan bytes, so execution follows the
        PLAN values and succeeds exactly as an untampered run."""
        h = Harness(tmp_path, pids=("1",))
        # Hand the engine's callers a fully poisoned mutation object.
        _gross_tamper(h.mutations[0], field)

        result = h.apply()

        assert result.status == "applied", (field, result.failed)
        assert result.writes_performed == 1
        # The write used the PLAN's proposed flag, not the tampered one.
        m_plan = fw.validate_plan_schema(h.plan)[0]
        expected_native = mailapp_index_from_flag(m_plan.proposed_flag)
        set_calls = [c for c in h.provider.calls
                     if c[0] == "set_flag_color_ref"]
        assert len(set_calls) == 1
        live = h.provider.resolve_scoped(
            h.engine._ref_for(m_plan))
        assert int(live.observed_native_flag) == expected_native
        assert live.evidence_digest == m_plan.evidence_digest

    def test_rollback_mutation_truth_also_derived(self, tmp_path):
        """Rollback scope reconstruction parses from the bound plan; a
        tampered external list does not exist and a tampered PLAN COPY is
        refused on integrity before anything runs."""
        h = Harness(tmp_path, pids=("1",))
        result = h.apply()
        assert result.status == "applied"
        m = h.mutations[0]                       # parsed earlier by harness
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

        # An attacker builds a rogue engine over a MUTATED plan copy with a
        # correctly recomputed hash — but the receipt binds the ORIGINAL
        # plan hash, so lineage refuses before provider contact.
        rogue_plan = dict(h.plan)
        rogue_muts = [dict(mm.to_dict(), proposed_flag="green")
                      for mm in h.mutations]
        rogue_plan["mutations"] = rogue_muts
        rogue_plan.pop("plan_hash")
        rogue_plan["plan_hash"] = fw.compute_plan_hash(rogue_plan)
        calls_before = len(h.provider.calls)
        rogue_engine = ScopedRollbackEngine(
            h.state_dir, h.ledger, h.overrides, rogue_plan)
        rb = rogue_engine.rollback_transaction(receipt=receipt,
                                               provider=h.provider)
        assert rb.status == "blocked"
        assert rb.error_code.startswith("receipt_lineage_mismatch")
        assert rb.writes_performed == 0
        assert len(h.provider.calls) == calls_before

    def test_positive_guard_valid_plan_still_applies(self, tmp_path):
        """The derivation path preserves the happy path end-to-end."""
        h = Harness(tmp_path, pids=("1", "2"))
        result = h.apply()
        assert result.status == "applied"
        assert result.writes_performed == 2
        for e in h.ledger.entries():
            if e["status"] == "verified":
                assert e["verified_post_state"]

    def test_rogue_rollback_plan_with_matching_hash_still_safe(
            self, tmp_path):
        """Even a forged plan whose hash MATCHES the receipt cannot help:
        its parsed mutations carry a different mutation_id (id binds full
        context), so the receipt lineage lookup misses → refused."""
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

        rogue_plan = dict(h.plan)
        rogue_muts = [dict(mm, proposed_flag="green", reason="forged")
                      for mm in h.plan["mutations"]]
        rogue_plan["mutations"] = rogue_muts
        rogue_plan.pop("plan_hash")
        rogue_plan["plan_hash"] = fw.compute_plan_hash(rogue_plan)
        # Force the receipt's plan_sha256 to match the ROGUE artifact and
        # re-hash the receipt too (full provenance forgery):
        receipt.plan_sha256 = rogue_plan["plan_hash"]
        receipt.content_hash = receipt.to_dict()["content_hash"]
        calls_before = len(h.provider.calls)
        rogue_engine = ScopedRollbackEngine(
            h.state_dir, h.ledger, h.overrides, rogue_plan)
        rb = rogue_engine.rollback_transaction(receipt=receipt,
                                               provider=h.provider)
        # The ledger's authoritative record still carries the ORIGINAL
        # plan/approval hashes — lineage must refuse.
        assert rb.status == "blocked"
        assert rb.writes_performed == 0
        assert len(h.provider.calls) == calls_before
