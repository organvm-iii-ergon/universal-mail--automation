"""Commit 6b acceptance: P0 transaction-bug regressions.

FIX 1 — native index 0 (RED) is a VALID observation; truthiness must never
        treat it as missing.
FIX 2 — idempotent replay is an EVENT; it can never erase authoritative
        verified state or rollback eligibility.
FIX 3 — pre-existing loose private dirs/files are re-hardened on every use.
"""

import os
import stat

import pytest

from core.flag_transactions import (
    ST_ALREADY_VERIFIED,
    ST_VERIFIED,
    TransactionLedger,
    TransactionRollbackReceipt,
)
from core.models import FlagColor
from providers.mailapp import mailapp_index_from_flag

from tests.test_commit6_transactions import (
    ELIG_SUBJECT,
    FakeMessage,
    FakeScopedProvider,
    Harness,
    _row,
)
import core.flag_workflow as fw


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


# --- FIX 1: every native observation -1..6 passes matching preflight ----------


class TestNativeZeroIsValid:
    @staticmethod
    def _forced_eligible_plan(plan):
        """Commit 6d doctrine: executable mutations come FROM the plan.
        To exercise the native matrix for every observed color, force
        structural eligibility in the SERIALIZED plan and recommit the
        hash — a self-consistent artifact the engine parses itself."""
        muts = [dict(m, auto_eligible=True, review_required=False)
                for m in plan["mutations"]]
        out = dict(
            plan,
            mutations=muts,
            auto_eligible_count=sum(
                mutation["auto_eligible"] for mutation in muts
            ),
        )
        out.pop("plan_hash")
        out["plan_hash"] = fw.compute_plan_hash(out)
        return out

    @staticmethod
    def _subject_for(observed: FlagColor) -> str:
        """A subject whose classifier target DIFFERS from `observed`, so
        the plan always contains a real (non-identity) mutation."""
        if observed is FlagColor.RED:
            # ELIG targets RED; RED observations need a different target.
            return "Please choose an interview slot"
        return ELIG_SUBJECT                        # targets RED

    @pytest.mark.parametrize("native,semantic", [
        (-1, FlagColor.NO_FLAG),
        (0, FlagColor.RED),
        (1, FlagColor.ORANGE),
        (2, FlagColor.YELLOW),
        (3, FlagColor.GREEN),
        (4, FlagColor.BLUE),
        (5, FlagColor.PURPLE),
        (6, FlagColor.GRAY),
    ])
    def test_matching_native_preflight_succeeds(self, tmp_path, native,
                                                semantic):
        """Build a plan whose observed state is `semantic`, set the live
        provider to the SAME native index — preflight must pass and the
        write must proceed. RED=0 is THE regression case."""
        snap = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=[_row("1", color=semantic,
                       subject=self._subject_for(semantic))],
            complete=True, scope_complete=True,
            status="complete", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=0, limit=500,
            since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0)
        plan = fw.build_plan(snap)
        plan = self._forced_eligible_plan(plan)
        mutations = fw.validate_plan_schema(plan)
        assert mutations, f"expected a non-identity mutation for {semantic}"
        assert all(m.auto_eligible and not m.review_required
                   for m in mutations)
        approval = fw.ApprovalReceipt.create(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=plan["snapshot_sha256"],
            policy_sha256=plan["policy_sha256"],
            approved_mutation_ids=[m.mutation_id for m in mutations],
            approving_operator="operator",
            canary_limit=max(1, len(mutations)))
        # Live provider EXACTLY at the observed native index AND with
        # evidence matching the plan (same sender/subject as the row).
        provider = FakeScopedProvider([
            FakeMessage(m.provider_id, native,
                        subject=self._subject_for(semantic))
            for m in mutations])
        overrides = fw.OverrideStore(tmp_path / "o.json")
        engine = __import__("core.flag_transactions",
                            fromlist=["TransactionEngine"]).TransactionEngine(
                                tmp_path / "state",
                                TransactionLedger(
                                    tmp_path / "state" / "l.jsonl"),
                                overrides)
        result = engine.apply_transaction(
            plan=dict(plan), approval=approval,
            provider=provider)
        assert result.status == "applied", (
            f"native={native} ({semantic.value}): {result.failed}")
        assert result.writes_performed == len(mutations)

    def test_red_zero_reaches_successful_apply_end_to_end(self, tmp_path):
        """THE P0: legacy RED (native 0) must migrate, not drift-block."""
        snap = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=[_row("1", color=FlagColor.RED,
                       subject=self._subject_for(FlagColor.RED))],
            complete=True, scope_complete=True, status="complete",
            errors=[], inaccessible_count=0, timeout_count=0,
            unknown_index_count=0, limit=500, since_days=None,
            total_matched=1, returned_count=1, hidden_by_limit=0)
        plan = fw.build_plan(snap)
        plan = self._forced_eligible_plan(plan)
        muts = fw.validate_plan_schema(plan)
        assert muts, "RED fixture must produce a non-identity mutation"
        approval = fw.ApprovalReceipt.create(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=plan["snapshot_sha256"],
            policy_sha256=plan["policy_sha256"],
            approved_mutation_ids=[x.mutation_id for x in muts],
            approving_operator="operator",
            canary_limit=len(muts))
        provider = FakeScopedProvider([
            FakeMessage(x.provider_id, 0,     # RED == 0
                        subject=self._subject_for(FlagColor.RED))
            for x in muts])
        overrides = fw.OverrideStore(tmp_path / "o.json")
        engine = __import__(
            "core.flag_transactions",
            fromlist=["TransactionEngine"]).TransactionEngine(
                tmp_path / "state", TransactionLedger(
                    tmp_path / "state" / "l.jsonl"), overrides)
        result = engine.apply_transaction(
            plan=dict(plan), approval=approval,
            provider=provider)
        assert result.status == "applied"
        assert "native_flag_drift" not in [
            f.get("error_code") for f in result.failed]
        write_calls = [c for c in provider.calls
                       if c[0] == "set_flag_color_ref"]
        assert len(write_calls) == 1

    def test_missing_bound_native_flag_refused(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        h.plan = h.engine and self.__class__._forced_eligible_plan(h.plan)
        # Strip the bound native index IN THE PLAN ARTIFACT itself.
        muts = [dict(m, observed_native_flag=None)
                for m in h.plan["mutations"]]
        h.plan = dict(h.plan, mutations=muts)
        h.plan.pop("plan_hash")
        h.plan["plan_hash"] = fw.compute_plan_hash(h.plan)
        # Strict artifact validation refuses the incoherent native/semantic
        # pair before approval or provider construction.
        with pytest.raises(fw.FlagWorkflowError, match="native"):
            fw.validate_plan_schema(h.plan)
        assert h.provider.calls == []

    def test_live_native_unavailable_refused(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        pid = h.mutations[0].provider_id
        h.provider.messages[pid].native = None
        result = h.apply()
        assert result.status == "blocked"
        assert result.failed[0]["error_code"] == "native_flag_unavailable"


# --- FIX 2: replay events never corrupt authority -------------------------------


class TestIdempotencyAuthority:
    def test_apply_x10_exactly_one_provider_write_total(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        statuses = []
        for i in range(10):
            result = h.apply()
            statuses.append(result.status)
            if i == 0:
                assert result.status == "applied"
                assert result.writes_performed == 1
            else:
                assert result.status == "already_applied", i
                assert result.writes_performed == 0, i
        write_calls = [c for c in h.provider.calls
                       if c[0] in ("set_flag_color_ref", "clear_flag_ref")]
        assert len(write_calls) == 1          # EXACTLY ONE, ever
        assert h.ledger.has_verified(h.plan["plan_hash"],
                                     h.mutations[0].mutation_id)

    def test_replay_preserves_rollback_eligibility(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        h.apply()
        for _ in range(5):                    # arbitrary replay storm
            assert h.apply().status == "already_applied"
        verified_pool = h.ledger.verified_transactions(h.plan["plan_hash"])
        assert [e["mutation_id"] for e in verified_pool] == \
            [h.mutations[0].mutation_id]
        assert h.ledger.authoritative_state(
            h.plan["plan_hash"], h.mutations[0].mutation_id) == ST_VERIFIED

    def test_rollback_after_replay_succeeds_exactly_once(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        first = h.apply()
        for _ in range(3):
            h.apply()                          # replays
        m = h.mutations[0]
        receipt = TransactionRollbackReceipt.create(
            transaction_id=first.verified[0]["transaction_id"],
            plan_sha256=h.plan["plan_hash"],
            approval_sha256=h.approval.content_hash,
            mutation_id=m.mutation_id,
            ref_digest=m.ref_digest,
            pre_native_flag=m.observed_native_flag,
            pre_semantic_flag=m.observed_flag.value,
            applied_native_flag=mailapp_index_from_flag(m.proposed_flag),
            applied_semantic_flag=m.proposed_flag.value)
        rb = h.rb_engine.rollback_transaction(receipt=receipt,
                                              provider=h.provider)
        assert rb.status == "rolled_back"
        assert rb.writes_performed == 1
        again = h.rb_engine.rollback_transaction(receipt=receipt,
                                                 provider=h.provider)
        assert again.status == "already_rolled_back"
        assert again.writes_performed == 0
        calls_now = [c for c in h.provider.calls
                     if c[0] in ("set_flag_color_ref", "clear_flag_ref")]
        assert len(calls_now) == 2             # apply + one rollback only

    def test_post_rollback_apply_is_deterministically_refused(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        first = h.apply()
        m = h.mutations[0]
        receipt = TransactionRollbackReceipt.create(
            transaction_id=first.verified[0]["transaction_id"],
            plan_sha256=h.plan["plan_hash"],
            approval_sha256=h.approval.content_hash,
            mutation_id=m.mutation_id,
            ref_digest=m.ref_digest,
            pre_native_flag=m.observed_native_flag,
            pre_semantic_flag=m.observed_flag.value,
            applied_native_flag=mailapp_index_from_flag(m.proposed_flag),
            applied_semantic_flag=m.proposed_flag.value)
        h.rb_engine.rollback_transaction(receipt=receipt,
                                         provider=h.provider)
        result = h.apply()
        # Rolled-back ≠ currently applied: re-running an undone migration
        # requires a NEW plan/approval cycle.
        assert result.status == "blocked"
        assert result.error_code == "previously_rolled_back"
        assert result.writes_performed == 0

    def test_event_rows_do_not_poison_authority(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        h.apply()
        h.apply()
        h.apply()
        raw_statuses = [e["status"] for e in h.ledger.entries()]
        assert ST_ALREADY_VERIFIED in raw_statuses       # events recorded
        # …and yet authority still reads verified:
        assert h.ledger.authoritative_state(
            h.plan["plan_hash"], h.mutations[0].mutation_id) == ST_VERIFIED


# --- FIX 3: pre-existing loose private files are re-hardened ---------------------


class TestRehardenPrivateState:
    def test_preexisting_loose_ledger_and_dir_hardened(self, tmp_path):
        ledger_path = tmp_path / "loose" / "transactions.jsonl"
        ledger_path.parent.mkdir(parents=True)
        ledger_path.write_text("")                    # exists but empty
        os.chmod(ledger_path, 0o644)
        os.chmod(ledger_path.parent, 0o755)

        ledger = TransactionLedger(ledger_path)
        from core.flag_transactions import TransactionRecord
        ledger.record(TransactionRecord(
            transaction_id="tx-" + "a" * 24,
            plan_sha256=fw.sha256_hex("p"),
            approval_sha256=fw.sha256_hex("a"),
            mutation_id="mut-" + "b" * 24,
            ref_digest=fw.sha256_hex("r"), pre_state=None,
            intended_state="red", verified_post_state=None,
            timestamp="2026-08-26T00:00:00+00:00", status="prepared"))
        assert _mode(ledger_path) == 0o600
        assert _mode(ledger_path.parent) == 0o700

    def test_preexisting_loose_lock_and_state_dir_hardened(self, tmp_path):
        from core.flag_transactions import AdvisoryFileLock
        lock_path = tmp_path / "locks" / "apply-abc.lock"
        lock_path.parent.mkdir(parents=True)
        lock_path.write_text("")
        os.chmod(lock_path, 0o644)
        os.chmod(lock_path.parent, 0o755)
        with AdvisoryFileLock(lock_path):
            pass
        assert _mode(lock_path) == 0o600
        assert _mode(lock_path.parent) == 0o700

    def test_engine_run_hardens_preexisting_loose_state_tree(self, tmp_path):
        """Full engine flow over a 0755/0644 pre-existing tree."""
        h = Harness(tmp_path, pids=("1",))
        state = h.state_dir
        state.mkdir(parents=True, exist_ok=True)
        os.chmod(state, 0o755)
        (state / "ledger").mkdir(exist_ok=True)
        os.chmod(state / "ledger", 0o755)
        ledger_file = state / "ledger" / "transactions.jsonl"
        ledger_file.touch()
        os.chmod(ledger_file, 0o644)
        (state / "locks").mkdir(exist_ok=True)
        os.chmod(state / "locks", 0o755)
        lock_file = state / "locks" / \
            f"apply-{h.plan['plan_hash'][:16]}.lock"
        lock_file.touch()
        os.chmod(lock_file, 0o644)

        result = h.apply()
        assert result.status == "applied"
        assert _mode(ledger_file) == 0o600
        assert _mode(ledger_file.parent) == 0o700
        assert _mode(lock_file) == 0o600
        assert _mode(lock_file.parent) == 0o700
        assert _mode(state) == 0o700                  # engine root hardened

    def test_preexisting_loose_override_store_hardened(self, tmp_path):
        store_path = tmp_path / "overrides.json"
        store_path.write_text(
            '{"last_automation": {}, "overrides": {}, "suppressed": {}}'
        )
        os.chmod(store_path, 0o644)
        os.chmod(tmp_path, 0o755)
        store = fw.OverrideStore(store_path)
        store.detect_override(fw.sha256_hex("r"), "orange", "yellow")
        assert _mode(store_path) == 0o600
        assert _mode(tmp_path) == 0o700
