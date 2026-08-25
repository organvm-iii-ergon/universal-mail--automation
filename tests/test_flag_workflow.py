"""Tests for core.flag_workflow — hashing, schemas, snapshots, plans,
approvals, ledger, overrides, rollback receipts (Commit 3 extraction)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from core.models import FlagColor
from core import flag_workflow as fw
from core.flag_policy import (
    MIGRATION_POLICY_VERSION,
    propose,
    RC_CAREER_SIGNAL_ORANGE,
    RC_AMBIGUOUS_PURPLE,
)


def _msg(provider_id="1", sender="a@b.com", subject="Hi",
         color=FlagColor.RED, account="acct", mailbox="INBOX"):
    return fw.SnapshotMessage(
        provider="mailapp", account=account, mailbox=mailbox,
        provider_id=provider_id, sender=sender, subject=subject,
        native_index=None, observed_flag=color, received_iso=None,
    )


def _snapshot(messages, complete=True):
    snap = fw.FlagSnapshot(
        schema=fw.SNAPSHOT_SCHEMA, snapshot_id="snap-test",
        generated_at=datetime.now(timezone.utc).isoformat(),
        provider="mailapp", account="acct", mailbox="INBOX",
        complete=complete, status="complete" if complete else "partial",
        zero_write_mode=True, errors=[],
        inaccessible_count=0, timeout_count=0, unknown_index_count=0,
        total_flagged_seen=len(messages), hidden_by_limit=0,
        messages=list(messages), content_hash="",
    )
    snap.content_hash = snap.to_dict()["content_hash"]
    return snap


class TestCanonicalHashing:
    def test_deterministic_and_order_insensitive(self):
        a = {"x": 1, "y": [2, 3]}
        b = {"y": [2, 3], "x": 1}
        assert fw.sha256_hex(a) == fw.sha256_hex(b)

    def test_full_64_hex(self):
        digest = fw.sha256_hex({"anything": True})
        assert len(digest) == 64
        assert set(digest) <= set("0123456789abcdef")

    def test_require_hex256_rejects_truncated(self):
        with pytest.raises(fw.FlagWorkflowError, match="full 64-char"):
            fw.require_hex256("abc123", "field")

    def test_plan_hash_excludes_itself(self):
        plan = {"schema": "x", "plan_hash": "PLACEHOLDER", "n": 1}
        h = fw.compute_plan_hash(plan)
        assert h == fw.compute_plan_hash({**plan, "plan_hash": "OTHER"})
        assert len(h) == 64


class TestSnapshotModel:
    def test_content_hash_changes_with_content(self):
        s1 = _snapshot([_msg(subject="A")])
        s2 = _snapshot([_msg(subject="B")])
        d1, d2 = s1.to_dict(), s2.to_dict()
        assert d1["content_hash"] != d2["content_hash"]
        assert len(d1["content_hash"]) == 64

    def test_public_safe_strips_pii(self):
        snap = _snapshot([
            _msg("11", "secret@corp.example", "Classified Subject X"),
        ])
        public = snap.to_public_safe()
        blob = json.dumps(public)
        assert "secret@corp.example" not in blob
        assert "Classified Subject X" not in blob
        assert "provider_id" not in blob          # raw id stripped
        # ref digests survive so the projection is still auditable
        assert any("ref_digest" in m for m in public["messages"])

    def test_build_snapshot_rejects_complete_with_errors(self):
        with pytest.raises(fw.FlagWorkflowError, match="errors are recorded"):
            fw.build_snapshot(
                provider_name="mailapp", account="a", mailbox="INBOX",
                rows=[], complete=True, errors=["boom"],
                inaccessible_count=0, timeout_count=0,
                unknown_index_count=0, total_flagged_seen=0,
                hidden_by_limit=0,
            )

    def test_load_snapshot_detects_tamper(self, tmp_path):
        snap = _snapshot([_msg()])
        path = tmp_path / "snap.json"
        path.write_text(json.dumps(snap.to_dict()))
        loaded = fw.load_snapshot(path)
        assert loaded.snapshot_id == snap.snapshot_id

        tampered = json.loads(path.read_text())
        tampered["total_flagged_seen"] = 999
        path.write_text(json.dumps(tampered))
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.load_snapshot(path)


class TestPlanBuildingAndValidation:
    def _complete_snapshot(self):
        return _snapshot([
            _msg("1", "recruiter@x.com", "great opportunity"),
            _msg("2", "unknown@y.com", "mystery"),
        ])

    def test_plan_binds_full_snapshot_hash_and_is_review_only(self):
        snap = self._complete_snapshot()
        plan = fw.build_plan(snap)
        assert plan["snapshot_sha256"] == snap.to_dict()["content_hash"]
        assert len(plan["plan_hash"]) == 64
        assert plan["policy_version"] == MIGRATION_POLICY_VERSION
        assert plan["zero_write_declaration"] is True
        for m in plan["mutations"]:
            assert m["review_required"] is True       # legacy policy gate
            assert m["confidence"] is None             # no fake 0.7
            assert "sender" not in m and "subject" not in m   # no PII

    def test_incomplete_snapshot_cannot_produce_plan(self):
        snap = self._complete_snapshot()
        broken = fw.FlagSnapshot(
            **{**snap.__dict__, "complete": False, "status": "partial"},
        )
        broken.content_hash = ""
        broken.content_hash = broken.to_dict()["content_hash"]
        with pytest.raises(fw.FlagWorkflowError, match="refusing"):
            fw.build_plan(broken)

    def test_validate_accepts_built_plan(self):
        plan = fw.build_plan(self._complete_snapshot())
        mutations = fw.validate_plan_schema(plan)
        assert all(isinstance(m, fw.PlannedMutation) for m in mutations)

    def test_validate_rejects_wrong_schema(self):
        plan = fw.build_plan(self._complete_snapshot())
        plan["schema"] = "uma.flags.migration.plan.v1"
        with pytest.raises(fw.FlagWorkflowError, match="schema must be"):
            fw.validate_plan_schema(plan)

    def test_validate_fails_closed_on_unknown_color_string(self):
        plan = fw.build_plan(self._complete_snapshot())
        if not plan["mutations"]:
            pytest.skip("no mutations produced")
        plan["mutations"][0]["proposed_flag"] = "magenta"
        plan.pop("plan_hash")
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(ValueError, match="Unknown flag color"):
            fw.validate_plan_schema(plan)

    def test_validate_rejects_tampered_mutations(self):
        plan = fw.build_plan(self._complete_snapshot())
        if not plan["mutations"]:
            pytest.skip("no mutations produced")
        plan["mutations"][0]["proposed_flag"] = "blue"
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.validate_plan_schema(plan)

    def test_validate_rejects_truncated_snapshot_hash(self):
        plan = fw.build_plan(self._complete_snapshot())
        plan["snapshot_sha256"] = plan["snapshot_sha256"][:16]
        plan.pop("plan_hash")
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(fw.FlagWorkflowError, match="full 64-char"):
            fw.validate_plan_schema(plan)


class TestApprovalValidation:
    def _approval(self, plan, mutations, canary_limit=10):
        now = datetime.now(timezone.utc)
        return fw.ApprovalReceipt(
            schema=fw.APPROVAL_SCHEMA,
            snapshot_sha256=plan["snapshot_sha256"],
            plan_hash=plan["plan_hash"],
            approved_mutation_ids=[m.mutation_id for m in mutations][:canary_limit],
            issued_at=(now - timedelta(minutes=1)).isoformat(),
            expires_at=(now + timedelta(hours=8)).isoformat(),
            approving_operator="operator",
            canary_limit=canary_limit,
        )

    def test_valid_approval_passes(self):
        plan = fw.build_plan(_snapshot([_msg()]))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts, canary_limit=min(10, max(1, len(muts))))
        approval.validate(plan_mutations=muts)

    @pytest.mark.parametrize("bad_limit", [0, -1, 11, 100])
    def test_canary_bounds_hard_enforced(self, bad_limit):
        plan = fw.build_plan(_snapshot([_msg("1"), _msg("2")]))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts, canary_limit=bad_limit)
        with pytest.raises(fw.FlagWorkflowError, match="canary_limit"):
            approval.validate(plan_mutations=muts)

    def test_expired_approval_rejected(self):
        plan = fw.build_plan(_snapshot([_msg()]))
        muts = fw.validate_plan_schema(plan)
        now = datetime.now(timezone.utc)
        approval = self._approval(plan, muts)
        approval.expires_at = (now - timedelta(seconds=1)).isoformat()
        with pytest.raises(fw.FlagWorkflowError, match="expired"):
            approval.validate(plan_mutations=muts, now=now)

    def test_unknown_mutation_id_rejected(self):
        plan = fw.build_plan(_snapshot([_msg()]))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts)
        approval.approved_mutation_ids = ["mut-doesnotexist"]
        with pytest.raises(fw.FlagWorkflowError, match="absent from plan"):
            approval.validate(plan_mutations=muts)


class TestAppliedPlanLedger:
    def test_record_then_has_true_idempotency_probe(self, tmp_path):
        ledger = fw.AppliedPlanLedger(tmp_path / "ledger.jsonl")
        ph = fw.sha256_hex("plan")
        assert ledger.has(ph, "mut-1") is False
        ledger.record(ph, "mut-1", verified=True)
        assert ledger.has(ph, "mut-1") is True
        assert ledger.all_entries()[0]["verified"] is True

    def test_entries_survive_reopen(self, tmp_path):
        ph = fw.sha256_hex("p")
        fw.AppliedPlanLedger(tmp_path / "l.jsonl").record(ph, "m", True)
        assert fw.AppliedPlanLedger(tmp_path / "l.jsonl").has(ph, "m")


class TestOverrideStore:
    def test_record_suppress_unlock_roundtrip(self, tmp_path):
        store = fw.OverrideStore(tmp_path / "overrides.json")
        ref = fw.sha256_hex("ref-1")
        assert store.is_overridden(ref) is False
        store.record_override(ref, "human changed RED -> GRAY after apply")
        assert store.is_overridden(ref) is True
        assert store.is_suppressed(ref) is True
        store.unlock(ref)
        assert store.is_suppressed(ref) is False
        assert store.is_overridden(ref) is False

    def test_verified_automation_state_clears_override(self, tmp_path):
        store = fw.OverrideStore(tmp_path / "o.json")
        ref = fw.sha256_hex("ref-2")
        store.record_override(ref, "diff")
        store.record_automation_state(ref, "orange", verified=True)
        assert store.is_overridden(ref) is False

    def test_corrupt_store_fails_closed(self, tmp_path):
        p = tmp_path / "o.json"
        p.write_text("{not json")
        store = fw.OverrideStore(p)
        with pytest.raises(fw.FlagWorkflowError, match="corrupt"):
            store.list_overrides()


class TestRollbackReceipt:
    def test_create_validate_roundtrip(self):
        entries = [fw.RollbackEntry(
            ref_digest=fw.sha256_hex("r"),
            pre_apply_native_index=0,
            pre_apply_flag=FlagColor.RED,
            automation_applied_flag=FlagColor.ORANGE,
        )]
        receipt = fw.RollbackReceipt.create(fw.sha256_hex("plan"), entries)
        receipt.validate()
        restored = fw.RollbackReceipt.from_dict(receipt.to_dict())
        assert restored.plan_hash == receipt.plan_hash

    def test_tamper_rejected(self):
        entries = [fw.RollbackEntry(
            ref_digest=fw.sha256_hex("r"),
            pre_apply_native_index=-1,
            pre_apply_flag=FlagColor.NO_FLAG,
            automation_applied_flag=FlagColor.BLUE,
        )]
        receipt = fw.RollbackReceipt.create(fw.sha256_hex("p"), entries)
        raw = receipt.to_dict()
        raw["entries"][0]["pre_apply_native_index"] = 6
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.RollbackReceipt.from_dict(raw)


class TestLegacyPolicyContract:
    def test_all_proposals_review_only_without_fake_confidence(self):
        for sender, subject, observed in [
            ("recruiter@x.com", "job opportunity", FlagColor.RED),
            ("a@b.com", "", FlagColor.RED),
            ("c@d.com", "meeting scheduled", FlagColor.RED),
            ("e@f.com", "", FlagColor.PURPLE),
        ]:
            p = propose(sender, subject, observed)
            if not p.is_identity:
                assert p.review_required is True
                assert p.confidence is None

    def test_reason_codes_are_deterministic(self):
        p1 = propose("recruiter@x.com", "interview", FlagColor.RED)
        p2 = propose("RECRUITER@X.COM", "INTERVIEW", FlagColor.RED)
        assert p1.reason_code == p2.reason_code == RC_CAREER_SIGNAL_ORANGE
        p3 = propose("nothing@matches.here", "no signals at all", FlagColor.RED)
        assert p3.reason_code == RC_AMBIGUOUS_PURPLE
