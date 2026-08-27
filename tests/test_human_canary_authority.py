"""Acceptance tests for the human-nominated activation-canary authority.

The fixture deliberately models a completed commerce receipt: classifier
review remains required, while its deterministic proof contains no active,
deadline, career, finance, or scheduling signal.  All provider operations
are in-memory; this file never constructs Mail.app or executes AppleScript.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import cli
from core import flag_workflow as fw
from core.flag_activation import (
    CanaryRollbackBundle,
    load_canary_activation,
    load_canary_rollback,
    make_rollback_engine,
    make_transaction_engine,
)
from core.models import FlagColor
from providers.mailapp import mailapp_index_from_flag
from tests.test_commit6_transactions import (
    FakeMessage,
    Harness,
    _row,
)
from tests.test_flags_activation import ContextFakeProvider, _write_calls


SAFE_SENDER = "orders@example.test"
SAFE_SUBJECT = "Receipt for your completed order"


def _write_json(path: Path, value: object) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _review_plan(tmp_path: Path, count: int = 1):
    snapshot = fw.build_snapshot(
        provider_name="mailapp",
        account="acct",
        mailbox="INBOX",
        rows=[
            _row(
                str(index),
                color=FlagColor.RED,
                sender=SAFE_SENDER,
                subject=SAFE_SUBJECT,
            )
            for index in range(1, count + 1)
        ],
        complete=True,
        scope_complete=True,
        status="complete",
        errors=[],
        inaccessible_count=0,
        timeout_count=0,
        unknown_index_count=0,
        limit=500,
        since_days=None,
        total_matched=count,
        returned_count=count,
        hidden_by_limit=0,
    )
    plan = fw.build_plan(snapshot)
    mutations = fw.validate_plan_schema(plan)
    assert all(m.auto_eligible is False for m in mutations)
    assert all(m.review_required is True for m in mutations)
    assert all(fw.human_canary_risk_blocker(m) is None for m in mutations)
    return snapshot, plan, mutations


def _human_artifacts(tmp_path: Path, count: int = 1):
    root = tmp_path / "artifacts"
    snapshot, plan, mutations = _review_plan(tmp_path, count)
    targets = [
        fw.HumanCanaryTarget(
            mutation_id=m.mutation_id,
            ref_digest=m.ref_digest,
            temporary_flag=FlagColor.BLUE,
        )
        for m in mutations
    ]
    approval = fw.ApprovalReceipt.create_human_canary(
        plan_hash=plan["plan_hash"],
        snapshot_sha256=plan["snapshot_sha256"],
        policy_sha256=plan["policy_sha256"],
        nominated_targets=targets,
        approving_operator="test-operator",
        canary_limit=count,
    )
    plan_path = _write_json(root / "plan.json", plan)
    snapshot_path = _write_json(root / "snapshot.json", snapshot.to_dict())
    approval_path = _write_json(root / "approval.json", approval.to_dict())
    activation = load_canary_activation(
        plan_path=plan_path,
        snapshot_path=snapshot_path,
        approval_path=approval_path,
        cli_limit=count,
        human_selected=True,
    )
    bundle = CanaryRollbackBundle.create(activation)
    bundle_path = _write_json(root / "rollback.json", bundle.to_dict())
    provider = ContextFakeProvider([
        FakeMessage(
            m.provider_id,
            m.observed_native_flag,
            received="2026-07-01T00:00:00",
            sender=SAFE_SENDER,
            subject=SAFE_SUBJECT,
        )
        for m in mutations
    ])
    return SimpleNamespace(
        root=root,
        snapshot=snapshot,
        plan=plan,
        mutations=mutations,
        approval=approval,
        plan_path=plan_path,
        snapshot_path=snapshot_path,
        approval_path=approval_path,
        activation=activation,
        bundle=bundle,
        bundle_path=bundle_path,
        provider=provider,
    )


def _human_apply_args(artifacts, **overrides):
    values = {
        "provider": "mailapp",
        "account": None,
        "canary": True,
        "human_selected": True,
        "plan": str(artifacts.plan_path),
        "snapshot": str(artifacts.snapshot_path),
        "approval": str(artifacts.approval_path),
        "limit": len(artifacts.mutations),
        "dry_run": False,
        "receipt_output": None,
        "proposal_output": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _provider_must_not_be_constructed(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("provider constructed before authority admitted")

    monkeypatch.setattr(cli, "get_provider", forbidden)


class TestHumanCanaryAuthority:
    def test_human_approval_command_is_artifact_only_and_exact(
            self, tmp_path, monkeypatch, capsys):
        artifacts = _human_artifacts(tmp_path)
        _provider_must_not_be_constructed(monkeypatch)
        mutation = artifacts.mutations[0]
        output = tmp_path / "approval-output.json"

        result = cli.cmd_flags_human_canary_approve(SimpleNamespace(
            canary=True,
            human_selected=True,
            plan=str(artifacts.plan_path),
            snapshot=str(artifacts.snapshot_path),
            nominate=[
                f"{mutation.mutation_id}:{mutation.ref_digest}:blue"
            ],
            operator="test-operator",
            ttl_seconds=60,
            output=str(output),
        ))

        assert result == 0
        rendered = json.loads(capsys.readouterr().out)
        created = fw.load_approval(output)
        assert rendered["live_writes_performed"] == 0
        assert created.is_human_canary is True
        assert created.approved_mutation_ids == [mutation.mutation_id]
        assert created.human_canary_targets[0].ref_digest == mutation.ref_digest
        assert created.human_canary_targets[0].temporary_flag is FlagColor.BLUE

    def test_human_approval_command_requires_both_explicit_switches(
            self, monkeypatch, capsys):
        _provider_must_not_be_constructed(monkeypatch)

        result = cli.cmd_flags_human_canary_approve(SimpleNamespace(
            canary=False, human_selected=False,
        ))

        assert result == 89
        assert "--canary" in capsys.readouterr().err

    def test_automatic_authority_still_rejects_review_required(self, tmp_path):
        snapshot, plan, mutations = _review_plan(tmp_path)
        approval = fw.ApprovalReceipt.create(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=snapshot.content_hash,
            policy_sha256=plan["policy_sha256"],
            approved_mutation_ids=[mutations[0].mutation_id],
            approving_operator="operator",
            canary_limit=1,
        )

        with pytest.raises(fw.FlagWorkflowError, match="auto_eligible"):
            approval.validate(plan=plan, plan_mutations=mutations)

    def test_human_canary_keeps_classifier_truth_immutable(self, tmp_path):
        artifacts = _human_artifacts(tmp_path)
        mutation = artifacts.mutations[0]

        assert mutation.auto_eligible is False
        assert mutation.review_required is True
        assert artifacts.approval.is_human_canary is True
        assert artifacts.approval.execution_flag_for(mutation) is FlagColor.BLUE
        assert artifacts.plan["mutations"][0]["auto_eligible"] is False
        assert artifacts.plan["mutations"][0]["review_required"] is True

    def test_classifier_uncertainty_is_review_not_a_human_canary_veto(
            self, tmp_path):
        snapshot = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=[_row(
                "uncertain", color=FlagColor.RED,
                sender="updates@example.test",
                subject="Product update notice",
            )],
            complete=True, scope_complete=True, status="complete", errors=[],
            inaccessible_count=0, timeout_count=0, unknown_index_count=0,
            limit=500, since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0,
        )
        plan = fw.build_plan(snapshot)
        mutation = fw.validate_plan_schema(plan)[0]
        assert mutation.review_required is True
        assert mutation.auto_eligible is False
        assert mutation.classification_proof.next_action_owner == "unknown"
        assert mutation.classification_proof.operator_state == "open_loop"
        assert fw.human_canary_risk_blocker(mutation) is None

        approval = fw.ApprovalReceipt.create_human_canary(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=snapshot.content_hash,
            policy_sha256=plan["policy_sha256"],
            nominated_targets=[fw.HumanCanaryTarget(
                mutation.mutation_id, mutation.ref_digest, FlagColor.BLUE,
            )],
            approving_operator="operator",
            canary_limit=1,
        )
        approval.validate(plan=plan, plan_mutations=[mutation])

    def test_explicit_private_text_risk_is_still_blocked(self):
        assert fw.human_canary_text_risk_blocker(
            "notices@example.test", "Password reset required"
        ) == "blocked_text_risk:security"

    def test_human_canary_hard_maximum_is_three(self, tmp_path):
        snapshot, plan, mutations = _review_plan(tmp_path, count=4)
        targets = [
            fw.HumanCanaryTarget(m.mutation_id, m.ref_digest, FlagColor.BLUE)
            for m in mutations
        ]
        approval = fw.ApprovalReceipt.create_human_canary(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=snapshot.content_hash,
            policy_sha256=plan["policy_sha256"],
            nominated_targets=targets,
            approving_operator="operator",
            canary_limit=4,
        )

        with pytest.raises(fw.FlagWorkflowError, match=r"within \[1,3\]"):
            approval.validate(plan=plan, plan_mutations=mutations)

    def test_exact_nominations_bind_ref_and_exclude_other_plan_items(
            self, tmp_path):
        snapshot, plan, mutations = _review_plan(tmp_path, count=2)
        bad = fw.HumanCanaryTarget(
            mutations[0].mutation_id,
            "0" * 64,
            FlagColor.BLUE,
        )
        approval = fw.ApprovalReceipt.create_human_canary(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=snapshot.content_hash,
            policy_sha256=plan["policy_sha256"],
            nominated_targets=[bad],
            approving_operator="operator",
            canary_limit=1,
        )
        with pytest.raises(fw.FlagWorkflowError, match="ref digest"):
            approval.validate(plan=plan, plan_mutations=mutations)

        artifacts = _human_artifacts(tmp_path / "valid", count=1)
        with pytest.raises(fw.FlagWorkflowError, match="absent from human"):
            artifacts.approval.execution_flag_for(mutations[1])

    def test_human_canary_refuses_deterministic_high_risk_class(self, tmp_path):
        snapshot = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=[_row(
                "risk", color=FlagColor.RED,
                sender="billing@corp.test",
                subject="Receipt for your completed payment",
            )],
            complete=True, scope_complete=True, status="complete", errors=[],
            inaccessible_count=0, timeout_count=0, unknown_index_count=0,
            limit=500, since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0,
        )
        plan = fw.build_plan(snapshot)
        mutation = fw.validate_plan_schema(plan)[0]
        approval = fw.ApprovalReceipt.create_human_canary(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=snapshot.content_hash,
            policy_sha256=plan["policy_sha256"],
            nominated_targets=[fw.HumanCanaryTarget(
                mutation.mutation_id, mutation.ref_digest, FlagColor.BLUE,
            )],
            approving_operator="operator",
            canary_limit=1,
        )

        with pytest.raises(fw.FlagWorkflowError, match="blocked_domain:finance"):
            approval.validate(plan=plan, plan_mutations=[mutation])

    def test_human_approval_requires_human_selected_cli_switch(
            self, tmp_path, monkeypatch, capsys):
        artifacts = _human_artifacts(tmp_path)
        _provider_must_not_be_constructed(monkeypatch)

        result = cli.cmd_flags_apply(_human_apply_args(
            artifacts, human_selected=False,
        ))

        assert result == 20
        assert "--human-selected" in capsys.readouterr().err

    def test_human_approval_cannot_be_reused_as_ordinary_migration(self,
                                                                    tmp_path):
        artifacts = _human_artifacts(tmp_path)

        with pytest.raises(fw.FlagWorkflowError, match="--human-selected"):
            load_canary_activation(
                plan_path=artifacts.plan_path,
                snapshot_path=artifacts.snapshot_path,
                approval_path=artifacts.approval_path,
                cli_limit=1,
                human_selected=False,
            )
        with pytest.raises(fw.FlagWorkflowError, match="human activation"):
            load_canary_rollback(
                plan_path=artifacts.plan_path,
                snapshot_path=artifacts.snapshot_path,
                approval_path=artifacts.approval_path,
                receipt_path=artifacts.bundle_path,
                human_selected=False,
            )

    def test_automatic_approval_rejects_human_selected_switch(self, tmp_path):
        # A normal automatic approval still has its ordinary authority shape;
        # the selected switch cannot reinterpret it as a human canary.
        harness = Harness(tmp_path / "harness", pids=("1",))
        root = tmp_path / "automatic"
        plan_path = _write_json(root / "plan.json", harness.plan)
        snapshot_path = _write_json(
            root / "snapshot.json", harness.snapshot.to_dict()
        )
        approval_path = _write_json(
            root / "approval.json", harness.approval.to_dict()
        )

        with pytest.raises(fw.FlagWorkflowError, match="requires a human"):
            load_canary_activation(
                plan_path=plan_path,
                snapshot_path=snapshot_path,
                approval_path=approval_path,
                cli_limit=1,
                human_selected=True,
            )

    def test_changed_candidate_preflight_blocks_entire_human_canary(
            self, tmp_path):
        artifacts = _human_artifacts(tmp_path, count=2)
        engine, _ledger = make_transaction_engine(tmp_path / "state")
        artifacts.provider.messages["2"].subject = "changed after nomination"

        result = engine.apply_canary_transaction(
            plan=artifacts.plan,
            approval=artifacts.approval,
            provider=artifacts.provider,
            max_count=2,
        )

        assert result.status == "blocked"
        assert result.writes_performed == 0
        assert _write_calls(artifacts.provider) == []

    def test_human_canary_wrong_readback_is_ambiguous_after_one_write(
            self, tmp_path):
        artifacts = _human_artifacts(tmp_path)

        class WrongReadbackProvider(ContextFakeProvider):
            def set_flag_color_ref(self, ref, color):
                result = super().set_flag_color_ref(ref, color)
                self.messages[ref.provider_id].native = \
                    mailapp_index_from_flag(FlagColor.ORANGE)
                return result

        artifacts.provider = WrongReadbackProvider(
            list(artifacts.provider.messages.values())
        )
        engine, _ledger = make_transaction_engine(tmp_path / "state")

        result = engine.apply_canary_transaction(
            plan=artifacts.plan,
            approval=artifacts.approval,
            provider=artifacts.provider,
            max_count=1,
        )

        assert result.status == "ambiguous"
        assert result.writes_performed == 1
        assert len(_write_calls(artifacts.provider)) == 1

    def test_apply_rollback_and_replays_are_exact_and_zero_write(
            self, tmp_path):
        artifacts = _human_artifacts(tmp_path)
        state = tmp_path / "state"
        engine, _ledger = make_transaction_engine(state)
        original_native = artifacts.mutations[0].observed_native_flag

        applied = engine.apply_canary_transaction(
            plan=artifacts.plan,
            approval=artifacts.approval,
            provider=artifacts.provider,
            max_count=1,
        )
        assert applied.status == "applied"
        assert applied.writes_performed == 1
        assert artifacts.provider.messages["1"].native == \
            mailapp_index_from_flag(FlagColor.BLUE)
        assert artifacts.mutations[0].proposed_flag is FlagColor.NO_FLAG
        assert artifacts.bundle.receipts[0].applied_semantic_flag == "blue"

        replay_apply = engine.apply_canary_transaction(
            plan=artifacts.plan,
            approval=artifacts.approval,
            provider=artifacts.provider,
            max_count=1,
        )
        assert replay_apply.writes_performed == 0
        assert replay_apply.status in {"already_applied", "blocked"}
        assert replay_apply.error_code in {
            None, "transaction_already_claimed",
        }

        rollback = make_rollback_engine(state, artifacts.plan)
        restored = rollback.rollback_transactions(
            receipts=artifacts.bundle.receipts,
            provider=artifacts.provider,
            max_count=1,
        )
        assert restored.status == "rolled_back"
        assert restored.writes_performed == 1
        assert artifacts.provider.messages["1"].native == original_native

        replay_rollback = rollback.rollback_transactions(
            receipts=artifacts.bundle.receipts,
            provider=artifacts.provider,
            max_count=1,
        )
        assert replay_rollback.status == "already_rolled_back"
        assert replay_rollback.writes_performed == 0
        assert len(_write_calls(artifacts.provider)) == 2
