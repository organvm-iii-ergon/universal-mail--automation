"""Focused acceptance tests for the canary-only Mail.app activation boundary.

Every provider in this file is an in-memory scoped fake.  The tests never
construct MailAppProvider, invoke AppleScript, or consult credentials.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import cli
from core import flag_workflow as fw
from core.flag_activation import (
    CanaryRollbackBundle,
    load_canary_activation,
    load_canary_rollback,
)
from core.flag_transactions import AdvisoryFileLock
from core.models import FlagColor
from providers.base import ProviderWriteAmbiguous
from providers.mailapp import mailapp_index_from_flag
from tests.test_commit6_transactions import (
    ELIG_SENDER,
    ELIG_SUBJECT,
    FakeScopedProvider,
    Harness,
    _row,
)
from tests.test_flag_workflow import _msg, _snapshot


class ContextFakeProvider(FakeScopedProvider):
    """The transaction fake plus the provider context-manager protocol."""

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def _write_json(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _artifact_set(tmp_path: Path, count: int = 1) -> SimpleNamespace:
    root = tmp_path / "artifacts"
    harness = Harness(
        root / "harness",
        pids=tuple(str(index) for index in range(1, count + 1)),
    )
    plan_path = _write_json(root / "plan.json", harness.plan)
    snapshot_path = _write_json(
        root / "snapshot.json", harness.snapshot.to_dict()
    )
    approval_path = _write_json(
        root / "approval.json", harness.approval.to_dict()
    )
    activation = load_canary_activation(
        plan_path=plan_path,
        snapshot_path=snapshot_path,
        approval_path=approval_path,
        cli_limit=count,
    )
    bundle = CanaryRollbackBundle.create(activation)
    bundle_path = _write_json(root / "rollback.json", bundle.to_dict())
    provider = ContextFakeProvider(list(harness.provider.messages.values()))
    return SimpleNamespace(
        root=root,
        harness=harness,
        plan_path=plan_path,
        snapshot_path=snapshot_path,
        approval_path=approval_path,
        activation=activation,
        bundle=bundle,
        bundle_path=bundle_path,
        provider=provider,
    )


def _apply_args(artifacts: SimpleNamespace, **overrides) -> SimpleNamespace:
    values = {
        "provider": "mailapp",
        "account": None,
        "canary": True,
        "plan": str(artifacts.plan_path),
        "snapshot": str(artifacts.snapshot_path),
        "approval": str(artifacts.approval_path),
        "limit": len(artifacts.activation.selected),
        "dry_run": False,
        "receipt_output": None,
        "proposal_output": None,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _rollback_args(
    artifacts: SimpleNamespace, receipt_path: Path, **overrides
) -> SimpleNamespace:
    values = {
        "provider": "mailapp",
        "account": None,
        "canary": True,
        "plan": str(artifacts.plan_path),
        "snapshot": str(artifacts.snapshot_path),
        "approval": str(artifacts.approval_path),
        "receipt": str(receipt_path),
        "dry_run": False,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _install_provider(monkeypatch, provider: ContextFakeProvider):
    calls = []

    def factory(name, **kwargs):
        calls.append((name, kwargs))
        return provider

    monkeypatch.setattr(cli, "get_provider", factory)
    return calls


def _provider_must_not_be_constructed(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("provider constructed before activation admitted")

    monkeypatch.setattr(cli, "get_provider", forbidden)


def _write_calls(provider: ContextFakeProvider):
    return [
        call
        for call in provider.calls
        if call[0] in {"set_flag_color_ref", "clear_flag_ref"}
    ]


def _parse_stdout(capsys):
    captured = capsys.readouterr()
    return json.loads(captured.out), captured


def _load_named_artifact(
    artifact_name: str, path: Path, artifacts: SimpleNamespace
):
    if artifact_name == "plan":
        return fw.load_plan(path)
    if artifact_name == "snapshot":
        return fw.load_snapshot(path)
    if artifact_name == "approval":
        return fw.load_approval(path)
    return load_canary_rollback(
        plan_path=artifacts.plan_path,
        snapshot_path=artifacts.snapshot_path,
        approval_path=artifacts.approval_path,
        receipt_path=path,
    )


class TestStrictArtifactLoaders:
    def test_valid_plan_snapshot_approval_and_bundle_round_trip(self, tmp_path):
        artifacts = _artifact_set(tmp_path, 3)

        assert fw.load_plan(artifacts.plan_path) == artifacts.harness.plan
        assert fw.load_snapshot(artifacts.snapshot_path).to_dict() == \
            artifacts.harness.snapshot.to_dict()
        assert fw.load_approval(artifacts.approval_path).to_dict() == \
            artifacts.harness.approval.to_dict()
        plan, snapshot, bundle = load_canary_rollback(
            plan_path=artifacts.plan_path,
            snapshot_path=artifacts.snapshot_path,
            approval_path=artifacts.approval_path,
            receipt_path=artifacts.bundle_path,
        )
        assert plan == artifacts.harness.plan
        assert snapshot.to_dict() == artifacts.harness.snapshot.to_dict()
        assert bundle.to_dict() == artifacts.bundle.to_dict()

    @pytest.mark.parametrize("artifact_name", [
        "plan", "snapshot", "approval", "bundle",
    ])
    def test_path_loaders_reject_duplicate_json_keys(
        self, tmp_path, artifact_name
    ):
        artifacts = _artifact_set(tmp_path, 1)
        source = {
            "plan": artifacts.plan_path,
            "snapshot": artifacts.snapshot_path,
            "approval": artifacts.approval_path,
            "bundle": artifacts.bundle_path,
        }[artifact_name]
        duplicate = artifacts.root / f"duplicate-{artifact_name}.json"
        raw = source.read_text(encoding="utf-8")
        duplicate.write_text(
            '{"schema":"duplicate",' + raw.lstrip()[1:],
            encoding="utf-8",
        )

        with pytest.raises(fw.FlagWorkflowError, match="contains invalid JSON"):
            _load_named_artifact(artifact_name, duplicate, artifacts)

    @pytest.mark.parametrize("artifact_name", [
        "plan", "snapshot", "approval", "bundle",
    ])
    def test_strict_loaders_reject_unknown_fields(
        self, tmp_path, artifact_name
    ):
        artifacts = _artifact_set(tmp_path, 1)
        values = {
            "plan": artifacts.harness.plan,
            "snapshot": artifacts.harness.snapshot.to_dict(),
            "approval": artifacts.harness.approval.to_dict(),
            "bundle": artifacts.bundle.to_dict(),
        }
        hostile = dict(values[artifact_name], unexpected="not allowed")
        path = _write_json(
            artifacts.root / f"extra-{artifact_name}.json", hostile
        )

        with pytest.raises(fw.FlagWorkflowError):
            _load_named_artifact(artifact_name, path, artifacts)


class TestCLIAdmissionBoundary:
    @pytest.mark.parametrize(
        ("handler", "args"),
        [
            (
                cli.cmd_flags_apply,
                SimpleNamespace(provider="mailapp", canary=False),
            ),
            (
                cli.cmd_flags_rollback,
                SimpleNamespace(provider="mailapp", canary=False),
            ),
        ],
    )
    def test_no_canary_exits_89_before_files_or_provider(
        self, monkeypatch, capsys, handler, args
    ):
        _provider_must_not_be_constructed(monkeypatch)

        assert handler(args) == 89
        captured = capsys.readouterr()
        assert "NOT_READY" in captured.err
        assert "no provider" in captured.err

    @pytest.mark.parametrize("limit", ["0", "4"])
    def test_first_canary_limit_rejected_by_parser(
        self, monkeypatch, capsys, limit
    ):
        monkeypatch.setattr(sys, "argv", [
            "prog", "flags", "apply", "--provider", "mailapp",
            "--canary", "--limit", limit,
            "--plan", "p.json", "--snapshot", "s.json",
            "--approval", "a.json",
        ])

        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == 2
        error = capsys.readouterr().err.lower()
        assert "integer" in error or "within [1,3]" in error

    def test_force_flag_is_unavailable(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", [
            "prog", "flags", "apply", "--provider", "mailapp",
            "--canary", "--force", "--plan", "p.json",
            "--snapshot", "s.json", "--approval", "a.json",
        ])

        with pytest.raises(SystemExit) as caught:
            cli.main()
        assert caught.value.code == 2
        assert "unrecognized arguments: --force" in capsys.readouterr().err

    def test_missing_approval_fails_closed_before_provider(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 1)
        _provider_must_not_be_constructed(monkeypatch)

        rc = cli.cmd_flags_apply(_apply_args(artifacts, approval=None))

        assert rc == 20
        assert "--approval" in capsys.readouterr().err

    def test_partial_plan_fails_closed_before_provider(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 1)
        partial = dict(artifacts.harness.plan)
        partial.pop("mutations")
        partial_path = _write_json(artifacts.root / "partial.json", partial)
        _provider_must_not_be_constructed(monkeypatch)

        rc = cli.cmd_flags_apply(
            _apply_args(artifacts, plan=str(partial_path))
        )

        assert rc == 20
        assert "activation refused" in capsys.readouterr().err

    def test_stale_plan_snapshot_pair_fails_closed_before_provider(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path / "current", 1)
        stale = _artifact_set(tmp_path / "stale", 1)
        _provider_must_not_be_constructed(monkeypatch)

        rc = cli.cmd_flags_apply(
            _apply_args(artifacts, snapshot=str(stale.snapshot_path))
        )

        assert rc == 20
        assert "supplied snapshot" in capsys.readouterr().err

    def test_incomplete_snapshot_fails_closed_before_provider(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 1)
        incomplete = fw.build_snapshot(
            provider_name="mailapp",
            account="acct",
            mailbox="INBOX",
            rows=[_row("1")],
            complete=False,
            scope_complete=True,
            status="bounded_partial",
            errors=[],
            inaccessible_count=0,
            timeout_count=0,
            unknown_index_count=0,
            limit=1,
            since_days=None,
            total_matched=2,
            returned_count=1,
            hidden_by_limit=1,
            next_cursor="next",
        )
        incomplete_path = _write_json(
            artifacts.root / "incomplete.json", incomplete.to_dict()
        )
        _provider_must_not_be_constructed(monkeypatch)

        rc = cli.cmd_flags_apply(
            _apply_args(artifacts, snapshot=str(incomplete_path))
        )

        assert rc == 20
        assert "activation refused" in capsys.readouterr().err

    def test_tampered_approval_fails_closed_before_provider(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 1)
        tampered = artifacts.harness.approval.to_dict()
        tampered["approving_operator"] = "attacker"
        tampered_path = _write_json(
            artifacts.root / "tampered-approval.json", tampered
        )
        _provider_must_not_be_constructed(monkeypatch)

        rc = cli.cmd_flags_apply(
            _apply_args(artifacts, approval=str(tampered_path))
        )

        assert rc == 20
        assert "content_hash mismatch" in capsys.readouterr().err

    def test_review_required_auto_ineligible_target_fails_before_provider(
        self, tmp_path, monkeypatch, capsys
    ):
        snapshot = _snapshot([_msg(
            sender="billing@corp.example",
            subject=(
                "Payment receipt: please confirm your appointment is "
                "scheduled tomorrow; overdue account suspension"
            ),
            color=FlagColor.ORANGE,
        )])
        plan = fw.build_plan(snapshot)
        mutation = fw.validate_plan_schema(plan)[0]
        assert mutation.review_required is True
        assert mutation.auto_eligible is False
        approval = fw.ApprovalReceipt.create(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=plan["snapshot_sha256"],
            policy_sha256=plan["policy_sha256"],
            approved_mutation_ids=[mutation.mutation_id],
            approving_operator="operator",
            canary_limit=1,
        )
        root = tmp_path / "review-required"
        plan_path = _write_json(root / "plan.json", plan)
        snapshot_path = _write_json(
            root / "snapshot.json", snapshot.to_dict()
        )
        approval_path = _write_json(
            root / "approval.json", approval.to_dict()
        )
        _provider_must_not_be_constructed(monkeypatch)

        rc = cli.cmd_flags_apply(SimpleNamespace(
            provider="mailapp",
            account=None,
            canary=True,
            plan=str(plan_path),
            snapshot=str(snapshot_path),
            approval=str(approval_path),
            limit=1,
            dry_run=True,
            receipt_output=None,
            proposal_output=None,
        ))

        assert rc == 20
        assert "activation refused" in capsys.readouterr().err

    @pytest.mark.parametrize(
        "collision",
        [
            "receipt_over_plan",
            "proposal_over_approval",
            "proposal_over_custom_receipt",
            "proposal_over_default_receipt",
            "case_variant_outputs",
            "unicode_variant_outputs",
        ],
    )
    def test_output_aliases_fail_before_artifact_or_provider_write(
        self, tmp_path, monkeypatch, capsys, collision
    ):
        artifacts = _artifact_set(tmp_path, 1)
        state_dir = tmp_path / "state"
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
        _provider_must_not_be_constructed(monkeypatch)
        original_plan = artifacts.plan_path.read_bytes()
        original_approval = artifacts.approval_path.read_bytes()
        shared = tmp_path / "shared-output.json"
        overrides = {}
        if collision == "receipt_over_plan":
            overrides["receipt_output"] = str(artifacts.plan_path)
        elif collision == "proposal_over_approval":
            overrides["proposal_output"] = str(artifacts.approval_path)
        elif collision == "proposal_over_custom_receipt":
            overrides.update({
                "receipt_output": str(shared),
                "proposal_output": str(shared),
            })
        elif collision == "case_variant_outputs":
            overrides.update({
                "receipt_output": str(tmp_path / "Collision.json"),
                "proposal_output": str(tmp_path / "collision.json"),
            })
        elif collision == "unicode_variant_outputs":
            overrides.update({
                "receipt_output": str(tmp_path / "caf\u00e9.json"),
                "proposal_output": str(tmp_path / "cafe\u0301.json"),
            })
        else:
            overrides["proposal_output"] = str(
                state_dir / "receipts" /
                f"{artifacts.bundle.canary_id}.json"
            )

        rc = cli.cmd_flags_apply(_apply_args(artifacts, **overrides))

        assert rc == 20
        assert "aliases" in capsys.readouterr().err
        assert artifacts.plan_path.read_bytes() == original_plan
        assert artifacts.approval_path.read_bytes() == original_approval
        assert not state_dir.exists()


class TestCanaryApply:
    @pytest.mark.parametrize("count", [1, 3])
    @pytest.mark.parametrize("dry_run", [True, False])
    def test_valid_mocked_one_and_three_message_canaries(
        self, tmp_path, monkeypatch, capsys, count, dry_run
    ):
        artifacts = _artifact_set(tmp_path, count)
        state_dir = tmp_path / "state"
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
        _install_provider(monkeypatch, artifacts.provider)

        rc = cli.cmd_flags_apply(
            _apply_args(artifacts, dry_run=dry_run)
        )

        output, _captured = _parse_stdout(capsys)
        assert rc == 0
        assert output["message_count"] == count
        assert output["writes_performed"] == (0 if dry_run else count)
        assert len(_write_calls(artifacts.provider)) == \
            (0 if dry_run else count)
        assert output["rollback_receipt_ready"] is True
        assert (
            state_dir / "receipts" / f"{output['canary_id']}.json"
        ).is_file()
        if dry_run:
            assert output["status"] == "canary_ready_for_approval"
            assert output["preflight_status"] == "preflight_passed"
            assert output["preflight_target_count"] == count
        else:
            assert output["status"] == "applied"
            assert output["verified_count"] == count
            for mutation in artifacts.activation.selected:
                assert artifacts.provider.messages[
                    mutation.provider_id
                ].native == mailapp_index_from_flag(mutation.proposed_flag)

    @pytest.mark.parametrize("drift_kind", ["native", "evidence", "unknown"])
    def test_drifted_target_blocks_entire_batch_with_zero_writes(
        self, tmp_path, monkeypatch, capsys, drift_kind
    ):
        artifacts = _artifact_set(tmp_path, 3)
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path / "state"))
        drifted = artifacts.activation.selected[1]
        message = artifacts.provider.messages[drifted.provider_id]
        if drift_kind == "native":
            message.native = 4
        elif drift_kind == "evidence":
            message.subject = "changed after the approved snapshot"
        else:
            message.native = None
        _install_provider(monkeypatch, artifacts.provider)

        rc = cli.cmd_flags_apply(_apply_args(artifacts))

        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["preflight_status"] == "blocked"
        assert output["writes_performed"] == 0
        assert _write_calls(artifacts.provider) == []

    def test_human_override_blocks_entire_batch_with_zero_writes(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 3)
        state_dir = tmp_path / "state"
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
        mutation = artifacts.activation.selected[1]
        fw.OverrideStore(state_dir / "overrides.json").detect_override(
            mutation.ref_digest,
            automation_expected_state=mutation.observed_flag.value,
            human_observed_state="yellow",
        )
        _install_provider(monkeypatch, artifacts.provider)

        rc = cli.cmd_flags_apply(_apply_args(artifacts))

        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["preflight_status"] == "blocked"
        assert output["writes_performed"] == 0
        assert _write_calls(artifacts.provider) == []

    def test_consumed_transaction_replay_is_zero_write_refusal(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 1)
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path / "state"))
        _install_provider(monkeypatch, artifacts.provider)
        args = _apply_args(artifacts)

        assert cli.cmd_flags_apply(args) == 0
        capsys.readouterr()
        writes_before = len(_write_calls(artifacts.provider))

        rc = cli.cmd_flags_apply(args)

        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["preflight_status"] == "blocked"
        assert output["writes_performed"] == 0
        assert len(_write_calls(artifacts.provider)) == writes_before

    def test_concurrent_claim_is_zero_write_refusal(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 1)
        state_dir = tmp_path / "state"
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
        _install_provider(monkeypatch, artifacts.provider)
        lock_path = (
            state_dir / "locks" /
            f"apply-{artifacts.activation.plan_hash[:16]}.lock"
        )

        with AdvisoryFileLock(lock_path):
            rc = cli.cmd_flags_apply(_apply_args(artifacts))

        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["preflight_status"] == "already_claimed"
        assert output["writes_performed"] == 0
        assert _write_calls(artifacts.provider) == []

    def test_wrong_readback_is_ambiguous_and_nonzero(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 1)
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path / "state"))

        def lying_write(ref, color):
            artifacts.provider.calls.append(
                ("set_flag_color_ref", ref.provider_id, color.value)
            )
            return True

        artifacts.provider.set_flag_color_ref = lying_write
        _install_provider(monkeypatch, artifacts.provider)

        rc = cli.cmd_flags_apply(_apply_args(artifacts))

        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["status"] == "ambiguous"
        assert output["writes_performed"] == 1
        assert len(_write_calls(artifacts.provider)) == 1

    def test_public_output_contains_digests_not_raw_scope_or_message_pii(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 1)
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path / "state"))
        _install_provider(monkeypatch, artifacts.provider)

        assert cli.cmd_flags_apply(
            _apply_args(artifacts, dry_run=True)
        ) == 0

        output, _captured = _parse_stdout(capsys)
        encoded = json.dumps(output, sort_keys=True)
        assert ELIG_SENDER not in encoded
        assert ELIG_SUBJECT not in encoded
        assert '"acct"' not in encoded
        assert '"INBOX"' not in encoded
        assert "/Users/" not in encoded
        for forbidden_key in {
            "account", "mailbox", "provider_id", "sender", "subject",
        }:
            assert forbidden_key not in output
            assert all(
                forbidden_key not in message
                for message in output["messages"]
            )
        for required_hash in {
            "snapshot_sha256", "plan_sha256", "policy_sha256",
            "approval_sha256", "rollback_bundle_sha256", "scope_digest",
        }:
            assert len(output[required_hash]) == 64


class TestCanaryRollback:
    def _applied(
        self, tmp_path, monkeypatch, capsys, count=3
    ) -> tuple[SimpleNamespace, Path]:
        artifacts = _artifact_set(tmp_path, count)
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path / "state"))
        _install_provider(monkeypatch, artifacts.provider)
        assert cli.cmd_flags_apply(_apply_args(artifacts)) == 0
        output, _captured = _parse_stdout(capsys)
        receipt_path = (
            tmp_path / "state" / "receipts" /
            f"{output['canary_id']}.json"
        )
        return artifacts, receipt_path

    @pytest.mark.parametrize("count", [1, 3])
    def test_batch_rollback_restores_exact_native_state(
        self, tmp_path, monkeypatch, capsys, count
    ):
        artifacts, receipt_path = self._applied(
            tmp_path, monkeypatch, capsys, count=count
        )
        writes_before = len(_write_calls(artifacts.provider))

        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )

        output, _captured = _parse_stdout(capsys)
        assert rc == 0
        assert output["status"] == "rolled_back"
        assert output["writes_performed"] == count
        assert len(_write_calls(artifacts.provider)) - writes_before == count
        for mutation in artifacts.activation.selected:
            assert artifacts.provider.messages[
                mutation.provider_id
            ].native == mutation.observed_native_flag

    def test_human_change_blocks_entire_rollback_batch_with_zero_writes(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts, receipt_path = self._applied(
            tmp_path, monkeypatch, capsys, count=3
        )
        mutation = artifacts.activation.selected[1]
        applied = mailapp_index_from_flag(mutation.proposed_flag)
        artifacts.provider.messages[mutation.provider_id].native = \
            6 if applied != 6 else 2
        writes_before = len(_write_calls(artifacts.provider))

        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )

        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["status"] == "blocked"
        assert output["writes_performed"] == 0
        assert len(_write_calls(artifacts.provider)) == writes_before

        # Returning the native state to the automation-applied color does not
        # silently restore authority: only an explicit operator unlock can.
        artifacts.provider.messages[mutation.provider_id].native = applied
        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )
        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["status"] == "blocked"
        assert output["writes_performed"] == 0
        assert len(_write_calls(artifacts.provider)) == writes_before

        fw.OverrideStore(
            tmp_path / "state" / "overrides.json"
        ).unlock(mutation.ref_digest, actor="test-operator")
        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )
        output, _captured = _parse_stdout(capsys)
        assert rc == 0
        assert output["status"] == "rolled_back"
        assert output["writes_performed"] == 3
        assert len(_write_calls(artifacts.provider)) - writes_before == 3

    @pytest.mark.parametrize(
        "failure_kind", ["wrong_readback", "provider_ambiguous"]
    )
    def test_unverified_rollback_write_remains_ambiguous(
        self, tmp_path, monkeypatch, capsys, failure_kind
    ):
        artifacts, receipt_path = self._applied(
            tmp_path, monkeypatch, capsys, count=1
        )
        writes_before = len(_write_calls(artifacts.provider))

        def unverified_write(ref, color):
            artifacts.provider.calls.append((
                "set_flag_color_ref", ref.provider_id, color.value
            ))
            if failure_kind == "provider_ambiguous":
                raise ProviderWriteAmbiguous("dispatch outcome unknown")
            return True

        artifacts.provider.set_flag_color_ref = unverified_write

        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )

        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["status"] == "ambiguous"
        assert output["writes_performed"] == 1
        assert len(_write_calls(artifacts.provider)) - writes_before == 1

    def test_exact_applied_canary_remains_rollbackable_after_approval_expiry(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts, receipt_path = self._applied(
            tmp_path, monkeypatch, capsys, count=1
        )
        writes_before = len(_write_calls(artifacts.provider))
        future = datetime.now(timezone.utc) + timedelta(hours=2)

        class FutureDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return future if tz is not None else future.replace(
                    tzinfo=None
                )

        monkeypatch.setattr(fw, "datetime", FutureDateTime)

        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )

        output, _captured = _parse_stdout(capsys)
        assert rc == 0
        assert output["status"] == "rolled_back"
        assert output["writes_performed"] == 1
        assert output["verified_restored_count"] == 1
        assert output["not_applied_count"] == 0
        assert output["already_rolled_back_count"] == 0
        assert output["failed_count"] == 0
        assert output["unattempted_count"] == 0
        assert len(_write_calls(artifacts.provider)) - writes_before == 1

    def test_partial_apply_verified_prefix_can_rollback_exact_bundle(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 3)
        state_dir = tmp_path / "state"
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
        _install_provider(monkeypatch, artifacts.provider)
        refused = artifacts.activation.selected[1]
        original_write = artifacts.provider.set_flag_color_ref

        def refuse_second(ref, color):
            if ref.provider_id == refused.provider_id:
                artifacts.provider.calls.append((
                    "set_flag_color_ref", ref.provider_id, color.value
                ))
                return False
            return original_write(ref, color)

        artifacts.provider.set_flag_color_ref = refuse_second

        rc = cli.cmd_flags_apply(_apply_args(artifacts))
        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["status"] == "partially_failed"
        assert output["writes_performed"] == 1
        receipt_path = (
            state_dir / "receipts" / f"{output['canary_id']}.json"
        )
        writes_before = len(_write_calls(artifacts.provider))

        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )

        output, _captured = _parse_stdout(capsys)
        assert rc == 0
        assert output["status"] == "rolled_back"
        assert output["writes_performed"] == 1
        assert output["verified_restored_count"] == 1
        assert output["not_applied_count"] == 2
        assert output["already_rolled_back_count"] == 0
        assert output["failed_count"] == 0
        assert output["unattempted_count"] == 0
        assert len(_write_calls(artifacts.provider)) - writes_before == 1
        for mutation in artifacts.activation.selected:
            assert artifacts.provider.messages[
                mutation.provider_id
            ].native == mutation.observed_native_flag

    def test_nonambiguous_partial_rollback_resumes_exact_bundle(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts, receipt_path = self._applied(
            tmp_path, monkeypatch, capsys, count=3
        )
        refused = artifacts.activation.selected[1]
        original_write = artifacts.provider.set_flag_color_ref

        def refuse_second(ref, color):
            if ref.provider_id == refused.provider_id:
                artifacts.provider.calls.append((
                    "set_flag_color_ref", ref.provider_id, color.value
                ))
                return False
            return original_write(ref, color)

        artifacts.provider.set_flag_color_ref = refuse_second
        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )
        output, _captured = _parse_stdout(capsys)
        assert rc == 20
        assert output["status"] == "partially_rolled_back"
        assert output["writes_performed"] == 1

        artifacts.provider.set_flag_color_ref = original_write
        writes_before_resume = len(_write_calls(artifacts.provider))
        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )
        output, _captured = _parse_stdout(capsys)
        assert rc == 0
        assert output["status"] == "rolled_back"
        assert output["writes_performed"] == 2
        assert output["verified_restored_count"] == 2
        assert output["already_rolled_back_count"] == 1
        assert output["not_applied_count"] == 0
        assert (
            len(_write_calls(artifacts.provider)) - writes_before_resume
        ) == 2
        for mutation in artifacts.activation.selected:
            assert artifacts.provider.messages[
                mutation.provider_id
            ].native == mutation.observed_native_flag

        writes_before_replay = len(_write_calls(artifacts.provider))
        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )
        output, _captured = _parse_stdout(capsys)
        assert rc == 0
        assert output["status"] == "already_rolled_back"
        assert output["writes_performed"] == 0
        assert output["verified_restored_count"] == 0
        assert output["already_rolled_back_count"] == 3
        assert len(_write_calls(artifacts.provider)) == writes_before_replay

    def test_never_applied_exact_bundle_reports_rollback_not_required(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts = _artifact_set(tmp_path, 3)
        state_dir = tmp_path / "state"
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
        _install_provider(monkeypatch, artifacts.provider)
        assert cli.cmd_flags_apply(
            _apply_args(artifacts, dry_run=True)
        ) == 0
        proposal, _captured = _parse_stdout(capsys)
        receipt_path = (
            state_dir / "receipts" / f"{proposal['canary_id']}.json"
        )

        rc = cli.cmd_flags_rollback(
            _rollback_args(artifacts, receipt_path)
        )

        output, _captured = _parse_stdout(capsys)
        assert rc == 0
        assert output["status"] == "rollback_not_required"
        assert output["writes_performed"] == 0
        assert output["verified_restored_count"] == 0
        assert output["already_rolled_back_count"] == 0
        assert output["not_applied_count"] == 3
        assert _write_calls(artifacts.provider) == []

    def test_rollback_replay_is_zero_write_refusal(
        self, tmp_path, monkeypatch, capsys
    ):
        artifacts, receipt_path = self._applied(
            tmp_path, monkeypatch, capsys, count=1
        )
        args = _rollback_args(artifacts, receipt_path)
        assert cli.cmd_flags_rollback(args) == 0
        capsys.readouterr()
        writes_before = len(_write_calls(artifacts.provider))

        rc = cli.cmd_flags_rollback(args)

        output, _captured = _parse_stdout(capsys)
        assert rc == 0
        assert output["status"] == "already_rolled_back"
        assert output["writes_performed"] == 0
        assert len(_write_calls(artifacts.provider)) == writes_before
