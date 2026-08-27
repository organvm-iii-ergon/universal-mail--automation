"""Exact independent-audit regressions for PR #192."""

import json
from dataclasses import replace

import pytest

from core import flag_workflow as fw
from core.flag_transactions import LedgerCorrupted, ST_VERIFIED
from core.models import FlagColor
from providers.mailapp import mailapp_index_from_flag
from tests.test_commit6_transactions import Harness
from tests.test_flag_workflow import _msg, _snapshot


CONFLICTING_SUBJECT = (
    "Payment receipt: please confirm your appointment is scheduled "
    "tomorrow; overdue account suspension"
)


def _conflicting_plan():
    snapshot = _snapshot([
        _msg(
            sender="billing@corp.example",
            subject=CONFLICTING_SUBJECT,
            color=FlagColor.ORANGE,
        ),
    ])
    return fw.build_plan(snapshot)


def _promote_conflict(plan, *, recompute_mutation_id):
    mutation = plan["mutations"][0]
    mutation["proposed_flag"] = FlagColor.RED.value
    mutation["reason_code"] = "deadline_evidence_red"
    mutation["confidence"] = 1.0
    mutation["review_required"] = False
    mutation["auto_eligible"] = True
    plan["auto_eligible_count"] = 1
    if recompute_mutation_id:
        mutation["mutation_id"] = fw.compute_mutation_id(
            mutation,
            policy_sha256=plan["policy_sha256"],
            snapshot_sha256=plan["snapshot_sha256"],
        )
    plan["plan_hash"] = fw.compute_plan_hash(plan)
    return plan


def test_post_write_ledger_failure_is_reported_honestly(tmp_path):
    harness = Harness(tmp_path, pids=("1",))
    original_record = harness.ledger.record

    def fail_verified_record(record):
        if record.status == ST_VERIFIED:
            raise LedgerCorrupted("simulated fsync failure after provider write")
        original_record(record)

    harness.ledger.record = fail_verified_record
    result = harness.apply()

    assert harness.provider.messages["1"].native == mailapp_index_from_flag(
        FlagColor.RED
    )
    assert result.writes_performed == 1


@pytest.mark.parametrize(
    "field", ["complete", "scope_complete", "zero_write_mode"]
)
def test_snapshot_boolean_strings_fail_closed(tmp_path, field):
    harness = Harness(tmp_path, pids=("1",))
    artifact = harness.snapshot.to_dict()
    artifact[field] = "false"
    artifact["content_hash"] = fw.sha256_hex(
        {key: value for key, value in artifact.items() if key != "content_hash"}
    )
    path = tmp_path / "hostile-snapshot.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")

    with pytest.raises(fw.FlagWorkflowError):
        fw.load_snapshot(path)


def _rehash_plan(plan):
    plan.pop("plan_hash", None)
    plan["plan_hash"] = fw.compute_plan_hash(plan)
    return plan


def test_plan_string_false_auto_eligibility_fails_closed(tmp_path):
    harness = Harness(tmp_path, pids=("1",))
    plan = dict(harness.plan)
    plan["mutations"] = [
        dict(plan["mutations"][0], auto_eligible="false")
    ]
    _rehash_plan(plan)

    with pytest.raises(fw.FlagWorkflowError):
        fw.validate_plan_schema(plan)


@pytest.mark.parametrize(
    "field", ["snapshot_complete", "zero_write_declaration"]
)
def test_plan_safety_declarations_are_enforced(tmp_path, field):
    harness = Harness(tmp_path, pids=("1",))
    plan = dict(harness.plan)
    plan[field] = False
    _rehash_plan(plan)

    with pytest.raises(fw.FlagWorkflowError):
        fw.validate_plan_schema(plan)


def test_hash_valid_conflicting_snapshot_cannot_be_promoted_to_auto_red():
    plan = _conflicting_plan()
    mutation = plan["mutations"][0]
    assert mutation["proposed_flag"] == FlagColor.PURPLE.value
    assert mutation["review_required"] is True
    assert mutation["auto_eligible"] is False

    _promote_conflict(plan, recompute_mutation_id=False)

    with pytest.raises(fw.FlagWorkflowError, match="mutation_id mismatch"):
        fw.validate_plan_schema(plan)


def test_mutation_id_rebinds_a_self_rehashed_reason_change():
    plan = _conflicting_plan()
    mutation = plan["mutations"][0]
    mutation["reason"] = "forged but internally hashed narrative"
    mutation["reason_sha256"] = fw.sha256_hex({
        "schema": "uma.flags.mutation_reason.v1",
        "reason": mutation["reason"],
    })
    plan["plan_hash"] = fw.compute_plan_hash(plan)

    with pytest.raises(fw.FlagWorkflowError, match="mutation_id mismatch"):
        fw.validate_plan_schema(plan)


def test_self_consistent_mutation_id_cannot_override_conflicting_semantics():
    plan = _promote_conflict(
        _conflicting_plan(), recompute_mutation_id=True,
    )

    with pytest.raises(fw.FlagWorkflowError, match="proposed_flag"):
        fw.validate_plan_schema(plan)


def test_public_self_rehash_cannot_override_conflicting_semantics():
    public = fw.to_public_safe_plan(_conflicting_plan())
    mutation = public["mutations"][0]
    mutation["proposed_flag"] = FlagColor.RED.value
    mutation["reason_code"] = "deadline_evidence_red"
    mutation["confidence"] = 1.0
    mutation["review_required"] = False
    mutation["auto_eligible"] = True
    mutation["mutation_id"] = fw.compute_mutation_id(
        mutation,
        policy_sha256=public["policy_sha256"],
        snapshot_sha256=public["snapshot_sha256"],
    )
    public["plan_public_hash"] = fw.sha256_hex({
        key: value
        for key, value in public.items()
        if key != "plan_public_hash"
    })

    with pytest.raises(fw.FlagWorkflowError, match="proposed_flag"):
        fw.validate_public_plan(public)


def test_approval_rederives_semantics_from_detached_mutation():
    plan = _conflicting_plan()
    original = fw.validate_plan_schema(plan)[0]
    forged = replace(
        original,
        proposed_flag=FlagColor.RED,
        reason_code="deadline_evidence_red",
        confidence=1.0,
        review_required=False,
        auto_eligible=True,
    )
    forged = replace(
        forged,
        mutation_id=fw.compute_mutation_id(
            forged.to_dict(),
            policy_sha256=plan["policy_sha256"],
            snapshot_sha256=plan["snapshot_sha256"],
        ),
    )
    approval = fw.ApprovalReceipt.create(
        plan_hash=plan["plan_hash"],
        snapshot_sha256=plan["snapshot_sha256"],
        policy_sha256=plan["policy_sha256"],
        approved_mutation_ids=[forged.mutation_id],
        approving_operator="attacker",
        canary_limit=1,
    )

    with pytest.raises(fw.FlagWorkflowError, match="proposed_flag"):
        approval.validate(plan=plan, plan_mutations=[forged])


def test_transaction_blocks_self_consistent_forgery_before_provider_contact(
        tmp_path):
    harness = Harness(tmp_path, pids=("1",))
    plan = _promote_conflict(
        _conflicting_plan(), recompute_mutation_id=True,
    )
    mutation_id = plan["mutations"][0]["mutation_id"]
    approval = fw.ApprovalReceipt.create(
        plan_hash=plan["plan_hash"],
        snapshot_sha256=plan["snapshot_sha256"],
        policy_sha256=plan["policy_sha256"],
        approved_mutation_ids=[mutation_id],
        approving_operator="attacker",
        canary_limit=1,
    )
    calls_before = list(harness.provider.calls)

    result = harness.engine.apply_transaction(
        plan=plan, approval=approval, provider=harness.provider,
    )

    assert result.status == "blocked"
    assert result.writes_performed == 0
    assert result.error_code.startswith("plan_invalid")
    assert harness.provider.calls == calls_before


def test_transaction_preflight_rederives_detached_mutation_semantics(tmp_path):
    harness = Harness(tmp_path, pids=("1",))
    plan = _conflicting_plan()
    original = fw.validate_plan_schema(plan)[0]
    forged = replace(
        original,
        proposed_flag=FlagColor.RED,
        reason_code="deadline_evidence_red",
        confidence=1.0,
        review_required=False,
        auto_eligible=True,
    )
    forged = replace(
        forged,
        mutation_id=fw.compute_mutation_id(
            forged.to_dict(),
            policy_sha256=plan["policy_sha256"],
            snapshot_sha256=plan["snapshot_sha256"],
        ),
    )
    approval = fw.ApprovalReceipt.create(
        plan_hash=plan["plan_hash"],
        snapshot_sha256=plan["snapshot_sha256"],
        policy_sha256=plan["policy_sha256"],
        approved_mutation_ids=[forged.mutation_id],
        approving_operator="attacker",
        canary_limit=1,
    )
    calls_before = list(harness.provider.calls)

    error = harness.engine.preflight_one(
        harness.provider, plan, forged, approval,
    )

    assert error == "mutation_contract_invalid"
    assert harness.provider.calls == calls_before


@pytest.mark.parametrize(
    ("subject", "semantic_type", "expected_flag"),
    [
        ("Appointment confirmed Tuesday", "event_confirmed", "green"),
        ("Please send the documents", "action_request", "orange"),
        (
            "Payment due tomorrow — account suspension otherwise",
            "action_request", "red",
        ),
        (
            "We received your documents and will respond",
            "awaiting_other_party", "yellow",
        ),
        ("No rush, revisit this in 2 weeks", "deferred_item", "gray"),
        ("Application received", "closed_or_receipt", "no_flag"),
        (
            "Payment receipt for your records",
            "closed_or_receipt", "blue",
        ),
        ("Tracking number 12345", "active_reference", "blue"),
        (
            CONFLICTING_SUBJECT,
            "conflicting_signals", "purple",
        ),
        (
            "Your account requires action",
            "unidentifiable_action", "purple",
        ),
        ("hello there", "unclassifiable", "purple"),
    ],
)
def test_all_canonical_semantic_decisions_round_trip(
        subject, semantic_type, expected_flag):
    plan = fw.build_plan(_snapshot([
        _msg(
            sender="sender@example.com",
            subject=subject,
            color=(
                FlagColor.ORANGE
                if expected_flag != FlagColor.ORANGE.value
                else FlagColor.RED
            ),
        ),
    ]))
    parsed = fw.validate_plan_schema(plan)
    assert parsed[0].classification_proof.semantic_type == semantic_type
    assert parsed[0].proposed_flag.value == expected_flag
    public = fw.to_public_safe_plan(plan)
    fw.validate_public_plan(public)
    assert subject not in json.dumps(public)
