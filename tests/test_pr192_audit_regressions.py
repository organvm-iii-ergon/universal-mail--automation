"""Exact independent-audit regressions for PR #192."""

import json

import pytest

from core import flag_workflow as fw
from core.flag_transactions import LedgerCorrupted, ST_VERIFIED
from core.models import FlagColor
from providers.mailapp import mailapp_index_from_flag
from tests.test_commit6_transactions import Harness


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
