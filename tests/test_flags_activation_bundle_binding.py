"""Regression tests for exact canary rollback-bundle binding."""

from __future__ import annotations

from pathlib import Path

import cli
from core.flag_activation import CanaryRollbackBundle, load_canary_rollback
from core.flag_workflow import FlagWorkflowError, sha256_hex
from tests.test_flags_activation import (
    _artifact_set,
    _provider_must_not_be_constructed,
    _rollback_args,
    _write_json,
)


def _rehash(value: dict) -> dict:
    result = dict(value)
    result.pop("content_hash", None)
    result["content_hash"] = sha256_hex(result)
    return result


def _self_rehashed_subset_bundle(artifacts) -> dict:
    bundle = artifacts.bundle.to_dict()
    bundle["receipts"] = bundle["receipts"][:1]
    mutation_ids = [
        receipt["mutation_id"] for receipt in bundle["receipts"]
    ]
    bundle["canary_id"] = "canary-" + sha256_hex({
        "plan_sha256": bundle["plan_sha256"],
        "approval_sha256": bundle["approval_sha256"],
        "mutation_ids": sorted(mutation_ids),
    })[:32]
    return _rehash(bundle)


def test_self_rehashed_subset_is_internally_valid_but_not_approved_set(
    tmp_path: Path,
):
    artifacts = _artifact_set(tmp_path, 3)
    hostile = _self_rehashed_subset_bundle(artifacts)
    hostile_path = _write_json(
        artifacts.root / "subset-rollback.json", hostile
    )

    parsed = CanaryRollbackBundle.from_dict(hostile)
    assert len(parsed.receipts) == 1

    try:
        load_canary_rollback(
            plan_path=artifacts.plan_path,
            snapshot_path=artifacts.snapshot_path,
            approval_path=artifacts.approval_path,
            receipt_path=hostile_path,
        )
    except FlagWorkflowError as exc:
        assert "exact approved activation set" in str(exc)
    else:  # pragma: no cover - explicit safety assertion
        raise AssertionError("self-rehashed subset bundle was admitted")


def test_cli_rejects_self_rehashed_subset_before_provider_construction(
    tmp_path: Path, monkeypatch,
):
    artifacts = _artifact_set(tmp_path, 3)
    hostile_path = _write_json(
        artifacts.root / "subset-rollback.json",
        _self_rehashed_subset_bundle(artifacts),
    )
    _provider_must_not_be_constructed(monkeypatch)

    rc = cli.cmd_flags_rollback(_rollback_args(
        artifacts,
        hostile_path,
        approval=str(artifacts.approval_path),
    ))

    assert rc == 20


def test_cli_requires_original_approval_before_provider_construction(
    tmp_path: Path, monkeypatch,
):
    artifacts = _artifact_set(tmp_path, 1)
    _provider_must_not_be_constructed(monkeypatch)

    rc = cli.cmd_flags_rollback(_rollback_args(
        artifacts,
        artifacts.bundle_path,
        approval=None,
    ))

    assert rc == 20


def test_self_rehashed_noncanonical_transaction_id_is_rejected(
    tmp_path: Path,
):
    artifacts = _artifact_set(tmp_path, 1)
    hostile = artifacts.bundle.to_dict()
    receipt = dict(hostile["receipts"][0])
    receipt["transaction_id"] = "tx-" + ("0" * 24)
    hostile["receipts"] = [_rehash(receipt)]
    hostile = _rehash(hostile)

    try:
        CanaryRollbackBundle.from_dict(hostile)
    except FlagWorkflowError as exc:
        assert "transaction id is not canonical" in str(exc)
    else:  # pragma: no cover - explicit safety assertion
        raise AssertionError("noncanonical transaction id was admitted")
