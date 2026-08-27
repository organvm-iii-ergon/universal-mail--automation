"""Managed-state output boundaries for the PR #192 activation canary.

Every provider here is an in-memory fake.  No test constructs MailAppProvider
or invokes AppleScript.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import cli
from tests.test_flags_activation import (
    _apply_args,
    _artifact_set,
    _install_provider,
    _provider_must_not_be_constructed,
    _write_calls,
)


@pytest.mark.parametrize(
    ("output_kind", "managed_relative"),
    [
        ("proposal_output", Path("receipts/prior-canary.json")),
        ("proposal_output", Path("plans/prior-plan.json")),
        ("receipt_output", Path("receipts/prior-canary.json")),
    ],
)
def test_optional_output_cannot_overwrite_prior_managed_artifact(
    tmp_path, monkeypatch, capsys, output_kind, managed_relative
):
    artifacts = _artifact_set(tmp_path / "fixture", 1)
    state_dir = tmp_path / "ManagedState"
    prior = state_dir / managed_relative
    prior.parent.mkdir(parents=True, exist_ok=True)
    original = b'{"prior":"rollback authority"}\n'
    prior.write_bytes(original)
    monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
    _provider_must_not_be_constructed(monkeypatch)

    rc = cli.cmd_flags_apply(_apply_args(
        artifacts,
        dry_run=True,
        **{output_kind: str(prior)},
    ))

    assert rc == 20
    assert "managed state" in capsys.readouterr().err
    assert prior.read_bytes() == original
    assert not (state_dir / "ledger").exists()
    assert not (state_dir / "overrides.json").exists()
    assert not (state_dir / "snapshots").exists()
    assert not (state_dir / "approvals").exists()


def test_case_variant_proposal_path_is_still_inside_managed_state(
    tmp_path, monkeypatch, capsys
):
    artifacts = _artifact_set(tmp_path / "fixture", 1)
    state_dir = tmp_path / "ManagedState"
    monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
    _provider_must_not_be_constructed(monkeypatch)

    rc = cli.cmd_flags_apply(_apply_args(
        artifacts,
        dry_run=True,
        proposal_output=str(
            tmp_path / "managedstate" / "receipts" / "proposal.json"
        ),
    ))

    assert rc == 20
    assert "managed state" in capsys.readouterr().err
    assert not state_dir.exists()


def test_custom_receipt_may_use_only_current_canonical_managed_path(
    tmp_path, monkeypatch, capsys
):
    artifacts = _artifact_set(tmp_path / "fixture", 1)
    state_dir = tmp_path / "state"
    canonical = (
        state_dir / "receipts" / f"{artifacts.bundle.canary_id}.json"
    )
    monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
    _install_provider(monkeypatch, artifacts.provider)

    rc = cli.cmd_flags_apply(_apply_args(
        artifacts,
        dry_run=True,
        receipt_output=str(canonical),
    ))

    output = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert output["status"] == "canary_ready_for_approval"
    assert canonical.is_file()
    assert json.loads(canonical.read_text())["schema"] == \
        "uma.flags.canary.rollback_bundle.v2"
    assert _write_calls(artifacts.provider) == []
