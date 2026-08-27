"""Regression tests for the tracked-file hygiene predicate."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_repository_hygiene import find_forbidden, forbidden_reason, tracked_paths


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        (".coverage", "coverage database"),
        ("universal_mail_automation.egg-info/PKG-INFO", "generated package metadata"),
        ("api/schemas.py.main", "merge-conflict scratch file"),
        ("pr130.txt", "pull-request scratch marker"),
        ("mail_export.tsv", "mailbox export"),
        (".worktrees/topic", "nested worktree state"),
        ("__pycache__/module.cpython-313.pyc", "Python bytecode cache"),
        ("core/__pycache__/module.cpython-313.pyc", "Python bytecode cache"),
        (".pytest_cache/v/cache/nodeids", "test-run cache"),
        ("config/protected_senders.local.txt", "private sender configuration"),
        ("nested/credentials.json", "credential material"),
        ("runtime/token.pickle", "credential material"),
        ("tmp/client_secret_local.json", "credential material"),
    ],
)
def test_forbidden_paths_are_classified(path: str, reason: str) -> None:
    """Every generated, private, or scratch example has a stable reason."""

    assert forbidden_reason(path) == reason


@pytest.mark.parametrize(
    "path",
    [
        "docs/reviews/reconciliation.md",
        "tests/test_repository_hygiene.py",
        "uv.lock",
        "audit/README.md",
        ".codex/plans/2026-08-27-repository-lifecycle-closeout.md",
    ],
)
def test_source_and_evidence_paths_are_allowed(path: str) -> None:
    """Legitimate source and durable evidence paths remain admissible."""

    assert forbidden_reason(path) is None


def test_current_checkout_contains_no_forbidden_tracked_paths() -> None:
    """The exact checkout must satisfy the same predicate enforced in CI."""

    assert find_forbidden(tracked_paths()) == []


def test_tracked_paths_enumerates_repository_root_from_subdirectory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subdirectory invocation still scans files from the checkout root."""

    monkeypatch.chdir(Path(__file__).resolve().parent)
    paths = tracked_paths()
    assert "pyproject.toml" in paths
    assert "scripts/check_repository_hygiene.py" in paths
