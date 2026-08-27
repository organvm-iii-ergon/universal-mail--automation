"""Regression tests for the tracked-file hygiene predicate."""

from __future__ import annotations

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
    ],
)
def test_forbidden_paths_are_classified(path: str, reason: str) -> None:
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
    assert forbidden_reason(path) is None


def test_current_checkout_contains_no_forbidden_tracked_paths() -> None:
    assert find_forbidden(tracked_paths()) == []
