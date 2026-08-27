"""Regression tests for the tracked-file hygiene predicate."""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_repository_hygiene import (
    find_forbidden,
    forbidden_reason,
    missing_dockerignore_patterns,
    tracked_paths,
)


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
        ("runtime/token.json", "credential material"),
        ("tmp/client_secret_local.json", "credential material"),
        ("pkg/.coverage", "coverage database"),
        ("pkg/pr130.txt", "pull-request scratch marker"),
        ("pkg/.pytest_cache/v/cache/nodeids", "test-run cache"),
        ("pkg/htmlcov/index.html", "coverage report"),
        ("pkg/build/output.whl", "package build output"),
        ("pkg/project.egg-info/PKG-INFO", "generated package metadata"),
        ("runtime/gmail_state.json", "mailbox runtime cursor"),
        ("runtime/.state.h8w2.tmp", "atomic mailbox state temp file"),
        ("data/customer-export.json", "private application data"),
        (".venv/lib/python/site.py", "virtual environment"),
        ("pkg/env/bin/python", "virtual environment"),
        ("tools/venv/Lib/site-packages/pkg.py", "virtual environment"),
        ("cache/module.pyo", "Python bytecode"),
        ("cache/native.pyd", "Python bytecode"),
        (".outlook_token_cache.json", "OAuth token cache"),
        ("secrets/team_token_cache_prod.json", "OAuth token cache"),
        ("web/cert.pem", "credential material"),
        ("prod.env", "environment secret file"),
        ("deploy/prod.env", "environment secret file"),
        (".env", "environment secret file"),
        ("nested/.env.production", "environment secret file"),
        ("ops/prod.env.local", "environment secret file"),
        ("runtime/mail_report.md", "mailbox report"),
        ("web/out/index.html", "frontend build output"),
        ("web/.next/server/app/index.html", "frontend build output"),
        ("web/node_modules/next/package.json", "frontend dependency output"),
        (".claude/settings.local.json", "personal agent permission settings"),
        ("audit/inbox_sweep-user.json", "private mailbox audit artifact"),
        ("audit/2026/run.csv", "private mailbox audit artifact"),
        ("audit/drafts_sent.json", "private mailbox audit artifact"),
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
        "audit/.gitignore",
        ".codex/plans/2026-08-27-repository-lifecycle-closeout.md",
        "prod.env.example",
        ".env.example",
    ],
)
def test_source_and_evidence_paths_are_allowed(path: str) -> None:
    """Legitimate source and durable evidence paths remain admissible."""

    assert forbidden_reason(path) is None


def test_current_checkout_contains_no_forbidden_tracked_paths() -> None:
    """The exact checkout must satisfy the same predicate enforced in CI."""

    assert find_forbidden(tracked_paths()) == []


def test_dockerignore_mirrors_private_runtime_boundaries() -> None:
    """Docker builds must not re-admit files excluded from source control."""

    assert missing_dockerignore_patterns() == []


def test_missing_dockerignore_patterns_reports_unsafe_context(tmp_path: Path) -> None:
    """A partial Docker ignore file fails the same predicate used in CI."""

    (tmp_path / ".dockerignore").write_text(".git/\n", encoding="utf-8")
    missing = missing_dockerignore_patterns(tmp_path)
    assert "credentials.json" in missing
    assert "*_state.json" in missing
    assert "*.env" in missing


def test_tracked_paths_enumerates_repository_root_from_subdirectory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subdirectory invocation still scans files from the checkout root."""

    monkeypatch.chdir(Path(__file__).resolve().parent)
    paths = tracked_paths()
    assert "pyproject.toml" in paths
    assert "scripts/check_repository_hygiene.py" in paths
