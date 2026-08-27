#!/usr/bin/env python3
"""Reject generated, private-runtime, and merge-residue files in Git.

The repository once accumulated coverage databases, ``*.egg-info`` output,
mailbox cursor/export files, and conflict scratch files.  ``.gitignore`` keeps
new untracked copies quiet; this executable predicate prevents a forced add or
an automated repair branch from reintroducing them.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
from collections.abc import Iterable

EXACT_PATHS = {
    ".coverage": "coverage database",
    "coverage.xml": "coverage report",
    "credentials.json": "credential material",
    "labeler_state.json": "mailbox runtime cursor",
    "mail_export.tsv": "mailbox export",
    "token.pickle": "credential material",
    "config/protected_senders.local.txt": "private sender configuration",
}

GLOB_RULES = (
    (".coverage.*", "coverage database"),
    ("htmlcov/**", "coverage report"),
    (".pytest_cache/**", "test-run cache"),
    (".mypy_cache/**", "type-check cache"),
    (".ruff_cache/**", "lint cache"),
    ("*.egg-info", "generated package metadata"),
    ("*.egg-info/**", "generated package metadata"),
    ("build/**", "package build output"),
    ("dist/**", "package build output"),
    ("__pycache__/**", "Python bytecode cache"),
    ("**/__pycache__/**", "Python bytecode cache"),
    ("*.pyc", "Python bytecode"),
    (".worktrees/**", "nested worktree state"),
    (".claude/worktrees/**", "agent worktree state"),
    (".claude/sessions/**", "agent session state"),
    (".codex/sessions/**", "agent session state"),
    (".serena/**", "agent session state"),
    ("audit/*.jsonl", "private mailbox audit receipt"),
    ("*.log", "runtime log"),
    ("*.db", "runtime database"),
    ("*.db-wal", "runtime database journal"),
    ("*.db-shm", "runtime database shared memory"),
    ("client_secret_*.json", "credential material"),
)


def forbidden_reason(path: str) -> str | None:
    """Return the policy reason when ``path`` must not be tracked."""

    normalized = path.replace("\\", "/").removeprefix("./")
    if normalized in EXACT_PATHS:
        return EXACT_PATHS[normalized]
    if normalized.endswith(".main"):
        return "merge-conflict scratch file"
    if re.fullmatch(r"pr\d+\.txt", normalized):
        return "pull-request scratch marker"
    for pattern, reason in GLOB_RULES:
        if fnmatch.fnmatchcase(normalized, pattern):
            return reason
    return None


def find_forbidden(paths: Iterable[str]) -> list[tuple[str, str]]:
    """Return sorted ``(path, reason)`` pairs for forbidden tracked paths."""

    found = []
    for path in paths:
        reason = forbidden_reason(path)
        if reason is not None:
            found.append((path, reason))
    return sorted(found)


def tracked_paths() -> list[str]:
    """Read the checkout's tracked paths without parsing human Git output."""

    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [
        value.decode("utf-8", errors="surrogateescape")
        for value in completed.stdout.split(b"\0")
        if value
    ]


def main() -> int:
    """Print a bounded violation report and return a predicate exit code."""

    violations = find_forbidden(tracked_paths())
    if not violations:
        print("repository hygiene: PASS")
        return 0

    print("repository hygiene: FAIL")
    for path, reason in violations:
        print(f"- {path}: {reason}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
