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
from pathlib import Path

EXACT_PATHS = {
    ".claude/settings.local.json": "personal agent permission settings",
    "config/protected_senders.local.txt": "private sender configuration",
}

FORBIDDEN_BASENAMES = {
    ".coverage": "coverage database",
    "coverage.xml": "coverage report",
    "credentials.json": "credential material",
    "labeler_state.json": "mailbox runtime cursor",
    "mail_export.tsv": "mailbox export",
    "mail_report.md": "mailbox report",
    "protected_senders.local.txt": "private sender configuration",
    "token.pickle": "credential material",
}

SENSITIVE_BASENAME_GLOBS = (
    ("client_secret_*.json", "credential material"),
    ("*token_cache*.json", "OAuth token cache"),
)

GLOB_RULES = (
    (".coverage.*", "coverage database"),
    ("htmlcov/**", "coverage report"),
    (".pytest_cache/**", "test-run cache"),
    (".mypy_cache/**", "type-check cache"),
    (".ruff_cache/**", "lint cache"),
    ("*_state.json", "mailbox runtime cursor"),
    ("*.egg-info", "generated package metadata"),
    ("*.egg-info/**", "generated package metadata"),
    ("build/**", "package build output"),
    ("dist/**", "package build output"),
    (".venv/**", "virtual environment"),
    ("env/**", "virtual environment"),
    ("venv/**", "virtual environment"),
    ("__pycache__/**", "Python bytecode cache"),
    ("**/__pycache__/**", "Python bytecode cache"),
    ("*.pyc", "Python bytecode"),
    ("*.pyo", "Python bytecode"),
    ("*.pyd", "Python bytecode"),
    ("node_modules/**", "frontend dependency output"),
    ("web/.next/**", "frontend build output"),
    ("web/out/**", "frontend build output"),
    (".worktrees/**", "nested worktree state"),
    (".claude/worktrees/**", "agent worktree state"),
    (".claude/sessions/**", "agent session state"),
    (".codex/sessions/**", "agent session state"),
    (".serena/**", "agent session state"),
    ("audit/*.jsonl", "private mailbox audit receipt"),
    ("data/**", "private application data"),
    ("*.log", "runtime log"),
    ("*.db", "runtime database"),
    ("*.db-wal", "runtime database journal"),
    ("*.db-shm", "runtime database shared memory"),
)

DOCKERIGNORE_REQUIRED_PATTERNS = frozenset(
    {
        ".git/",
        "credentials.json",
        "token.pickle",
        "client_secret_*.json",
        "*token_cache*.json",
        "config/protected_senders.local.txt",
        ".env",
        ".env.*",
        "*.env",
        "*.env.*",
        "!.env.example",
        "!*.env.example",
        "*_state.json",
        "audit/",
        "mail_export.tsv",
        "mail_report.md",
        "data/",
        "*.db",
        "*.db-wal",
        "*.db-shm",
        "*.log",
        ".venv/",
        "env/",
        "venv/",
        "node_modules/",
        "web/node_modules/",
        "web/.next/",
        "web/out/",
        ".claude/",
        ".codex/",
        ".worktrees/",
        ".serena/",
    }
)


def forbidden_reason(path: str) -> str | None:
    """Return the policy reason when ``path`` must not be tracked."""

    normalized = path.replace("\\", "/").removeprefix("./")
    if normalized in EXACT_PATHS:
        return EXACT_PATHS[normalized]
    basename = normalized.rsplit("/", 1)[-1]
    if basename in FORBIDDEN_BASENAMES:
        return FORBIDDEN_BASENAMES[basename]
    is_public_env_example = basename == ".env.example" or basename.endswith(
        ".env.example"
    )
    if not is_public_env_example and (
        basename == ".env"
        or basename.startswith(".env.")
        or basename.endswith(".env")
        or ".env." in basename
    ):
        return "environment secret file"
    for pattern, reason in SENSITIVE_BASENAME_GLOBS:
        if fnmatch.fnmatchcase(basename, pattern):
            return reason
    if basename.endswith(".main"):
        return "merge-conflict scratch file"
    if re.fullmatch(r"pr\d+\.txt", basename):
        return "pull-request scratch marker"
    for pattern, reason in GLOB_RULES:
        if fnmatch.fnmatchcase(normalized, pattern) or fnmatch.fnmatchcase(
            normalized, f"*/{pattern}"
        ):
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


def repository_root() -> str:
    """Resolve the checkout root even when invoked from a subdirectory."""

    completed = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def tracked_paths() -> list[str]:
    """Read the checkout's tracked paths without parsing human Git output."""

    completed = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
        cwd=repository_root(),
    )
    return [
        value.decode("utf-8", errors="surrogateescape")
        for value in completed.stdout.split(b"\0")
        if value
    ]


def missing_dockerignore_patterns(root: str | Path | None = None) -> list[str]:
    """Return required private/runtime patterns absent from ``.dockerignore``."""

    checkout = Path(root) if root is not None else Path(repository_root())
    dockerignore = checkout / ".dockerignore"
    if not dockerignore.is_file():
        return sorted(DOCKERIGNORE_REQUIRED_PATTERNS)
    active_patterns = {
        line.strip()
        for line in dockerignore.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    return sorted(DOCKERIGNORE_REQUIRED_PATTERNS - active_patterns)


def main() -> int:
    """Print a bounded violation report and return a predicate exit code."""

    violations = find_forbidden(tracked_paths())
    missing_dockerignore = missing_dockerignore_patterns()
    if not violations and not missing_dockerignore:
        print("repository hygiene: PASS")
        return 0

    print("repository hygiene: FAIL")
    for path, reason in violations:
        print(f"- {path}: {reason}")
    for pattern in missing_dockerignore:
        print(f"- .dockerignore: missing required pattern {pattern}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
