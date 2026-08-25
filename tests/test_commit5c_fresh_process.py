"""Commit 5c acceptance: artifact-only planning must work in a COMPLETELY
FRESH PROCESS — provider codec bootstrapping without any runtime provider
import, construction, connection, enumeration, or osascript execution.

These tests spawn REAL subprocesses; monkeypatching inside pytest's
already-imported interpreter cannot prove fresh-process behavior because
earlier tests silently prime the global validator registry.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from core import flag_workflow as fw
from core.models import FlagColor

REPO_ROOT = Path(__file__).resolve().parents[1]


def _build_snapshot_rows():
    row = SimpleNamespace(
        provider_id="42", account="acct", mailbox="INBOX",
        sender="vip@bank.example", subject="Statement July",
        native_index=0, flag_color=FlagColor.RED,
        received_iso="2026-07-01T00:00:00")
    return [row]


def _valid_snapshot_file(tmp_path):
    """Built by a SUBPROCESS so the parent pytest registry is irrelevant."""
    code = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
from types import SimpleNamespace
from core import flag_workflow as fw
from core.models import FlagColor
row = SimpleNamespace(provider_id="42", account="acct", mailbox="INBOX",
    sender="vip@bank.example", subject="Statement July", native_index=0,
    flag_color=FlagColor.RED, received_iso="2026-07-01T00:00:00")
snap = fw.build_snapshot(provider_name="mailapp", account="acct",
    mailbox="INBOX", rows=[row], complete=True, scope_complete=True,
    status="complete", errors=[], inaccessible_count=0, timeout_count=0,
    unknown_index_count=0, limit=500, since_days=None,
    total_matched=1, returned_count=1, hidden_by_limit=0)
print(fw.write_private_snapshot(snap, fw.Path({str(tmp_path / 'snaps')!r})))
"""
    out = subprocess.run([sys.executable, "-c", code],
                         capture_output=True, text=True, cwd=REPO_ROOT)
    assert out.returncode == 0, out.stderr
    return Path(out.stdout.strip())


def _impossible_pair_snapshot_file(tmp_path):
    """native_index=4 (BLUE) stamped as RED, hash recomputed by the
    'attacker' — must fail closed in the fresh process."""
    valid = _valid_snapshot_file(tmp_path)
    d = json.loads(valid.read_text())
    d.pop("content_hash")
    d["messages"][0]["native_index"] = 4          # BLUE's index
    d["messages"][0]["observed_flag"] = "red"
    d["content_hash"] = fw.sha256_hex(d)
    evil = tmp_path / "evil-snap.json"
    evil.write_text(json.dumps(d))
    return evil


def _sentinel_env(tmp_path):
    """PATH whose `osascript` is a sentinel: records invocation to a marker
    file and exits non-zero. If ANYTHING tries to execute AppleScript, the
    marker appears and the test fails."""
    bindir = tmp_path / "sentinel-bin"
    bindir.mkdir()
    marker = tmp_path / "OSASCRIPT-WAS-INVOKED"
    sentinel = bindir / "osascript"
    sentinel.write_text(
        "#!/bin/sh\n"
        f"touch {shq(marker)}\n"
        "echo 'osascript execution is FORBIDDEN in artifact-only planning' >&2\n"
        "exit 73\n"
    )
    sentinel.chmod(sentinel.stat().st_mode | stat.S_IEXEC)
    env = dict(os.environ)
    env["PATH"] = f"{bindir}{os.pathsep}/usr/bin{os.pathsep}/bin"
    return env, marker


def shq(path):
    return "'" + str(path).replace("'", "'\\''") + "'"


def _run_plan_cli(snapshot_path, output_path, env):
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "cli.py"), "flags", "plan",
         "--snapshot", str(snapshot_path), "--output", str(output_path)],
        capture_output=True, text=True, env=env, cwd=REPO_ROOT)


# --- Required fresh-process tests ------------------------------------------------


class TestFreshProcessArtifactPlanning:
    def test_valid_mailapp_snapshot_plans_without_any_osascript(
            self, tmp_path):
        snap_file = _valid_snapshot_file(tmp_path)
        out_plan = tmp_path / "plan.json"
        env, marker = _sentinel_env(tmp_path)

        proc = _run_plan_cli(snap_file, out_plan, env)

        assert proc.returncode == 0, proc.stderr
        assert out_plan.exists()
        # Plan validates against the strict schema in the parent process.
        plan = json.loads(out_plan.read_text())
        mutations = fw.validate_plan_schema(plan)   # must not raise
        assert len(mutations) == 1
        # The defining assertion: NO Mail.app/osascript interaction.
        assert not marker.exists(), (
            "osascript was invoked during artifact-only planning!")

    def test_impossible_native_pair_fails_closed_in_fresh_process(
            self, tmp_path):
        snap_file = _impossible_pair_snapshot_file(tmp_path)
        env, marker = _sentinel_env(tmp_path)

        proc = _run_plan_cli(snap_file, tmp_path / "never.json", env)

        assert proc.returncode != 0
        assert "maps to" in proc.stderr          # exact-mapping rejection
        assert not (tmp_path / "never.json").exists()
        assert not marker.exists()               # still zero Mail.app contact

    def test_codec_import_is_io_free_and_pulls_no_runtime_provider(self):
        """providers.flag_codecs must be importable WITHOUT dragging in the
        runtime provider module (subprocess proof, not monkeypatching)."""
        code = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
import providers.flag_codecs as fc
assert "providers.mailapp" not in sys.modules, \\
    "codec import pulled in the runtime provider!"
assert fc.flag_from_mailapp_index(4).value == "blue"
assert fc.mailapp_index_from_flag(fc.FlagColor.RED) == 0
assert fc.validate_mailapp_native_pair(None).value == "unknown_unknown" \\
    or fc.validate_mailapp_native_pair(None) == fc.FlagColor.UNKNOWN
assert fc.validate_mailapp_native_pair(99) == fc.FlagColor.UNKNOWN
print("CODEC-CLEAN")
"""
        out = subprocess.run([sys.executable, "-c", code],
                             capture_output=True, text=True, cwd=REPO_ROOT)
        assert out.returncode == 0, out.stderr
        assert "CODEC-CLEAN" in out.stdout

    def test_full_cli_startup_does_not_import_runtime_provider(self,
                                                                tmp_path):
        """`python cli.py flags plan ...` never loads providers.mailapp —
        proven by dumping sys.modules from inside the CLI subprocess."""
        snap_file = _valid_snapshot_file(tmp_path)
        out_plan = tmp_path / "unused-plan.json"
        code = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
sys.argv = ["cli.py", "flags", "plan",
            "--snapshot", {str(snap_file)!r},
            "--output", {str(out_plan)!r}]
import runpy
try:
    runpy.run_path({str(REPO_ROOT / 'cli.py')!r}, run_name="__main__")
except SystemExit as e:
    rc = e.code
loaded = "providers.mailapp" in sys.modules
print(f"RC={{rc}} MAILAPP_LOADED={{loaded}}")
assert loaded is False, "CLI startup imported providers.mailapp!"
"""
        out = subprocess.run([sys.executable, "-c", code],
                             capture_output=True, text=True, cwd=REPO_ROOT)
        assert out.returncode == 0, out.stderr
        assert "MAILAPP_LOADED=False" in out.stdout


# --- Registry hardening -----------------------------------------------------------


class TestRegistryNonOverwriting:
    def test_conflicting_duplicate_registration_rejected(self):
        # Ensure the mailapp codec is registered (fresh-process suite may
        # run before anything else imported it).
        fw._native_validator_for("mailapp")

        def other_validator(native_index):
            return FlagColor.UNKNOWN      # different function object

        with pytest.raises(fw.FlagWorkflowError,
                           match="conflicting registration refused"):
            fw.register_native_flag_validator("mailapp", other_validator)

    def test_identical_idempotent_registration_harmless(self):
        from providers.flag_codecs import validate_mailapp_native_pair
        # Identical function: accepted no-op, registry unchanged.
        fw.register_native_flag_validator("mailapp",
                                          validate_mailapp_native_pair)
        assert fw._native_validator_for("mailapp") is (
            validate_mailapp_native_pair)

    def test_lazy_bootstrap_resolves_without_prior_import(self):
        """Simulate the fresh-process miss path IN-PROCESS by checking the
        declared codec module resolves through the lazy bootstrap."""
        # The mailapp validator is registered by codec import elsewhere in
        # this suite; drop it to exercise the bootstrap branch directly.
        saved = fw._NATIVE_FLAG_VALIDATORS.pop("mailapp", None)
        try:
            validator = fw._native_validator_for("mailapp")
            assert callable(validator)
            assert validator(0) is FlagColor.RED
            assert validator(None) is FlagColor.UNKNOWN
        finally:
            if saved is not None:
                fw._NATIVE_FLAG_VALIDATORS["mailapp"] = saved
