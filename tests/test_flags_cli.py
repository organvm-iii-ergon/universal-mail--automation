"""CLI handler tests for the flags subcommands (thin-layer contract).

These invoke the REAL cmd_* handlers with monkeypatched providers — no
Mail.app, no AppleScript execution. They prove the CLI layer only parses,
delegates, renders, and maps failures to exit codes.
"""

import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

import cli
from core.models import FlagColor, EmailMessage
from core.flag_workflow import SNAPSHOT_SCHEMA


class FakeEnumeration:
    """Builds a REAL providers.mailapp.EnumerationResult via .build() so
    completeness/status semantics have one source of truth."""

    def __init__(self, rows=(), complete=None, errors=None,
                 inaccessible=0, timeouts=0, unknown=0, total_seen=None,
                 hidden=0, scope_complete=None):
        from providers.mailapp import EnumerationResult
        rows = list(rows)
        if scope_complete is None:
            scope_complete = not errors and inaccessible == 0
        if total_seen is None:
            total_seen = len(rows)
        result = EnumerationResult.build(
            rows=rows,
            scope_complete=bool(scope_complete),
            errors=list(errors or []),
            inaccessible_count=inaccessible,
            timeout_count=timeouts,
            unknown_index_count=unknown,
            hidden_by_limit=hidden,
            scanned_boundary={
                "provider": "mailapp", "account": "acct",
                "mailbox": "INBOX", "limit": 500, "since_days": None,
                "ordering": "received_desc",
                "total_flagged_seen": total_seen,
                "returned_count": len(rows),
                "hidden_by_limit": hidden,
            },
        )
        self.__dict__.update({
            "rows": result.rows, "complete": result.complete,
            "scope_complete": result.scope_complete,
            "status": result.status, "errors": result.errors,
            "inaccessible_count": result.inaccessible_count,
            "timeout_count": result.timeout_count,
            "unknown_index_count": result.unknown_index_count,
            "next_cursor": result.next_cursor,
            "scanned_boundary": result.scanned_boundary,
        })
        # Explicit overrides AFTER construction (tests may force shapes).
        if complete is not None:
            self.complete = complete


def _fake_provider(monkeypatch, enumeration=None, message=None):
    from providers.mailapp import MailAppProvider

    class FakeProvider(MailAppProvider):
        seen_refs = []

        def __init__(self, account=None):
            self.account = account
            self._created_mailboxes = set()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def enumerate_flagged(self, mailbox="INBOX", limit=500,
                              since_days=None, timeout_seconds=600,
                              account=None, mailbox_path=None):
            del account, mailbox_path
            return enumeration or FakeEnumeration()

        def discover_surfaces(self, timeout_seconds=300):
            del timeout_seconds
            from providers.mailapp import SurfaceRef
            return [SurfaceRef(account="acct", mailbox="INBOX")]

        def get_message_details_ref(self, message_ref):
            self.seen_refs.append(message_ref)
            return message

    monkeypatch.setattr(cli, "get_provider", lambda name, account=None: FakeProvider(account=account))
    return FakeProvider


def _failing_context_provider(monkeypatch, detail="connection unavailable"):
    """Mail.app-shaped fake whose context entry fails before any read."""
    from providers.mailapp import MailAppProvider

    class FailingProvider(MailAppProvider):
        def __init__(self, account=None):
            self.account = account

        def __enter__(self):
            raise RuntimeError(detail)

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(
        cli,
        "get_provider",
        lambda name, account=None: FailingProvider(account=account),
    )


class TestFlagsExplainHandler:
    """Carry-forward from Commit 2b review: a GENUINE handler test."""

    def test_explain_renders_semantic_flag_without_native_index(self, monkeypatch, capsys):
        msg = EmailMessage(
            id="42", sender="boss@corp.example", subject="Q3 numbers",
            is_read=False, is_starred=False, flag_color=FlagColor.RED,
        )
        fake_type = _fake_provider(monkeypatch, message=msg)
        args = type("Args", (), {})()
        args.provider = "mailapp"
        args.account = "acct"
        args.mailbox = "INBOX"
        args.message_ref = "42"
        rc = cli.cmd_flags_explain(args)
        out = capsys.readouterr().out
        assert rc == 0
        assert "Red" in out and "CRITICAL / ACT NOW" in out
        assert fake_type.seen_refs[-1].account == "acct"
        assert fake_type.seen_refs[-1].mailbox == "INBOX"
        assert fake_type.seen_refs[-1].provider_id == "42"

    def test_explain_message_not_found_exit_1(self, monkeypatch, capsys):
        _fake_provider(monkeypatch, message=None)
        args = type("Args", (), {})()
        args.provider = "mailapp"
        args.account = "acct"
        args.mailbox = "INBOX"
        args.message_ref = "404"
        rc = cli.cmd_flags_explain(args)
        assert rc == 1
        assert "not found" in capsys.readouterr().err.lower()

    def test_explain_non_mailapp_provider_rejected(self, monkeypatch):
        args = type("Args", (), {})()
        args.provider = "gmail"
        args.account = None
        args.mailbox = "INBOX"
        args.message_ref = "x"
        assert cli.cmd_flags_explain(args) == 1

    @pytest.mark.parametrize("message_ref", [
        "1) or true",
        "-1",
        "0",
        "１２",
    ])
    def test_explain_rejects_non_numeric_id_before_provider_construction(
            self, monkeypatch, capsys, message_ref):
        monkeypatch.setattr(
            cli,
            "get_provider",
            lambda *a, **k: pytest.fail("provider must not be constructed"),
        )
        args = type("Args", (), {
            "provider": "mailapp",
            "account": "acct",
            "mailbox": "INBOX",
            "message_ref": message_ref,
        })()
        assert cli.cmd_flags_explain(args) == 1
        assert "numeric" in capsys.readouterr().err

    def test_explain_requires_account_before_provider_construction(
            self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "get_provider",
            lambda *a, **k: pytest.fail("provider must not be constructed"),
        )
        args = type("Args", (), {
            "provider": "mailapp",
            "account": None,
            "mailbox": "INBOX",
            "message_ref": "42",
        })()
        assert cli.cmd_flags_explain(args) == 2
        assert "--account is required" in capsys.readouterr().err

    def test_explain_rejects_empty_mailbox_before_provider_construction(
            self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "get_provider",
            lambda *a, **k: pytest.fail("provider must not be constructed"),
        )
        args = type("Args", (), {
            "provider": "mailapp",
            "account": "acct",
            "mailbox": " ",
            "message_ref": "42",
        })()
        assert cli.cmd_flags_explain(args) == 2
        assert "--mailbox must be non-empty" in capsys.readouterr().err

    def test_explain_connection_failure_is_controlled(
            self, monkeypatch, capsys):
        _failing_context_provider(monkeypatch)
        args = type("Args", (), {
            "provider": "mailapp",
            "account": "acct",
            "mailbox": "INBOX",
            "message_ref": "42",
        })()
        assert cli.cmd_flags_explain(args) == 1
        assert "scoped lookup failed" in capsys.readouterr().err


class TestFlagsAuditHandler:
    def _args(self, **kw):
        defaults = dict(
            provider="mailapp", account="acct", mailbox="INBOX",
            limit=100, since_days=None, flagged_only=True,
            output="table", receipt=None, allow_partial=False,
        )
        defaults.update(kw)
        return type("Args", (), defaults)()

    def test_incomplete_scan_exits_20_without_allow_partial(
            self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        _fake_provider(monkeypatch, FakeEnumeration(complete=False, errors=["timeout"]))
        rc = cli.cmd_flags_audit(self._args())
        err = capsys.readouterr().err
        assert rc == 20
        assert "PARTIAL" in err or "FAILED" in err or "BOUNDED" in err
        # must never claim empty success
        assert "no messages found" not in err.lower()

    def test_incomplete_scan_leaves_durable_failure_receipt(
            self, monkeypatch, capsys, tmp_path):
        """P0 #6: failure evidence is persisted BEFORE the exit-20 gate."""
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        _fake_provider(monkeypatch,
                       FakeEnumeration(complete=False, errors=["boom"]))
        rc = cli.cmd_flags_audit(self._args())
        assert rc == 20
        snaps = list((tmp_path / "snapshots").glob("*.json"))
        assert len(snaps) == 1, "failure receipt missing"
        data = json.loads(snaps[0].read_text())
        assert data["complete"] is False
        assert data["status"] in ("partial", "failed")
        assert data["zero_write_mode"] is True

    def test_bounded_partial_hidden_rows_break_completeness(
            self, monkeypatch, capsys, tmp_path):
        """hidden_by_limit>0 → incomplete + bounded_partial, never plan-grade."""
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        _fake_provider(monkeypatch, FakeEnumeration(
            scope_complete=True, hidden=3, total_seen=3))
        rc = cli.cmd_flags_audit(self._args())     # no --allow-partial
        assert rc == 20
        snap = json.loads((tmp_path / "snapshots").glob("*.json")
                          .__iter__().__next__().read_text())
        assert snap["status"] == "bounded_partial"
        assert snap["hidden_by_limit"] == 3
        assert snap["next_cursor"]

    def test_incomplete_scan_allowed_with_allow_partial(
            self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        _fake_provider(monkeypatch, FakeEnumeration(complete=False, errors=["partial"]))
        rc = cli.cmd_flags_audit(self._args(allow_partial=True))
        assert rc == 0
        err = capsys.readouterr().err
        assert "status: failed" in err   # errors recorded -> honest 'failed'

    def test_json_output_is_pure_machine_readable(
            self, monkeypatch, capsys, tmp_path):
        """Rendering is mutually exclusive: --output json emits ONLY JSON."""
        import json as _json
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        from providers.mailapp import FlaggedRow
        rows = [FlaggedRow(
            provider_id="7", account="acct", mailbox="INBOX",
            sender="s@x.com", subject="Subj", native_index=0,
            flag_color=FlagColor.RED, received_iso=None)]
        _fake_provider(monkeypatch, FakeEnumeration(rows=rows))
        rc = cli.cmd_flags_audit(self._args(output="json"))
        out = capsys.readouterr().out
        assert rc == 0
        parsed = _json.loads(out)          # would fail if table text preceded
        assert parsed["schema"] == SNAPSHOT_SCHEMA

    def test_csv_output_is_pure_csv(
            self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        from providers.mailapp import FlaggedRow
        rows = [FlaggedRow(
            provider_id="7", account="acct", mailbox="INBOX",
            sender="s@x.com", subject="Subj", native_index=0,
            flag_color=FlagColor.RED, received_iso=None)]
        _fake_provider(monkeypatch, FakeEnumeration(rows=rows))
        rc = cli.cmd_flags_audit(self._args(output="csv"))
        out = capsys.readouterr().out
        assert rc == 0
        lines = out.strip().splitlines()
        assert lines[0].startswith("id,sender")       # header row first
        assert "is_read" not in lines[0]
        assert "Private snapshot" not in out          # no mixed human text

    def test_receipt_notice_stays_on_stderr_for_json_output(
            self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path / "state"))
        receipt = tmp_path / "public.json"
        _fake_provider(monkeypatch, FakeEnumeration())
        rc = cli.cmd_flags_audit(self._args(
            output="json",
            receipt=str(receipt),
        ))
        captured = capsys.readouterr()
        assert rc == 0
        json.loads(captured.out)
        assert "receipt written" not in captured.out.lower()
        assert "receipt written" in captured.err.lower()

    def test_writes_private_snapshot_and_public_safe_receipt(
            self, monkeypatch, capsys, tmp_path):
        state_dir = tmp_path / "state"
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
        from providers.mailapp import FlaggedRow
        rows = [
            FlaggedRow(
                provider_id="7", account="acct", mailbox="INBOX",
                sender="vip@bank.example", subject="Statement July",
                native_index=0, flag_color=FlagColor.RED,
                received_iso="2026-07-01T00:00:00",
            ),
        ]
        _fake_provider(monkeypatch, FakeEnumeration(rows=rows))
        receipt_path = tmp_path / "public.json"
        rc = cli.cmd_flags_audit(self._args(receipt=str(receipt_path)))
        assert rc == 0
        # Private snapshot exists under the state dir, mode 0600.
        snaps = list((state_dir / "snapshots").glob("*.json"))
        assert len(snaps) == 1
        mode = snaps[0].stat().st_mode & 0o777
        assert mode == 0o600, f"private snapshot mode {oct(mode)}"
        snap_data = json.loads(snaps[0].read_text())
        assert snap_data["schema"] == SNAPSHOT_SCHEMA
        assert snap_data["zero_write_mode"] is True
        assert snap_data["content_hash"]
        # Public receipt has NO PII.
        public_text = receipt_path.read_text()
        assert "vip@bank.example" not in public_text
        assert "Statement July" not in public_text
        assert '"provider_id"' not in public_text

    def test_complete_empty_scope_says_no_messages_once(
            self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        _fake_provider(monkeypatch, FakeEnumeration(rows=[]))   # complete, none found
        rc = cli.cmd_flags_audit(self._args())
        assert rc == 0
        assert "No flagged messages found in scope." in capsys.readouterr().out

    def test_single_surface_requires_account_before_provider_construction(
            self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "get_provider",
            lambda *a, **k: pytest.fail("provider must not be constructed"),
        )
        rc = cli.cmd_flags_audit(self._args(account=None, estate=False))
        assert rc == 2
        assert "--account is required" in capsys.readouterr().err

    def test_estate_audit_allows_omitted_account(
            self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        _fake_provider(monkeypatch, FakeEnumeration())
        rc = cli.cmd_flags_audit(self._args(account=None, estate=True))
        assert rc == 0
        assert "--account is required" not in capsys.readouterr().err

    def test_connection_failure_persists_failed_snapshot(
            self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        _failing_context_provider(monkeypatch)

        assert cli.cmd_flags_audit(self._args()) == 20

        snapshots = list((tmp_path / "snapshots").glob("*.json"))
        assert len(snapshots) == 1
        payload = json.loads(snapshots[0].read_text(encoding="utf-8"))
        assert payload["complete"] is False
        assert payload["scope_complete"] is False
        assert payload["status"] == "failed"
        assert "connection unavailable" in payload["errors"][0]
        assert "Private evidence snapshot was still written" in (
            capsys.readouterr().err
        )

    def test_invalid_provider_evidence_is_controlled(
            self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path))
        invalid = FakeEnumeration()
        invalid.status = "complete"
        invalid.errors = ["contradiction"]
        _fake_provider(monkeypatch, invalid)

        assert cli.cmd_flags_audit(self._args()) == 20
        assert "invalid scan evidence" in capsys.readouterr().err

    def test_public_receipt_failure_precedes_stdout(
            self, monkeypatch, capsys, tmp_path):
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(tmp_path / "state"))
        _fake_provider(monkeypatch, FakeEnumeration())
        receipt_directory = tmp_path / "receipt-dir"
        receipt_directory.mkdir()

        assert cli.cmd_flags_audit(self._args(
            output="json", receipt=str(receipt_directory)
        )) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "public receipt failed" in captured.err

    def test_empty_mailbox_rejected_before_provider_construction(
            self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "get_provider",
            lambda *a, **k: pytest.fail("provider must not be constructed"),
        )
        assert cli.cmd_flags_audit(self._args(mailbox="")) == 2
        assert "--mailbox must be non-empty" in capsys.readouterr().err


class TestFlagsQueueHandler:
    @staticmethod
    def _args(**overrides):
        defaults = {
            "provider": "mailapp",
            "account": "acct",
            "mailbox": "INBOX",
            "limit": 200,
            "output": "table",
        }
        defaults.update(overrides)
        return type("Args", (), defaults)()

    @staticmethod
    def _row():
        from providers.mailapp import FlaggedRow
        return FlaggedRow(
            provider_id="7",
            account="acct",
            mailbox="INBOX",
            sender="sender@example.com",
            subject="Please review",
            native_index=1,
            flag_color=FlagColor.ORANGE,
            received_iso=None,
        )

    @staticmethod
    def _unknown_row():
        from providers.mailapp import FlaggedRow
        return FlaggedRow(
            provider_id="8",
            account="acct",
            mailbox="INBOX",
            sender="unknown@example.com",
            subject="Native flag needs review",
            native_index=99,
            flag_color=FlagColor.UNKNOWN,
            received_iso=None,
        )

    def test_table_reads_dataclass_attributes(self, monkeypatch, capsys):
        _fake_provider(monkeypatch, FakeEnumeration(rows=[self._row()]))
        assert cli.cmd_flags_queue(self._args()) == 0
        out = capsys.readouterr().out
        assert "sender@example.com" in out
        assert "Please review" in out

    def test_json_keeps_all_queue_keys_and_structured_rows(
            self, monkeypatch, capsys):
        _fake_provider(monkeypatch, FakeEnumeration(rows=[self._row()]))
        assert cli.cmd_flags_queue(self._args(output="json")) == 0
        payload = json.loads(capsys.readouterr().out)
        assert list(payload) == [
            "NOW", "ACTION", "WAITING", "SCHEDULED", "REFERENCE",
            "REVIEW", "LATER", "UNKNOWN",
        ]
        assert payload["ACTION"][0]["id"] == "7"
        assert payload["ACTION"][0]["flag_color"] == "orange"
        assert isinstance(payload["ACTION"][0], dict)

    def test_unknown_rows_are_explicit_not_silently_dropped(
            self, monkeypatch, capsys):
        row = self._unknown_row()
        _fake_provider(
            monkeypatch,
            FakeEnumeration(rows=[row], unknown=1),
        )
        assert cli.cmd_flags_queue(self._args(output="json")) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["UNKNOWN"] == [{
            "id": "8",
            "account": "acct",
            "mailbox": "INBOX",
            "sender": "unknown@example.com",
            "subject": "Native flag needs review",
            "native_index": 99,
            "flag_color": "unknown",
            "received_iso": None,
        }]

    def test_incomplete_enumeration_is_refused(self, monkeypatch, capsys):
        _fake_provider(
            monkeypatch,
            FakeEnumeration(errors=["enumeration failed"]),
        )
        assert cli.cmd_flags_queue(self._args()) == 20
        assert "refusing failed enumeration" in capsys.readouterr().err

    def test_account_is_required_before_provider_construction(
            self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "get_provider",
            lambda *a, **k: pytest.fail("provider must not be constructed"),
        )
        assert cli.cmd_flags_queue(self._args(account=None)) == 2
        assert "--account is required" in capsys.readouterr().err

    def test_connection_failure_is_controlled(self, monkeypatch, capsys):
        _failing_context_provider(monkeypatch)
        assert cli.cmd_flags_queue(self._args()) == 1
        assert "enumeration failed" in capsys.readouterr().err

    def test_empty_mailbox_rejected_before_provider_construction(
            self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "get_provider",
            lambda *a, **k: pytest.fail("provider must not be constructed"),
        )
        assert cli.cmd_flags_queue(self._args(mailbox="")) == 2
        assert "--mailbox must be non-empty" in capsys.readouterr().err


class TestFlagsOverridesHandler:
    @staticmethod
    def _args(**overrides):
        defaults = {
            "provider": "mailapp",
            "account": "acct",
            "mailbox": "INBOX",
            "limit": 200,
        }
        defaults.update(overrides)
        return type("Args", (), defaults)()

    def test_incomplete_enumeration_is_refused(self, monkeypatch, capsys):
        _fake_provider(
            monkeypatch,
            FakeEnumeration(timeouts=1, scope_complete=False),
        )
        assert cli.cmd_flags_overrides(self._args()) == 20
        assert "refusing timed_out enumeration" in capsys.readouterr().err

    def test_account_is_required_before_provider_construction(
            self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "get_provider",
            lambda *a, **k: pytest.fail("provider must not be constructed"),
        )
        assert cli.cmd_flags_overrides(self._args(account=None)) == 2
        assert "--account is required" in capsys.readouterr().err

    def test_connection_failure_is_controlled(self, monkeypatch, capsys):
        _failing_context_provider(monkeypatch)
        assert cli.cmd_flags_overrides(self._args()) == 1
        assert "enumeration failed" in capsys.readouterr().err

    def test_empty_mailbox_rejected_before_provider_construction(
            self, monkeypatch, capsys):
        monkeypatch.setattr(
            cli,
            "get_provider",
            lambda *a, **k: pytest.fail("provider must not be constructed"),
        )
        assert cli.cmd_flags_overrides(self._args(mailbox="")) == 2
        assert "--mailbox must be non-empty" in capsys.readouterr().err


class TestFlagsPlanArtifactBoundary:
    def test_malformed_snapshot_json_is_controlled_error(
            self, tmp_path, capsys):
        snapshot = tmp_path / "broken.json"
        snapshot.write_text("{truncated", encoding="utf-8")
        output = tmp_path / "plan.json"
        args = type("Args", (), {
            "snapshot": str(snapshot),
            "output": str(output),
        })()
        assert cli.cmd_flags_plan(args) == 20
        assert "flags plan:" in capsys.readouterr().err
        assert not output.exists()

    def test_private_plan_is_written_mode_0600(
            self, monkeypatch, capsys, tmp_path):
        state_dir = tmp_path / "state"
        monkeypatch.setenv("UMA_FLAGS_STATE_DIR", str(state_dir))
        _fake_provider(monkeypatch, FakeEnumeration())
        audit_args = TestFlagsAuditHandler()._args()
        assert cli.cmd_flags_audit(audit_args) == 0
        capsys.readouterr()
        snapshot = next((state_dir / "snapshots").glob("*.json"))
        output = tmp_path / "private" / "plan.json"
        plan_args = type("Args", (), {
            "snapshot": str(snapshot),
            "output": str(output),
        })()
        assert cli.cmd_flags_plan(plan_args) == 0
        assert output.stat().st_mode & 0o777 == 0o600


class TestFlagsParserContracts:
    @staticmethod
    def _run(*args):
        return subprocess.run(
            [sys.executable, str(Path(cli.__file__).resolve()), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    @pytest.mark.parametrize("args", [
        ("flags", "--provider", "mailapp", "apply", "--plan", "x.json"),
        ("flags", "apply", "--provider", "mailapp", "--plan", "x.json"),
    ])
    def test_provider_options_work_on_either_side(self, args):
        result = self._run(*args)
        assert result.returncode == 89
        assert "NOT_READY" in result.stderr

    @pytest.mark.parametrize("args", [
        (
            "flags", "--provider", "mailapp", "--account", "acct",
            "explain", "not-numeric",
        ),
        (
            "flags", "explain", "--provider", "mailapp", "--account",
            "acct", "not-numeric",
        ),
    ])
    def test_provider_option_placement_reaches_scoped_handler(self, args):
        result = self._run(*args)
        assert result.returncode == 1
        assert "message reference must be a numeric Mail.app id" in result.stderr

    def test_missing_flags_subcommand_prints_usage_and_exits_2(self):
        result = self._run("flags")
        assert result.returncode == 2
        assert "usage:" in result.stderr.lower()

    @pytest.mark.parametrize("args", [
        (
            "flags", "audit", "--provider", "mailapp", "--account", "acct",
            "--since-days", "-1",
        ),
        (
            "flags", "audit", "--provider", "mailapp", "--account", "acct",
            "--limit", "0",
        ),
        (
            "flags", "queue", "--provider", "mailapp", "--account", "acct",
            "--limit", "-2",
        ),
        (
            "flags", "overrides", "--provider", "mailapp",
            "--account", "acct", "--limit", "0",
        ),
    ])
    def test_nonpositive_scan_bounds_exit_2_during_parsing(self, args):
        result = self._run(*args)
        assert result.returncode == 2
        assert "positive integer" in result.stderr

    @pytest.mark.parametrize("subcommand", [
        "audit", "queue", "overrides", "explain",
    ])
    def test_empty_mailbox_exits_2_during_parsing(self, subcommand):
        args = [
            "flags", subcommand, "--provider", "mailapp",
            "--account", "acct", "--mailbox", "",
        ]
        if subcommand == "explain":
            args.append("42")
        result = self._run(*args)
        assert result.returncode == 2
        assert "expected a non-empty value" in result.stderr


class TestStarCapabilityConstructionGates:
    class _Provider:
        from providers.base import ProviderCapabilities

        name = "fake"
        capabilities = ProviderCapabilities.TRUE_LABELS

        def __init__(self, message):
            self.message = message
            self.actions = []

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def list_messages(self, **kwargs):
            from providers.base import ListMessagesResult
            return ListMessagesResult(messages=[self.message])

        def get_message_details(self, message_id):
            return self.message

        def apply_actions(self, actions, audit=None):
            from core.models import ProcessingResult
            self.actions.extend(actions)
            return ProcessingResult(success_count=len(actions))

    @staticmethod
    def _classification():
        tier = SimpleNamespace(
            name="Critical",
            color="red",
            folder=None,
            star=True,
            keep_in_inbox=True,
        )
        return SimpleNamespace(
            is_vip=False,
            label="Priority",
            tier_config=tier,
            tier=1,
            vip_note="",
            time_sensitive=True,
        )

    @pytest.mark.parametrize("tier_routing", [False, True])
    def test_labeler_never_builds_star_action_without_capability(
            self, monkeypatch, tier_routing):
        message = EmailMessage(
            id="1",
            sender="sender@example.com",
            subject="Please respond",
        )
        provider = self._Provider(message)
        monkeypatch.setattr(
            cli,
            "categorize_with_tier",
            lambda *a: self._classification(),
        )
        monkeypatch.setattr(cli, "should_star", lambda label: True)
        monkeypatch.setattr(cli, "should_keep_in_inbox", lambda label: True)
        monkeypatch.setattr(cli.time, "sleep", lambda seconds: None)

        cli.run_labeler(
            provider=provider,
            query="",
            limit=1,
            dry_run=False,
            remove_label=None,
            state_file=None,
            tier_routing=tier_routing,
        )

        assert len(provider.actions) == 1
        assert provider.actions[0].star is False

    def test_escalation_never_builds_star_action_without_capability(
            self, monkeypatch, capsys):
        message = EmailMessage(
            id="1",
            sender="sender@example.com",
            subject="Please respond",
            date=None,
        )
        provider = self._Provider(message)
        classification = self._classification()
        monkeypatch.setattr(cli, "get_provider", lambda *a, **k: provider)
        monkeypatch.setattr(cli, "load_config", lambda: SimpleNamespace())
        monkeypatch.setattr(
            cli,
            "apply_vip_senders_from_config",
            lambda config: 0,
        )
        monkeypatch.setattr(cli, "_make_audit", lambda *a, **k: None)
        monkeypatch.setattr(
            cli,
            "categorize_with_tier",
            lambda *a: classification,
        )
        monkeypatch.setattr(cli, "calculate_email_age_hours", lambda date: 99)
        monkeypatch.setattr(
            cli,
            "escalate_by_age",
            lambda **kwargs: SimpleNamespace(
                should_escalate=True,
                escalated_tier=1,
                original_tier=2,
                reason="stale",
            ),
        )
        monkeypatch.setattr(
            cli,
            "get_tier_config",
            lambda tier: classification.tier_config,
        )
        args = type("Args", (), {
            "provider": "fake",
            "host": None,
            "user": None,
            "password": None,
            "account": None,
            "gmail_extensions": False,
            "query": "",
            "limit": 1,
            "dry_run": False,
        })()

        assert cli.cmd_escalate(args) == 0
        capsys.readouterr()
        assert len(provider.actions) == 1
        assert provider.actions[0].star is False


class TestMutationGatesRemainDisabled:
    @pytest.mark.parametrize("handler,args_attr,value", [
        ("cmd_flags_apply", "plan", "/nonexistent.json"),
        ("cmd_flags_rollback", "receipt", "/nonexistent.json"),
    ])
    def test_not_ready_exit_89(self, handler, args_attr, value, capsys):
        args = type("Args", (), {})()
        args.provider = "mailapp"
        setattr(args, args_attr, value)
        rc = getattr(cli, handler)(args)
        err = capsys.readouterr().err
        assert rc == 89
        assert "NOT_READY" in err


class TestDoctorLayerContract:
    def test_connection_failure_is_controlled(self, monkeypatch, capsys):
        _failing_context_provider(monkeypatch)
        args = type("Args", (), {
            "provider": "mailapp",
            "account": "acct",
        })()

        assert cli.cmd_flags_doctor(args) == 1
        assert "connection failed" in capsys.readouterr().err

    def test_doctor_never_calls_list_messages(self, monkeypatch, capsys):
        from providers.base import ProviderCapabilities
        calls = []

        class SpyProvider:
            name = "mailapp"
            capabilities = ProviderCapabilities.COLORED_FLAGS

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def list_messages(self, *a, **k):     # MUST NOT be called
                calls.append(("list_messages", a, k))
                raise AssertionError("doctor called unbounded list_messages")

        monkeypatch.setattr(cli, "get_provider", lambda *a, **k: SpyProvider())
        args = type("Args", (), {})()
        args.provider = "mailapp"
        args.account = None
        rc = cli.cmd_flags_doctor(args)
        out = capsys.readouterr().out
        assert calls == []
        assert rc == 0
        assert "not live-tested" in out.lower()
        assert "NOT performed" in out
