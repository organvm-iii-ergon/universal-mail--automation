"""CLI handler tests for the flags subcommands (thin-layer contract).

These invoke the REAL cmd_* handlers with monkeypatched providers — no
Mail.app, no AppleScript execution. They prove the CLI layer only parses,
delegates, renders, and maps failures to exit codes.
"""

import json

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
        def __init__(self, account=None):
            self.account = account
            self._created_mailboxes = set()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def enumerate_flagged(self, mailbox="INBOX", limit=500,
                              since_days=None, timeout_seconds=600):
            return enumeration or FakeEnumeration()

        def get_message_details(self, message_id):
            return message

    monkeypatch.setattr(cli, "get_provider", lambda name, account=None: FakeProvider(account=account))
    return FakeProvider


class TestFlagsExplainHandler:
    """Carry-forward from Commit 2b review: a GENUINE handler test."""

    def test_explain_renders_semantic_flag_without_native_index(self, monkeypatch, capsys):
        msg = EmailMessage(
            id="42", sender="boss@corp.example", subject="Q3 numbers",
            is_read=False, is_starred=False, flag_color=FlagColor.RED,
        )
        _fake_provider(monkeypatch, message=msg)
        args = type("Args", (), {})()
        args.provider = "mailapp"
        args.account = None
        args.message_ref = "42"
        rc = cli.cmd_flags_explain(args)
        out = capsys.readouterr().out
        assert rc == 0
        assert "Red" in out and "CRITICAL / ACT NOW" in out

    def test_explain_message_not_found_exit_1(self, monkeypatch, capsys):
        _fake_provider(monkeypatch, message=None)
        args = type("Args", (), {})()
        args.provider = "mailapp"
        args.account = None
        args.message_ref = "missing"
        rc = cli.cmd_flags_explain(args)
        assert rc == 1
        assert "not found" in capsys.readouterr().err.lower()

    def test_explain_non_mailapp_provider_rejected(self, monkeypatch):
        args = type("Args", (), {})()
        args.provider = "gmail"
        args.account = None
        args.message_ref = "x"
        assert cli.cmd_flags_explain(args) == 1


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
            scope_complete=True, hidden=3, total_seen=5))
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
        assert "Private snapshot" not in out          # no mixed human text

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