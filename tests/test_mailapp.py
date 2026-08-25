"""Mail.app provider regressions."""

from datetime import datetime

import pytest

from core.models import FlagColor, LabelAction
from providers.mailapp import (
    MailAppProvider,
    MAILAPP_INDEX_TO_FLAG,
    MAILAPP_FLAG_TO_INDEX,
    flag_from_mailapp_index,
    mailapp_index_from_flag,
    _FIELD_SEP,
    _HDR_SEP,
)


def _canned_list_output(rows):
    """Build the exact osascript stdout list_messages parses: one line per message with
    unit-separator (\\x1f) columns, header lines joined by record-separator (\\x1e), plus
    the trailing ---TOTAL: sentinel. `rows` is a list of
    (id, sender, subject, is_read, is_flagged, flag_index, [header_lines])."""
    lines = []
    for r in rows:
        mid, sender, subject, read, flagged = r[0], r[1], r[2], r[3], r[4]
        flag_index = r[5] if len(r) > 5 else "-1"
        hdr_lines = r[6] if len(r) > 6 else []
        bulk = _HDR_SEP.join(hdr_lines)
        lines.append(_FIELD_SEP.join([mid, sender, subject, read, flagged, flag_index, bulk]))
    return "\n".join(lines) + f"\n---TOTAL:{len(rows)}"


def test_list_messages_captures_bulk_headers():
    provider = MailAppProvider()
    provider._run_applescript = lambda script: _canned_list_output([
        ("1", "Feross Aboukhadijeh <feross@socket.dev>", "Socket Weekly", "false", "false", "-1",
         ["List-Unsubscribe: <https://socket.dev/unsub>"]),
        ("2", "User One <user.one@example.com>", "Legal Matter (Depositions)",
         "false", "false", "-1", []),
    ])

    result = provider.list_messages(limit=10)
    by_id = {m.id: m for m in result.messages}

    # Bulk newsletter carries the header; personal message carries none (fail-open).
    assert by_id["1"].headers.get("list-unsubscribe") == "<https://socket.dev/unsub>"
    assert by_id["2"].headers == {}


def test_bulk_headers_flow_end_to_end_to_obligation(tmp_path):
    """The full live path: provider fetch -> receipt row -> obligations_build. A swept
    message carrying List-Unsubscribe becomes a cls=bulk no-reply obligation; a personal
    message with no bulk headers stays reply-owed. Uses the real reported cases as fixtures."""
    import json
    import inbox_sweep
    from obligations_build import build

    # The 8 real cases: 5 junk (bulk-headered) suppressed; 3 real kept reply-owed.
    JUNK = [
        ("j1", "Feross Aboukhadijeh <feross@socket.dev>", "Socket Weekly",
         ["List-Unsubscribe: <https://socket.dev/unsub>"]),
        ("j2", "Hello Developer <developer@insideapple.apple.com>", "Hello Developer",
         ["List-Id: Hello Developer <hello.apple.com>"]),
        ("j3", "Laughing Buddha Comedy <laughingbuddhacomedy@buytickets.at>",
         "Your ticket confirmation", ["List-Unsubscribe: <mailto:u@buytickets.at>"]),
        ("j4", "Naga Saikumar <naga.saikumar@stage4solutions.com>", "Exciting opportunity",
         ["Precedence: bulk"]),
        ("j5", "ML <ml@ceiamerica.com>", "Quick check-in",
         ["List-Unsubscribe: <https://ceiamerica.com/unsub>"]),
    ]
    REAL = [
        ("r1", "User One <user.one@example.com>", "Legal Matter (Depositions)"),
        ("r2", "User Two <user.two@example.com>", "Air Space Intelligence interview"),
        ("r3", "User Three <user.three@example.com>", "quick question on FastMCP + auth"),
    ]
    rows = []
    for mid, sender, subject, hdrs in JUNK:
        rows.append((mid, sender, subject, "false", "false", "-1", hdrs))
    for mid, sender, subject in REAL:
        rows.append((mid, sender, subject, "false", "false", "-1", []))

    provider = MailAppProvider()
    provider._run_applescript = lambda script: _canned_list_output(rows)

    swept = inbox_sweep.classify_inbox(provider, "INBOX", limit=50)
    # Force every swept row to surface as a fire so it reaches the obligation cascade
    # (isolates the bulk-vs-precedent decision from the archive/keep triage).
    for r in swept:
        r["action"] = "fire"

    receipt = {"result": {"account": "acct", "total": len(swept)}, "rows": swept}
    (tmp_path / "inbox_sweep-acct.json").write_text(json.dumps(receipt), encoding="utf-8")

    ledger = build(str(tmp_path))
    reply_owed = {o["domain"] for o in ledger["obligations"] if o["requires_reply"]}
    bulk = {o["domain"] for o in ledger["obligations"] if o["cls"] == "bulk"}

    # Every junk sender suppressed to bulk; NONE of them reply-owed.
    for dom in ("socket.dev", "insideapple.apple.com", "buytickets.at",
                "stage4solutions.com", "ceiamerica.com"):
        assert dom in bulk, dom
        assert dom not in reply_owed, dom
    # The 3 real senders stay reply-owed.
    for dom in ("example.com", "example.com", "example.com"):
        assert dom in reply_owed, dom


def test_mailapp_star_accepts_due_date_from_base_apply_actions():
    provider = MailAppProvider()
    scripts = []
    provider._run_applescript = lambda script: scripts.append(script) or "ok"

    result = provider.apply_actions([
        LabelAction(
            message_id="123",
            sender="promo@some-shop.example",
            star=True,
            due_date=datetime(2026, 6, 1),
        )
    ])

    assert result.error_count == 0
    assert result.success_count == 1
    assert scripts and "flagged status" in scripts[0]


# --- bounded archive enumeration (the archive-timeout fix) ---------------------------------

def test_build_list_script_unbounded_full_scans_oldest_first():
    """The hot INBOX path is unchanged: full `messages of targetMailbox`, oldest-first slice,
    NO date predicate. This is the regression guard that the fix stayed additive."""
    script = MailAppProvider(account="user@icloud.example.com")._build_list_script(
        "INBOX", start_offset=0, limit=50, since_days=None)
    assert "set allMsgs to messages of targetMailbox" in script
    assert "whose date received" not in script
    assert "repeat with i from 1 to ((0 + 50))" in script   # oldest-first, offset+limit
    assert 'of account "user@icloud.example.com"' in script


def test_build_list_script_bounded_uses_date_predicate_newest_first():
    """since_days ⇒ a server-side `whose date received > cutoff` predicate (bounds what Mail.app
    materializes) walked NEWEST-first (`by -1`). This is the whole fix — the archive is never
    fully materialized, so a large All-Mail can't time out."""
    script = MailAppProvider(account="user@icloud.example.com")._build_list_script(
        "Archive", start_offset=0, limit=500, since_days=180)
    assert "whose date received > cutoffDate" in script
    assert "set cutoffDate to (current date) - (180 * days)" in script
    assert "by -1" in script                       # newest-first tail walk
    assert "set hiIdx to totalMsgs - 0" in script  # offset 0 ⇒ start at the newest
    assert "set loIdx to hiIdx - 500 + 1" in script
    # It must NOT full-materialize the whole mailbox.
    assert "set allMsgs to messages of targetMailbox\n" not in script


def test_build_list_script_bounded_offset_pages_newest_first():
    """A non-zero offset shifts the newest-first window down by that many messages, so
    classify_inbox's 50-at-a-time pagination walks strictly older each page."""
    script = MailAppProvider()._build_list_script(
        "Archive", start_offset=50, limit=50, since_days=90)
    assert "set hiIdx to totalMsgs - 50" in script
    assert "set loIdx to hiIdx - 50 + 1" in script
    assert "set cutoffDate to (current date) - (90 * days)" in script


def test_list_messages_bounded_passes_generous_timeout_unbounded_keeps_default():
    """Non-breaking-signature guard: the bounded path passes timeout=900; the unbounded path
    calls _run_applescript with the SAME one-arg shape as before (so 1-arg mocks/callers
    never break). This is why adding the kwarg didn't regress the hot path."""
    provider = MailAppProvider(account="user@icloud.example.com")
    calls = []

    def fake(script, *args, **kwargs):
        calls.append(kwargs.get("timeout", args[0] if args else None))
        return _canned_list_output([("1", "x@y.com", "Hi", "false", "false", "-1", [])])

    provider._run_applescript = fake
    provider.list_messages(mailbox="Archive", limit=5)                    # unbounded
    provider.list_messages(mailbox="Archive", limit=5, since_days=180)    # bounded
    assert calls[0] is None    # unbounded: NO timeout kwarg (byte-identical to pre-change call)
    assert calls[1] == 900     # bounded: generous timeout


def test_classify_inbox_threads_since_days_only_when_set():
    """classify_inbox passes since_days to the provider ONLY when set — so providers whose
    list_messages predates the kwarg are never handed an unexpected argument."""
    import inbox_sweep
    from types import SimpleNamespace

    def make_prov(seen):
        class FakeProv:
            def list_messages(self, query="", limit=50, page_token=None, mailbox="INBOX", **kw):
                seen.append(kw.get("since_days", "OMITTED"))
                return SimpleNamespace(messages=[], next_page_token=None)
        return FakeProv()

    seen = []
    inbox_sweep.classify_inbox(make_prov(seen), "Archive", limit=10)
    inbox_sweep.classify_inbox(make_prov(seen), "Archive", limit=10, since_days=180)
    assert seen == ["OMITTED", 180]


# --- Provider-owned native index mapping ------------------------------------------


class TestMailAppFlagMapping:
    """Bidirectional mapping between Mail.app native flag indices and
    provider-agnostic FlagColor semantics. Unknown indices fail closed
    to UNKNOWN, never to NO_FLAG."""

    def test_known_indices_map_correctly(self):
        assert flag_from_mailapp_index(-1) == FlagColor.NO_FLAG
        assert flag_from_mailapp_index(0) == FlagColor.RED
        assert flag_from_mailapp_index(1) == FlagColor.ORANGE
        assert flag_from_mailapp_index(2) == FlagColor.YELLOW
        assert flag_from_mailapp_index(3) == FlagColor.GREEN
        assert flag_from_mailapp_index(4) == FlagColor.BLUE
        assert flag_from_mailapp_index(5) == FlagColor.PURPLE
        assert flag_from_mailapp_index(6) == FlagColor.GRAY

    def test_unknown_index_returns_unknown(self):
        assert flag_from_mailapp_index(7) == FlagColor.UNKNOWN
        assert flag_from_mailapp_index(99) == FlagColor.UNKNOWN
        assert flag_from_mailapp_index(-2) == FlagColor.UNKNOWN

    def test_known_flags_map_to_correct_indices(self):
        assert mailapp_index_from_flag(FlagColor.NO_FLAG) == -1
        assert mailapp_index_from_flag(FlagColor.RED) == 0
        assert mailapp_index_from_flag(FlagColor.ORANGE) == 1
        assert mailapp_index_from_flag(FlagColor.YELLOW) == 2
        assert mailapp_index_from_flag(FlagColor.GREEN) == 3
        assert mailapp_index_from_flag(FlagColor.BLUE) == 4
        assert mailapp_index_from_flag(FlagColor.PURPLE) == 5
        assert mailapp_index_from_flag(FlagColor.GRAY) == 6

    def test_unknown_flag_raises_keyerror(self):
        with pytest.raises(KeyError):
            mailapp_index_from_flag(FlagColor.UNKNOWN)

    def test_roundtrip_known_flags(self):
        for flag in (FlagColor.NO_FLAG, FlagColor.RED, FlagColor.ORANGE,
                     FlagColor.YELLOW, FlagColor.GREEN, FlagColor.BLUE,
                     FlagColor.PURPLE, FlagColor.GRAY):
            index = mailapp_index_from_flag(flag)
            assert flag_from_mailapp_index(index) == flag

    def test_mapping_tables_are_inverses(self):
        for index, flag in MAILAPP_INDEX_TO_FLAG.items():
            if flag == FlagColor.UNKNOWN:
                continue
            assert MAILAPP_FLAG_TO_INDEX[flag] == index


def test_list_messages_parses_flag_index_to_flag_color():
    """list_messages uses the provider mapping, not FlagColor.from_index."""
    provider = MailAppProvider()
    provider._run_applescript = lambda script: _canned_list_output([
        ("1", "a@b.com", "Red msg", "false", "false", "0", []),
        ("2", "c@d.com", "No flag", "false", "false", "-1", []),
        ("3", "e@f.com", "Unknown", "false", "false", "99", []),
    ])
    result = provider.list_messages(limit=10)
    by_id = {m.id: m for m in result.messages}
    assert by_id["1"].flag_color == FlagColor.RED
    assert by_id["2"].flag_color == FlagColor.NO_FLAG
    assert by_id["3"].flag_color == FlagColor.UNKNOWN


class TestMailAppFlagReadFailure:
    """Mail.app flag read failures propagate as exceptions, not UNKNOWN."""

    def test_get_flag_color_applescript_error_raises(self):
        provider = MailAppProvider()
        provider._run_applescript = lambda script: (_ for _ in ()).throw(RuntimeError("AppleScript timeout"))
        with pytest.raises(RuntimeError, match="AppleScript timeout"):
            provider.get_flag_color("msg1")

    def test_get_flag_color_malformed_output_raises(self):
        provider = MailAppProvider()
        provider._run_applescript = lambda script: "not an integer"
        with pytest.raises(ValueError):
            provider.get_flag_color("msg1")


class TestMailAppUnknownIndexHandling:
    """Successfully read but unrecognized native index returns UNKNOWN."""

    def test_unknown_index_returns_unknown(self):
        provider = MailAppProvider()
        provider._run_applescript = lambda script: "99"
        assert provider.get_flag_color("msg1") is FlagColor.UNKNOWN


class TestFlagsExplainWithSemanticEnum:
    """flags explain CLI works with semantic FlagColor, no int() call."""

    def test_explain_uses_flagcolor_not_native_index(self):
        provider = MailAppProvider()
        # AppleScript output: sender, subject, read, flagged, flagIndex, mailbox
        provider._run_applescript = lambda script: "\t".join([
            "sender@example.com", "Test Subject", "true", "true", "0", "INBOX"
        ])
        msg = provider.get_message_details("msg1")
        assert msg is not None
        assert msg.flag_color == FlagColor.RED
        # The flag_color is a semantic FlagColor, not a native index
        assert isinstance(msg.flag_color, FlagColor)
        assert msg.flag_color == FlagColor.RED
        # No int() conversion needed or possible
        assert msg.flag_color.value == "red"
