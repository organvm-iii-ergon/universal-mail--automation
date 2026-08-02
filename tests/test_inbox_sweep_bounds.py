"""`--limit` never bounded Mail.app's work, and the INBOX sweep hung it for 421 seconds.

THE MEASURED DEFECT (macOS hang reports, 2026-07-26 -> 2026-08-02, escalating 1/day -> 4/day):

    Mail_2026-08-02-101334.hang   Duration: 421.09s
      AEProcessAppleEvent
        -[NSScriptCommand executeCommand]
          -[MFMailbox(ScriptingSupport) messages]
            -[MFLibraryIMAPStore copyOfAllMessagesWithOptions:]
              -[EDPersistenceDatabase __performReadWithCaller:usingBlock:]

Mail's main thread, inside an Apple Event, materializing a scripting object for EVERY message
in the store. `messages of targetMailbox` is not a cursor: Mail builds the whole list before
AppleScript slices anything, so `--limit 2000` bounded the Python slice and nothing else.

Two guards looked like they covered this and did not:

  * ``mail-beat.sh`` wraps the sweep in ``timeout 240``. That kills the osascript CLIENT; it does
    not cancel an Apple Event already executing inside Mail, which keeps churning after the beat
    moves on and reports healthy. Hence a 421s beachball under a 240s timeout.
  * ``--limit`` is applied by the ``repeat`` loop, i.e. after materialization.

The bounded selector already existed for the archive path (``whose date received > cutoffDate``),
already had tests, and its own docstring calls it "the whole fix — the archive is never fully
materialized, so a large All-Mail can't time out". It was simply never wired to INBOX; the
regression guard at ``test_build_list_script_unbounded_full_scans_oldest_first`` pinned INBOX to
the unbounded selector to keep that change "additive".

This suite covers the wiring, not the selector (``test_mailapp.py`` owns the selector).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import inbox_sweep  # noqa: E402
from providers.mailapp import MailAppProvider  # noqa: E402


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """Run main() far enough to observe what classify_inbox was asked for, touching no mailbox."""
    seen: dict[str, object] = {}

    monkeypatch.setattr(inbox_sweep.MailAppProvider, "connect", lambda self: None)
    monkeypatch.setattr(inbox_sweep, "pick_inbox_name", lambda provider: "INBOX")
    monkeypatch.setattr(inbox_sweep, "report", lambda *a, **k: None)

    def _classify(provider, inbox_name, limit, since_days=None):
        seen.update(inbox=inbox_name, limit=limit, since_days=since_days)
        return []

    monkeypatch.setattr(inbox_sweep, "classify_inbox", _classify)
    return seen


def test_since_days_reaches_the_enumeration(captured: dict[str, object]) -> None:
    inbox_sweep.main(["--account", "a@example.com", "--since-days", "14"])
    assert captured["since_days"] == 14


def test_the_default_preserves_the_historical_unbounded_behaviour(captured: dict[str, object]) -> None:
    """Changing the default would silently narrow what every existing caller sees.

    The beat opts in explicitly; a bare invocation still enumerates everything.
    """
    inbox_sweep.main(["--account", "a@example.com"])
    assert captured["since_days"] is None


def test_zero_means_unbounded_not_an_empty_window(captured: dict[str, object]) -> None:
    """`--since-days 0` must not build `date received > (current date) - 0 days`, which would
    match nothing and silently sweep an empty inbox -- a false all-clear."""
    inbox_sweep.main(["--account", "a@example.com", "--since-days", "0"])
    assert captured["since_days"] is None


def test_limit_is_still_honoured_alongside_the_window(captured: dict[str, object]) -> None:
    inbox_sweep.main(["--account", "a@example.com", "--since-days", "7", "--limit", "50"])
    assert captured["limit"] == 50
    assert captured["since_days"] == 7


# --- the selector this wiring exists to reach -------------------------------------------------


def test_a_window_stops_mail_from_materializing_the_whole_mailbox() -> None:
    """The end the wiring serves: with a window, `messages of targetMailbox` is never emitted.

    This is the line that hung Mail's main thread for 421 seconds.
    """
    script = MailAppProvider(account="a@example.com")._build_list_script(
        "INBOX", start_offset=0, limit=50, since_days=14
    )
    assert "set allMsgs to messages of targetMailbox\n" not in script
    assert "whose date received > cutoffDate" in script
    assert "set cutoffDate to (current date) - (14 * days)" in script


def test_without_a_window_the_unbounded_selector_is_still_what_ships() -> None:
    """The hazard is unchanged for callers that do not opt in -- which is why the beat must."""
    script = MailAppProvider(account="a@example.com")._build_list_script(
        "INBOX", start_offset=0, limit=50, since_days=None
    )
    assert "set allMsgs to messages of targetMailbox" in script
