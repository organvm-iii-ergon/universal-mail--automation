"""Provider-chokepoint enforcement tests for the protected-sender gate.

These cover the gap the 2026-05-31 audit found: the gate LOGIC (core.rules) was
correct but UNENFORCED on every provider path. The invariant under test is:
a protected sender is NEVER archived or moved out of inbox, on ANY provider —
enforced at base.apply_actions (inherited by IMAP/Outlook/Mailapp) and at the
Gmail apply_actions override, with the From carried on LabelAction.sender.

Fixtures are synthetic: example-lawfirm.com is shipped in EXAMPLE_PROTECTED_SENDERS.
"""

import importlib
import sys
from types import ModuleType

import pytest

from core.models import FlagColor, LabelAction, MessageReference
from providers.base import EmailProvider, ProviderCapabilities

PROTECTED = "Lawyer <a@example-lawfirm.com>"
NORMAL = "Sale <promo@some-shop.example>"


@pytest.fixture
def gmail_provider(monkeypatch):
    missing = object()
    prior_gmail_module = sys.modules.get("providers.gmail", missing)
    try:
        gmod = importlib.import_module("providers.gmail")
    except ModuleNotFoundError as exc:
        if exc.name not in {"googleapiclient", "googleapiclient.errors"}:
            raise
        google_module = ModuleType("googleapiclient")
        errors_module = ModuleType("googleapiclient.errors")

        class _HttpError(Exception):
            pass

        errors_module.HttpError = _HttpError
        google_module.errors = errors_module
        monkeypatch.setitem(sys.modules, "googleapiclient", google_module)
        monkeypatch.setitem(
            sys.modules, "googleapiclient.errors", errors_module
        )
        gmod = importlib.import_module("providers.gmail")

    monkeypatch.setattr(gmod.time, "sleep", lambda *_a, **_k: None)
    bodies = []

    class _Exec:
        def execute(self):
            return {}

    class _Messages:
        def batchModify(self, userId, body):
            bodies.append(body)
            return _Exec()

    class _Users:
        def messages(self):
            return _Messages()

    class _Service:
        def users(self):
            return _Users()

    provider = gmod.GmailProvider(service=_Service())
    provider.ensure_label_exists = lambda label: label
    provider._execute_with_backoff = lambda fn, _desc: fn()
    yield provider, bodies

    if prior_gmail_module is missing:
        sys.modules.pop("providers.gmail", None)


def _scoped_ref(provider_id):
    return MessageReference(
        provider="gmail",
        account="acct",
        mailbox="INBOX",
        provider_id=provider_id,
    ).with_resolved_evidence(
        "2026-01-01T00:00:00+00:00",
        "sender@example.com",
        "Synthetic subject",
    )


class RecordingProvider(EmailProvider):
    """Minimal label-style provider that records every destructive call."""
    name = "recording"
    capabilities = ProviderCapabilities.TRUE_LABELS | ProviderCapabilities.ARCHIVE

    def __init__(self):
        self.archived = []
        self.removed = []   # (message_id, label)
        self.applied = []   # (message_id, label)

    def connect(self):  # pragma: no cover - trivial
        pass

    def disconnect(self):  # pragma: no cover - trivial
        pass

    def list_messages(self, query=None, limit=None, page_token=None):  # pragma: no cover
        return None

    def get_message_details(self, message_id):  # pragma: no cover
        return None

    def apply_label(self, message_id, label):
        self.applied.append((message_id, label))
        return True

    def remove_label(self, message_id, label):
        self.removed.append((message_id, label))
        return True

    def ensure_label_exists(self, label):
        return label

    def archive(self, message_id):
        self.archived.append(message_id)
        return True


class RecordingFolderProvider(RecordingProvider):
    """Folder-style provider: applying a label IS an out-of-inbox MOVE.

    Models the real move-on-label providers (Outlook Graph /move, Mail.app
    AppleScript move). Under the corrected design the FOLDERS capability alone
    no longer implies a move — the provider must declare ``LABEL_IS_MOVE`` so
    the gate suppresses the label for protected senders and the audit records
    the disposition as a move rather than an additive label.
    """
    name = "recording-folder"
    capabilities = ProviderCapabilities.FOLDERS | ProviderCapabilities.ARCHIVE
    LABEL_IS_MOVE = True


class TestDropIfProtected:
    def test_protected_clears_archive_and_strips_inbox(self):
        p = RecordingProvider()
        action = LabelAction(
            message_id="m1", sender=PROTECTED, archive=True,
            remove_labels=["INBOX", "Uncategorized"],
        )
        assert p._drop_if_protected(action) is True
        assert action.archive is False
        assert "INBOX" not in action.remove_labels
        assert "Uncategorized" in action.remove_labels  # non-inbox removals survive

    def test_blank_sender_fails_closed(self):
        p = RecordingProvider()
        action = LabelAction(message_id="m1", sender="", archive=True, remove_labels=["INBOX"])
        assert p._drop_if_protected(action) is True
        assert action.archive is False
        assert action.remove_labels == []

    def test_normal_sender_untouched(self):
        p = RecordingProvider()
        action = LabelAction(message_id="m1", sender=NORMAL, archive=True, remove_labels=["INBOX"])
        assert p._drop_if_protected(action) is False
        assert action.archive is True
        assert action.remove_labels == ["INBOX"]


class TestBaseApplyActionsChokepoint:
    def test_protected_never_archived_or_inbox_removed(self):
        p = RecordingProvider()
        p.apply_actions([
            LabelAction(message_id="prot", sender=PROTECTED, archive=True,
                        remove_labels=["INBOX"], add_labels=["Finance/Banking"]),
            LabelAction(message_id="noise", sender=NORMAL, archive=True,
                        remove_labels=["INBOX"], add_labels=["Marketing"]),
        ])
        # protected: never archived, INBOX never removed
        assert "prot" not in p.archived
        assert ("prot", "INBOX") not in p.removed
        # label adds are fine on a label-style provider (not a move)
        assert ("prot", "Finance/Banking") in p.applied
        # noise: archived as normal
        assert "noise" in p.archived

    def test_folder_provider_suppresses_label_move_for_protected(self):
        p = RecordingFolderProvider()
        p.apply_actions([
            LabelAction(message_id="prot", sender=PROTECTED, archive=True,
                        add_labels=["Archive"], remove_labels=["INBOX"]),
            LabelAction(message_id="noise", sender=NORMAL,
                        add_labels=["Archive"], remove_labels=["INBOX"]),
        ])
        # For a FOLDER provider applying a label IS a move -> suppressed when protected
        assert ("prot", "Archive") not in p.applied
        assert "prot" not in p.archived
        assert ("prot", "INBOX") not in p.removed
        # noise still moved
        assert ("noise", "Archive") in p.applied


class TestGmailOverrideChokepoint:
    def test_protected_id_never_gets_inbox_removed(self, gmail_provider):
        gp, bodies = gmail_provider

        gp.apply_actions([
            LabelAction(message_id="prot", sender=PROTECTED, archive=True),
            LabelAction(message_id="noise", sender=NORMAL, archive=True),
        ])

        inbox_removed_ids = set()
        for body in bodies:
            if "INBOX" in body.get("removeLabelIds", []):
                inbox_removed_ids.update(body.get("ids", []))

        assert "prot" not in inbox_removed_ids   # protected lawyer never archived
        assert "noise" in inbox_removed_ids       # noise archived as normal

    def test_colored_action_is_rejected_without_any_gmail_api_call(
            self, gmail_provider):
        gp, bodies = gmail_provider

        result = gp.apply_actions([
            LabelAction(
                message_id="colored",
                sender=NORMAL,
                flag_color=FlagColor.RED,
                message_ref=_scoped_ref("colored"),
            )
        ])

        assert result.processed_count == 1
        assert result.error_count == 1
        assert result.success_count == 0
        assert any("does not support COLORED_FLAGS" in e
                   for e in result.errors)
        assert bodies == []

    def test_invalid_mixed_flag_action_is_rejected_before_protection_gate(
            self, gmail_provider):
        gp, bodies = gmail_provider
        action = LabelAction(
            message_id="mixed",
            sender=PROTECTED,
            archive=True,
            flag_color=FlagColor.RED,
            message_ref=_scoped_ref("mixed"),
        )

        result = gp.apply_actions([action])

        assert result.error_count == 1
        assert result.success_count == 0
        assert "flag mutation cannot be combined" in result.errors[0]
        assert action.archive is True
        assert bodies == []

    def test_rejected_colored_action_does_not_block_valid_sibling(
            self, gmail_provider):
        gp, bodies = gmail_provider

        result = gp.apply_actions([
            LabelAction(
                message_id="colored",
                sender=NORMAL,
                flag_color=FlagColor.RED,
                message_ref=_scoped_ref("colored"),
            ),
            LabelAction(
                message_id="valid",
                sender=NORMAL,
                add_labels=["Reference"],
            ),
        ])

        assert result.processed_count == 2
        assert result.error_count == 1
        assert result.success_count == 1
        assert len(bodies) == 1
        assert bodies[0]["ids"] == ["valid"]
