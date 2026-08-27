"""Tests for core.models — EmailMessage, LabelAction, ProcessingResult."""

from datetime import datetime, timezone

import pytest

from core.models import (
    ActionType,
    EmailMessage,
    LabelAction,
    LabelActionValidationError,
    ProcessingResult,
    FlagColor,
    StateSource,
    FlagMutation,
    MessageReference,
)


class TestMessageReference:
    def test_ref_digest_rejects_unscoped_values(self):
        ref = MessageReference(
            provider="mailapp",
            account="acct",
            mailbox="INBOX",
            provider_id="",
        )
        with pytest.raises(ValueError, match="provider_id"):
            _ = ref.ref_digest

    @pytest.mark.parametrize("field,value", [
        ("received_iso", float("nan")),
        ("sender", False),
        ("subject", 7),
    ])
    def test_evidence_digest_rejects_non_string_values(self, field, value):
        values = {
            "received_iso": None,
            "sender": "sender@example.com",
            "subject": "Subject",
        }
        values[field] = value
        with pytest.raises(ValueError, match=field):
            MessageReference.compute_evidence_digest(**values)


class TestActionType:
    def test_enum_values(self):
        assert ActionType.ADD_LABEL.value == "add_label"
        assert ActionType.REMOVE_LABEL.value == "remove_label"
        assert ActionType.ARCHIVE.value == "archive"
        assert ActionType.STAR.value == "star"
        assert ActionType.MOVE_TO_FOLDER.value == "move_to_folder"

    def test_all_actions_exist(self):
        names = {a.name for a in ActionType}
        assert names == {
            "ADD_LABEL", "REMOVE_LABEL", "ARCHIVE", "STAR",
            "UNSTAR", "MARK_READ", "MARK_UNREAD", "MOVE_TO_FOLDER",
            "SET_FLAG", "CLEAR_FLAG",
        }


class TestEmailMessage:
    def test_basic_creation(self):
        msg = EmailMessage(id="1", sender="a@b.com", subject="Hello")
        assert msg.id == "1"
        assert msg.sender == "a@b.com"
        assert msg.subject == "Hello"
        assert msg.date is None
        assert msg.labels == set()
        assert msg.is_read is False
        assert msg.is_starred is False
        assert msg.priority_tier is None
        assert msg.categories == set()

    def test_with_all_fields(self):
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        msg = EmailMessage(
            id="2",
            sender="test@example.com",
            subject="Test",
            date=dt,
            labels={"Inbox", "Dev/GitHub"},
            is_read=True,
            is_starred=True,
            priority_tier=1,
            categories={"Red category"},
        )
        assert msg.date == dt
        assert "Inbox" in msg.labels
        assert msg.is_read is True
        assert msg.is_starred is True
        assert msg.priority_tier == 1
        assert "Red category" in msg.categories

    def test_immutability(self):
        msg = EmailMessage(id="3", sender="a@b.com", subject="Hi")
        try:
            msg.id = "changed"
            assert False, "Should raise FrozenInstanceError"
        except AttributeError:
            pass

    def test_combined_text(self):
        msg = EmailMessage(id="1", sender="Alerts@GitHub.com", subject="PR Review Needed")
        assert msg.combined_text == "alerts@github.com pr review needed"

    def test_combined_text_empty(self):
        msg = EmailMessage(id="1", sender="", subject="")
        assert msg.combined_text == " "


class TestLabelAction:
    def test_defaults(self):
        action = LabelAction(message_id="1")
        assert action.add_labels == []
        assert action.remove_labels == []
        assert action.archive is False
        assert action.star is False
        assert action.target_folder is None
        assert action.category is None
        assert action.due_date is None

    def test_with_labels(self):
        action = LabelAction(
            message_id="1",
            add_labels=["Dev/GitHub", "Work"],
            remove_labels=["Misc/Other"],
            archive=True,
            star=True,
        )
        assert "Dev/GitHub" in action.add_labels
        assert "Misc/Other" in action.remove_labels
        assert action.archive is True

    def test_merge_combines_labels(self):
        a = LabelAction(message_id="1", add_labels=["A"], remove_labels=["X"])
        b = LabelAction(message_id="1", add_labels=["B"], remove_labels=["Y"])
        merged = a.merge(b)
        assert set(merged.add_labels) == {"A", "B"}
        assert set(merged.remove_labels) == {"X", "Y"}

    def test_merge_deduplicates(self):
        a = LabelAction(message_id="1", add_labels=["A", "B"])
        b = LabelAction(message_id="1", add_labels=["B", "C"])
        merged = a.merge(b)
        assert sorted(merged.add_labels) == ["A", "B", "C"]

    def test_merge_or_flags(self):
        a = LabelAction(message_id="1", archive=False, star=True)
        b = LabelAction(message_id="1", archive=True, star=False)
        merged = a.merge(b)
        assert merged.archive is True
        assert merged.star is True

    def test_merge_prefers_other_folder(self):
        a = LabelAction(message_id="1", target_folder="Old")
        b = LabelAction(message_id="1", target_folder="New")
        merged = a.merge(b)
        assert merged.target_folder == "New"

    def test_merge_keeps_self_folder_if_other_none(self):
        a = LabelAction(message_id="1", target_folder="Keep")
        b = LabelAction(message_id="1")
        merged = a.merge(b)
        assert merged.target_folder == "Keep"

    def test_merge_preserves_red_flag_color(self):
        """Regression: the old 'or' truthiness discarded explicit flag_color
        values. With the new str enum, NO_FLAG is truthy — the fix uses
        'is not None' instead of boolean or."""
        a = LabelAction(message_id="1", flag_color=FlagColor.BLUE)
        b = LabelAction(message_id="1", flag_color=FlagColor.RED)
        merged = a.merge(b)
        assert merged.flag_color == FlagColor.RED

    def test_merge_keeps_self_flag_when_other_none(self):
        a = LabelAction(message_id="1", flag_color=FlagColor.RED)
        b = LabelAction(message_id="1")
        merged = a.merge(b)
        assert merged.flag_color == FlagColor.RED

    def test_merge_other_no_flag_overrides_self(self):
        """Explicit NO_FLAG from other should override, not be treated as None."""
        a = LabelAction(message_id="1", flag_color=FlagColor.RED)
        b = LabelAction(message_id="1", flag_color=FlagColor.NO_FLAG)
        merged = a.merge(b)
        assert merged.flag_color == FlagColor.NO_FLAG

    def test_merge_preserves_message_ref_other_wins(self):
        """4b #6: merged colored actions keep a qualified reference
        (other-wins), else downstream validation would reject the product."""
        a = LabelAction(message_id="1", flag_color=FlagColor.RED,
                        message_ref=_vref())
        b = LabelAction(message_id="1", flag_color=FlagColor.BLUE,
                        message_ref=_vref(provider_id="2"))
        merged = a.merge(b)
        assert merged.message_ref is b.message_ref

    def test_merge_keeps_self_ref_when_other_lacks_one(self):
        a = LabelAction(message_id="1", flag_color=FlagColor.RED,
                        message_ref=_vref())
        b = LabelAction(message_id="1", flag_color=FlagColor.BLUE)
        merged = a.merge(b)
        assert merged.message_ref is a.message_ref

    def test_merged_action_with_ref_passes_validation(self):
        """End-to-end: merge product of two ref'd actions still validates."""
        a = LabelAction(message_id="1", message_ref=_vref())
        b = LabelAction(message_id="1", flag_color=FlagColor.ORANGE,
                        message_ref=_vref(provider_id="1"))
        merged = a.merge(b)
        merged.validate()          # must not raise


def _vref(evidence=True, provider_id="1"):
    """Valid scoped reference for validation tests."""
    from core.models import MessageReference
    r = MessageReference(provider="mailapp", account="acct",
                         mailbox="INBOX", provider_id=provider_id)
    if evidence:
        return r.with_resolved_evidence("2026-01-01T00:00:00",
                                        "a@b.com", "Subject")
    return r


class TestLabelActionValidation:
    def test_clear_flag_with_flag_color_raises(self):
        action = LabelAction(
            message_id="1", clear_flag=True, flag_color=FlagColor.RED
        )
        with pytest.raises(
            LabelActionValidationError,
            match="clear_flag and flag_color are mutually exclusive",
        ):
            action.validate()

    def test_clear_flag_with_star_raises(self):
        action = LabelAction(message_id="1", clear_flag=True, star=True)
        with pytest.raises(
            LabelActionValidationError,
            match="clear_flag and star are mutually exclusive",
        ):
            action.validate()

    def test_clear_flag_alone_is_valid(self):
        action = LabelAction(message_id="1", clear_flag=True,
                             message_ref=_vref())
        action.validate()

    def test_flag_color_alone_is_valid(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.RED,
                             message_ref=_vref())
        action.validate()

    def test_missing_reference_rejected(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.RED)
        with pytest.raises(
            LabelActionValidationError,
            match="requires a qualified MessageReference",
        ):
            action.validate()

    def test_evidence_less_reference_rejected(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.RED,
                             message_ref=_vref(evidence=False))
        with pytest.raises(
            LabelActionValidationError,
            match="lacks durable evidence",
        ):
            action.validate()

    def test_message_id_must_match_scoped_provider_id(self):
        action = LabelAction(
            message_id="1",
            flag_color=FlagColor.RED,
            message_ref=_vref(provider_id="2"),
        )
        with pytest.raises(
            LabelActionValidationError,
            match="message_id must match message_ref.provider_id",
        ):
            action.validate()

    def test_resolved_evidence_preserves_missing_received_date(self):
        reference = _vref(evidence=False)
        resolved = reference.with_resolved_evidence(
            None, "a@b.com", "Subject"
        )
        assert resolved.received_iso is None
        assert resolved.evidence_digest is not None

    def test_star_with_flag_color_rejected(self):
        action = LabelAction(message_id="1", star=True, flag_color=FlagColor.RED)
        with pytest.raises(
            LabelActionValidationError,
            match="star and flag_color are mutually exclusive",
        ):
            action.validate()

    def test_flag_color_no_flag_rejected(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.NO_FLAG)
        with pytest.raises(
            LabelActionValidationError,
            match="flag_color='no_flag' cannot be used as a mutation target",
        ):
            action.validate()

    def test_flag_color_unknown_rejected(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.UNKNOWN)
        with pytest.raises(
            LabelActionValidationError,
            match="flag_color='unknown' cannot be used as a mutation target",
        ):
            action.validate()

    def test_flag_mutation_with_archive_rejected(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.RED, archive=True,
                             message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with add_labels",
        ):
            action.validate()

    def test_flag_mutation_with_target_folder_rejected(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.RED,
                             target_folder="Archive", message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with add_labels",
        ):
            action.validate()

    def test_flag_mutation_with_category_rejected(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.RED,
                             category="Work", message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with category",
        ):
            action.validate()

    def test_flag_mutation_with_add_labels_rejected(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.RED,
                             add_labels=["Work"], message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with add_labels",
        ):
            action.validate()

    def test_flag_mutation_with_remove_labels_rejected(self):
        action = LabelAction(message_id="1", flag_color=FlagColor.RED,
                             remove_labels=["Inbox"], message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with add_labels",
        ):
            action.validate()

    def test_clear_flag_with_add_labels_rejected(self):
        action = LabelAction(message_id="1", clear_flag=True, add_labels=["Work"],
                             message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with add_labels",
        ):
            action.validate()

    def test_clear_flag_with_remove_labels_rejected(self):
        action = LabelAction(message_id="1", clear_flag=True,
                             remove_labels=["INBOX"], message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with add_labels",
        ):
            action.validate()

    def test_clear_flag_with_archive_rejected(self):
        action = LabelAction(message_id="1", clear_flag=True, archive=True,
                             message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with add_labels",
        ):
            action.validate()

    def test_clear_flag_with_target_folder_rejected(self):
        action = LabelAction(message_id="1", clear_flag=True,
                             target_folder="Archive", message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with add_labels",
        ):
            action.validate()

    def test_clear_flag_with_category_rejected(self):
        action = LabelAction(message_id="1", clear_flag=True, category="Work",
                             message_ref=_vref())
        with pytest.raises(
            LabelActionValidationError,
            match="flag mutation cannot be combined with category",
        ):
            action.validate()

    def test_clear_flag_alone_stays_valid_after_all_exclusions(self):
        action = LabelAction(message_id="1", clear_flag=True,
                             message_ref=_vref())
        action.validate()


class TestFlagColorCanonicalRoundTrip:
    def test_no_flag_canonical_roundtrip(self):
        assert FlagColor.from_string(FlagColor.NO_FLAG.value) is FlagColor.NO_FLAG

    def test_all_colors_canonical_roundtrip(self):
        for color in FlagColor:
            if color == FlagColor.NO_FLAG:
                continue
            assert FlagColor.from_string(color.value) is color

    def test_aliases_work(self):
        assert FlagColor.from_string("none") is FlagColor.NO_FLAG
        assert FlagColor.from_string("no flag") is FlagColor.NO_FLAG
        assert FlagColor.from_string("no-flag") is FlagColor.NO_FLAG
        assert FlagColor.from_string("grey") is FlagColor.GRAY


class TestProcessingResult:
    def test_defaults(self):
        result = ProcessingResult()
        assert result.processed_count == 0
        assert result.success_count == 0
        assert result.error_count == 0
        assert result.label_counts == {}
        assert result.errors == []

    def test_add_label_stat(self):
        result = ProcessingResult()
        result.add_label_stat("Dev/GitHub")
        result.add_label_stat("Dev/GitHub")
        result.add_label_stat("Finance/Banking")
        assert result.label_counts["Dev/GitHub"] == 2
        assert result.label_counts["Finance/Banking"] == 1

    def test_accumulate_errors(self):
        result = ProcessingResult()
        result.errors.append("Failed to process msg001")
        result.error_count += 1
        assert result.error_count == 1
        assert len(result.errors) == 1


class TestFlagColor:
    def test_enum_values(self):
        assert FlagColor.NO_FLAG == "no_flag"
        assert FlagColor.RED == "red"
        assert FlagColor.ORANGE == "orange"
        assert FlagColor.YELLOW == "yellow"
        assert FlagColor.GREEN == "green"
        assert FlagColor.BLUE == "blue"
        assert FlagColor.PURPLE == "purple"
        assert FlagColor.GRAY == "gray"
        assert FlagColor.UNKNOWN == "unknown"

    def test_name_str(self):
        assert FlagColor.NO_FLAG.name_str == "No Flag"
        assert FlagColor.RED.name_str == "Red"
        assert FlagColor.ORANGE.name_str == "Orange"
        assert FlagColor.YELLOW.name_str == "Yellow"
        assert FlagColor.GREEN.name_str == "Green"
        assert FlagColor.BLUE.name_str == "Blue"
        assert FlagColor.PURPLE.name_str == "Purple"
        assert FlagColor.GRAY.name_str == "Gray"
        assert FlagColor.UNKNOWN.name_str == "Unknown"

    def test_operator_posture(self):
        assert FlagColor.NO_FLAG.operator_posture == "NO ACTIVE FLAG / WORKFLOW STATE SEPARATE"
        assert FlagColor.RED.operator_posture == "CRITICAL / ACT NOW"
        assert FlagColor.ORANGE.operator_posture == "ACTION OWED"
        assert FlagColor.YELLOW.operator_posture == "WAITING / FOLLOW-UP"
        assert FlagColor.GREEN.operator_posture == "SCHEDULED / COMMITTED"
        assert FlagColor.BLUE.operator_posture == "ACTIVE REFERENCE"
        assert FlagColor.PURPLE.operator_posture == "HUMAN JUDGMENT REQUIRED"
        assert FlagColor.GRAY.operator_posture == "DELIBERATELY DEFERRED"
        assert FlagColor.UNKNOWN.operator_posture == "UNKNOWN / UNMAPPED NATIVE INDEX"

    def test_queue_label(self):
        assert FlagColor.NO_FLAG.queue_label == "UNFLAGGED"
        assert FlagColor.RED.queue_label == "NOW"
        assert FlagColor.ORANGE.queue_label == "ACTION"
        assert FlagColor.YELLOW.queue_label == "WAITING"
        assert FlagColor.GREEN.queue_label == "SCHEDULED"
        assert FlagColor.BLUE.queue_label == "REFERENCE"
        assert FlagColor.PURPLE.queue_label == "REVIEW"
        assert FlagColor.GRAY.queue_label == "LATER"
        assert FlagColor.UNKNOWN.queue_label == "UNKNOWN"

    def test_from_string(self):
        assert FlagColor.from_string("none") == FlagColor.NO_FLAG
        assert FlagColor.from_string("no flag") == FlagColor.NO_FLAG
        assert FlagColor.from_string("no-flag") == FlagColor.NO_FLAG
        assert FlagColor.from_string("red") == FlagColor.RED
        assert FlagColor.from_string("orange") == FlagColor.ORANGE
        assert FlagColor.from_string("yellow") == FlagColor.YELLOW
        assert FlagColor.from_string("green") == FlagColor.GREEN
        assert FlagColor.from_string("blue") == FlagColor.BLUE
        assert FlagColor.from_string("purple") == FlagColor.PURPLE
        assert FlagColor.from_string("gray") == FlagColor.GRAY
        assert FlagColor.from_string("grey") == FlagColor.GRAY
        assert FlagColor.from_string("unknown") == FlagColor.UNKNOWN
        assert FlagColor.from_string("RED") == FlagColor.RED
        assert FlagColor.from_string("  purple  ") == FlagColor.PURPLE

    def test_from_string_unknown_raises(self):
        with pytest.raises(ValueError, match="Unknown flag color"):
            FlagColor.from_string("notacolor")
        with pytest.raises(ValueError, match="Unknown flag color"):
            FlagColor.from_string("magenta")
        with pytest.raises(ValueError, match="Unknown flag color"):
            FlagColor.from_string("")

    def test_is_str_enum(self):
        assert isinstance(FlagColor.RED, str)
        assert FlagColor.RED == "red"
        assert str(FlagColor.RED) == "FlagColor.RED"


class TestFlagMutation:
    def test_defaults(self):
        mut = FlagMutation(message_id="1")
        assert mut.message_id == "1"
        assert mut.current_flag == FlagColor.NO_FLAG
        assert mut.proposed_flag == FlagColor.NO_FLAG
        assert mut.confidence == 1.0
        assert mut.state_source == StateSource.MIGRATION
        assert mut.is_noop() is True

    def test_is_noop(self):
        mut = FlagMutation(message_id="1", current_flag=FlagColor.RED, proposed_flag=FlagColor.RED)
        assert mut.is_noop() is True
        mut2 = FlagMutation(message_id="1", current_flag=FlagColor.RED, proposed_flag=FlagColor.ORANGE)
        assert mut2.is_noop() is False

    def test_with_all_fields(self):
        from datetime import datetime, timezone
        mut = FlagMutation(
            message_id="1",
            sender="test@example.com",
            current_flag=FlagColor.RED,
            proposed_flag=FlagColor.ORANGE,
            reason="Test reason",
            confidence=0.8,
            state_source=StateSource.MODEL,
            due_at=datetime.now(timezone.utc),
            follow_up_at=datetime.now(timezone.utc),
            next_action="Reply",
            urgency=5,
            human_override=False,
            transaction_id="txn_123",
        )
        assert mut.sender == "test@example.com"
        assert mut.current_flag == FlagColor.RED
        assert mut.proposed_flag == FlagColor.ORANGE
        assert mut.reason == "Test reason"
        assert mut.confidence == 0.8
        assert mut.state_source == StateSource.MODEL
        assert mut.next_action == "Reply"
        assert mut.urgency == 5
        assert mut.human_override is False
        assert mut.transaction_id == "txn_123"
        assert mut.is_noop() is False


class TestStateSource:
    def test_values(self):
        assert StateSource.HUMAN == "human"
        assert StateSource.DETERMINISTIC_RULE == "deterministic_rule"
        assert StateSource.MODEL == "model"
        assert StateSource.MIGRATION == "migration"
        assert StateSource.LEGACY_UNKNOWN == "legacy_unknown"
