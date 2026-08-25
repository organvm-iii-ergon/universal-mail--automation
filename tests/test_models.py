"""Tests for core.models — EmailMessage, LabelAction, ProcessingResult."""

from datetime import datetime, timezone

from core.models import (
    ActionType,
    EmailMessage,
    LabelAction,
    ProcessingResult,
    FlagColor,
    StateSource,
    FlagMutation,
)


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
        assert FlagColor.NO_FLAG == -1
        assert FlagColor.RED == 0
        assert FlagColor.ORANGE == 1
        assert FlagColor.YELLOW == 2
        assert FlagColor.GREEN == 3
        assert FlagColor.BLUE == 4
        assert FlagColor.PURPLE == 5
        assert FlagColor.GRAY == 6

    def test_name_str(self):
        assert FlagColor.NO_FLAG.name_str == "No Flag"
        assert FlagColor.RED.name_str == "Red"
        assert FlagColor.ORANGE.name_str == "Orange"
        assert FlagColor.YELLOW.name_str == "Yellow"
        assert FlagColor.GREEN.name_str == "Green"
        assert FlagColor.BLUE.name_str == "Blue"
        assert FlagColor.PURPLE.name_str == "Purple"
        assert FlagColor.GRAY.name_str == "Gray"

    def test_operator_posture(self):
        assert FlagColor.NO_FLAG.operator_posture == "CLOSED / COMPLETED / NO OPEN LOOP"
        assert FlagColor.RED.operator_posture == "CRITICAL / ACT NOW"
        assert FlagColor.ORANGE.operator_posture == "ACTION OWED"
        assert FlagColor.YELLOW.operator_posture == "WAITING / FOLLOW-UP"
        assert FlagColor.GREEN.operator_posture == "SCHEDULED / COMMITTED"
        assert FlagColor.BLUE.operator_posture == "ACTIVE REFERENCE"
        assert FlagColor.PURPLE.operator_posture == "HUMAN JUDGMENT REQUIRED"
        assert FlagColor.GRAY.operator_posture == "DELIBERATELY DEFERRED"

    def test_queue_label(self):
        assert FlagColor.NO_FLAG.queue_label == "DONE"
        assert FlagColor.RED.queue_label == "NOW"
        assert FlagColor.ORANGE.queue_label == "ACTION"
        assert FlagColor.YELLOW.queue_label == "WAITING"
        assert FlagColor.GREEN.queue_label == "SCHEDULED"
        assert FlagColor.BLUE.queue_label == "REFERENCE"
        assert FlagColor.PURPLE.queue_label == "REVIEW"
        assert FlagColor.GRAY.queue_label == "LATER"

    def test_from_index(self):
        assert FlagColor.from_index(-1) == FlagColor.NO_FLAG
        assert FlagColor.from_index(0) == FlagColor.RED
        assert FlagColor.from_index(1) == FlagColor.ORANGE
        assert FlagColor.from_index(2) == FlagColor.YELLOW
        assert FlagColor.from_index(3) == FlagColor.GREEN
        assert FlagColor.from_index(4) == FlagColor.BLUE
        assert FlagColor.from_index(5) == FlagColor.PURPLE
        assert FlagColor.from_index(6) == FlagColor.GRAY
        # Out of range defaults to NO_FLAG
        assert FlagColor.from_index(7) == FlagColor.NO_FLAG
        assert FlagColor.from_index(-2) == FlagColor.NO_FLAG

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
        assert FlagColor.from_string("unknown") == FlagColor.NO_FLAG
        assert FlagColor.from_string("RED") == FlagColor.RED
        assert FlagColor.from_string("  purple  ") == FlagColor.PURPLE


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
