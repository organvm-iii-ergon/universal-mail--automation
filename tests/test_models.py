"""Tests for core.models — EmailMessage, LabelAction, ProcessingResult."""

from datetime import datetime, timezone

from core.models import ActionType, EmailMessage, LabelAction, ProcessingResult


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
