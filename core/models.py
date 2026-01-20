"""
Data models for email automation.

Provides provider-agnostic data structures for email messages and label actions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Set
from enum import Enum


class ActionType(Enum):
    """Types of label/folder actions that can be applied to messages."""
    ADD_LABEL = "add_label"
    REMOVE_LABEL = "remove_label"
    ARCHIVE = "archive"
    STAR = "star"
    UNSTAR = "unstar"
    MARK_READ = "mark_read"
    MARK_UNREAD = "mark_unread"
    MOVE_TO_FOLDER = "move_to_folder"


@dataclass(frozen=True)
class EmailMessage:
    """
    Provider-agnostic representation of an email message.

    Immutable dataclass containing the minimum fields needed for categorization
    and action decisions. Provider implementations extract these fields from
    their native message formats.

    Attributes:
        id: Provider-specific message identifier (Gmail ID, IMAP UID, etc.)
        sender: The 'From' header value
        subject: The 'Subject' header value
        date: Message date (optional, for filtering/sorting)
        labels: Current labels/folders on the message
        is_read: Whether the message has been read
        is_starred: Whether the message is starred/flagged
        priority_tier: Eisenhower matrix tier (1=Critical, 2=Important, 3=Delegate, 4=Reference)
        categories: Color categories (Outlook)
    """
    id: str
    sender: str
    subject: str
    date: Optional[datetime] = None
    labels: Set[str] = field(default_factory=set)
    is_read: bool = False
    is_starred: bool = False
    priority_tier: Optional[int] = None
    categories: Set[str] = field(default_factory=set)

    @property
    def combined_text(self) -> str:
        """Returns sender + subject combined for pattern matching."""
        return f"{self.sender} {self.subject}".lower()


@dataclass
class LabelAction:
    """
    Represents a label/folder action to apply to a message.

    Accumulates multiple actions for batch processing. Provider implementations
    translate these into API-specific calls (Gmail batchModify, IMAP STORE, etc.)

    Attributes:
        message_id: The message to act upon
        add_labels: Labels to add to the message
        remove_labels: Labels to remove from the message
        archive: Whether to remove from inbox (archive)
        star: Whether to star/flag the message
        target_folder: For folder-based systems, the destination folder
        category: Color category name (Outlook)
        category_color: Color preset for the category (Outlook)
        due_date: Due date for flagged items (Outlook To Do integration)
    """
    message_id: str
    add_labels: List[str] = field(default_factory=list)
    remove_labels: List[str] = field(default_factory=list)
    archive: bool = False
    star: bool = False
    target_folder: Optional[str] = None
    category: Optional[str] = None
    category_color: Optional[str] = None
    due_date: Optional[datetime] = None

    def merge(self, other: "LabelAction") -> "LabelAction":
        """Merge another action into this one (same message_id assumed)."""
        return LabelAction(
            message_id=self.message_id,
            add_labels=list(set(self.add_labels + other.add_labels)),
            remove_labels=list(set(self.remove_labels + other.remove_labels)),
            archive=self.archive or other.archive,
            star=self.star or other.star,
            target_folder=other.target_folder or self.target_folder,
            category=other.category or self.category,
            category_color=other.category_color or self.category_color,
            due_date=other.due_date or self.due_date,
        )


@dataclass
class ProcessingResult:
    """
    Summary of a batch processing operation.

    Returned by provider process methods to report statistics.
    """
    processed_count: int = 0
    success_count: int = 0
    error_count: int = 0
    label_counts: dict = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add_label_stat(self, label: str) -> None:
        """Increment the count for a label."""
        self.label_counts[label] = self.label_counts.get(label, 0) + 1
