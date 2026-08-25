"""
Data models for email automation.

Provides provider-agnostic data structures for email messages and label actions.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Set, Dict
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
    SET_FLAG = "set_flag"
    CLEAR_FLAG = "clear_flag"


class FlagColor(str, Enum):
    """Provider-agnostic semantic flag colors.

    These represent universal operator posture, never subject matter.
    Provider-native integer indices (e.g. Mail.app flag index) are NOT
    encoded here — each provider owns an explicit bidirectional mapping.
    Unknown native values map to UNKNOWN, never to NO_FLAG.
    """

    NO_FLAG = "no_flag"
    RED = "red"
    ORANGE = "orange"
    YELLOW = "yellow"
    GREEN = "green"
    BLUE = "blue"
    PURPLE = "purple"
    GRAY = "gray"
    UNKNOWN = "unknown"

    @property
    def name_str(self) -> str:
        """Human-readable name for the flag color."""
        return _NAME_MAP[self]

    @property
    def operator_posture(self) -> str:
        """Universal operator posture this flag represents."""
        return _POSTURE_MAP[self]

    @property
    def queue_label(self) -> str:
        """Short label for flags queue display."""
        return _QUEUE_MAP[self]

    @classmethod
    def from_string(cls, s: str) -> "FlagColor":
        """Parse flag color from string (case-insensitive).

        Raises ValueError for unrecognized strings — never silently
        returns NO_FLAG for an unknown color name.
        """
        s = s.lower().strip()
        mapping = {
            "none": cls.NO_FLAG,
            "no flag": cls.NO_FLAG,
            "no-flag": cls.NO_FLAG,
            "red": cls.RED,
            "orange": cls.ORANGE,
            "yellow": cls.YELLOW,
            "green": cls.GREEN,
            "blue": cls.BLUE,
            "purple": cls.PURPLE,
            "gray": cls.GRAY,
            "grey": cls.GRAY,
            "unknown": cls.UNKNOWN,
        }
        try:
            return mapping[s]
        except KeyError:
            raise ValueError(f"Unknown flag color: {s!r}") from None


_NAME_MAP = {
    FlagColor.NO_FLAG: "No Flag",
    FlagColor.RED: "Red",
    FlagColor.ORANGE: "Orange",
    FlagColor.YELLOW: "Yellow",
    FlagColor.GREEN: "Green",
    FlagColor.BLUE: "Blue",
    FlagColor.PURPLE: "Purple",
    FlagColor.GRAY: "Gray",
    FlagColor.UNKNOWN: "Unknown",
}

_POSTURE_MAP = {
    FlagColor.NO_FLAG: "CLOSED / COMPLETED / NO OPEN LOOP",
    FlagColor.RED: "CRITICAL / ACT NOW",
    FlagColor.ORANGE: "ACTION OWED",
    FlagColor.YELLOW: "WAITING / FOLLOW-UP",
    FlagColor.GREEN: "SCHEDULED / COMMITTED",
    FlagColor.BLUE: "ACTIVE REFERENCE",
    FlagColor.PURPLE: "HUMAN JUDGMENT REQUIRED",
    FlagColor.GRAY: "DELIBERATELY DEFERRED",
    FlagColor.UNKNOWN: "UNKNOWN / UNMAPPED NATIVE INDEX",
}

_QUEUE_MAP = {
    FlagColor.NO_FLAG: "DONE",
    FlagColor.RED: "NOW",
    FlagColor.ORANGE: "ACTION",
    FlagColor.YELLOW: "WAITING",
    FlagColor.GREEN: "SCHEDULED",
    FlagColor.BLUE: "REFERENCE",
    FlagColor.PURPLE: "REVIEW",
    FlagColor.GRAY: "LATER",
    FlagColor.UNKNOWN: "UNKNOWN",
}


class StateSource(str, Enum):
    """Source of the operator state assignment."""
    HUMAN = "human"
    DETERMINISTIC_RULE = "deterministic_rule"
    MODEL = "model"
    MIGRATION = "migration"
    LEGACY_UNKNOWN = "legacy_unknown"


@dataclass
class FlagMutation:
    """
    Represents a flag color mutation to apply to a message.

    Used for batch-planning and receipt-bound flag operations.
    """
    message_id: str
    sender: str = ""
    current_flag: FlagColor = FlagColor.NO_FLAG
    proposed_flag: FlagColor = FlagColor.NO_FLAG
    reason: str = ""
    confidence: float = 1.0
    state_source: StateSource = StateSource.MIGRATION
    due_at: Optional[datetime] = None
    follow_up_at: Optional[datetime] = None
    next_action: str = ""
    urgency: int = 0  # 0-10 scale
    human_override: bool = False
    transaction_id: str = ""

    def is_noop(self) -> bool:
        """True if this mutation would not change the flag."""
        return self.current_flag == self.proposed_flag


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
        is_starred: Whether the message is starred/flagged (boolean, backward compat)
        flag_color: The colored flag (FlagColor), NO_FLAG if unflagged
        priority_tier: Eisenhower matrix tier (1=Critical, 2=Important, 3=Delegate, 4=Reference)
        categories: Color categories (Outlook)
        snippet: Short preview of the body (provider-supplied, optional)
        body: Full plain-text body when fetched (optional; used for research)
        headers: Cheap headers captured at list time, as a {name: value} map
            (lower-cased names). The mailing-list / bulk / auto markers (list-unsubscribe,
            list-id, list-post, precedence, auto-submitted) so the classifier can suppress
            bulk mail from the reply-owed rung, PLUS reply-to so the draft leaf can prefer
            the sender's stated reply address (see core.protocols.CAPTURE_HEADERS). Empty
            when a provider does not (or cannot cheaply) supply headers — fail-open.
        -- Separate classification axes (extendable, domain-agnostic) --
        domain: Semantic domain/category (e.g., "Career", "Finance", "Legal")
        semantic_type: Fine-grained semantic type within domain
        operator_state: Current operator posture (maps to FlagColor)
        urgency: Urgency level 0-10
        next_action: Concrete next action description
        due_at: Calendar-bound due date
        follow_up_at: Follow-up date
        confidence: Classification confidence 0.0-1.0
        state_source: Source of state assignment
        observed_flag: Flag color observed at fetch time
        proposed_flag: Flag color proposed by automation
        human_override: Whether human has overridden automation
        message_id_digest: Stable RFC Message-ID digest for cross-provider identity
        mutation_txn_id: Transaction/receipt ID for last mutation
    """
    id: str
    sender: str
    subject: str
    date: Optional[datetime] = None
    labels: Set[str] = field(default_factory=set)
    is_read: bool = False
    is_starred: bool = False
    flag_color: FlagColor = FlagColor.NO_FLAG
    priority_tier: Optional[int] = None
    categories: Set[str] = field(default_factory=set)
    snippet: str = ""
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    # Separate classification axes
    domain: Optional[str] = None
    semantic_type: Optional[str] = None
    operator_state: Optional[FlagColor] = None
    urgency: int = 0
    next_action: str = ""
    due_at: Optional[datetime] = None
    follow_up_at: Optional[datetime] = None
    confidence: float = 1.0
    state_source: StateSource = StateSource.LEGACY_UNKNOWN
    observed_flag: FlagColor = FlagColor.NO_FLAG
    proposed_flag: FlagColor = FlagColor.NO_FLAG
    human_override: bool = False
    message_id_digest: Optional[str] = None
    mutation_txn_id: Optional[str] = None

    @property
    def combined_text(self) -> str:
        """Returns sender + subject combined for pattern matching."""
        return f"{self.sender} {self.subject}".lower()

    @property
    def content_text(self) -> str:
        """
        Returns the richest available text for context research:
        subject plus body (preferred) or snippet. Used by core.research.
        """
        detail = self.body.strip() or self.snippet.strip()
        if detail:
            return f"{self.subject}\n\n{detail}".strip()
        return self.subject


class LabelActionValidationError(ValueError):
    """Raised when a LabelAction contains contradictory flag combinations."""


@dataclass
class LabelAction:
    """
    Represents a label/folder/flag action to apply to a message.

    Accumulates multiple actions for batch processing. Provider implementations
    translate these into API-specific calls (Gmail batchModify, IMAP STORE, etc.)

    Attributes:
        message_id: The message to act upon
        sender: The 'From' header value — REQUIRED for the protected-sender gate.
            Carried so the provider chokepoint can re-check is_protected_sender
            before any archive/move; if blank, the fail-closed gate treats it as
            protected (never archived). Populate it at every action-building site.
        add_labels: Labels to add to the message
        remove_labels: Labels to remove from the message
        archive: Whether to remove from inbox (archive)
        star: Whether to star/flag the message (boolean, backward compat)
        flag_color: Specific flag color to set (FlagColor), None = no change
        clear_flag: Whether to clear the flag entirely (set to NO_FLAG)
        target_folder: For folder-based systems, the destination folder
        category: Color category name (Outlook)
        category_color: Color preset for the category (Outlook)
        due_date: Due date for flagged items (Outlook To Do integration)
    """
    message_id: str
    sender: str = ""
    add_labels: List[str] = field(default_factory=list)
    remove_labels: List[str] = field(default_factory=list)
    archive: bool = False
    star: bool = False
    flag_color: Optional[FlagColor] = None
    clear_flag: bool = False
    target_folder: Optional[str] = None
    category: Optional[str] = None
    category_color: Optional[str] = None
    due_date: Optional[datetime] = None

    def merge(self, other: "LabelAction") -> "LabelAction":
        """Merge another action into this one (same message_id assumed).

        Uses ``is not None`` for flag_color and other Optional fields so that
        explicit values (including NO_FLAG whose str value is truthy) are never
        silently discarded by boolean truthiness.
        """
        return LabelAction(
            message_id=self.message_id,
            sender=self.sender or other.sender,
            add_labels=list(set(self.add_labels + other.add_labels)),
            remove_labels=list(set(self.remove_labels + other.remove_labels)),
            archive=self.archive or other.archive,
            star=self.star or other.star,
            flag_color=(
                other.flag_color if other.flag_color is not None else self.flag_color
            ),
            clear_flag=other.clear_flag or self.clear_flag,
            target_folder=(
                other.target_folder
                if other.target_folder is not None
                else self.target_folder
            ),
            category=other.category if other.category is not None else self.category,
            category_color=(
                other.category_color
                if other.category_color is not None
                else self.category_color
            ),
            due_date=other.due_date or self.due_date,
        )

    def validate(self) -> None:
        """Reject contradictory flag-action combinations before provider execution.

        Raises LabelActionValidationError on any invalid combination.
        Call this inside apply_actions before dispatching to provider methods.
        """
        if self.clear_flag and self.flag_color is not None:
            raise LabelActionValidationError(
                "clear_flag and flag_color are mutually exclusive"
            )
        if self.clear_flag and self.star:
            raise LabelActionValidationError(
                "clear_flag and star are mutually exclusive"
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
    label_counts: Dict[str, int] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add_label_stat(self, label: str) -> None:
        """Increment the count for a label."""
        self.label_counts[label] = self.label_counts.get(label, 0) + 1
