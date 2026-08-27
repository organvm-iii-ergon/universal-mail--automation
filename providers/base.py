"""
Abstract base class for email providers.

Defines the interface that all email provider implementations must follow,
enabling consistent behavior across Gmail, IMAP, Mail.app, and Outlook.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple, TYPE_CHECKING
from enum import Flag, auto

from core.models import (
    EmailMessage,
    LabelAction,
    LabelActionValidationError,
    MessageReference,
    ProcessingResult,
    FlagColor,
)
from core.rules import is_protected_sender

if TYPE_CHECKING:  # avoid any import-time coupling; AuditLog is duck-typed at runtime
    from core.audit import AuditLog


class ProviderCapabilities(Flag):
    """
    Flags indicating what features a provider supports.

    Used to adapt behavior for providers with different capabilities
    (e.g., Gmail has true labels, IMAP uses folders).
    """
    NONE = 0
    TRUE_LABELS = auto()          # Supports multiple labels per message (Gmail)
    FOLDERS = auto()              # Uses folders instead of labels (IMAP, Outlook)
    STAR = auto()                 # Can star/flag messages (boolean)
    ARCHIVE = auto()              # Can archive (remove from inbox without deleting)
    BATCH_OPERATIONS = auto()     # Supports batch API calls
    SEARCH_QUERY = auto()         # Supports server-side search queries
    GMAIL_EXTENSIONS = auto()     # Supports Gmail IMAP extensions (X-GM-LABELS)
    CATEGORIES = auto()           # Supports color categories (Outlook)
    COLORED_FLAGS = auto()        # Supports 7-color flag index (Mail.app)


class ProviderWriteAmbiguous(RuntimeError):
    """A provider write crossed dispatch but its outcome is not provable.

    Providers raise this only when a mutating request may have reached the
    backing service (including failures during provider-internal post-write
    verification).  Callers must conservatively count the operation as a
    possible write and must not report a zero-write refusal.

    Exceptions raised before dispatch use their ordinary provider-specific
    type; an explicit ``False`` return continues to mean the provider refused
    the write before it occurred.
    """


class ProviderNativeStateDrift(RuntimeError):
    """A scoped provider refused a write before dispatch due to native drift.

    This exception is the compare-and-set refusal boundary.  Providers may
    raise it only after proving that the live native state does not equal the
    caller-bound expected state and before issuing the mutation.  Transaction
    callers can therefore persist a human-override suppression while keeping
    ``writes_performed`` unchanged.
    """

    def __init__(self, expected_native: int, observed_native: Optional[int]):
        self.expected_native = expected_native
        self.observed_native = observed_native
        super().__init__(
            "native flag changed before dispatch "
            f"(expected {expected_native}, observed {observed_native})"
        )


@dataclass
class ListMessagesResult:
    """Result from listing messages, including pagination info."""
    messages: List[EmailMessage]
    next_page_token: Optional[str] = None
    total_estimate: Optional[int] = None


class EmailProvider(ABC):
    """
    Abstract base class for email provider implementations.

    Providers implement this interface to enable consistent email processing
    across different services. The class supports context manager protocol
    for clean connection management.

    Example:
        with GmailProvider() as provider:
            messages = provider.list_messages("has:nouserlabels", limit=100)
            for msg in messages.messages:
                label = categorize_message(...)
                provider.apply_label(msg.id, label)

    Attributes:
        name: Human-readable provider name
        capabilities: Flags indicating supported features
    """

    name: str = "abstract"
    capabilities: ProviderCapabilities = ProviderCapabilities.NONE

    # Whether this provider's apply_label() physically MOVES a message out of the
    # inbox (vs. adding an additive label that leaves it in place). True for
    # folder providers whose only "label" is the containing folder (Outlook,
    # Mail.app). False for Gmail (additive labels) AND for IMAP — even with
    # X-GM-LABELS, apply_label is +X-GM-LABELS / a COPY that leaves the original
    # in the inbox; IMAP's out-of-inbox departure happens via remove_label("INBOX")
    # or archive(), which are observed directly. Drives MOVED-vs-LABELED in the
    # audit receipt so the disposition reflects real semantics, not a capability
    # proxy. See core/audit.py.
    LABEL_IS_MOVE: bool = False

    def __enter__(self) -> "EmailProvider":
        """Context manager entry - establish connection."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - close connection."""
        self.disconnect()

    @abstractmethod
    def connect(self) -> None:
        """
        Establish connection to the email service.

        Called automatically when using context manager. May involve
        OAuth token refresh, IMAP login, etc.

        Raises:
            ConnectionError: If connection cannot be established
            AuthenticationError: If credentials are invalid
        """
        pass

    @abstractmethod
    def disconnect(self) -> None:
        """
        Close connection to the email service.

        Called automatically when exiting context manager. Should be
        idempotent (safe to call multiple times).
        """
        pass

    @abstractmethod
    def list_messages(
        self,
        query: str = "",
        limit: int = 100,
        page_token: Optional[str] = None,
    ) -> ListMessagesResult:
        """
        List messages matching the query.

        Args:
            query: Provider-specific query string (e.g., Gmail search syntax,
                   IMAP SEARCH criteria)
            limit: Maximum messages to return per page
            page_token: Token for fetching next page (from previous result)

        Returns:
            ListMessagesResult with messages and pagination info

        Note:
            Initial result may contain only message IDs. Call
            get_message_details() or batch_get_details() to fetch headers.
        """
        pass

    @abstractmethod
    def get_message_details(self, message_id: str) -> Optional[EmailMessage]:
        """
        Fetch full details for a single message.

        Args:
            message_id: Provider-specific message identifier

        Returns:
            EmailMessage with populated headers, or None if not found
        """
        pass

    def batch_get_details(
        self,
        message_ids: List[str],
    ) -> Dict[str, EmailMessage]:
        """
        Fetch details for multiple messages efficiently.

        Default implementation calls get_message_details() sequentially.
        Providers with batch APIs should override for better performance.

        Args:
            message_ids: List of message IDs to fetch

        Returns:
            Dict mapping message_id to EmailMessage (missing IDs omitted)
        """
        results = {}
        for msg_id in message_ids:
            msg = self.get_message_details(msg_id)
            if msg:
                results[msg_id] = msg
        return results

    @abstractmethod
    def apply_label(self, message_id: str, label: str) -> bool:
        """
        Add a label to a message.

        For folder-based providers, this may move the message to a folder.
        For label-based providers (Gmail), adds the label to the message.

        Args:
            message_id: Message to label
            label: Label/folder name to apply

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def remove_label(self, message_id: str, label: str) -> bool:
        """
        Remove a label from a message.

        Args:
            message_id: Message to modify
            label: Label/folder name to remove

        Returns:
            True if successful, False otherwise
        """
        pass

    def archive(self, message_id: str) -> bool:
        """
        Archive a message (remove from inbox without deleting).

        Default implementation removes "INBOX" label. Providers may override.

        Args:
            message_id: Message to archive

        Returns:
            True if successful, False otherwise
        """
        return self.remove_label(message_id, "INBOX")

    def star(self, message_id: str, due_date: Any = None) -> bool:
        """
        Star/flag a message for priority handling.

        Args:
            message_id: Message to star
            due_date: Optional due date for task integration (provider-specific)

        Returns:
            True if successful, False otherwise
        """
        if not (self.capabilities & ProviderCapabilities.STAR):
            return False
        return self.apply_label(message_id, "STARRED")

    def unstar(self, message_id: str) -> bool:
        """
        Remove star/flag from a message.

        Args:
            message_id: Message to unstar

        Returns:
            True if successful, False otherwise
        """
        if not (self.capabilities & ProviderCapabilities.STAR):
            return False
        return self.remove_label(message_id, "STARRED")

    def apply_category(
        self,
        message_id: str,
        category: str,
        color: str = "blue",
    ) -> bool:
        """
        Apply a color category to a message.

        Only supported by providers with CATEGORIES capability.
        Default implementation returns False.

        Args:
            message_id: Message to categorize
            category: Category name to apply
            color: Color for category (provider-specific)

        Returns:
            True if successful, False otherwise
        """
        if not (self.capabilities & ProviderCapabilities.CATEGORIES):
            return False
        return False  # Subclasses override

    def get_flag_color(self, message_id: str) -> FlagColor:
        """
        Bare-id colored reads are NOT part of the colored-flag contract.

        Providers capable of colored flags implement the ref-based API
        (:meth:`get_flag_color_ref`). This stub exists only so non-flag
        providers fail closed identically to before.

        Raises:
            NotImplementedError: Always — use get_flag_color_ref(ref).
        """
        raise NotImplementedError(
            "bare-id colored flag read removed; use get_flag_color_ref"
            "(MessageReference)"
        )

    # --- Ref-based colored-flag contract (the ONLY supported surface) ------

    def get_flag_color_ref(self, ref: MessageReference) -> FlagColor:
        """Scoped semantic read for a qualified reference."""
        if not (self.capabilities & ProviderCapabilities.COLORED_FLAGS):
            raise NotImplementedError(
                f"{self.name} does not support COLORED_FLAGS capability"
            )
        raise NotImplementedError(
            "subclass must implement get_flag_color_ref")

    def set_flag_color_ref(self, ref: MessageReference, color: FlagColor) -> bool:
        """Evidence-verified compare-and-set scoped write.

        ``ref.observed_native_flag`` is the mandatory expected-current value.
        The provider must compare it and perform the write in one provider
        request.  True is returned only when post-write re-read confirms the
        expected target value.

        Raises:
            ProviderNativeStateDrift: Live native state differed before the
                write and the provider proved that no mutation was dispatched.
            ProviderWriteAmbiguous: Dispatch may have crossed the provider's
                write boundary but the final outcome cannot be proved.
        """
        if not (self.capabilities & ProviderCapabilities.COLORED_FLAGS):
            raise NotImplementedError(
                f"{self.name} does not support COLORED_FLAGS capability"
            )
        raise NotImplementedError(
            "subclass must implement set_flag_color_ref")

    def clear_flag_ref(self, ref: MessageReference) -> bool:
        """Evidence-verified scoped unflag (NO_FLAG)."""
        return self.set_flag_color_ref(ref, FlagColor.NO_FLAG)

    @abstractmethod
    def ensure_label_exists(self, label: str) -> str:
        """
        Ensure a label/folder exists, creating if necessary.

        Args:
            label: Label/folder name (hierarchical with "/" separator)

        Returns:
            The provider-specific label ID or name

        Raises:
            PermissionError: If unable to create the label
        """
        pass

    def _drop_if_protected(self, action: LabelAction) -> bool:
        """Fail-closed never-archive gate, enforced at the provider CHOKEPOINT.

        The product's headline invariant — a protected sender is NEVER archived or
        moved out of inbox — lives HERE (and in the Gmail apply_actions override),
        because every provider funnels through apply_actions and the From is
        carried on LabelAction.sender. If the sender is protected, neutralize every
        out-of-inbox operation IN PLACE (archive=False; strip INBOX/\\Inbox from
        remove_labels) and return True so the caller can also suppress the
        label-as-MOVE for folder providers. A blank sender fails closed (protected).
        """
        if not is_protected_sender(action.sender):
            return False
        action.archive = False
        action.remove_labels = [
            lbl for lbl in action.remove_labels if lbl.upper() not in ("INBOX", "\\INBOX")
        ]
        return True

    def apply_actions(
        self,
        actions: List[LabelAction],
        audit: Optional["AuditLog"] = None,
    ) -> ProcessingResult:
        """
        Apply a batch of label actions.

        Default implementation processes actions sequentially. Providers
        with batch APIs should override for better performance.

        Args:
            actions: List of LabelAction objects to apply
            audit: Optional AuditLog. When supplied, each message's post-gate
                disposition (protected_held / archived / moved / labeled / kept)
                is recorded as an independent trust receipt — see core/audit.py.

        Returns:
            ProcessingResult with statistics and any errors
        """
        result = ProcessingResult()
        is_folder = bool(self.capabilities & ProviderCapabilities.FOLDERS)
        for action in actions:
            # Initialize observation state BEFORE validation so the audit block
            # below is well-defined even when validation rejects the action.
            protected = False
            did_leave_inbox = False     # archive() or INBOX-removal actually ran
            did_label_move = False      # a move-on-label apply_label() actually ran
            applied_labels = []
            # Validate FIRST, before the protected-sender gate can mutate the
            # action in place. Validation must assess what the caller REQUESTED,
            # not the gate-normalized representation — otherwise an invalid
            # archive+flag combination on a protected sender could be silently
            # normalized into a valid-looking flag-only operation.
            try:
                action.validate()
                if action.star and not (
                    self.capabilities & ProviderCapabilities.STAR
                ):
                    raise LabelActionValidationError(
                        "provider does not support STAR capability"
                    )
                if action.category and not (
                    self.capabilities & ProviderCapabilities.CATEGORIES
                ):
                    raise LabelActionValidationError(
                        "provider does not support CATEGORIES capability"
                    )
                if action.clear_flag or action.flag_color is not None:
                    if not (
                        self.capabilities & ProviderCapabilities.COLORED_FLAGS
                    ):
                        raise LabelActionValidationError(
                            "provider does not support COLORED_FLAGS capability"
                        )
                protected = self._drop_if_protected(action)
                # For providers where apply_label IS a move (Outlook/Mail.app), a
                # protected sender must not have labels applied either — that would
                # itself move the message out of the inbox.
                move_via_label = protected and self.LABEL_IS_MOVE
                if not move_via_label:
                    for label in action.add_labels:
                        self.ensure_label_exists(label)
                        if self.apply_label(action.message_id, label):
                            result.add_label_stat(label)
                            applied_labels.append(label)
                            if self.LABEL_IS_MOVE:
                                did_label_move = True
                for label in action.remove_labels:
                    if self.remove_label(action.message_id, label) and \
                            label.upper() in ("INBOX", "\\INBOX"):
                        did_leave_inbox = True
                if action.archive:
                    if self.archive(action.message_id):
                        did_leave_inbox = True
                if action.star:
                    if not self.star(action.message_id, due_date=action.due_date):
                        raise RuntimeError("provider failed to star message")
                if action.category:
                    if not self.apply_category(
                        action.message_id,
                        action.category,
                        action.category_color or "blue",
                    ):
                        raise RuntimeError("provider failed to apply category")
                # Colored flag operations (do not move messages). Capability gate
                # runs BEFORE any provider call so an unsupported provider never
                # reaches its (default-raising) flag methods. Dispatch is ALWAYS
                # through the scoped, evidence-verified ref API — there is no
                # bare-id colored path anywhere in the codebase.
                if action.clear_flag or action.flag_color is not None:
                    if action.message_ref is None:   # belt+braces; validate() also enforces
                        raise LabelActionValidationError(
                            "colored flag operation requires a qualified "
                            "MessageReference"
                        )
                    if action.clear_flag:
                        if not self.clear_flag_ref(action.message_ref):
                            raise RuntimeError("provider failed to clear flag")
                    elif action.flag_color is not None:
                        if not self.set_flag_color_ref(
                                action.message_ref, action.flag_color):
                            raise RuntimeError("provider failed to set flag color")
                result.success_count += 1
            except Exception as e:
                result.error_count += 1
                result.errors.append(f"{action.message_id}: {e}")
            result.processed_count += 1

            if audit is not None:
                # Record AFTER execution, from the operations that actually ran.
                # Folder provider: leaving the inbox (by removal or move-on-label)
                # is a MOVE; label provider: INBOX-removal/archive is an ARCHIVE.
                # No `and not protected` fudge — if a regressed gate let a protected
                # message leave the inbox, archived/moved is TRUE here so the
                # receipt's invariant check fires instead of being silenced.
                if is_folder:
                    moved = did_leave_inbox or did_label_move
                    archived = False
                else:
                    archived = did_leave_inbox
                    moved = False
                audit.record(
                    message_id=action.message_id,
                    sender=action.sender,
                    protected=protected,
                    archived=archived,
                    moved=moved,
                    labels_added=applied_labels,
                )
        return result

    def get_label_cache(self) -> Dict[str, str]:
        """
        Get a mapping of label names to provider-specific IDs.

        Returns:
            Dict mapping label names to IDs (or names if no IDs)
        """
        return {}

    def health_check(self) -> Tuple[bool, str]:
        """
        Verify the provider connection is healthy.

        Returns:
            Tuple of (is_healthy, status_message)
        """
        try:
            self.list_messages(limit=1)
            return True, "OK"
        except Exception as e:
            return False, str(e)
