"""
Abstract base class for email providers.

Defines the interface that all email provider implementations must follow,
enabling consistent behavior across Gmail, IMAP, Mail.app, and Outlook.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Iterator, Dict, Any, Tuple
from enum import Flag, auto

from core.models import EmailMessage, LabelAction, ProcessingResult


class ProviderCapabilities(Flag):
    """
    Flags indicating what features a provider supports.

    Used to adapt behavior for providers with different capabilities
    (e.g., Gmail has true labels, IMAP uses folders).
    """
    NONE = 0
    TRUE_LABELS = auto()          # Supports multiple labels per message (Gmail)
    FOLDERS = auto()              # Uses folders instead of labels (IMAP, Outlook)
    STAR = auto()                 # Can star/flag messages
    ARCHIVE = auto()              # Can archive (remove from inbox without deleting)
    BATCH_OPERATIONS = auto()     # Supports batch API calls
    SEARCH_QUERY = auto()         # Supports server-side search queries
    GMAIL_EXTENSIONS = auto()     # Supports Gmail IMAP extensions (X-GM-LABELS)


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

    def star(self, message_id: str) -> bool:
        """
        Star/flag a message for priority handling.

        Args:
            message_id: Message to star

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

    def apply_actions(self, actions: List[LabelAction]) -> ProcessingResult:
        """
        Apply a batch of label actions.

        Default implementation processes actions sequentially. Providers
        with batch APIs should override for better performance.

        Args:
            actions: List of LabelAction objects to apply

        Returns:
            ProcessingResult with statistics and any errors
        """
        result = ProcessingResult()
        for action in actions:
            try:
                for label in action.add_labels:
                    self.ensure_label_exists(label)
                    if self.apply_label(action.message_id, label):
                        result.add_label_stat(label)
                for label in action.remove_labels:
                    self.remove_label(action.message_id, label)
                if action.archive:
                    self.archive(action.message_id)
                if action.star:
                    self.star(action.message_id)
                result.success_count += 1
            except Exception as e:
                result.error_count += 1
                result.errors.append(f"{action.message_id}: {e}")
            result.processed_count += 1
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
