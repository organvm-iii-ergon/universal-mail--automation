"""
IMAP provider implementation.

Supports standard IMAP servers and Gmail IMAP with X-GM-LABELS extension.
"""

import email
import imaplib
import logging
import os
import ssl
import subprocess
from email.header import decode_header
from typing import Dict, List, Optional, Tuple

from providers.base import (
    EmailProvider,
    ProviderCapabilities,
    ListMessagesResult,
)
from core.models import EmailMessage, LabelAction, ProcessingResult

logger = logging.getLogger(__name__)


def _decode_header_value(s: str) -> str:
    """Decode an email header value handling different encodings."""
    if not s:
        return ""
    decoded = decode_header(s)
    parts = []
    for text, enc in decoded:
        if isinstance(text, bytes):
            parts.append(text.decode(enc or "utf-8", errors="ignore"))
        else:
            parts.append(text)
    return " ".join(parts)


class IMAPProvider(EmailProvider):
    """
    Generic IMAP provider with optional Gmail extensions.

    Supports standard IMAP servers as well as Gmail's IMAP implementation
    with X-GM-LABELS for true label operations.

    Configuration via environment variables:
        IMAP_HOST: IMAP server hostname (default: imap.gmail.com)
        IMAP_USER: Username/email address
        IMAP_PASS: Password or app-specific password
        OP_ACCOUNT, OP_ITEM, OP_FIELD: 1Password integration for password

    Example:
        provider = IMAPProvider(
            host="imap.gmail.com",
            user="user@gmail.com",
            password="app-password",  # allow-secret
            use_gmail_extensions=True,
        )
        with provider:
            result = provider.list_messages("ALL", limit=100)
    """

    name = "imap"

    def __init__(
        self,
        host: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,  # allow-secret
        use_gmail_extensions: bool = False,
        port: int = 993,
    ):
        """
        Initialize IMAP provider.

        Args:
            host: IMAP server hostname (or IMAP_HOST env var)
            user: Username (or IMAP_USER env var)
            password: Password (or IMAP_PASS/1Password env vars)  # allow-secret
            use_gmail_extensions: Enable Gmail-specific IMAP extensions
            port: IMAP port (default 993 for SSL)
        """
        self.host = host or os.getenv("IMAP_HOST", "imap.gmail.com")
        self.user = user or os.getenv("IMAP_USER")
        self._password = password
        self.use_gmail_extensions = use_gmail_extensions
        self.port = port
        self._connection: Optional[imaplib.IMAP4_SSL] = None
        self._created_folders: set = set()
        self._current_mailbox: Optional[str] = None

        # Set capabilities based on mode
        self.capabilities = ProviderCapabilities.FOLDERS | ProviderCapabilities.SEARCH_QUERY
        if use_gmail_extensions:
            self.capabilities |= ProviderCapabilities.GMAIL_EXTENSIONS
            self.capabilities |= ProviderCapabilities.TRUE_LABELS
            self.capabilities |= ProviderCapabilities.STAR

    def _load_password(self) -> str:
        """Load password from environment or 1Password."""
        if self._password:
            return self._password

        if os.getenv("IMAP_PASS"):
            return os.getenv("IMAP_PASS")

        # Try 1Password CLI
        op_account = os.getenv("OP_ACCOUNT")
        op_item = os.getenv("OP_ITEM")
        op_field = os.getenv("OP_FIELD", "password")

        if op_account and op_item:
            try:
                result = subprocess.check_output(
                    ["op", "item", "get", op_item, "--account", op_account, f"--field={op_field}"],
                    text=True,
                ).strip()
                return result
            except Exception as e:
                logger.warning(f"Failed to load password from 1Password: {e}")

        raise ValueError(
            "IMAP password not configured. Set IMAP_PASS or use 1Password env vars "
            "(OP_ACCOUNT, OP_ITEM, OP_FIELD)"
        )

    def connect(self) -> None:
        """Establish IMAP connection with SSL."""
        if self._connection:
            return

        if not self.user:
            raise ValueError("IMAP_USER not configured")

        password = self._load_password()  # allow-secret

        ctx = ssl.create_default_context()
        self._connection = imaplib.IMAP4_SSL(self.host, port=self.port, ssl_context=ctx)
        self._connection.login(self.user, password)
        logger.info(f"IMAP connected to {self.host} as {self.user}")

    def disconnect(self) -> None:
        """Close IMAP connection."""
        if self._connection:
            try:
                self._connection.logout()
            except Exception as e:
                logger.debug(f"Error during IMAP logout: {e}")
            finally:
                self._connection = None
                self._current_mailbox = None
        logger.debug("IMAP disconnected")

    def _select_mailbox(self, mailbox: str = "INBOX") -> None:
        """Select a mailbox if not already selected."""
        if self._current_mailbox != mailbox:
            res, _ = self._connection.select(mailbox)
            if res != "OK":
                raise RuntimeError(f"Failed to select mailbox: {mailbox}")
            self._current_mailbox = mailbox

    def list_messages(
        self,
        query: str = "ALL",
        limit: int = 100,
        page_token: Optional[str] = None,
        mailbox: str = "INBOX",
    ) -> ListMessagesResult:
        """
        List messages matching IMAP search criteria.

        Args:
            query: IMAP SEARCH criteria (e.g., "ALL", "UNSEEN", "FROM example.com")
            limit: Maximum messages to return
            page_token: Start offset as string (for pagination)
            mailbox: Mailbox to search in (default INBOX)

        Returns:
            ListMessagesResult with message UIDs
        """
        self._select_mailbox(mailbox)

        res, data = self._connection.uid("search", None, query)
        if res != "OK":
            raise RuntimeError(f"IMAP search failed: {query}")

        uids = data[0].split() if data[0] else []
        total = len(uids)

        # Handle pagination via offset
        start = int(page_token) if page_token else 0
        # Take most recent first (reverse order)
        uids = uids[max(0, total - start - limit):total - start]

        messages = []
        for uid in uids:
            messages.append(EmailMessage(
                id=uid.decode() if isinstance(uid, bytes) else str(uid),
                sender="",
                subject="",
            ))

        # Calculate next page token
        next_start = start + limit
        next_token = str(next_start) if next_start < total else None

        return ListMessagesResult(
            messages=messages,
            next_page_token=next_token,
            total_estimate=total,
        )

    def get_message_details(self, message_id: str) -> Optional[EmailMessage]:
        """Fetch message headers by UID."""
        res, data = self._connection.uid(
            "fetch",
            message_id,
            "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])",
        )
        if res != "OK" or not data or data[0] is None:
            return None

        msg = email.message_from_bytes(data[0][1])
        sender = _decode_header_value(msg.get("From", ""))
        subject = _decode_header_value(msg.get("Subject", ""))

        # Get flags/labels
        labels = set()
        is_starred = False
        is_read = False

        if self.use_gmail_extensions:
            # Fetch Gmail labels
            res, label_data = self._connection.uid("fetch", message_id, "(X-GM-LABELS)")
            if res == "OK" and label_data and label_data[0]:
                # Parse X-GM-LABELS response
                raw = label_data[0][1] if isinstance(label_data[0], tuple) else label_data[0]
                if raw:
                    raw_str = raw.decode() if isinstance(raw, bytes) else str(raw)
                    # Extract labels from parentheses
                    import re
                    match = re.search(r'\(([^)]*)\)', raw_str)
                    if match:
                        for label in match.group(1).split():
                            label = label.strip('"')
                            labels.add(label)
                            if label == "\\Starred":
                                is_starred = True

        # Fetch flags for read status
        res, flag_data = self._connection.uid("fetch", message_id, "(FLAGS)")
        if res == "OK" and flag_data and flag_data[0]:
            raw = flag_data[0][1] if isinstance(flag_data[0], tuple) else flag_data[0]
            if raw:
                raw_str = raw.decode() if isinstance(raw, bytes) else str(raw)
                is_read = "\\Seen" in raw_str
                if "\\Flagged" in raw_str:
                    is_starred = True

        return EmailMessage(
            id=message_id,
            sender=sender,
            subject=subject,
            labels=labels,
            is_starred=is_starred,
            is_read=is_read,
        )

    def apply_label(self, message_id: str, label: str) -> bool:
        """
        Add a label to a message.

        For Gmail IMAP: Uses X-GM-LABELS extension.
        For standard IMAP: Copies message to folder.
        """
        if self.use_gmail_extensions:
            try:
                self._connection.uid("STORE", message_id, "+X-GM-LABELS", f'"{label}"')
                return True
            except Exception as e:
                logger.error(f"Failed to apply Gmail label {label}: {e}")
                return False
        else:
            # Standard IMAP: copy to folder
            self.ensure_label_exists(label)
            try:
                res, _ = self._connection.uid("COPY", message_id, f'"{label}"')
                return res == "OK"
            except Exception as e:
                logger.error(f"Failed to copy to folder {label}: {e}")
                return False

    def remove_label(self, message_id: str, label: str) -> bool:
        """
        Remove a label from a message.

        For Gmail IMAP: Uses X-GM-LABELS extension.
        For standard IMAP: Not directly supported (would need move).
        """
        if self.use_gmail_extensions:
            try:
                self._connection.uid("STORE", message_id, "-X-GM-LABELS", f'"{label}"')
                return True
            except Exception as e:
                logger.error(f"Failed to remove Gmail label {label}: {e}")
                return False
        else:
            logger.warning("remove_label not supported for standard IMAP (folder-based)")
            return False

    def archive(self, message_id: str) -> bool:
        """Archive a message."""
        if self.use_gmail_extensions:
            return self.remove_label(message_id, "\\Inbox")
        else:
            # Standard IMAP: move to Archive folder (if exists)
            try:
                res, _ = self._connection.uid("COPY", message_id, '"Archive"')
                if res == "OK":
                    self._connection.uid("STORE", message_id, "+FLAGS", r"(\Deleted)")
                    return True
                return False
            except Exception as e:
                logger.error(f"Failed to archive message: {e}")
                return False

    def star(self, message_id: str) -> bool:
        """Flag/star a message."""
        try:
            self._connection.uid("STORE", message_id, "+FLAGS", r"(\Flagged)")
            return True
        except Exception as e:
            logger.error(f"Failed to star message: {e}")
            return False

    def unstar(self, message_id: str) -> bool:
        """Remove flag/star from a message."""
        try:
            self._connection.uid("STORE", message_id, "-FLAGS", r"(\Flagged)")
            return True
        except Exception as e:
            logger.error(f"Failed to unstar message: {e}")
            return False

    def ensure_label_exists(self, label: str) -> str:
        """Ensure folder exists, creating if necessary."""
        if label in self._created_folders:
            return label

        try:
            res, _ = self._connection.create(label)
            # OK = created, NO = already exists
            if res in ("OK", "NO"):
                self._created_folders.add(label)
        except Exception as e:
            logger.debug(f"Folder create attempt for {label}: {e}")

        return label

    def mark_read(self, message_id: str) -> bool:
        """Mark message as read."""
        try:
            self._connection.uid("STORE", message_id, "+FLAGS", r"(\Seen)")
            return True
        except Exception as e:
            logger.error(f"Failed to mark read: {e}")
            return False

    def mark_unread(self, message_id: str) -> bool:
        """Mark message as unread."""
        try:
            self._connection.uid("STORE", message_id, "-FLAGS", r"(\Seen)")
            return True
        except Exception as e:
            logger.error(f"Failed to mark unread: {e}")
            return False
