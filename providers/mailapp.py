"""
macOS Mail.app provider implementation.

Uses AppleScript via subprocess to interact with Mail.app for email
categorization and organization.
"""

import json
import logging
import subprocess
import sys
from datetime import datetime
from typing import Dict, List, Optional

from providers.base import (
    EmailProvider,
    ProviderCapabilities,
    ListMessagesResult,
)
from core.models import EmailMessage, LabelAction, ProcessingResult

logger = logging.getLogger(__name__)


class MailAppProvider(EmailProvider):
    """
    macOS Mail.app provider using AppleScript.

    Provides access to Mail.app for reading and organizing emails using
    AppleScript commands via the `osascript` subprocess.

    Notes:
        - Mail.app uses mailboxes (folders) instead of labels
        - Only one category can be applied per message (move operation)
        - Requires Mail.app to be running
        - Only works on macOS

    Example:
        with MailAppProvider() as mail:
            result = mail.list_messages(limit=100)
            for msg in result.messages:
                details = mail.get_message_details(msg.id)
                mail.apply_label(msg.id, "Work/Dev/GitHub")
    """

    name = "mailapp"
    capabilities = (
        ProviderCapabilities.FOLDERS |
        ProviderCapabilities.STAR |
        ProviderCapabilities.ARCHIVE
    )

    def __init__(self, account: Optional[str] = None):
        """
        Initialize Mail.app provider.

        Args:
            account: Optional account name to filter messages by.
                     If None, processes messages from all accounts.
        """
        self.account = account
        self._created_mailboxes: set = set()

    def _run_applescript(self, script: str) -> str:
        """Execute AppleScript and return output."""
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                logger.error(f"AppleScript error: {result.stderr}")
                raise RuntimeError(f"AppleScript failed: {result.stderr}")
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            raise RuntimeError("AppleScript timed out")
        except FileNotFoundError:
            raise RuntimeError("osascript not found - this provider only works on macOS")

    def connect(self) -> None:
        """Verify Mail.app is accessible."""
        if sys.platform != "darwin":
            raise RuntimeError("MailAppProvider only works on macOS")

        # Check if Mail.app is running, start if not
        script = '''
        tell application "System Events"
            set mailRunning to (name of processes) contains "Mail"
        end tell
        if not mailRunning then
            tell application "Mail" to activate
            delay 2
        end if
        return "ok"
        '''
        self._run_applescript(script)
        logger.info("Mail.app provider connected")

    def disconnect(self) -> None:
        """Disconnect (no-op for Mail.app)."""
        logger.debug("Mail.app provider disconnected")

    def list_messages(
        self,
        query: str = "",
        limit: int = 100,
        page_token: Optional[str] = None,
        mailbox: str = "INBOX",
    ) -> ListMessagesResult:
        """
        List messages from Mail.app.

        Args:
            query: Not used (Mail.app doesn't have server-side search via AppleScript)
            limit: Maximum messages to return
            page_token: Start offset as string (for pagination)
            mailbox: Mailbox name to search in (default INBOX)

        Returns:
            ListMessagesResult with message IDs
        """
        start_offset = int(page_token) if page_token else 0

        # Build AppleScript to list messages
        account_filter = ""
        if self.account:
            account_filter = f'of account "{self.account}"'

        script = f'''
        tell application "Mail"
            set msgList to {{}}
            set msgCount to 0
            set targetMailbox to mailbox "{mailbox}" {account_filter}
            set allMsgs to messages of targetMailbox
            set totalMsgs to count of allMsgs

            -- Process messages starting from offset
            repeat with i from {start_offset + 1} to (({start_offset} + {limit}))
                if i > totalMsgs then exit repeat
                set msg to item i of allMsgs
                set msgId to id of msg
                set msgSender to ""
                try
                    set msgSender to sender of msg
                end try
                set msgSubject to ""
                try
                    set msgSubject to subject of msg
                end try
                set msgRead to read status of msg
                set msgFlagged to flagged status of msg

                -- Output as pseudo-JSON (tab-separated for parsing)
                set msgInfo to (msgId as string) & "\\t" & msgSender & "\\t" & msgSubject & "\\t" & (msgRead as string) & "\\t" & (msgFlagged as string)
                set end of msgList to msgInfo
                set msgCount to msgCount + 1
            end repeat

            -- Return messages and total count
            set AppleScript's text item delimiters to linefeed
            return (msgList as string) & "\\n---TOTAL:" & (totalMsgs as string)
        end tell
        '''

        try:
            output = self._run_applescript(script)
        except RuntimeError as e:
            logger.error(f"Failed to list messages: {e}")
            return ListMessagesResult(messages=[], next_page_token=None)

        messages = []
        total = 0
        lines = output.split("\n")

        for line in lines:
            if line.startswith("---TOTAL:"):
                total = int(line.replace("---TOTAL:", ""))
                continue
            if not line.strip():
                continue

            parts = line.split("\t")
            if len(parts) >= 5:
                msg_id, sender, subject, is_read, is_flagged = parts[:5]
                messages.append(EmailMessage(
                    id=msg_id,
                    sender=sender,
                    subject=subject,
                    is_read=is_read.lower() == "true",
                    is_starred=is_flagged.lower() == "true",
                ))

        # Calculate next page token
        next_offset = start_offset + limit
        next_token = str(next_offset) if next_offset < total else None

        return ListMessagesResult(
            messages=messages,
            next_page_token=next_token,
            total_estimate=total,
        )

    def get_message_details(self, message_id: str) -> Optional[EmailMessage]:
        """Fetch message details by ID."""
        script = f'''
        tell application "Mail"
            set targetMsg to first message whose id is {message_id}
            set msgSender to ""
            try
                set msgSender to sender of targetMsg
            end try
            set msgSubject to ""
            try
                set msgSubject to subject of targetMsg
            end try
            set msgRead to read status of targetMsg
            set msgFlagged to flagged status of targetMsg
            set msgMailbox to name of mailbox of targetMsg

            return (msgSender) & "\\t" & (msgSubject) & "\\t" & (msgRead as string) & "\\t" & (msgFlagged as string) & "\\t" & msgMailbox
        end tell
        '''

        try:
            output = self._run_applescript(script)
        except RuntimeError:
            return None

        parts = output.split("\t")
        if len(parts) < 5:
            return None

        sender, subject, is_read, is_flagged, mailbox = parts[:5]
        return EmailMessage(
            id=message_id,
            sender=sender,
            subject=subject,
            is_read=is_read.lower() == "true",
            is_starred=is_flagged.lower() == "true",
            labels={mailbox} if mailbox else set(),
        )

    def apply_label(self, message_id: str, label: str) -> bool:
        """
        Move message to a mailbox (folder).

        Mail.app doesn't support labels, so this moves the message
        to a mailbox named after the label.
        """
        # Ensure mailbox exists
        self.ensure_label_exists(label)

        account_filter = ""
        if self.account:
            account_filter = f'of account "{self.account}"'

        script = f'''
        tell application "Mail"
            set targetMsg to first message whose id is {message_id}
            set targetMailbox to mailbox "{label}" {account_filter}
            move targetMsg to targetMailbox
            return "ok"
        end tell
        '''

        try:
            self._run_applescript(script)
            return True
        except RuntimeError as e:
            logger.error(f"Failed to move message to {label}: {e}")
            return False

    def remove_label(self, message_id: str, label: str) -> bool:
        """
        Not directly supported in Mail.app.

        Mail.app uses folders, so removing a "label" would mean moving
        the message somewhere else. This is a no-op.
        """
        logger.warning("remove_label not supported for Mail.app (folder-based)")
        return False

    def archive(self, message_id: str) -> bool:
        """Move message to Archive mailbox."""
        return self.apply_label(message_id, "Archive")

    def star(self, message_id: str) -> bool:
        """Flag a message."""
        script = f'''
        tell application "Mail"
            set targetMsg to first message whose id is {message_id}
            set flagged status of targetMsg to true
            return "ok"
        end tell
        '''
        try:
            self._run_applescript(script)
            return True
        except RuntimeError as e:
            logger.error(f"Failed to flag message: {e}")
            return False

    def unstar(self, message_id: str) -> bool:
        """Unflag a message."""
        script = f'''
        tell application "Mail"
            set targetMsg to first message whose id is {message_id}
            set flagged status of targetMsg to false
            return "ok"
        end tell
        '''
        try:
            self._run_applescript(script)
            return True
        except RuntimeError as e:
            logger.error(f"Failed to unflag message: {e}")
            return False

    def ensure_label_exists(self, label: str) -> str:
        """Ensure mailbox exists, creating if necessary."""
        if label in self._created_mailboxes:
            return label

        account_filter = ""
        if self.account:
            account_filter = f'of account "{self.account}"'

        # Check if mailbox exists
        script = f'''
        tell application "Mail"
            try
                set targetMailbox to mailbox "{label}" {account_filter}
                return "exists"
            on error
                -- Create mailbox
                make new mailbox with properties {{name:"{label}"}} {account_filter}
                return "created"
            end try
        end tell
        '''

        try:
            result = self._run_applescript(script)
            self._created_mailboxes.add(label)
            if result == "created":
                logger.info(f"Created mailbox: {label}")
        except RuntimeError as e:
            logger.error(f"Failed to ensure mailbox {label}: {e}")

        return label

    def mark_read(self, message_id: str) -> bool:
        """Mark message as read."""
        script = f'''
        tell application "Mail"
            set targetMsg to first message whose id is {message_id}
            set read status of targetMsg to true
            return "ok"
        end tell
        '''
        try:
            self._run_applescript(script)
            return True
        except RuntimeError as e:
            logger.error(f"Failed to mark read: {e}")
            return False

    def mark_unread(self, message_id: str) -> bool:
        """Mark message as unread."""
        script = f'''
        tell application "Mail"
            set targetMsg to first message whose id is {message_id}
            set read status of targetMsg to false
            return "ok"
        end tell
        '''
        try:
            self._run_applescript(script)
            return True
        except RuntimeError as e:
            logger.error(f"Failed to mark unread: {e}")
            return False

    def get_accounts(self) -> List[str]:
        """Get list of configured email accounts."""
        script = '''
        tell application "Mail"
            set accountNames to name of every account
            set AppleScript's text item delimiters to linefeed
            return accountNames as string
        end tell
        '''
        try:
            output = self._run_applescript(script)
            return [name.strip() for name in output.split("\n") if name.strip()]
        except RuntimeError:
            return []

    def get_mailboxes(self) -> List[str]:
        """Get list of mailboxes for the current account."""
        account_filter = ""
        if self.account:
            account_filter = f'of account "{self.account}"'

        script = f'''
        tell application "Mail"
            set mailboxNames to name of every mailbox {account_filter}
            set AppleScript's text item delimiters to linefeed
            return mailboxNames as string
        end tell
        '''
        try:
            output = self._run_applescript(script)
            return [name.strip() for name in output.split("\n") if name.strip()]
        except RuntimeError:
            return []
