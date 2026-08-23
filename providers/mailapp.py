"""
macOS Mail.app provider implementation.

Uses AppleScript via subprocess to interact with Mail.app for email
categorization and organization.
"""

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
from core.models import EmailMessage, FlagColor
from core.protocols import CAPTURE_HEADERS

logger = logging.getLogger(__name__)

# In-band delimiters for the AppleScript pseudo-JSON transport. Chosen from the C0 control
# range so they can never collide with a header value, subject, or sender. FIELD_SEP splits
# the per-message tuple columns; HDR_SEP splits captured "name: value" header lines within
# the single headers column (a raw header block's own newlines would break the row protocol).
_FIELD_SEP = "\x1f"   # unit separator — between columns
_HDR_SEP = "\x1e"     # record separator — between header lines in the headers column


def _parse_bulk_headers(blob: str) -> Dict[str, str]:
    """Parse the captured bulk-header column (``name: value`` lines joined by ``_HDR_SEP``)
    into a lower-cased {name: value} map. Fail-open: empty/garbage → {}."""
    out: Dict[str, str] = {}
    for line in (blob or "").split(_HDR_SEP):
        if ":" in line:
            name, _, val = line.partition(":")
            name = name.strip().lower()
            if name:
                out[name] = val.strip()
    return out


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
        ProviderCapabilities.ARCHIVE |
        ProviderCapabilities.COLORED_FLAGS
    )
    # Mail.app has no labels — apply_label runs an AppleScript `move` that
    # relocates the message to a mailbox, out of the inbox. The audit records this
    # as MOVED, and the gate suppresses it for protected senders.
    LABEL_IS_MOVE = True

    def __init__(self, account: Optional[str] = None):
        """
        Initialize Mail.app provider.

        Args:
            account: Optional account name to filter messages by.
                     If None, processes messages from all accounts.
        """
        self.account = account
        self._created_mailboxes: set = set()

    def _run_applescript(self, script: str, timeout: int = 30) -> str:
        """Execute AppleScript and return output.

        `timeout` is tunable: the hot INBOX path keeps the 30s default, but a
        bounded archive/All-Mail scan (a per-run diagnostic, not the beat) passes
        a generous value — the `whose date received` predicate materializes only
        the recent slice, but a cold iCloud archive can still take tens of seconds
        to page envelopes in.
        """
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=timeout,
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

    def _build_list_script(
        self,
        mailbox: str,
        start_offset: int,
        limit: int,
        since_days: Optional[int] = None,
    ) -> str:
        """Build the list_messages AppleScript. PURE (no I/O) so the enumeration
        strategy is unit-testable without Mail.app.

        Two modes share ONE extraction body — only the *selector* changes:
        - Unbounded (since_days is None): `messages of targetMailbox`, oldest-first,
          sliced [start_offset, start_offset+limit]. The original inbox behaviour.
        - Bounded (since_days set): `messages ... whose date received > cutoff` — Mail.app
          materializes only the in-window slice (NOT the whole 40k-message archive),
          walked NEWEST-first with the same offset/limit so classify_inbox's 50-at-a-time
          pagination still works. This is the archive-timeout fix; mirrors the proven
          `whose` idiom in inbox_sweep._list_flagged.
        """
        account_filter = f'of account "{self.account}"' if self.account else ""

        # AppleScript list of the header names to keep (lower-cased for the prefix match):
        # the bulk-signal headers PLUS Reply-To (CAPTURE_HEADERS). Only these lines survive —
        # no body is ever fetched, so a message carrying List-Unsubscribe et al. (or a distinct
        # Reply-To for the draft leaf) is detectable at classification time cheaply.
        bulk_keys_as = "{" + ", ".join(
            f'"{h.lower()}:"' for h in CAPTURE_HEADERS
        ) + "}"

        if since_days is not None:
            # Server-side date predicate bounds what materializes to the recent slice.
            # The filtered list is oldest-first, so walk the tail down (newest-first),
            # honouring offset/limit for paging.
            enumerate_block = (
                f'set cutoffDate to (current date) - ({int(since_days)} * days)\n'
                f'            set targetMailbox to mailbox "{mailbox}" {account_filter}\n'
                f'            set allMsgs to (messages of targetMailbox whose date received > cutoffDate)\n'
                f'            set totalMsgs to count of allMsgs\n'
                f'            set hiIdx to totalMsgs - {start_offset}\n'
                f'            set loIdx to hiIdx - {limit} + 1\n'
                f'            if loIdx < 1 then set loIdx to 1'
            )
            repeat_open = (
                'repeat with i from hiIdx to loIdx by -1\n'
                '                if i < 1 then exit repeat'
            )
        else:
            enumerate_block = (
                f'set targetMailbox to mailbox "{mailbox}" {account_filter}\n'
                f'            set allMsgs to messages of targetMailbox\n'
                f'            set totalMsgs to count of allMsgs'
            )
            repeat_open = (
                f'repeat with i from {start_offset + 1} to (({start_offset} + {limit}))\n'
                '                if i > totalMsgs then exit repeat'
            )

        return f'''
        set fieldSep to (ASCII character 31)
        set hdrSep to (ASCII character 30)
        set bulkKeys to {bulk_keys_as}
        tell application "Mail"
            set msgList to {{}}
            set msgCount to 0
            {enumerate_block}

            -- Process messages within the [offset, offset+limit] window
            {repeat_open}
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
                set msgFlagIndex to flag index of msg

                -- Capture ONLY the bulk-signal header lines (never the body). `all headers`
                -- is already resident on the message object, so this pulls no extra content.
                set bulkHdrs to ""
                try
                    set hdrText to all headers of msg
                    set keptLines to {{}}
                    repeat with para in (paragraphs of hdrText)
                        set ln to (para as string)
                        if ln is not "" then
                            set lnLower to my toLower(ln)
                            repeat with k in bulkKeys
                                if lnLower starts with (k as string) then
                                    set end of keptLines to ln
                                    exit repeat
                                end if
                            end repeat
                        end if
                    end repeat
                    set AppleScript's text item delimiters to hdrSep
                    set bulkHdrs to (keptLines as string)
                    set AppleScript's text item delimiters to ""
                end try

                -- Output as pseudo-JSON (unit-separator-delimited columns for parsing)
                set msgInfo to (msgId as string) & fieldSep & msgSender & fieldSep & msgSubject & fieldSep & (msgRead as string) & fieldSep & (msgFlagged as string) & fieldSep & (msgFlagIndex as string) & fieldSep & bulkHdrs
                set end of msgList to msgInfo
                set msgCount to msgCount + 1
            end repeat

            -- Return messages and total count
            set AppleScript's text item delimiters to linefeed
            return (msgList as string) & "\\n---TOTAL:" & (totalMsgs as string)
        end tell

        on toLower(s)
            set upperChars to "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            set lowerChars to "abcdefghijklmnopqrstuvwxyz"
            set outp to ""
            repeat with c in (characters of s)
                set c to (c as string)
                set oset to (offset of c in upperChars)
                if oset > 0 then
                    set outp to outp & (character oset of lowerChars)
                else
                    set outp to outp & c
                end if
            end repeat
            return outp
        end toLower
        '''

    def list_messages(
        self,
        query: str = "",
        limit: int = 100,
        page_token: Optional[str] = None,
        mailbox: str = "INBOX",
        since_days: Optional[int] = None,
    ) -> ListMessagesResult:
        """
        List messages from Mail.app.

        Args:
            query: Not used (Mail.app doesn't have server-side search via AppleScript)
            limit: Maximum messages to return
            page_token: Start offset as string (for pagination)
            mailbox: Mailbox name to search in (default INBOX)
            since_days: When set, enumerate ONLY messages received within the last
                `since_days` days, newest-first, via a server-side `whose date received`
                predicate — bounding what Mail.app materializes so a large Archive/All-Mail
                never blocks (the fix for the INBOX-only sweep timing out on iCloud).
                None → the full oldest-first inbox behaviour, unchanged.

        Returns:
            ListMessagesResult with message IDs
        """
        start_offset = int(page_token) if page_token else 0
        script = self._build_list_script(mailbox, start_offset, limit, since_days)

        try:
            if since_days is not None:
                # A bounded recent-window scan is a per-run diagnostic, not the hot beat
                # path, so it gets a generous timeout. The unbounded inbox path deliberately
                # calls _run_applescript with the SAME one-arg signature as before, so every
                # existing caller/mock is untouched (additive, non-breaking).
                output = self._run_applescript(script, timeout=900)
            else:
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

            parts = line.split(_FIELD_SEP)
            if len(parts) >= 6:
                msg_id, sender, subject, is_read, is_flagged, flag_index = parts[:6]
                bulk_blob = parts[6] if len(parts) >= 7 else ""
                messages.append(EmailMessage(
                    id=msg_id,
                    sender=sender,
                    subject=subject,
                    is_read=is_read.lower() == "true",
                    is_starred=is_flagged.lower() == "true",
                    flag_color=FlagColor.from_index(int(flag_index)),
                    headers=_parse_bulk_headers(bulk_blob),
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
            set msgFlagIndex to flag index of targetMsg
            set msgMailbox to name of mailbox of targetMsg

            return (msgSender) & "\\t" & (msgSubject) & "\\t" & (msgRead as string) & "\\t" & (msgFlagged as string) & "\\t" & (msgFlagIndex as string) & "\\t" & msgMailbox
        end tell
        '''

        try:
            output = self._run_applescript(script)
        except RuntimeError:
            return None

        parts = output.split("\t")
        if len(parts) < 6:
            return None

        sender, subject, is_read, is_flagged, flag_index, mailbox = parts[:6]
        return EmailMessage(
            id=message_id,
            sender=sender,
            subject=subject,
            is_read=is_read.lower() == "true",
            is_starred=is_flagged.lower() == "true",
            flag_color=FlagColor.from_index(int(flag_index)),
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

    def star(self, message_id: str, due_date: Optional[datetime] = None) -> bool:
        """Flag a message. due_date is ignored by Mail.app."""
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

    def get_flag_color(self, message_id: str) -> FlagColor:
        """
        Get the current flag color of a message.
        
        Reads Mail.app's `flag index` property which maps to FlagColor enum:
        -1 = NO_FLAG, 0 = RED, 1 = ORANGE, 2 = YELLOW, 3 = GREEN, 4 = BLUE, 5 = PURPLE, 6 = GRAY
        """
        script = f'''
        tell application "Mail"
            set targetMsg to first message whose id is {message_id}
            return flag index of targetMsg
        end tell
        '''
        try:
            output = self._run_applescript(script)
            index = int(output.strip())
            return FlagColor.from_index(index)
        except (RuntimeError, ValueError) as e:
            logger.error(f"Failed to get flag color for message {message_id}: {e}")
            return FlagColor.NO_FLAG

    def set_flag_color(self, message_id: str, color: FlagColor) -> bool:
        """
        Set a specific flag color on a message.
        
        Uses Mail.app's `flag index` property. Setting to NO_FLAG (-1) clears the flag.
        Boolean `flagged status` is NOT used here to preserve colored flag semantics.
        """
        if color == FlagColor.NO_FLAG:
            return self.clear_flag(message_id)
        
        script = f'''
        tell application "Mail"
            set targetMsg to first message whose id is {message_id}
            set flag index of targetMsg to {int(color)}
            return "ok"
        end tell
        '''
        try:
            self._run_applescript(script)
            return True
        except RuntimeError as e:
            logger.error(f"Failed to set flag color {color.name_str} on message {message_id}: {e}")
            return False

    def clear_flag(self, message_id: str) -> bool:
        """Clear the flag from a message (set flag index to -1)."""
        script = f'''
        tell application "Mail"
            set targetMsg to first message whose id is {message_id}
            set flag index of targetMsg to -1
            return "ok"
        end tell
        '''
        try:
            self._run_applescript(script)
            return True
        except RuntimeError as e:
            logger.error(f"Failed to clear flag on message {message_id}: {e}")
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
                -- Create mailbox (must use `at end of mailboxes [of account]`; the
                -- bare `make new mailbox with properties {{...}} of account` form errors)
                make new mailbox at end of mailboxes {account_filter} with properties {{name:"{label}"}}
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

    @staticmethod
    def _as_applescript(s: str) -> str:
        """Render a Python string as a valid AppleScript string EXPRESSION, preserving
        newlines (AppleScript literals can't hold a raw newline) and escaping quotes."""
        s = (s or "").replace("\\", "\\\\").replace('"', '\\"')
        s = s.replace("\r\n", "\n").replace("\r", "\n").replace("\n", '" & linefeed & "')
        return '"' + s + '"'

    def create_draft(self, to_addr: str, subject: str, body: str,
                     account: Optional[str] = None) -> bool:
        """Save a DRAFT (never sent) to Mail.app, addressed to ``to_addr``.

        Keyless outbound: ``make new outgoing message … save`` writes to the Drafts
        mailbox. Drafts is a REAL folder (even on Gmail, where the inbox is a label),
        so unlike archiving this sticks reliably with no write-scope gate. When an
        ``account`` is given we route the draft from that account's address so it lands
        in the right Drafts and replies from the right identity; on lookup failure it
        falls back to the default account (fail-open, never errors out).

        This NEVER sends — there is no ``send`` call and no scheduling. The user always
        presses send. Returns True on save."""
        acct = account or self.account
        subj_e = self._as_applescript(subject)
        body_e = self._as_applescript(body)
        to_e = self._as_applescript(to_addr)
        acct_e = self._as_applescript(acct) if acct else None
        from_block = (f'''
            try
                set fromAddr to item 1 of (get email addresses of account {acct_e})
                try
                    set sender of newMsg to fromAddr
                end try
            end try''' if acct_e else "")
        script = f'''
        tell application "Mail"
            set newMsg to make new outgoing message with properties {{subject:{subj_e}, content:{body_e}, visible:false}}
            tell newMsg
                make new to recipient at end of to recipients with properties {{address:{to_e}}}
            end tell{from_block}
            save newMsg
            return "saved"
        end tell
        '''
        try:
            return self._run_applescript(script).strip() == "saved"
        except RuntimeError as e:
            logger.error(f"Failed to create draft to {to_addr}: {e}")
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
            # `name of every mailbox of account` intermittently exceeds 30s on a busy Mail.app
            # (many mailboxes, cold IPC) and fails open to [] — which silently drops the whole
            # account from an archive scan. This is a per-run resolution step, not the hot path,
            # so give it a generous timeout.
            output = self._run_applescript(script, timeout=300)
            return [name.strip() for name in output.split("\n") if name.strip()]
        except RuntimeError:
            return []
