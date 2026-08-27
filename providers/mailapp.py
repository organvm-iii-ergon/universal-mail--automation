"""
macOS Mail.app provider implementation.

Uses AppleScript via subprocess to interact with Mail.app for email
categorization and organization.
"""

import logging
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from providers.base import (
    EmailProvider,
    ListMessagesResult,
    ProviderNativeStateDrift,
    ProviderCapabilities,
    ProviderWriteAmbiguous,
)
from core.models import EmailMessage, FlagColor, MessageReference
from core.protocols import CAPTURE_HEADERS

logger = logging.getLogger(__name__)


class ProviderScriptError(RuntimeError):
    """Typed provider failure: AppleScript transport/parse/mutation problem."""


class ProviderTimeoutError(ProviderScriptError):
    """osascript exceeded its deadline.

    STRUCTURAL timeout signal: callers must classify incompleteness from
    this type, never from message substrings (which break across osascript
    versions, localizations, and reworded wrappers).
    """


class ProviderDispatchUnavailable(ProviderScriptError):
    """A provider command could not be dispatched, so no write occurred."""


class MessageNotFoundError(ProviderScriptError):
    """Scoped lookup resolved zero candidates in the exact account+mailbox."""


class FlagStateDriftError(ProviderScriptError):
    """Live evidence no longer matches the reference's bound evidence digest,
    or the reference carries no durable evidence. Mutation refused."""


@dataclass(frozen=True)
class SurfaceRef:
    """One discovered account/mailbox surface of the local Mail estate."""
    account: str
    mailbox: str
    path_components: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        components = self.path_components or _mailbox_path_from_scope(
            self.mailbox,
        )
        canonical = _canonical_mailbox_scope(components)
        object.__setattr__(self, "path_components", components)
        object.__setattr__(self, "mailbox", canonical)

# --- Mail.app native index <-> semantic FlagColor mapping ---
# The mapping is OWNED by the pure, I/O-free module providers.flag_codecs so
# artifact validation can work in a fresh process without importing this
# runtime provider. Names are re-exported here for existing consumers.
from providers.flag_codecs import MAILAPP_FLAG_TO_INDEX  # noqa: F401 E402
from providers.flag_codecs import MAILAPP_INDEX_TO_FLAG  # noqa: F401 E402
from providers.flag_codecs import flag_from_mailapp_index  # noqa: F401 E402
from providers.flag_codecs import mailapp_index_from_flag  # noqa: F401 E402

# In-band delimiters for the AppleScript pseudo-JSON transport. Chosen from the C0 control
# range so they can never collide with a header value, subject, or sender. FIELD_SEP splits
# the per-message tuple columns; HDR_SEP splits captured "name: value" header lines within
# the single headers column (a raw header block's own newlines would break the row protocol).
_FIELD_SEP = "\x1f"   # unit separator — between columns
_HDR_SEP = "\x1e"     # record separator — between header lines in the headers column
_ROW_SEP = "\x1d"     # group separator — between flagged-enumeration rows


def _canonical_mailbox_scope(path_components: Sequence[str]) -> str:
    """Encode exact Mail.app mailbox path components into a stable scope.

    This uses JSON Pointer escaping so a nested ``Parent/Child`` path cannot
    collide with a single mailbox literally named ``Parent/Child``.  A
    top-level ordinary mailbox remains the familiar ``INBOX`` string.
    """
    if not path_components:
        raise ProviderScriptError("mailbox path must contain at least one component")
    encoded: List[str] = []
    for component in path_components:
        if not isinstance(component, str) or not component:
            raise ProviderScriptError(
                "mailbox path components must be non-empty strings",
            )
        encoded.append(component.replace("~", "~0").replace("/", "~1"))
    return "/".join(encoded)


def _mailbox_path_from_scope(mailbox: str) -> Tuple[str, ...]:
    """Decode a canonical mailbox scope back to its exact path tuple."""
    if not isinstance(mailbox, str) or not mailbox:
        raise ProviderScriptError("mailbox scope must be a non-empty string")
    return tuple(
        component.replace("~1", "/").replace("~0", "~")
        for component in mailbox.split("/")
    )


@dataclass(frozen=True)
class FlaggedRow:
    """One flagged message as observed at enumeration time (transport level).

    ``native_index`` is None when Mail.app returned something non-numeric;
    ``flag_color`` is UNKNOWN when the index is missing or unmapped. Both
    failure shapes are counted separately by :class:`EnumerationResult`.
    """
    provider_id: str
    account: str
    mailbox: str
    sender: str
    subject: str
    native_index: Optional[int]
    flag_color: FlagColor
    received_iso: Optional[str] = None


@dataclass
class EnumerationResult:
    """Typed result of a flagged-message enumeration. Never a bare list.

    Completeness is TWO-valued and neither may be faked:

    - ``scope_complete``: the requested bounded window (account+mailbox+
      date window) was walked with zero omissions.
    - ``complete`` (estate-honest): scope_complete AND nothing hidden by
      ``limit`` AND zero inaccessible rows. Only ``complete`` snapshots are
      eligible to produce plans.

    ``next_cursor`` is an opaque resume descriptor (never a fake offset):
    when rows were hidden, it records how to widen the window honestly.
    """
    rows: List[FlaggedRow]
    complete: bool
    scope_complete: bool
    status: str                      # complete|bounded_partial|partial|failed|timed_out
    errors: List[str]
    inaccessible_count: int
    timeout_count: int
    unknown_index_count: int
    next_cursor: Optional[str]
    scanned_boundary: Dict[str, Any]

    @property
    def total_rows(self) -> int:
        return len(self.rows)

    @staticmethod
    def _status(scope_complete: bool, errors: List[str], inaccessible: int,
                timeouts: int, hidden: int) -> str:
        """Delegate to THE canonical derivation (single precedence)."""
        from core.flag_workflow import canonical_scan_status
        return canonical_scan_status(
            scope_complete=scope_complete,
            errors=errors,
            inaccessible_count=inaccessible,
            timeout_count=timeouts,
            hidden_by_limit=hidden,
        )

    @classmethod
    def build(cls, *, rows: List[FlaggedRow], scope_complete: bool,
              errors: List[str], inaccessible_count: int,
              timeout_count: int, unknown_index_count: int,
              hidden_by_limit: int,
              scanned_boundary: Dict[str, Any]) -> "EnumerationResult":
        """Single construction path enforcing the completeness contract."""
        complete = (
            scope_complete
            and not errors
            and inaccessible_count == 0
            and hidden_by_limit == 0
        )
        cursor = None
        if hidden_by_limit > 0:
            import json as _json
            b = scanned_boundary
            cursor = _json.dumps({
                "resume": "widen-limit-or-narrow-window",
                "account": b.get("account"),
                "mailbox": b.get("mailbox"),
                "since_days": b.get("since_days"),
                "total_matched": b.get("total_flagged_seen"),
                "returned": len(rows),
                "hidden": hidden_by_limit,
                "ordering": "received_desc",
            }, sort_keys=True)
        return cls(
            rows=rows, complete=complete, scope_complete=scope_complete,
            status=cls._status(scope_complete, errors, inaccessible_count,
                               timeout_count, hidden_by_limit),
            errors=errors, inaccessible_count=inaccessible_count,
            timeout_count=timeout_count,
            unknown_index_count=unknown_index_count,
            next_cursor=cursor, scanned_boundary=scanned_boundary,
        )


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


def _flag_color_from_raw(raw_index: str) -> FlagColor:
    """Map a native index token without letting malformed metadata abort a read."""
    try:
        return flag_from_mailapp_index(int(raw_index.strip()))
    except (AttributeError, ValueError):
        return FlagColor.UNKNOWN


def _parse_received_datetime(received_iso: Optional[str]) -> Optional[datetime]:
    """Parse Mail.app ISO text as an aware UTC datetime when available."""
    if not received_iso:
        return None
    try:
        parsed = datetime.fromisoformat(received_iso.replace("Z", "+00:00"))
    except (OverflowError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


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
            # Preserve C0 field/record separators.  ``str.strip()`` treats
            # \x1c-\x1f as whitespace and corrupts valid empty result frames
            # such as ``"0\x1f"``.  osascript's line ending is the only
            # transport suffix removed here.
            return result.stdout.rstrip("\r\n")
        except subprocess.TimeoutExpired as exc:
            raise ProviderTimeoutError(
                f"AppleScript timed out after {timeout}s"
            ) from exc
        except OSError as exc:
            raise ProviderDispatchUnavailable(
                "osascript unavailable - this provider only works on macOS",
            ) from exc

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
                    flag_color=_flag_color_from_raw(flag_index),
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
        if not message_id.strip().lstrip("-").isdigit():
            logger.error("Refusing non-numeric Mail.app message id")
            return None
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
            flag_color=_flag_color_from_raw(flag_index),
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

    # --- Scoped colored-flag reads/writes (MessageReference required) --------
    #
    # There is deliberately NO bare-id colored-flag path on this provider.
    # A global Mail.app id is ambiguous across accounts, and a mutation
    # without evidence verification cannot be trusted. All colored ops go:
    #   resolve within exact account+mailbox -> verify evidence digest ->
    #   mutate -> re-read and verify native result.

    def _mailbox_reference(
        self,
        mailbox: str,
        account: str,
        path_components: Optional[Sequence[str]] = None,
    ) -> str:
        """Render an exact nested mailbox reference for AppleScript.

        ``mailbox`` is the canonical, reversible public scope.  Discovery
        additionally carries ``path_components`` so no parsing is needed;
        direct/scoped callers decode the same canonical representation.
        """
        if not isinstance(account, str) or not account.strip():
            raise ProviderScriptError(
                "an explicit Mail.app account is required",
            )
        components = (
            tuple(path_components)
            if path_components is not None
            else _mailbox_path_from_scope(mailbox)
        )
        canonical = _canonical_mailbox_scope(components)
        if canonical != mailbox:
            raise ProviderScriptError(
                "mailbox scope does not match its exact path components",
            )
        reference = f"account {self._as_applescript(account)}"
        for component in components:
            reference = (
                f"mailbox {self._as_applescript(component)} of {reference}"
            )
        return reference

    def _build_scoped_lookup_script(self, mailbox: str, account: str,
                                    provider_id: str) -> str:
        """PURE builder for the scoped resolve. No 'first message whose id is'
        outside an exact mailbox-of-account context; ids validated numeric;
        account/mailbox escaped as AppleScript string expressions."""
        if (
            not isinstance(provider_id, str)
            or not provider_id
            or not provider_id.isascii()
            or not provider_id.isdigit()
            or provider_id[0] == "0"
        ):
            raise ProviderScriptError(
                f"refusing to interpolate non-numeric or non-positive "
                f"Mail.app id: "
                f"{provider_id!r}"
            )
        mailbox_ref = self._mailbox_reference(mailbox, account)
        return (
            '        set fieldSep to (ASCII character 31)\n'
            '        tell application "Mail"\n'
            f'            set targetMailbox to {mailbox_ref}\n'
            f'            set candidates to (messages of targetMailbox whose id is {provider_id})\n'
            '            if (count of candidates) is 0 then return "NOT_FOUND"\n'
            '            set m to item 1 of candidates\n'
            '            set outp to (flag index of m as string) & fieldSep\n'
            '            try\n'
            '                set outp to outp & ((date received of m) as «class isot» as string)\n'
            '            on error\n'
            '                set outp to outp & ""\n'
            '            end try\n'
            '            set outp to outp & fieldSep\n'
            '            try\n'
            '                set outp to outp & (sender of m)\n'
            '            on error\n'
            '                set outp to outp & ""\n'
            '            end try\n'
            '            set outp to outp & fieldSep\n'
            '            try\n'
            '                set outp to outp & (subject of m)\n'
            '            on error\n'
            '                set outp to outp & ""\n'
            '            end try\n'
            '            set msgIdHeader to ""\n'
            '            try\n'
            '                repeat with para in (paragraphs of (all headers of m))\n'
            '                    set ln to (para as string)\n'
            '                    if ln starts with "Message-ID:" or ln starts with "Message-Id:" then\n'
            '                        set msgIdHeader to ln\n'
            '                        exit repeat\n'
            '                    end if\n'
            '                end repeat\n'
            '            end try\n'
            '            set outp to outp & fieldSep & msgIdHeader\n'
            '            set outp to outp & fieldSep\n'
            '            try\n'
            '                set outp to outp & (read status of m as string)\n'
            '            on error\n'
            '                set outp to outp & ""\n'
            '            end try\n'
            '            set outp to outp & fieldSep\n'
            '            try\n'
            '                set outp to outp & (flagged status of m as string)\n'
            '            on error\n'
            '                set outp to outp & ""\n'
            '            end try\n'
            '            return outp\n'
            '        end tell\n'
            '        '
        )

    @staticmethod
    def _validate_mailapp_ref(ref: MessageReference) -> None:
        """Reject foreign or noncanonical refs before AppleScript exists."""
        try:
            ref.validate_scoped()
        except ValueError as exc:
            raise ProviderScriptError(f"invalid scoped reference: {exc}") \
                from exc
        if ref.provider != "mailapp":
            raise ProviderScriptError(
                f"Mail.app refuses foreign provider {ref.provider!r}"
            )
        provider_id = ref.provider_id
        if (
            not provider_id.isascii()
            or not provider_id.isdigit()
            or provider_id[0] == "0"
        ):
            raise ProviderScriptError(
                "Mail.app provider_id must be a positive ASCII decimal"
            )

    def _resolve_scoped_fields(self, ref: MessageReference
                               ) -> Dict[str, Optional[str]]:
        """Resolve one reference inside its exact scope. Raises typed errors."""
        self._validate_mailapp_ref(ref)
        script = self._build_scoped_lookup_script(
            ref.mailbox, ref.account, ref.provider_id)
        try:
            # Strip ONLY newlines for parsing — str.strip() would also eat
            # \x1f control chars and collapse legitimate trailing empty
            # fields (e.g. an absent Message-ID header column).
            output = self._run_applescript(script).strip("\n")
        except RuntimeError as e:
            raise ProviderScriptError(
                f"scoped resolve failed for {ref}: {e}") from e
        if output.strip() == "NOT_FOUND":
            raise MessageNotFoundError(
                f"no message {ref.provider_id} in "
                f"{ref.account}/{ref.mailbox}")
        parts = output.split(_FIELD_SEP)
        if len(parts) < 5:
            raise ProviderScriptError(
                f"malformed scoped-resolve output for {ref}")
        native_raw, received_iso, sender, subject, msgid_header = parts[:5]
        is_read = parts[5] if len(parts) > 5 else None
        is_flagged = parts[6] if len(parts) > 6 else None
        try:
            native_index: Optional[int] = int(native_raw.strip())
        except ValueError:
            native_index = None
        return {
            "native_index": str(native_index)
            if native_index is not None else None,
            "received_iso": received_iso or None,
            "sender": sender,
            "subject": subject,
            "message_id_raw": msgid_header or None,
            "is_read": is_read,
            "is_flagged": is_flagged,
        }

    def resolve_scoped(self, ref: MessageReference) -> MessageReference:
        """Re-resolve the message and return an enriched copy of the ref.

        The returned reference carries current observed fields + a freshly
        computed evidence_digest + RFC Message-ID digest when present. Callers
        compare digests against their snapshot-bound ref BEFORE mutating.
        """
        self._validate_mailapp_ref(ref)
        fields = self._resolve_scoped_fields(ref)
        enriched = ref.with_resolved_evidence(
            received_iso=fields["received_iso"],
            sender=fields["sender"] or "",
            subject=fields["subject"] or "",
            message_id_raw=fields["message_id_raw"],
        )
        raw_idx = fields["native_index"]
        return MessageReference(
            **{**enriched.__dict__,
               "observed_native_flag": int(raw_idx) if raw_idx else None},
        )

    def get_message_details_ref(
        self,
        ref: MessageReference,
    ) -> Optional[EmailMessage]:
        """Fetch message details inside an exact qualified Mail.app scope."""
        self._validate_mailapp_ref(ref)
        try:
            fields = self._resolve_scoped_fields(ref)
        except MessageNotFoundError:
            return None
        raw_index = fields["native_index"]
        color = (
            flag_from_mailapp_index(int(raw_index))
            if raw_index is not None
            else FlagColor.UNKNOWN
        )
        flagged_raw = fields.get("is_flagged")
        is_starred = (
            flagged_raw.lower() == "true"
            if flagged_raw is not None
            else color not in (FlagColor.NO_FLAG, FlagColor.UNKNOWN)
        )
        read_raw = fields.get("is_read")
        return EmailMessage(
            id=ref.provider_id,
            sender=fields["sender"] or "",
            subject=fields["subject"] or "",
            date=_parse_received_datetime(fields["received_iso"]),
            labels={ref.mailbox},
            is_read=read_raw is not None and read_raw.lower() == "true",
            is_starred=is_starred,
            flag_color=color,
        )

    def _verify_evidence(self, ref: MessageReference) -> Dict[str, Optional[str]]:
        """Resolve live fields and enforce the evidence binding.

        Refuses mutation when the reference carries no durable evidence, or
        when live evidence no longer matches what was observed.
        """
        self._validate_mailapp_ref(ref)
        if ref.evidence_digest is None:
            raise FlagStateDriftError(
                f"{ref}: no durable evidence bound; automatic mutation "
                "is ineligible"
            )
        fields = self._resolve_scoped_fields(ref)
        live_digest = MessageReference.compute_evidence_digest(
            fields["received_iso"], fields["sender"], fields["subject"])
        if live_digest != ref.evidence_digest:
            raise FlagStateDriftError(
                f"{ref}: live evidence {live_digest[:12]}… != bound "
                f"{ref.evidence_digest[:12]}… — refusing mutation"
            )
        return fields

    def get_flag_color_ref(self, ref: MessageReference) -> FlagColor:
        """Scoped read: exact account+mailbox lookup, mapped semantic color."""
        self._validate_mailapp_ref(ref)
        fields = self._resolve_scoped_fields(ref)
        raw = fields["native_index"]
        if raw is None:
            return FlagColor.UNKNOWN
        return flag_from_mailapp_index(int(raw))

    def set_flag_color_ref(self, ref: MessageReference, color: FlagColor) -> bool:
        """Evidence-verified compare-and-set with post-write verification.

        UNKNOWN has no native index (KeyError by contract). After the write,
        the message is RE-RESOLVED and both properties must hold:
        (a) the evidence digest is still bound — a change between pre-write
            verify and post-write re-read means the message was moved or
            edited mid-flight and the outcome is AMBIGUOUS;
        (b) the native flag index equals the expected value exactly.
        Returns True only when both hold.
        """
        self._validate_mailapp_ref(ref)
        index = mailapp_index_from_flag(color)   # KeyError for UNKNOWN
        expected_native = ref.observed_native_flag
        if isinstance(expected_native, bool) or not isinstance(
                expected_native, int):
            raise FlagStateDriftError(
                f"{ref}: no durable expected native flag bound; automatic "
                "mutation is ineligible"
            )
        if flag_from_mailapp_index(expected_native) == FlagColor.UNKNOWN:
            raise FlagStateDriftError(
                f"{ref}: expected native flag {expected_native!r} is not "
                "a writable Mail.app state"
            )
        pre_fields = self._verify_evidence(ref)
        pre_native_raw = pre_fields["native_index"]
        if pre_native_raw is None or int(pre_native_raw) != expected_native:
            raise ProviderNativeStateDrift(
                expected_native,
                None if pre_native_raw is None else int(pre_native_raw),
            )
        mailbox_ref = self._mailbox_reference(ref.mailbox, ref.account)
        script = (
            '        tell application "Mail"\n'
            f'            set targetMailbox to {mailbox_ref}\n'
            f'            set candidates to (messages of targetMailbox whose id is {ref.provider_id})\n'
            '            if (count of candidates) is 0 then error "NOT_FOUND"\n'
            '            set targetMessage to item 1 of candidates\n'
            '            set currentFlagIndex to flag index of targetMessage\n'
            f'            if currentFlagIndex is not {expected_native} then return '
            '"STATE_DRIFT:" & (currentFlagIndex as string)\n'
            '            set flag index of targetMessage to '
            f'{index}\n'
            '            return "ok"\n'
            '        end tell\n'
            '        '
        )
        try:
            outcome = self._run_applescript(script)
        except ProviderDispatchUnavailable:
            # Process creation failed before osascript could receive the
            # command.  This is an ordinary zero-write provider failure.
            raise
        except RuntimeError as e:
            logger.error(f"scoped set failed for {ref}: {e}")
            raise ProviderWriteAmbiguous(
                f"scoped set dispatch failed for {ref}; write may have occurred",
            ) from e
        if outcome.startswith("STATE_DRIFT:"):
            observed_text = outcome.partition(":")[2].strip()
            try:
                observed_native = int(observed_text)
            except ValueError:
                observed_native = None
            raise ProviderNativeStateDrift(expected_native, observed_native)
        if outcome != "ok":
            raise ProviderWriteAmbiguous(
                f"scoped set returned an unknown outcome for {ref}; "
                "write may have occurred"
            )
        # Post-write: re-resolve ALL evidence fields and require the digest
        # to still match, then verify the exact native index.
        try:
            fields = self._resolve_scoped_fields(ref)
        except RuntimeError as e:
            raise ProviderWriteAmbiguous(
                f"post-write verification failed for {ref}",
            ) from e
        live_digest = MessageReference.compute_evidence_digest(
            fields["received_iso"], fields["sender"], fields["subject"])
        bound_digest = ref.evidence_digest
        if bound_digest is None:      # unreachable: _verify_evidence enforced
            raise ProviderWriteAmbiguous(
                f"{ref}: evidence binding vanished during write",
            )
        if live_digest != bound_digest:
            raise ProviderWriteAmbiguous(
                f"{ref}: evidence changed during write ({live_digest[:12]}… "
                f"!= {bound_digest[:12]}…); outcome ambiguous"
            )
        post_native_raw = fields["native_index"]
        target_native: Optional[int] = (
            -1 if color == FlagColor.NO_FLAG else int(index)
        )
        if post_native_raw is None or int(post_native_raw) != target_native:
            raise ProviderWriteAmbiguous(
                f"post-write verification failed for {ref}: expected native "
                f"index {target_native}, read back {post_native_raw}"
            )
        return True

    def clear_flag_ref(self, ref: MessageReference) -> bool:
        """Evidence-verified unflag with read-after-write verification."""
        self._validate_mailapp_ref(ref)
        return self.set_flag_color_ref(ref, FlagColor.NO_FLAG)

    def discover_surfaces(self, timeout_seconds: int = 300
                          ) -> List["SurfaceRef"]:
        """Discover every account/mailbox surface this Mac exposes.

        Read-only. Per-call timeout; failures surface as typed errors so an
        estate scan can mark itself partial instead of silently shrinking.
        """
        script = (
            '        set fieldSep to (ASCII character 31)\n'
            '        set recSep to (ASCII character 29)\n'
            '        tell application "Mail"\n'
            '            set outRows to {}\n'
            '            repeat with acct in accounts\n'
            '                set acctName to name of acct\n'
            '                set foundRows to my collectMailboxRows('
            'acct, acctName, {}, fieldSep)\n'
            '                set outRows to outRows & foundRows\n'
            '            end repeat\n'
            '            set AppleScript\'s text item delimiters to recSep\n'
            '            return outRows as string\n'
            '        end tell\n'
            '\n'
            '        on collectMailboxRows(containerRef, acctName, '
            'parentPath, fieldSep)\n'
            '            tell application "Mail"\n'
            '                set gathered to {}\n'
            '                repeat with mbx in (mailboxes of containerRef)\n'
            '                    set componentName to (name of mbx as string)\n'
            '                    set exactPath to parentPath & {componentName}\n'
            '                    set rowParts to {acctName} & exactPath\n'
            '                    set AppleScript\'s text item delimiters to fieldSep\n'
            '                    set end of gathered to (rowParts as string)\n'
            '                    set childRows to my collectMailboxRows('
            'mbx, acctName, exactPath, fieldSep)\n'
            '                    set gathered to gathered & childRows\n'
            '                end repeat\n'
            '                return gathered\n'
            '            end tell\n'
            '        end collectMailboxRows\n'
            '        '
        )
        try:
            output = self._run_applescript(script, timeout=timeout_seconds)
        except RuntimeError as e:
            raise ProviderScriptError(f"surface discovery failed: {e}") from e
        surfaces: List[SurfaceRef] = []
        for row in output.split(_ROW_SEP):
            line = row.strip("\n")
            if not line:
                continue
            parts = line.split(_FIELD_SEP)
            if len(parts) < 2:
                continue
            path_components = tuple(parts[1:])
            surfaces.append(SurfaceRef(
                account=parts[0],
                mailbox=_canonical_mailbox_scope(path_components),
                path_components=path_components,
            ))
        return surfaces

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

    # --- Bounded flagged-message enumeration ---------------------------------
    #
    # Owns the AppleScript for flagged-estate scans so no CLI/workflow layer
    # ever constructs AppleScript or touches _run_applescript. The flagged
    # `whose` predicate bounds what Mail.app materializes; a date window can
    # further bound it. Rows come back newest-first (sorted client-side on
    # received date) and are truncated to `limit` AFTER the full honest count,
    # so the result can report how much a limit hid.

    def _build_flagged_script(
        self,
        mailbox: str,
        account: str,
        since_days: Optional[int],
        mailbox_path: Optional[Sequence[str]] = None,
    ) -> str:
        """Build the flagged-enumeration AppleScript. PURE (no I/O).

        Account and mailbox names go through _as_applescript so quotes and
        newlines in either cannot break out of the string literal. Each row
        field degrades independently (empty placeholder) so one bad property
        never drops the whole message.
        """
        if since_days is not None and (
            isinstance(since_days, bool)
            or not isinstance(since_days, int)
            or since_days <= 0
        ):
            raise ProviderScriptError(
                "since_days must be a positive integer or None"
            )
        mailbox_ref = self._mailbox_reference(
            mailbox,
            account,
            mailbox_path,
        )
        if since_days is not None:
            predicate = (
                "set cutoffDate to (current date) - "
                f"({since_days} * days)\n"
                "            set flaggedMsgs to (messages of targetMailbox "
                "whose flagged status is true and date received > cutoffDate)"
            )
        else:
            predicate = (
                "set flaggedMsgs to (messages of targetMailbox "
                "whose flagged status is true)"
            )
        return (
            '        set fieldSep to (ASCII character 31)\n'
            '        set recSep to (ASCII character 29)\n'
            '        tell application "Mail"\n'
            f'            set targetMailbox to {mailbox_ref}\n'
            f'            {predicate}\n'
            '            set rowCount to count of flaggedMsgs\n'
            '            set outRows to {}\n'
            '            repeat with m in flaggedMsgs\n'
            '                set rowText to (id of m as string)\n'
            '                try\n'
            '                    set rowText to rowText & fieldSep & (sender of m)\n'
            '                on error\n'
            '                    set rowText to rowText & fieldSep & ""\n'
            '                end try\n'
            '                try\n'
            '                    set rowText to rowText & fieldSep & (subject of m)\n'
            '                on error\n'
            '                    set rowText to rowText & fieldSep & ""\n'
            '                end try\n'
            '                try\n'
            '                    set rowText to rowText & fieldSep & (flag index of m as string)\n'
            '                on error\n'
            '                    set rowText to rowText & fieldSep & "?"\n'
            '                end try\n'
            '                try\n'
            '                    set rowText to rowText & fieldSep & '
            '((date received of m) as «class isot» as string)\n'
            '                on error\n'
            '                    set rowText to rowText & fieldSep & ""\n'
            '                end try\n'
            '                set end of outRows to rowText\n'
            '            end repeat\n'
            '            set AppleScript\'s text item delimiters to recSep\n'
            '            return (rowCount as string) & fieldSep & (outRows as string)\n'
            '        end tell\n'
            '        '
        )

    def enumerate_flagged(
        self,
        mailbox: str = "INBOX",
        limit: int = 500,
        since_days: Optional[int] = None,
        timeout_seconds: int = 600,
        account: Optional[str] = None,
        mailbox_path: Optional[Sequence[str]] = None,
    ) -> EnumerationResult:
        """Enumerate flagged messages in one account-scoped mailbox surface.

        ``account`` overrides the constructor-scoped account for THIS call
        (used by estate scans that sweep many surfaces on one provider).

        Honors ``limit`` (rows truncated newest-first AFTER counting the full
        predicate-bounded set — truncation is VISIBLE and breaks estate
        completeness) and ``since_days`` (Mail.app-side date predicate).
        Inaccessible rows also break completeness. A failure raises nothing
        and returns an INCOMPLETE result with the error recorded — never an
        empty success.
        """
        account = account if account is not None else (self.account or "")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ProviderScriptError("limit must be a positive integer")
        if since_days is not None and (
            isinstance(since_days, bool)
            or not isinstance(since_days, int)
            or since_days <= 0
        ):
            raise ProviderScriptError(
                "since_days must be a positive integer or None"
            )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds <= 0
        ):
            raise ProviderScriptError(
                "timeout_seconds must be a positive integer"
            )
        boundary: Dict[str, Any] = {
            "provider": self.name,
            "account": account,
            "mailbox": mailbox,
            "limit": limit,
            "since_days": since_days,
            "ordering": "received_desc",
        }
        errors: List[str] = []
        inaccessible = 0
        unknown_index = 0
        timeout_count = 0

        if not isinstance(account, str) or not account.strip():
            errors.append(
                "account_required: explicit Mail.app account scope is required",
            )
            return EnumerationResult.build(
                rows=[], scope_complete=False, errors=errors,
                inaccessible_count=0, timeout_count=0,
                unknown_index_count=0, hidden_by_limit=0,
                scanned_boundary=boundary,
            )

        try:
            script = self._build_flagged_script(
                mailbox,
                account,
                since_days,
                mailbox_path,
            )
        except ProviderScriptError as e:
            errors.append(f"enumeration setup failed: {e}")
            return EnumerationResult.build(
                rows=[], scope_complete=False, errors=errors,
                inaccessible_count=0, timeout_count=0,
                unknown_index_count=0, hidden_by_limit=0,
                scanned_boundary=boundary,
            )
        try:
            output = self._run_applescript(script, timeout=timeout_seconds)
        except ProviderTimeoutError as e:
            errors.append(f"enumeration timed out: {e}")
            return EnumerationResult.build(
                rows=[], scope_complete=False, errors=errors,
                inaccessible_count=0, timeout_count=1,
                unknown_index_count=0, hidden_by_limit=0,
                scanned_boundary=boundary,
            )
        except RuntimeError as e:
            errors.append(f"enumeration failed: {e}")
            return EnumerationResult.build(
                rows=[], scope_complete=False, errors=errors,
                inaccessible_count=0, timeout_count=0,
                unknown_index_count=0, hidden_by_limit=0,
                scanned_boundary=boundary,
            )

        rows: List[FlaggedRow] = []
        total_seen = -1
        if _FIELD_SEP not in output:
            errors.append("malformed enumeration output (missing header)")
            return EnumerationResult.build(
                rows=[], scope_complete=False, errors=errors,
                inaccessible_count=0, timeout_count=0,
                unknown_index_count=0, hidden_by_limit=0,
                scanned_boundary=boundary,
            )
        header, _, body = output.partition(_FIELD_SEP)
        try:
            total_seen = int(header.strip())
        except ValueError:
            errors.append("malformed enumeration header count")

        parsed_rows: List[FlaggedRow] = []
        for raw in body.split(_ROW_SEP):
            line = raw.strip("\n")
            if not line:
                continue
            parts = line.split(_FIELD_SEP)
            if len(parts) < 5:
                inaccessible += 1
                continue
            provider_id, sender, subject, index_s, received_iso = parts[:5]
            candidate_id = provider_id.strip()
            if (
                not candidate_id
                or not candidate_id.isascii()
                or not candidate_id.isdigit()
                or candidate_id[0] == "0"
            ):
                inaccessible += 1
                continue
            try:
                native_index: Optional[int] = int(index_s.strip())
            except ValueError:
                native_index = None
            color = flag_from_mailapp_index(native_index) if native_index is not None \
                else FlagColor.UNKNOWN
            parsed_rows.append(FlaggedRow(
                provider_id=candidate_id,
                account=account,
                mailbox=mailbox,
                sender=sender,
                subject=subject,
                native_index=native_index,
                flag_color=color,
                received_iso=received_iso or None,
            ))

        # Newest-first by received date where parseable; unparseable dates sink.
        def _sort_key(r: FlaggedRow) -> datetime:
            return _parse_received_datetime(
                r.received_iso,
            ) or datetime.min.replace(tzinfo=timezone.utc)

        parsed_rows.sort(key=_sort_key, reverse=True)
        hidden_by_limit = max(0, len(parsed_rows) - limit)
        rows = parsed_rows[:limit]
        unknown_index = sum(
            row.flag_color == FlagColor.UNKNOWN for row in rows
        )
        boundary["total_flagged_seen"] = (
            total_seen if total_seen >= 0 else len(parsed_rows))
        boundary["returned_count"] = len(rows)
        boundary["hidden_by_limit"] = hidden_by_limit

        scope_complete = total_seen >= 0 and not errors
        return EnumerationResult.build(
            rows=rows, scope_complete=scope_complete, errors=errors,
            inaccessible_count=inaccessible, timeout_count=timeout_count,
            unknown_index_count=unknown_index,
            hidden_by_limit=hidden_by_limit,
            scanned_boundary=boundary,
        )
