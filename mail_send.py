#!/usr/bin/env python3
"""mail-send — receipt-bound, headless CLI send lane (Gmail, keyed SMTP).

This is NOT the autonomic sender. `send_drafts.py` is the beat's batch lane and stays
tier-locked behind LIMEN_MAIL_SEND + the mail-tiers registry; it decides for itself and
therefore must be disarmed by default. THIS tool sends exactly what a human (or a session
acting on a human's explicit ask) invokes it with.  Invocation alone is never authorization:
the default is a zero-write preview, while a send requires ``--apply`` and an unexpired
``uma.mail_send_authorization.v1`` receipt bound to the exact outgoing message and
authenticated by a separately-custodied key.  Each apply claims its attempt ID durably
before SMTP, so retries require a fresh attempt and receipt.  It is never wired into the
beat.

Every send is server-verified: after SMTP accepts, the tool polls [Gmail]/Sent Mail for
the outgoing Message-ID and prints a loud VERIFIED/UNVERIFIED verdict (non-zero exit if
unverified). Fail-closed everywhere else: missing credentials, invalid recipients, and
missing/oversized attachments refuse the send.

Modes
    --to A --subject S --body-file F [--cc B --bcc C --attach P ...]   compose + send
    --reply-to-search "fragment or <message-id>" --body-file F         threaded reply
        (locates the newest matching message in [Gmail]/All Mail, sets In-Reply-To/
         References, Re:-prefixes the subject, and defaults --to to the original sender)
    --from-draft "subject fragment"                                    send existing draft
        (fetches the newest matching [Gmail]/Drafts message, sends it VERBATIM over SMTP
         — Bcc header stripped from the wire copy — then moves the draft to [Gmail]/Trash)
    --self-test --attempt-id ID                                        end-to-end predicate
        (builds a deterministic message for ID; an authorized apply sends it to the
         authenticated address and verifies it in Sent;
         exit 0 ⟺ the whole lane works)
    (default)                                                          print, send nothing
    --apply --attempt-id ID --authorization-receipt PATH               authorize one send
      (receipt is verified by the fixed, public Ed25519 authority key)

Credentials come from the env the credential organ hydrates (GMAIL_USER/GMAIL_APP_PASSWORD
or IMAP_USER/IMAP_PASS), or from a credential env file parsed strictly as data — never
sourced or evaluated as shell code.
"""

from __future__ import annotations

import argparse
import email
import email.policy
import hashlib
import imaplib
import json
import logging
import os
import smtplib
import sys
import time
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import getaddresses, make_msgid, parseaddr
from pathlib import Path

from mail_send_safety import (
    AuthorizationError,
    AuthorizationGrant,
    CredentialFileError,
    assert_grant_current,
    authorization_binding,
    authorization_request,
    claim_authorized_attempt,
    normalize_address,
    normalized_recipients,
    resolve_smtp_credentials,
    validate_attempt_id,
    validate_authorization_receipt,
)
from send_drafts import _attach, classify_attachments

logger = logging.getLogger("mail_send")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465
IMAP_HOST = os.environ.get("IMAP_HOST", "imap.gmail.com")
ALL_MAIL = "[Gmail]/All Mail"
DRAFTS = os.environ.get("LIMEN_MAIL_DRAFTS_MAILBOX", "[Gmail]/Drafts")
SENT = os.environ.get("LIMEN_MAIL_SENT_MAILBOX", "[Gmail]/Sent Mail")
TRASH = "[Gmail]/Trash"
HEADER_SCAN_WINDOW = 100  # newest N messages scanned per mailbox for a match
DEFAULT_CREDENTIAL_FILE = "~/.config/mail_automation/credentials.env"
DEFAULT_AUTHORIZATION_KEY_FILE = "/etc/universal-mail-automation/mail-send-authorization.pub"
DEFAULT_ATTEMPT_STORE = "~/.local/state/universal-mail-automation/mail-send-attempts"

EXIT_OK = 0
EXIT_UNVERIFIED = 2
EXIT_FAIL_CLOSED = 3
EXIT_NOT_FOUND = 4


def _decode_subject(raw: str | None) -> str:
    if not raw:
        return ""
    try:
        return str(make_header(decode_header(raw)))
    except Exception:  # noqa: BLE001 — a mangled header should not kill a scan
        return raw


class GmailImap:
    """Thin, purpose-built IMAP helper (search newest / fetch raw / verify Sent / trash draft).

    Deliberately separate from providers.imap.IMAPProvider, whose surface is shaped around
    the obligations pipeline; this one serves the interactive send lane only.
    """

    def __init__(self, creds: tuple[str, str], host: str = IMAP_HOST):
        self._user, self._pw = creds
        self._host = host
        self._conn: imaplib.IMAP4_SSL | None = None

    def _connection(self) -> imaplib.IMAP4_SSL:
        if self._conn is None:
            conn = imaplib.IMAP4_SSL(self._host)
            conn.login(self._user, self._pw)
            self._conn = conn
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.logout()
            except Exception:  # noqa: BLE001
                pass
            self._conn = None

    def _uid_window(self, conn: imaplib.IMAP4_SSL) -> list[bytes]:
        typ, data = conn.uid("SEARCH", None, "ALL")
        if typ != "OK" or not data or not data[0]:
            return []
        return data[0].split()[-HEADER_SCAN_WINDOW:]

    def newest_matching(self, mailbox: str, query: str) -> tuple[bytes, dict] | None:
        """Newest message in `mailbox` matching `query`.

        A query shaped like an RFC Message-ID (<...@...>) matches the Message-ID header
        exactly (server-side SEARCH); anything else is a case-insensitive substring match
        against the decoded Subject of the newest HEADER_SCAN_WINDOW messages (unicode-safe
        — IMAP SUBJECT SEARCH is ASCII-only, so we match client-side).
        Returns (uid, headers dict) or None.
        """
        conn = self._connection()
        typ, _ = conn.select(f'"{mailbox}"', readonly=True)
        if typ != "OK":
            return None
        if query.startswith("<") and query.endswith(">") and "@" in query:
            typ, data = conn.uid("SEARCH", "HEADER", "Message-ID", query)
            uids = data[0].split() if typ == "OK" and data and data[0] else []
        else:
            uids = []
            frag = query.casefold()
            for uid in reversed(self._uid_window(conn)):
                hdr = self._fetch_headers(conn, uid)
                if hdr and frag in _decode_subject(hdr.get("Subject")).casefold():
                    uids = [uid]
                    break
        if not uids:
            return None
        uid = uids[-1]
        hdr = self._fetch_headers(conn, uid)
        return (uid, hdr) if hdr else None

    def _fetch_headers(self, conn: imaplib.IMAP4_SSL, uid: bytes) -> dict | None:
        typ, data = conn.uid(
            "FETCH",
            uid,
            "(BODY.PEEK[HEADER.FIELDS (SUBJECT MESSAGE-ID REFERENCES FROM TO DATE)])",
        )
        if typ != "OK" or not data or data[0] is None:
            return None
        raw = b""
        for part in data:
            if isinstance(part, tuple) and len(part) > 1:
                raw = part[1]
                break
        msg = email.message_from_bytes(raw)
        return {
            k: msg.get(k)
            for k in ("Subject", "Message-ID", "References", "From", "To", "Date")
        }

    def fetch_raw(self, mailbox: str, uid: bytes) -> bytes | None:
        conn = self._connection()
        typ, _ = conn.select(f'"{mailbox}"', readonly=True)
        if typ != "OK":
            return None
        typ, data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
        if typ != "OK" or not data:
            return None
        for part in data:
            if isinstance(part, tuple) and len(part) > 1:
                return part[1]
        return None

    def sent_has(self, message_id: str, timeout_s: int = 60, step_s: int = 5) -> bool:
        """Poll [Gmail]/Sent Mail for `message_id` — the server-truth send verification."""
        deadline = time.monotonic() + timeout_s
        while True:
            conn = self._connection()
            typ, _ = conn.select(f'"{SENT}"', readonly=True)
            if typ == "OK":
                typ, data = conn.uid("SEARCH", "HEADER", "Message-ID", message_id)
                if typ == "OK" and data and data[0]:
                    return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(step_s)

    def trash_draft(self, uid: bytes) -> bool:
        """Move a Drafts message to [Gmail]/Trash (reversible for ~30 days)."""
        conn = self._connection()
        typ, _ = conn.select(f'"{DRAFTS}"')
        if typ != "OK":
            return False
        # MOVE is atomic and scoped to this UID on Gmail and modern IMAP servers.
        typ, _ = conn.uid("MOVE", uid, f'"{TRASH}"')
        if typ == "OK":
            return True
        # UIDPLUS fallback: never call mailbox-wide EXPUNGE, which could erase
        # unrelated messages another client had already marked \Deleted.
        typ, _ = conn.uid("COPY", uid, f'"{TRASH}"')
        if typ != "OK":
            return False
        typ, _ = conn.uid("STORE", uid, "+FLAGS", r"(\Deleted)")
        if typ != "OK":
            return False
        typ, _ = conn.uid("EXPUNGE", uid)
        if typ == "OK":
            return True
        # Best-effort rollback of our deletion mark; the Trash copy is harmless
        # and preferable to a global expunge of unrelated drafts.
        conn.uid("STORE", uid, "-FLAGS", r"(\Deleted)")
        return False


def _validate_recipients(addrs: list[str]) -> list[str]:
    """Fail-closed recipient validation; returns problems (empty ⇒ ok)."""
    problems = []
    for a in addrs:
        addr = parseaddr(a)[1]
        if "@" not in addr:
            problems.append(f"not an address: {a!r}")
        elif addr.lower().endswith("privaterelay.appleid.com"):
            problems.append(f"private-relay address refused: {addr}")
    return problems


def _split_addrs(values: list[str] | None) -> list[str]:
    out: list[str] = []
    for v in values or []:
        out.extend(a.strip() for a in v.split(",") if a.strip())
    return out


def _normalize_addrs(values: list[str]) -> list[str]:
    """Normalize and deduplicate an already-validated recipient list."""
    return sorted({addr for value in values if (addr := normalize_address(value))})


def _message_id_domain(sender: str) -> str:
    address = normalize_address(sender)
    if "@" not in address:
        raise AuthorizationError("authenticated sender has no Message-ID domain")
    return address.rsplit("@", 1)[1]


def build_message(
    creds: tuple[str, str],
    to: list[str],
    subject: str,
    body: str,
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    attachments: list | None = None,
    reply_headers: dict | None = None,
    attempt_id: str | None = None,
) -> EmailMessage:
    """Compose the outgoing RFC822 message; sets a Message-ID so the send can be verified."""
    user, _ = creds
    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = ", ".join(to)
    if cc:
        msg["Cc"] = ", ".join(cc)
    if bcc:
        msg["Bcc"] = ", ".join(bcc)
    if reply_headers:
        orig_id = reply_headers.get("Message-ID")
        if orig_id:
            msg["In-Reply-To"] = orig_id
            prior = (reply_headers.get("References") or "").split()
            msg["References"] = " ".join(prior + [orig_id]).strip()
        orig_subject = _decode_subject(reply_headers.get("Subject")) or subject
        subject = (
            orig_subject
            if orig_subject.lower().startswith("re:")
            else f"Re: {orig_subject}"
        )
    msg["Subject"] = subject
    if attempt_id is None:
        msg["Message-ID"] = make_msgid()
    else:
        validate_attempt_id(attempt_id)
        deterministic_id = hashlib.sha256(
            f"mail-send\0{attempt_id}".encode()
        ).hexdigest()[:32]
        msg["Message-ID"] = (
            f"<uma-send-{deterministic_id}@{_message_id_domain(user)}>"
        )
    msg.set_content(body)
    _attach(msg, attachments)
    return msg


def build_self_test_message(creds: tuple[str, str], attempt_id: str) -> EmailMessage:
    """Build the deterministic, exactly authorizable self-test message."""
    to = [creds[0]]
    subject = f"mail-send self-test {attempt_id}"
    body = (
        "This is the mail-send lane self-test.\n"
        f"Attempt-ID: {attempt_id}\n"
        f"An authorized apply uses SMTP ({SMTP_HOST}:{SMTP_PORT}) and verifies against {SENT}.\n"
        "Exit 0 from this run means the headless CLI send lane works end to end.\n"
    )
    msg = build_message(creds, to, subject, body, attempt_id=attempt_id)
    deterministic_id = hashlib.sha256(attempt_id.encode("utf-8")).hexdigest()[:32]
    msg.replace_header(
        "Message-ID",
        f"<uma-self-test-{deterministic_id}@{_message_id_domain(creds[0])}>",
    )
    return msg


def _smtp_send(
    msg: EmailMessage,
    creds: tuple[str, str],
    to_addrs: list[str] | None = None,
    *,
    before_data=None,
) -> bool:
    """Perform one all-recipients-or-no-DATA SMTP transaction.

    ``SMTP.send_message`` transmits DATA whenever *any* RCPT succeeds and only
    reports the refused subset afterwards.  That creates a partial send whose
    failure exit invites duplicate retries.  This implementation performs every
    RCPT command first and issues RSET without DATA if even one address is refused.
    """
    user, pw = creds
    wire = msg
    if "Bcc" in msg:  # never transmit the Bcc header itself
        wire = email.message_from_bytes(msg.as_bytes(), policy=email.policy.default)
        del wire["Bcc"]
    recipients = _normalize_addrs(to_addrs or [])
    if not recipients:
        roles = normalized_recipients(msg)
        recipients = sorted(set(roles["to"]) | set(roles["cc"]) | set(roles["bcc"]))
    if not recipients:
        print("mail-send: SMTP refused: no envelope recipients", file=sys.stderr)
        return False
    envelope_sender = normalize_address(user)
    if not envelope_sender:
        print("mail-send: SMTP refused: invalid envelope sender", file=sys.stderr)
        return False
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.login(user, pw)
            code, response = s.mail(envelope_sender)
            if not 200 <= code < 300:
                print(
                    f"mail-send: SMTP MAIL FROM refused ({code}): {response!r}",
                    file=sys.stderr,
                )
                return False
            refused: dict[str, tuple[int, object]] = {}
            for address in recipients:
                code, response = s.rcpt(address)
                if not 200 <= code < 300:
                    refused[address] = (code, response)
            if refused:
                try:
                    s.rset()
                except Exception:  # noqa: BLE001 - closing the connection still aborts DATA
                    pass
                refused_addresses = sorted(refused)
                print(
                    "mail-send: SMTP refused one or more recipients before DATA; "
                    "no message body was transmitted: " + ", ".join(refused_addresses),
                    file=sys.stderr,
                )
                return False
            if before_data is not None:
                before_data()
            code, response = s.data(wire.as_bytes(policy=email.policy.SMTP))
            if not 200 <= code < 300:
                print(
                    f"mail-send: SMTP DATA refused ({code}): {response!r}",
                    file=sys.stderr,
                )
                return False
        return True
    except Exception as e:  # noqa: BLE001 — CLI reports and exits nonzero; never a stack trace at him
        print(f"mail-send: SMTP send failed: {e}", file=sys.stderr)
        return False


def send_and_verify(
    msg: EmailMessage,
    creds: tuple[str, str],
    imap: GmailImap,
    verify_timeout: int,
    grant: AuthorizationGrant,
    action: str,
    attempt_id: str,
    to_addrs: list[str] | None = None,
    effect_context: dict[str, str] | None = None,
) -> int:
    """Claim a one-shot attempt, send, then verify server-side custody."""
    try:
        binding = authorization_binding(
            msg,
            envelope_sender=creds[0],
            action=action,
            attempt_id=attempt_id,
            effect_context=effect_context,
        )
        bound_roles = binding["recipients"]
        bound_envelope = sorted(
            set(bound_roles["to"]) | set(bound_roles["cc"]) | set(bound_roles["bcc"])
        )
        requested_envelope = (
            _normalize_addrs(to_addrs) if to_addrs is not None else bound_envelope
        )
        if requested_envelope != bound_envelope:
            raise AuthorizationError(
                "SMTP envelope recipients do not match the authorized recipient roles"
            )
        assert_grant_current(grant, binding)
        claim = claim_authorized_attempt(
            grant,
            binding,
            DEFAULT_ATTEMPT_STORE,
        )
    except AuthorizationError as exc:
        print(f"mail-send: authorization refused before SMTP: {exc}", file=sys.stderr)
        return EXIT_FAIL_CLOSED

    def recheck_before_data() -> None:
        current_binding = authorization_binding(
            msg,
            envelope_sender=creds[0],
            action=action,
            attempt_id=attempt_id,
            effect_context=effect_context,
        )
        assert_grant_current(grant, current_binding)

    print(f"mail-send: one-shot attempt claimed at {claim}")
    if not _smtp_send(
        msg,
        creds,
        to_addrs=requested_envelope,
        before_data=recheck_before_data,
    ):
        return EXIT_FAIL_CLOSED
    msgid = msg["Message-ID"]
    print(f"mail-send: SMTP accepted ({msgid})")
    if imap.sent_has(msgid, timeout_s=verify_timeout):
        print(f"mail-send: VERIFIED in {SENT}: {msg['Subject']}")
        return EXIT_OK
    print(
        f"mail-send: UNVERIFIED — SMTP accepted but {msgid} not visible in {SENT} "
        f"within {verify_timeout}s. Check the mailbox before retrying (a retry may double-send).",
        file=sys.stderr,
    )
    return EXIT_UNVERIFIED


def _preview_or_authorize(
    msg: EmailMessage,
    creds: tuple[str, str],
    *,
    action: str,
    attempt_id: str,
    apply: bool,
    authorization_receipt: str | None,
    authorization_key_file: str | None,
    effect_context: dict[str, str] | None = None,
) -> AuthorizationGrant | None:
    """Print the non-authorizing request or validate an exact apply grant."""
    binding = authorization_binding(
        msg,
        envelope_sender=creds[0],
        action=action,
        attempt_id=attempt_id,
        effect_context=effect_context,
    )
    if not apply:
        print("mail-send: AUTHORIZATION REQUEST (preview only; authorized=false)")
        print(json.dumps(authorization_request(binding), indent=2, sort_keys=True))
        return None
    if not authorization_receipt:
        raise AuthorizationError("--apply requires --authorization-receipt")
    if not authorization_key_file:
        raise AuthorizationError("fixed authorization public key is unavailable")
    return validate_authorization_receipt(
        authorization_receipt,
        binding,
        authorization_key_file=authorization_key_file,
    )


def run_from_draft(
    fragment: str,
    creds: tuple[str, str],
    imap: GmailImap,
    verify_timeout: int,
    *,
    apply: bool,
    attempt_id: str,
    authorization_receipt: str | None,
    authorization_key_file: str | None,
) -> int:
    hit = imap.newest_matching(DRAFTS, fragment)
    if not hit:
        print(f"mail-send: no draft in {DRAFTS} matching {fragment!r}", file=sys.stderr)
        return EXIT_NOT_FOUND
    uid, _hdr = hit
    raw = imap.fetch_raw(DRAFTS, uid)
    if not raw:
        print("mail-send: draft fetch failed", file=sys.stderr)
        return EXIT_FAIL_CLOSED
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    header_sender = normalize_address(str(msg.get("From") or ""))
    envelope_sender = normalize_address(creds[0])
    if not header_sender or header_sender != envelope_sender:
        print(
            f"mail-send: draft From does not match authenticated sender ({header_sender} != {envelope_sender})",
            file=sys.stderr,
        )
        return EXIT_FAIL_CLOSED
    rcpts = _normalize_addrs(
        [
            a
            for _, a in getaddresses(
                msg.get_all("To", []) + msg.get_all("Cc", []) + msg.get_all("Bcc", [])
            )
        ]
    )
    problems = _validate_recipients(rcpts)
    if not rcpts or problems:
        print(
            f"mail-send: draft recipients invalid: {problems or 'none found'}",
            file=sys.stderr,
        )
        return EXIT_FAIL_CLOSED
    if not msg.get("Message-ID"):
        deterministic_id = hashlib.sha256(
            attempt_id.encode("utf-8") + b"\0" + raw
        ).hexdigest()[:32]
        msg["Message-ID"] = (
            f"<uma-draft-{deterministic_id}@{_message_id_domain(creds[0])}>"
        )
    try:
        source_uid = uid.decode("ascii", errors="strict")
    except (AttributeError, UnicodeDecodeError):
        print("mail-send: draft source returned an invalid UID", file=sys.stderr)
        return EXIT_FAIL_CLOSED
    effect_context = {
        "source_mailbox": DRAFTS,
        "source_uid": source_uid,
        "source_message_id": str(msg.get("Message-ID") or ""),
    }
    try:
        grant = _preview_or_authorize(
            msg,
            creds,
            action="from_draft",
            attempt_id=attempt_id,
            apply=apply,
            authorization_receipt=authorization_receipt,
            authorization_key_file=authorization_key_file,
            effect_context=effect_context,
        )
    except AuthorizationError as exc:
        print(f"mail-send: authorization refused: {exc}", file=sys.stderr)
        return EXIT_FAIL_CLOSED
    if not apply:
        print(f"DRY-RUN — would send draft verbatim to {rcpts}:\n")
        print(msg.as_string()[:4000])
        return EXIT_OK
    assert grant is not None
    rc = send_and_verify(
        msg,
        creds,
        imap,
        verify_timeout,
        grant,
        "from_draft",
        attempt_id,
        to_addrs=rcpts,
        effect_context=effect_context,
    )
    if rc == EXIT_OK:
        if imap.trash_draft(uid):
            print(f"mail-send: draft moved to {TRASH}")
        else:
            print(
                "mail-send: WARNING — sent, but the draft copy could not be trashed; remove it by hand"
            )
    return rc


def main(argv=None) -> int:
    logging.basicConfig(level=logging.WARNING)
    ap = argparse.ArgumentParser(
        prog="mail-send",
        description="Interactive headless Gmail send (keyed SMTP) with built-in Sent verification.",
    )
    ap.add_argument(
        "--to", action="append", help="recipient (repeatable or comma-separated)"
    )
    ap.add_argument("--cc", action="append")
    ap.add_argument("--bcc", action="append")
    ap.add_argument("--subject")
    ap.add_argument(
        "--body-file", help="file containing the plain-text body (never inline)"
    )
    ap.add_argument("--attach", action="append", help="attachment path (repeatable)")
    source = ap.add_mutually_exclusive_group()
    source.add_argument(
        "--reply-to-search",
        metavar="QUERY",
        help="thread as a reply to the newest [Gmail]/All Mail message matching a subject fragment or <Message-ID>",
    )
    source.add_argument(
        "--from-draft",
        metavar="FRAGMENT",
        help="send the newest matching [Gmail]/Drafts message verbatim, then trash it",
    )
    source.add_argument(
        "--self-test",
        action="store_true",
        help="build a deterministic self-test for --attempt-id (an authorized apply sends and verifies it)",
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument(
        "--apply",
        action="store_true",
        help="perform the send (requires an exact authorization receipt); default is preview only",
    )
    mode.add_argument(
        "--dry-run",
        action="store_true",
        help="explicit alias for the default zero-write preview",
    )
    ap.add_argument(
        "--attempt-id",
        help="unique 8-128 character attempt ID used by both preview and authorization receipt",
    )
    ap.add_argument(
        "--authorization-receipt",
        help="path to an unexpired uma.mail_send_authorization.v1 JSON receipt (required with --apply)",
    )
    ap.add_argument(
        "--credentials-file",
        action="append",
        help="credential env file parsed as literal data, never sourced (repeatable)",
    )
    ap.add_argument(
        "--verify-timeout",
        type=int,
        default=60,
        help="seconds to wait for the Sent-mailbox verification (default 60)",
    )
    args = ap.parse_args(argv)

    if not 1 <= args.verify_timeout <= 300:
        print("mail-send: --verify-timeout must be between 1 and 300", file=sys.stderr)
        return EXIT_FAIL_CLOSED
    compose_options = bool(
        args.to or args.cc or args.bcc or args.subject or args.body_file or args.attach
    )
    if (args.self_test or args.from_draft) and compose_options:
        print(
            "mail-send: compose options cannot be combined with --self-test or --from-draft",
            file=sys.stderr,
        )
        return EXIT_FAIL_CLOSED
    if not args.self_test and not args.from_draft:
        if not _split_addrs(args.to) and not args.reply_to_search:
            ap.error("--to is required (or --reply-to-search with a resolvable sender)")
        if not args.body_file:
            ap.error("--body-file is required for compose/reply sends")
        if not args.subject and not args.reply_to_search:
            ap.error("--subject is required unless replying (--reply-to-search)")

    try:
        attempt_id = validate_attempt_id(args.attempt_id or "")
    except AuthorizationError as exc:
        print(f"mail-send: refusing invocation: {exc}", file=sys.stderr)
        return EXIT_FAIL_CLOSED
    if args.apply and not args.authorization_receipt:
        print("mail-send: --apply requires --authorization-receipt", file=sys.stderr)
        return EXIT_FAIL_CLOSED
    authorization_key_file = str(Path(DEFAULT_AUTHORIZATION_KEY_FILE).expanduser())
    if args.apply and not Path(authorization_key_file).is_file():
        print(
            "mail-send: fixed authorization public key is not installed",
            file=sys.stderr,
        )
        return EXIT_FAIL_CLOSED
    if not args.apply and args.authorization_receipt:
        print(
            "mail-send: --authorization-receipt is only valid with --apply",
            file=sys.stderr,
        )
        return EXIT_FAIL_CLOSED
    credential_files = args.credentials_file
    if credential_files is None:
        default_credential_file = Path(DEFAULT_CREDENTIAL_FILE).expanduser()
        credential_files = (
            [str(default_credential_file)] if default_credential_file.is_file() else []
        )
    try:
        creds = resolve_smtp_credentials(credential_files, os.environ)
    except CredentialFileError as exc:
        print(f"mail-send: credential file refused: {exc}", file=sys.stderr)
        return EXIT_FAIL_CLOSED
    if not creds:
        print(
            "mail-send: no credentials (GMAIL_USER/GMAIL_APP_PASSWORD or IMAP_USER/IMAP_PASS). "
            "Hydrate via the credential owner or pass --credentials-file; files are parsed without shell evaluation.",
            file=sys.stderr,
        )
        return EXIT_FAIL_CLOSED
    sender = normalize_address(creds[0])
    if not sender or "@" not in sender:
        print("mail-send: credential username is not a valid sender", file=sys.stderr)
        return EXIT_FAIL_CLOSED
    creds = (sender, creds[1])

    imap = GmailImap(creds)
    try:
        if args.from_draft:
            return run_from_draft(
                args.from_draft,
                creds,
                imap,
                args.verify_timeout,
                apply=args.apply,
                attempt_id=attempt_id,
                authorization_receipt=args.authorization_receipt,
                authorization_key_file=authorization_key_file,
            )

        if args.self_test:
            to = [creds[0]]
            msg = build_self_test_message(creds, attempt_id)
            try:
                grant = _preview_or_authorize(
                    msg,
                    creds,
                    action="self_test",
                    attempt_id=attempt_id,
                    apply=args.apply,
                    authorization_receipt=args.authorization_receipt,
                    authorization_key_file=authorization_key_file,
                )
            except AuthorizationError as exc:
                print(f"mail-send: authorization refused: {exc}", file=sys.stderr)
                return EXIT_FAIL_CLOSED
            if not args.apply:
                print(msg.as_string())
                return EXIT_OK
            assert grant is not None
            return send_and_verify(
                msg,
                creds,
                imap,
                args.verify_timeout,
                grant,
                "self_test",
                attempt_id,
                to_addrs=_normalize_addrs(to),
            )

        to = _split_addrs(args.to)
        cc = _split_addrs(args.cc)
        bcc = _split_addrs(args.bcc)
        reply_headers = None
        effect_context: dict[str, str] | None = None
        if args.reply_to_search:
            hit = imap.newest_matching(ALL_MAIL, args.reply_to_search)
            if not hit:
                print(
                    f"mail-send: no message in {ALL_MAIL} matching {args.reply_to_search!r}",
                    file=sys.stderr,
                )
                return EXIT_NOT_FOUND
            reply_uid, reply_headers = hit
            try:
                reply_uid_text = reply_uid.decode("ascii", errors="strict")
            except (AttributeError, UnicodeDecodeError):
                print(
                    "mail-send: reply source returned an invalid UID", file=sys.stderr
                )
                return EXIT_FAIL_CLOSED
            effect_context = {
                "source_mailbox": ALL_MAIL,
                "source_uid": reply_uid_text,
                "source_message_id": str(reply_headers.get("Message-ID") or ""),
            }
            if not to:  # default the recipient to the original sender
                sender = parseaddr(reply_headers.get("From") or "")[1]
                if sender:
                    to = [sender]

        if not to:
            ap.error("--to is required (or --reply-to-search with a resolvable sender)")

        problems = _validate_recipients(to + cc + bcc)
        if problems:
            print("mail-send: refusing send — " + "; ".join(problems), file=sys.stderr)
            return EXIT_FAIL_CLOSED

        to = _normalize_addrs(to)
        cc = _normalize_addrs(cc)
        bcc = _normalize_addrs(bcc)

        ok_files, oversized, missing = classify_attachments(args.attach or [])
        if oversized or missing:
            print(
                f"mail-send: refusing send — attachments missing={missing} oversized={oversized}",
                file=sys.stderr,
            )
            return EXIT_FAIL_CLOSED

        try:
            body = Path(args.body_file).read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            print(f"mail-send: cannot read body file: {exc}", file=sys.stderr)
            return EXIT_FAIL_CLOSED
        msg = build_message(
            creds,
            to,
            args.subject or "",
            body,
            cc=cc,
            bcc=bcc,
            attachments=ok_files,
            reply_headers=reply_headers,
            attempt_id=attempt_id,
        )
        action = "reply" if reply_headers else "compose"
        try:
            grant = _preview_or_authorize(
                msg,
                creds,
                action=action,
                attempt_id=attempt_id,
                apply=args.apply,
                authorization_receipt=args.authorization_receipt,
                authorization_key_file=authorization_key_file,
                effect_context=effect_context,
            )
        except AuthorizationError as exc:
            print(f"mail-send: authorization refused: {exc}", file=sys.stderr)
            return EXIT_FAIL_CLOSED
        if not args.apply:
            print(msg.as_string()[:4000])
            return EXIT_OK
        assert grant is not None
        return send_and_verify(
            msg,
            creds,
            imap,
            args.verify_timeout,
            grant,
            action,
            attempt_id,
            to_addrs=(to + cc + bcc) or None,
            effect_context=effect_context,
        )
    finally:
        imap.close()


if __name__ == "__main__":
    sys.exit(main())
