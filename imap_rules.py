"""
Lightweight IMAP rules engine to apply Gmail-style labels/folders using shared LABEL_RULES.

Usage:
  DRY_RUN=1 IMAP_HOST=imap.gmail.com IMAP_USER="padavano.anthony@gmail.com" IMAP_PASS="app-password" python imap_rules.py --limit 200
  # Remove DRY_RUN to apply actions.

Notes:
  - Uses IMAP with STARTTLS/SSL.
  - For Gmail, labels are applied via IMAP folders. Ensure the IMAP label exists (create via Gmail/IMAP if missing).
  - Uses shared rules from core.rules module.
  - Default query pulls INBOX unseen; you can override with --mailbox.
"""

import argparse
import imaplib
import email
import os
import re
import ssl
from email.header import decode_header
from typing import List, Tuple, Dict
import subprocess
import getpass

from core.rules import LABEL_RULES, categorize_from_strings


def decode_str(s: str) -> str:
    decoded = decode_header(s)
    parts = []
    for text, enc in decoded:
        if isinstance(text, bytes):
            parts.append(text.decode(enc or "utf-8", errors="ignore"))
        else:
            parts.append(text)
    return " ".join(parts)


def connect_imap(host: str, user: str, password: str) -> imaplib.IMAP4_SSL:  # allow-secret
    ctx = ssl.create_default_context()
    imap = imaplib.IMAP4_SSL(host, ssl_context=ctx)
    imap.login(user, password)
    return imap


def load_password() -> str:
    """
    Load IMAP_PASS from env or 1Password CLI (OP_ACCOUNT and OP_ITEM must be set).
    Example env:
      OP_ACCOUNT=my.op.com
      OP_ITEM=mail-imap-pass
      OP_FIELD=password   # optional, defaults to 'password'
    """
    if os.getenv("IMAP_PASS"):
        return os.getenv("IMAP_PASS")
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
            print(f"Failed to load password from 1Password: {e}")
    try:
        return getpass.getpass("IMAP password (will not echo): ")
    except Exception:
        return ""
    return ""


def fetch_headers(imap: imaplib.IMAP4_SSL, uid: str) -> Tuple[str, str]:
    res, data = imap.uid("fetch", uid, "(BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])")
    if res != "OK" or not data or data[0] is None:
        return "", ""
    msg = email.message_from_bytes(data[0][1])
    frm = decode_str(msg.get("From", ""))
    subj = decode_str(msg.get("Subject", ""))
    return frm, subj


def categorize(frm: str, subj: str) -> str:
    """Categorize using shared core rules."""
    return categorize_from_strings(frm, subj)


def ensure_label(imap: imaplib.IMAP4_SSL, label: str, created_cache: set):
    if label in created_cache:
        return
    res, _ = imap.create(label)
    if res in ("OK", "NO"):  # OK created, NO exists
        created_cache.add(label)


def apply_label(imap: imaplib.IMAP4_SSL, uid: str, label: str, gmail_labels: bool):
    if gmail_labels:
        # Gmail-specific extension to add labels without moving.
        imap.uid("STORE", uid, "+X-GM-LABELS", f'"{label}"')
    else:
        # IMAP fallback: copy to folder.
        imap.uid("COPY", uid, f'"{label}"')
    imap.uid("STORE", uid, "+FLAGS", r"(\Seen)")


def main():
    parser = argparse.ArgumentParser(description="IMAP rule applier using LABEL_RULES.")
    parser.add_argument("--mailbox", default="INBOX", help="IMAP mailbox to scan (default INBOX)")
    parser.add_argument("--query", default="ALL", help="IMAP SEARCH criteria (default ALL)")
    parser.add_argument("--limit", type=int, default=200, help="Max messages to process")
    parser.add_argument("--start", type=int, default=0, help="Start offset into UID list (for paging)")
    parser.add_argument("--gmail-labels", action="store_true", help="Use Gmail X-GM-LABELS instead of COPY")
    args = parser.parse_args()

    host = os.getenv("IMAP_HOST", "imap.gmail.com")
    user = os.getenv("IMAP_USER")
    password = load_password()  # allow-secret
    dry_run = os.getenv("DRY_RUN", "1") == "1"

    if not user or not password:
        print("IMAP_USER and IMAP_PASS (or OP_ACCOUNT/OP_ITEM) must be set.")
        return

    imap = connect_imap(host, user, password)
    imap.select(args.mailbox)

    res, data = imap.uid("search", None, args.query)
    if res != "OK":
        print(f"Search failed for query: {args.query}")
        return

    uids: List[str] = data[0].split()
    if not uids:
        print("No messages matched query.")
        return
    # Page through most recent messages, respecting start/limit.
    uids = uids[max(0, len(uids) - args.start - args.limit) : len(uids) - args.start]

    created_cache = set()
    stats = {}

    for uid in uids:
        frm, subj = fetch_headers(imap, uid.decode())
        target = categorize(frm, subj)
        stats[target] = stats.get(target, 0) + 1
        if dry_run:
            continue
        ensure_label(imap, target, created_cache)
        apply_label(imap, uid.decode(), target, gmail_labels=args.gmail_labels)

    imap.logout()
    print(f"Processed {len(uids)} messages (dry_run={dry_run}) from {args.mailbox} query={args.query} start={args.start}")
    for k, v in sorted(stats.items(), key=lambda x: x[1], reverse=True):
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
