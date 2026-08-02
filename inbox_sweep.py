#!/usr/bin/env python3
"""
inbox_sweep.py — Phase-0 inbox triage for Apple Mail (all accounts, no cloud creds).

Why: the claude.ai Gmail MCP connector is read-only and the Gmail-API path needs `op`
(not signed in). Apple Mail holds every account authenticated and is AppleScript-
drivable, so it's the cheapest working apply lane. Reuses the vetted classifier +
protected-sender gate from core.rules and the MailAppProvider primitives.

The coarse Eisenhower tier alone over-flags (treats every Apple receipt / GitHub
usage notice / FICO update as a "fire"). So on top of the tier we apply an
ACTION-vs-NOISE refinement so only genuine action items + real humans + gov/legal
stay surfaced; receipts / marketing / usage-FYI are archived even from big-brand
domains. Three outcomes:

    FIRE    -> flag + keep in inbox (+ goes to the obligations ledger)   [surfaced]
    KEEP    -> leave in inbox untouched (protected, ambiguous)           [safe]
    ARCHIVE -> mark read + move to <noise mailbox>                       [noise out]

DRY RUN by default. --apply to act. Nothing deleted; noise → one reversible mailbox.
Fail-open: a single message error never aborts the sweep. Writes a JSON receipt.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from providers.mailapp import MailAppProvider  # noqa: E402
from core.rules import categorize_with_tier, is_protected_sender  # noqa: E402
from core.protocols import requires_reply_match  # noqa: E402

NOISE_MAILBOX_DEFAULT = "AI-Triaged"

# A genuine, consequential action is required.
ACTION_SIGNALS = re.compile(r"""(?ix)
    default | garnish | wage | unsuccessful | declined | past\s*due | overdue |
    suspend | paused | (problem\s*billing) | (billing\s*problem) | underpayment |
    outstanding | (action\s*required) | (immediate\s*action) | fraud | unauthorized |
    unrecognized | (confirm\s*you) | (did\s*you\s*make) | (verify\s*(your|it|these)) |
    (fsa\s*id) | (was\s*changed) | (prevent\s*wage) | (take\s*action) | (final\s*reminder) |
    (last\s*chance\s*to\s*stay) | constituent | mediat | docusign | (deletion\s*notice) |
    expiring | (expire\s*soon) | disconnected | (security\s*alert) | suspicious | locked |
    (past[-\s]*due) | reinstate | (resign) | compliant | consent\s*form | zoom\s*link |
    (paid\s+membership) | (membership\s+confirmation) | (membership\s+renewal) |
    (auto[-\s]*renew(al)?) | (automatically\s+renew) | (membership\s+fee)
""")

# Receipts / marketing / usage-FYI — archive even from protected big brands (reversible).
NOISE_SIGNALS = re.compile(r"""(?ix)
    receipt | (your\s*order) | ordered | (order\s*\#) | delivered | shipped | tracking |
    (out\s*for\s*delivery) | (review\s*your) | (how\s*was) | (rate\s*your) | feedback |
    survey | fico | loyalty | (\d+%\s*off) | (off\s*your) | \bsale\b | \bdeal\b | newsletter |
    digest | changelog | webinar | (offer\s*inside) | (\$\d+\s*off) | testflight |
    (data\s*is\s*ready) | takeout | (used\s*\d+%) | (scheduled\s*tasks) | (back\s*in\s*stock) |
    (new\s*groups) | celebrate | \bgifts?\b | introducing | (early\s*bird) | promotion |
    (week(ly)?\s*(performance|financial)) | (monthly\s*(account\s*)?statement) | (dive\s*deeper)
""")

ROLE_LOCALPARTS = (
    "noreply",
    "no-reply",
    "donotreply",
    "do-not-reply",
    "notification",
    "notifications",
    "alert",
    "alerts",
    "support",
    "info",
    "hello",
    "team",
    "deals",
    "news",
    "marketing",
    "auto",
    "mailer",
    "updates",
    "account",
    "billing",
    "service",
    "services",
    "member",
    "reply",
    "sales",
    "contact",
    "admin",
    "shop",
    "express",
    "store",
    "order",
    "payments",
    "securityalert",
)

# Brand/dept/ESP tokens — if any appear in the FULL address (local+domain) the sender
# is a role mailbox, not a person (e.g. dxl@reviews.dxl.com, questfeedback@…, invoice+…).
ROLE_TOKENS = ROLE_LOCALPARTS + (
    "reviews",
    "feedback",
    "survey",
    "invoice",
    "statement",
    "medallia",
    "mystore",
    "satisfaction",
    "notify",
    "campaign",
    "questfeedback",
    "customersat",
    "mailchimp",
)

IMPORTANT_DOMAINS = (
    "studentaid.gov",
    ".gov",
    "legalzoom.com",
    "docusign",
    "irs.gov",
    "ssa.gov",
    "court",
    "nysenate",
    "nysenate.gov",
)

# Bulk / newsletter mailboxes. A sender is bulk if its EXACT local-part is a role
# address (welcome@/offers@/referrals@/news@…) OR its domain leads with a bulk-ESP
# subdomain label (mail.notion.so, email.tiktok.com, news.termius.com, e.atlassian.com).
# These are the senders whose human-LOOKING display name ("Ivan at Notion", "Hong Yi
# from Warp", "OpenRouter Team") otherwise tricked looks_human() into firing — the root
# cause of the flagged-newsletter storm. Matched on the EXACT local-part / leading
# domain label (never a raw substring), so a genuine personal address is never swept in.
BULK_LOCALPARTS = frozenset(
    {
        "welcome",
        "offers",
        "offer",
        "referrals",
        "referral",
        "newsletter",
        "newsletters",
        "digest",
        "news",
        "press",
        "hello",
        "hi",
        "hey",
        "team",
        "post",
        "posts",
        "community",
        "growth",
        "product",
        "education",
        "learn",
        "announce",
        "announcements",
        "greetings",
        "connect",
        "social",
        "join",
        "discover",
        "explore",
        "insights",
        "updates",
        "update",
        "notify",
        "notification",
        "notifications",
        "noreply",
        "no-reply",
        "donotreply",
        "do-not-reply",
        "mailer",
        "marketing",
        "deals",
        "promo",
        "promotions",
        "email",
        "members",
        "member",
        "story",
        "stories",
        "info",
    }
)
BULK_SUBDOMAINS = frozenset(
    {
        "mail",
        "email",
        "e",
        "em",
        "news",
        "mktg",
        "marketing",
        "members",
        "member",
        "go",
        "send",
        "click",
        "links",
        "link",
        "updates",
        "newsletter",
        "mailer",
        "info",
        "reply",
        "notify",
        "notifications",
        "message",
        "messaging",
        "campaign",
        "t",
        "cp",
        "engage",
    }
)


def _addr(sender):
    return sender.split("<")[-1].rstrip(">").strip().lower() if "<" in sender else sender.strip().lower()


def looks_human(sender):
    addr = _addr(sender)
    if any(k in addr for k in ROLE_TOKENS):
        return False
    name = sender.split("<")[0].strip().strip('"')
    parts = [p for p in re.split(r"\s+", name) if p]
    brandish = any(
        b in name.lower()
        for b in (
            "via",
            "inc",
            "llc",
            "bank",
            "card",
            "health",
            "pharmacy",
            "deals",
            "store",
            "cinema",
            "finance",
            "co.",
            "labs",
            "group",
            "diagnostics",
            "edison",
            "platform",
            "pbc",
            "big +",
        )
    )
    return len(parts) >= 2 and not name.isupper() and "@" not in name and not brandish


def important_sender(sender):
    addr = _addr(sender)
    return any(d in addr for d in IMPORTANT_DOMAINS)


def is_bulk_sender(sender):
    """True for a role / newsletter mailbox: an EXACT bulk local-part, or a domain
    whose LEADING label is a bulk-ESP subdomain. Exact-match semantics (never a raw
    substring), so 'feross@socket.dev' (real person) is NOT bulk while
    'welcome@openrouter.ai' / 'ivan@mail.notion.so' / 'referrals@warp.dev' are."""
    addr = _addr(sender)
    if "@" not in addr:
        return False
    local, _, domain = addr.partition("@")
    local = local.split("+", 1)[0]
    if local in BULK_LOCALPARTS:
        return True
    labels = domain.split(".")
    return len(labels) >= 3 and labels[0] in BULK_SUBDOMAINS


def decide(sender, subject, tier, protected, label=""):
    """Return 'fire' | 'keep' | 'archive'."""
    text = f"{subject}"
    # "Promotional" = a bulk/newsletter mailbox, a definitively-promotional category the
    # vetted classifier already assigned (Marketing/Entertainment), or a noise subject.
    promotional = is_bulk_sender(sender) or label in ("Marketing", "Entertainment") or bool(NOISE_SIGNALS.search(text))
    # 1. A genuine, consequential action ALWAYS surfaces first — preserves every real
    #    obligation (billing/default/fraud/security/verify/expiry) regardless of sender.
    if ACTION_SIGNALS.search(text):
        return "fire"
    # 2. Government / legal / e-sign senders always surface (high-stakes).
    if important_sender(sender):
        return "fire"
    # 2.5 A requires_reply PROTOCOL outranks the noise router. The sweep is the funnel
    #     for obligations_build — it must never drop mail the protocol registry owns
    #     (a LinkedIn InMail relay rides a Social label and a noreply sender; a recruiter
    #     blast can ride Marketing). Same invariant as derive()'s protocol-beats-bulk
    #     rung, applied one tier earlier. Envelope-only: no snippet exists at sweep time.
    if requires_reply_match(sender, subject, label):
        return "fire"
    # 3. Clearly promotional mail is NEVER a fire — even when a First-Last display name
    #    makes it "look human" ("IBEN Team" <IBEN@ibo.org>, "Ivan at Notion"
    #    <ivan@mail.notion.so>, "Hong Yi from Warp" <referrals@warp.dev>). This is the
    #    ROOT-CAUSE fix for the flagged-newsletter storm (looks_human previously
    #    over-fired on ~every newsletter fronting a human name). A PROTECTED sender is
    #    still shielded from archiving — kept in inbox, never moved.
    if promotional:
        return "keep" if protected else "archive"
    # 4. A real person writing personally surfaces.
    if looks_human(sender):
        return "fire"
    if protected:
        return "keep"  # HARD fail-closed never-archive gate: a protected sender is
        # NEVER archived. Must precede the tier fall-through below.
    if tier <= 2:
        return "keep"
    return "archive"


def classify_inbox(provider, inbox_name, limit, since_days=None):
    # since_days (when set) bounds the fetch to a recent window, newest-first — used by the
    # archived-unanswered scan so a large Archive/All-Mail never full-materializes. Passed
    # through ONLY when set, so providers whose list_messages predates the kwarg are untouched.
    extra = {"since_days": since_days} if since_days is not None else {}
    rows, page_token, fetched = [], None, 0
    while fetched < limit:
        res = provider.list_messages(
            query="", limit=min(limit - fetched, 50), page_token=page_token, mailbox=inbox_name, **extra
        )
        if not res.messages:
            break
        for m in res.messages:
            sender, subject = m.sender or "", m.subject or ""
            protected = is_protected_sender(sender)
            cat = categorize_with_tier(sender, subject)
            row = {
                "id": m.id,
                "sender": sender,
                "subject": subject,
                "is_read": m.is_read,
                "is_flagged": m.is_starred,
                "label": cat.label,
                "tier": cat.tier,
                "protected": protected,
                "action": decide(sender, subject, cat.tier, protected, cat.label),
            }
            # Persist the bulk-signal headers (List-Unsubscribe / List-Id / Precedence …)
            # captured at fetch time so obligations_build can suppress bulk mail from the
            # reply-owed rung end-to-end. Omitted when the provider supplied none (fail-open).
            hdrs = getattr(m, "headers", None)
            if hdrs:
                row["headers"] = dict(hdrs)
                # Reply-To (captured alongside the bulk headers) → a top-level receipt field so
                # obligations_build / draft_writer can prefer it over the raw From (InMail relays
                # and role senders thread back through a distinct reply-* address). Absent → omit.
                reply_to = (hdrs.get("reply-to") or hdrs.get("Reply-To") or "").strip()
                if reply_to:
                    row["reply_to"] = reply_to
            rows.append(row)
        fetched += len(res.messages)
        page_token = res.next_page_token
        if not page_token:
            break
    return rows


def report(account, inbox_name, rows):
    acts = Counter(r["action"] for r in rows)
    print(f"\n=== {account}  (mailbox: {inbox_name})  — {len(rows)} messages ===")
    print(f"  plan : FIRE(flag+keep)={acts['fire']}   KEEP(leave)={acts['keep']}   ARCHIVE→noise={acts['archive']}")
    fires = [r for r in rows if r["action"] == "fire"]
    print(f"\n  --- FIRES → flag + keep in inbox + ledger ({len(fires)}) ---")
    for r in fires:
        print(f"    [{r['label'][:18]:18}] {r['sender'][:34]:34}  {r['subject'][:50]}")
    keep = [r for r in rows if r["action"] == "keep"]
    if keep:
        print(f"\n  --- KEEP (left in inbox, unflagged) ({len(keep)}) ---")
        for r in keep[:15]:
            print(f"    [{r['label'][:14]:14}] {r['sender'][:30]:30} {r['subject'][:42]}")
        if len(keep) > 15:
            print(f"    … +{len(keep) - 15} more")
    noise = [r for r in rows if r["action"] == "archive"]
    print(f"\n  --- ARCHIVE → '{NOISE_MAILBOX_DEFAULT}' ({len(noise)}), sample ---")
    for r in noise[:20]:
        print(f"    [{r['label'][:14]:14}] {r['sender'][:28]:28} {r['subject'][:40]}")
    if len(noise) > 20:
        print(f"    … +{len(noise) - 20} more")


def _osa(script, timeout=900):
    r = subprocess.run(["osascript", "-e", script], capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def _account_is_gmail(account):
    """Gmail accounts expose an 'All Mail' archive mailbox; folder stores don't."""
    _, out, _ = _osa(
        f'''tell application "Mail"
      set acc to account "{account}"
      repeat with mb in (every mailbox of acc)
        if name of mb is "All Mail" then return "yes"
      end repeat
      return "no"
    end tell''',
        timeout=120,
    )
    return out.strip() == "yes"


GMAIL_BATCH = 10  # archive this many per sync cycle
GMAIL_SETTLE = 20  # seconds to let each batch commit server-side


def _flag_fires(account, inbox, fire_ids):
    """Flag fires in one pass. Flagging is a status bit, not a label-move, so Gmail
    respects it immediately and reliably (no revert)."""
    if not fire_ids:
        return 0, 0
    flist = "{" + ", ".join(fire_ids) + "}"
    _, out, _ = _osa(
        f'''tell application "Mail"
      set mb to mailbox "{inbox}" of account "{account}"
      set fc to 0
      set ec to 0
      repeat with anId in {flist}
        try
          set flagged status of (first message of mb whose id is (anId as integer)) to true
          set fc to fc + 1
        on error
          set ec to ec + 1
        end try
      end repeat
      return (fc as string) & "," & (ec as string)
    end tell''',
        timeout=300,
    )
    try:
        fc, ec = (int(x) for x in out.split(","))
    except ValueError:
        fc, ec = 0, 0
    return fc, ec


def _unflag_noise(account, inbox, unflag_ids):
    """Clear the flag on messages the classifier no longer considers fires — the
    residue of the earlier looks_human over-fire (and the dormant labeler's
    Tech/Security auto-stars). Symmetric to _flag_fires: a keyless status-bit toggle
    Gmail respects immediately (no revert). Reversible; the receipt records every id."""
    if not unflag_ids:
        return 0, 0
    ulist = "{" + ", ".join(unflag_ids) + "}"
    _, out, _ = _osa(
        f'''tell application "Mail"
      set mb to mailbox "{inbox}" of account "{account}"
      set uc to 0
      set ec to 0
      repeat with anId in {ulist}
        try
          set flagged status of (first message of mb whose id is (anId as integer)) to false
          set uc to uc + 1
        on error
          set ec to ec + 1
        end try
      end repeat
      return (uc as string) & "," & (ec as string)
    end tell''',
        timeout=300,
    )
    try:
        uc, ec = (int(x) for x in out.split(","))
    except ValueError:
        uc, ec = 0, 0
    return uc, ec


def _list_flagged(account, inbox):
    """Enumerate ONLY the currently-flagged messages in a mailbox via a `whose`
    filter (fast — returns the ~dozens flagged, not the whole inbox), as
    id\\tsender\\tsubject rows. Used by the one-time backlog un-flag so stars deeper
    than the bounded --limit inbox slice are still cleaned."""
    _, out, _ = _osa(
        f'''tell application "Mail"
      set mb to mailbox "{inbox}" of account "{account}"
      set outp to ""
      repeat with m in (messages of mb whose flagged status is true)
        try
          set outp to outp & (id of m as string) & tab & (sender of m) & tab & (subject of m) & linefeed
        end try
      end repeat
      return outp
    end tell''',
        timeout=600,
    )
    rows = []
    for line in out.split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            rows.append({"id": parts[0].strip(), "sender": parts[1], "subject": parts[2]})
    return rows


def _archive_folder(account, inbox, arch_ids, noise_mailbox):
    """Folder store (iCloud/IMAP): a single move out of INBOX archives. Sticks."""
    if not arch_ids:
        return 0, 0
    _osa(
        f'''tell application "Mail"
      try
        set mb to mailbox "{noise_mailbox}" of account "{account}"
      on error
        make new mailbox at end of mailboxes of account "{account}" with properties {{name:"{noise_mailbox}"}}
      end try
    end tell''',
        timeout=60,
    )
    alist = "{" + ", ".join(arch_ids) + "}"
    _, out, _ = _osa(
        f'''tell application "Mail"
      set mb to mailbox "{inbox}" of account "{account}"
      set noiseMb to mailbox "{noise_mailbox}" of account "{account}"
      set mc to 0
      set ec to 0
      repeat with anId in {alist}
        try
          set m to (first message of mb whose id is (anId as integer))
          set read status of m to true
          move m to noiseMb
          set mc to mc + 1
        on error
          set ec to ec + 1
        end try
      end repeat
      return (mc as string) & "," & (ec as string)
    end tell''',
        timeout=900,
    )
    try:
        mc, ec = (int(x) for x in out.split(","))
    except ValueError:
        mc, ec = 0, 0
    return mc, ec


def _archive_gmail(account, inbox, arch_ids):
    """Gmail: mailboxes are LABELS, not folders. A bulk move to a noise mailbox/All Mail
    is optimistically applied locally then REVERTED on the next server sync (the INBOX
    label re-asserts). The reliable gesture is to archive DIRECTLY to 'All Mail' (Gmail's
    archive = drop the INBOX label) in SMALL batches, calling `synchronize` and settling
    after each so every batch commits server-side before the next. Proven to stick where
    the bulk move did not. Reversible: archived mail lives in All Mail and the JSON receipt
    is the exact undo manifest (sender/subject/id of everything moved)."""
    want = {int(i) for i in arch_ids}
    if not want:
        return 0, 0
    script = f'''tell application "Mail"
      set acc to account "{account}"
      set amBox to missing value
      repeat with b in (every mailbox of acc)
        if name of b is "All Mail" then
          set amBox to b
          exit repeat
        end if
      end repeat
      if amBox is missing value then return "0,0"
      set inb to mailbox "{inbox}" of account "{account}"
      set targetIds to {{{", ".join(str(i) for i in want)}}}
      set mc to 0
      set ec to 0
      set iter to 0
      repeat
        set iter to iter + 1
        if iter > 40 then exit repeat
        set inboxIds to (id of every message of inb)
        set todo to {{}}
        repeat with t in targetIds
          if inboxIds contains (t as integer) then set end of todo to (t as integer)
        end repeat
        if (count of todo) is 0 then exit repeat
        set n to 0
        repeat with aid in todo
          if n ≥ {GMAIL_BATCH} then exit repeat
          try
            move (first message of inb whose id is (aid as integer)) to amBox
            set n to n + 1
            set mc to mc + 1
          on error
            set ec to ec + 1
          end try
        end repeat
        synchronize with acc
        delay {GMAIL_SETTLE}
      end repeat
      return (mc as string) & "," & (ec as string)
    end tell'''
    # Generous timeout: up to ~40 sync cycles of GMAIL_SETTLE seconds each.
    _, out, _ = _osa(script, timeout=max(900, 40 * (GMAIL_SETTLE + 5)))
    try:
        mc, ec = (int(x) for x in out.split(","))
    except ValueError:
        mc, ec = 0, 0
    return mc, ec


def apply(account, inbox, rows, noise_mailbox, flag_only_gmail=False):
    """Flag the fires (surface obligations) and archive the noise out of the inbox,
    reversibly. Branches by store type: Gmail (label store) archives directly to All
    Mail in synced small batches that actually stick; iCloud/IMAP (folder store) use a
    single move to the reversible noise mailbox. Fires are flagged in place either way.

    flag_only_gmail: for the autonomic heartbeat — skip the heavy/futile Gmail bulk-archive
    loop (Gmail archive is currently gated on a write door, L-MCP/L-OAUTH/L-IMAP-APP-PW) but
    STILL flag the Gmail fires (reliable status bit) and STILL archive folder stores
    (iCloud/Outlook, reliable). Keeps the beat bounded and fast without ever dead-stopping."""
    fire_ids = [str(r["id"]) for r in rows if r["action"] == "fire" and not r["is_flagged"]]
    arch_ids = [str(r["id"]) for r in rows if r["action"] == "archive"]
    # Symmetric to flagging: a message that is flagged but the classifier now calls
    # noise (archive) gets its flag CLEARED, so the flag pile converges to "flagged
    # ⟺ fire" every beat instead of accreting the over-fire residue. Only 'archive'
    # is unflagged — a flagged 'keep' (protected/ambiguous) is left as the user set it.
    unflag_ids = [str(r["id"]) for r in rows if r["action"] == "archive" and r["is_flagged"]]
    is_gmail = _account_is_gmail(account)

    fc, fe = _flag_fires(account, inbox, fire_ids)
    uc, ue = _unflag_noise(account, inbox, unflag_ids)
    if is_gmail:
        mc, me = (0, 0) if flag_only_gmail else _archive_gmail(account, inbox, arch_ids)
    else:
        mc, me = _archive_folder(account, inbox, arch_ids, noise_mailbox)

    return {
        "flag_requested": len(fire_ids),
        "unflag_requested": len(unflag_ids),
        "archive_requested": len(arch_ids),
        "is_gmail": is_gmail,
        "flag_only_gmail": flag_only_gmail,
        "flagged": fc,
        "unflagged": uc,
        "archived": mc,
        "errors": fe + ue + me,
        "applescript": f"flagged={fc} unflagged={uc} archived={mc} err={fe + ue + me}",
    }


def unflag_backlog_run(account, inbox, do_apply, receipt_path=None):
    """Backlog flag-hygiene pass: enumerate EVERY currently-flagged message in the
    inbox, re-classify with the current rules, and clear the flag on those now judged
    noise (archive). Reaches stars deeper than the bounded --limit inbox slice — the
    accumulated residue of the looks_human over-fire + the dormant Tech/Security
    labeler. Dry-run by default; NOTHING is archived or deleted, only flags cleared
    (fully reversible). Writes a receipt naming every message whose flag it clears."""
    flagged = _list_flagged(account, inbox)
    decided = []
    for r in flagged:
        sender, subject = r["sender"] or "", r["subject"] or ""
        protected = is_protected_sender(sender)
        cat = categorize_with_tier(sender, subject)
        action = decide(sender, subject, cat.tier, protected, cat.label)
        decided.append({**r, "label": cat.label, "tier": cat.tier, "protected": protected, "action": action})
    noise = [d for d in decided if d["action"] == "archive"]
    keep = [d for d in decided if d["action"] != "archive"]
    print(f"\n=== {account}  (mailbox: {inbox})  — {len(decided)} FLAGGED ===")
    print(f"  un-flag (noise) = {len(noise)}   keep flagged (fire/keep) = {len(keep)}")
    print(f"\n  --- WILL UN-FLAG — noise ({len(noise)}) ---")
    for d in noise:
        print(f"    [{d['label'][:16]:16}] {d['sender'][:34]:34} {d['subject'][:44]}")
    print(f"\n  --- KEEP FLAGGED — real fires/keep ({len(keep)}) ---")
    for d in keep:
        print(f"    [{d['label'][:16]:16}] {d['sender'][:34]:34} {d['subject'][:44]}")
    result = {
        "account": account,
        "inbox": inbox,
        "mode": "unflag-apply" if do_apply else "unflag-dry",
        "flagged_total": len(decided),
        "unflag_planned": len(noise),
        "keep": len(keep),
    }
    if do_apply:
        uc, ue = _unflag_noise(account, inbox, [d["id"] for d in noise])
        result.update({"unflagged": uc, "errors": ue})
        print(f"\n  done: un-flagged {uc}, errors {ue}")
    else:
        print("\n  DRY RUN — no flags changed. Re-run with --apply to execute.")
    receipt = receipt_path or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "audit", f"unflag_backlog-{account.replace('@', '_at_')}.json"
    )
    os.makedirs(os.path.dirname(receipt), exist_ok=True)
    with open(receipt, "w") as f:
        json.dump({"result": result, "rows": decided}, f, indent=2)
    print(f"  receipt → {receipt}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Phase-0 Apple Mail inbox sweep (dry run by default).")
    ap.add_argument("--account", required=True)
    ap.add_argument("--limit", type=int, default=2000)
    ap.add_argument("--apply", action="store_true", help="actually flag/move (default: dry run)")
    ap.add_argument(
        "--flag-only-gmail",
        action="store_true",
        help="autonomic mode: flag Gmail fires + archive folder stores, but skip the "
        "heavy/futile Gmail bulk-archive loop (gated on a write door)",
    )
    ap.add_argument(
        "--unflag-noise",
        action="store_true",
        help="backlog flag-hygiene: enumerate all flagged inbox messages and clear the "
        "flag on those the classifier now judges noise (nothing archived/deleted)",
    )
    ap.add_argument("--noise-mailbox", default=NOISE_MAILBOX_DEFAULT)
    ap.add_argument("--receipt", default=None, help="path to write JSON receipt of all decisions")
    ap.add_argument(
        "--since-days",
        type=int,
        default=None,
        help="bound the enumeration to messages received in the last N days. WITHOUT "
        "this, Mail.app materializes a scripting object for EVERY message in the "
        "mailbox before --limit slices anything, which hangs its main thread. "
        "0 or unset = unbounded (the historical behaviour).",
    )
    args = ap.parse_args(argv)

    provider = MailAppProvider(account=args.account)
    provider.connect()
    inbox = pick_inbox_name(provider)
    if args.unflag_noise:
        return unflag_backlog_run(args.account, inbox, args.apply, args.receipt)
    # `--limit` bounds the Python slice, never Mail.app's work: the unbounded selector materializes
    # every message in the mailbox BEFORE anything is sliced. Only `since_days` reaches the
    # AppleScript `whose` predicate, which is what actually bounds what Mail builds.
    rows = classify_inbox(provider, inbox, args.limit, since_days=args.since_days or None)
    report(args.account, inbox, rows)

    result = {"account": args.account, "inbox": inbox, "total": len(rows), "mode": "apply" if args.apply else "dry_run"}
    if args.apply:
        n = sum(1 for r in rows if r["action"] == "archive")
        mode = "flag-only-gmail" if args.flag_only_gmail else "full"
        print(f"\n  APPLYING [{mode}] (flag fires; move {n} noise → '{args.noise_mailbox}')…")
        result.update(apply(args.account, inbox, rows, args.noise_mailbox, flag_only_gmail=args.flag_only_gmail))
        print(f"  done: {result}")
    else:
        print("\n  DRY RUN — no changes. Re-run with --apply to execute.")

    receipt = args.receipt or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "audit", f"inbox_sweep-{args.account.replace('@', '_at_')}.json"
    )
    os.makedirs(os.path.dirname(receipt), exist_ok=True)
    with open(receipt, "w") as f:
        json.dump({"result": result, "rows": rows}, f, indent=2)
    print(f"  receipt → {receipt}")
    return 0


def pick_inbox_name(provider):
    try:
        boxes = provider.get_mailboxes()
    except Exception:
        boxes = []
    for cand in ("INBOX", "Inbox"):
        if cand in boxes:
            return cand
    for b in boxes:
        if "inbox" in b.lower():
            return b
    return "INBOX"


if __name__ == "__main__":
    raise SystemExit(main())
