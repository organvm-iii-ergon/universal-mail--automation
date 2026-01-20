"""
Configure Apple Mail smart mailboxes for priority/triage views.

This edits ~/Library/Mail/V10/MailData/SyncedSmartMailboxes.plist.
It preserves existing entries and adds/updates a small set keyed by MailboxName.

Run:
    source .venv/bin/activate && python configure_smart_mailboxes.py
"""

import plistlib
import shutil
import uuid
from pathlib import Path

PLIST_PATH = Path("~/Library/Mail/V10/MailData/SyncedSmartMailboxes.plist").expanduser()
BACKUP_PATH = PLIST_PATH.with_suffix(".backup")

# Smart mailbox definitions keyed by MailboxName.
SMART_DEFS = {
    # Flagged mail (Gmail STARRED) and key work/finance/security labels.
    "PRIORITY": [
        {"Header": "Flag", "Qualifier": "IsEqualTo", "Expression": "MessageIsFlagged"},
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Work/Dev"},
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Tech/Security"},
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Finance/Payments"},
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Finance/Banking"},
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Awaiting Reply"},
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Personal"},
    ],
    # Personal mail by address.
    "PERSONAL": [
        {"Header": "From", "Qualifier": "ContainsString", "Expression": "padavano"},
    ],
    # Finance buckets.
    "RECEIPTS & BILLS": [
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Finance/Payments"},
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Finance/Banking"},
    ],
    # Misc catch-all triage.
    "MISC/OTHER (TRIAGE)": [
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Misc/Other"},
    ],
    # Waiting on replies.
    "AWAITING REPLY": [
        {"Header": "Mailbox", "Qualifier": "ContainsString", "Expression": "Awaiting Reply"},
    ],
}


def new_id() -> str:
    return str(uuid.uuid4()).upper()


def make_criterion(header: str, qualifier: str = None, expression: str = None, special: int = None):
    crit = {"CriterionUniqueId": new_id(), "Header": header}
    if qualifier:
        crit["Qualifier"] = qualifier
    if expression is not None:
        crit["Expression"] = expression
    if special is not None:
        crit["SpecialMailboxType"] = special
    return crit


def make_smart_mailbox(name: str, user_criteria: list):
    # Base filters: omit trash, omit sent, omit junk.
    criteria = [
        make_criterion("NotInTrashMailbox"),
        make_criterion("NotInASpecialMailbox", special=3),
        {
            "CriterionUniqueId": new_id(),
            "Header": "Compound",
            "Name": "user criteria",
            "AllCriteriaMustBeSatisfied": False,  # treat criteria as OR list
            "Criteria": user_criteria,
        },
        make_criterion("NotInJunkMailbox"),
    ]

    return {
        "IMAPMailboxAttributes": 17,
        "MailboxAllCriteriaMustBeSatisfied": True,
        "MailboxChildren": [],
        "MailboxCriteria": criteria,
        "MailboxID": new_id(),
        "MailboxName": name,
        "MailboxType": 7,
    }


def main():
    if not PLIST_PATH.exists():
        raise SystemExit(f"Smart mailbox plist not found: {PLIST_PATH}")

    # Backup first.
    shutil.copy2(PLIST_PATH, BACKUP_PATH)

    with PLIST_PATH.open("rb") as fh:
        data = plistlib.load(fh)

    if not isinstance(data, list):
        raise SystemExit(f"Unexpected plist format in {PLIST_PATH}")

    # Index existing by MailboxName for replacement.
    by_name = {entry.get("MailboxName"): entry for entry in data if isinstance(entry, dict)}

    for name, crits in SMART_DEFS.items():
        entry = make_smart_mailbox(name, crits)
        by_name[name] = entry

    # Preserve order: existing (minus replaced) then new/replaced in definition order.
    new_list = [entry for entry in data if entry.get("MailboxName") not in SMART_DEFS]
    for name in SMART_DEFS:
        new_list.append(by_name[name])

    with PLIST_PATH.open("wb") as fh:
        plistlib.dump(new_list, fh)

    print(f"Updated smart mailboxes in {PLIST_PATH}")
    print(f"Backup saved at {BACKUP_PATH}")
    print("Restart Mail or toggle accounts to refresh smart mailboxes.")


if __name__ == "__main__":
    main()
