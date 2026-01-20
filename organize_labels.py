"""
Organize Gmail labels by renaming related folders into a consistent hierarchy.

Usage:
  source .venv/bin/activate && python organize_labels.py
"""

import time
from typing import Dict

from googleapiclient.errors import HttpError

import gmail_auth

RENAMES: Dict[str, str] = {
    "Dev/GitHub": "Work/Dev/GitHub",
    "Dev/Code-Review": "Work/Dev/Code-Review",
    "Dev/Infrastructure": "Work/Dev/Infrastructure",
    "Security/1Password": "Tech/Security/1Password",
    "Security/Codes": "Tech/Security/Codes",
    "Newsletters/CodePen": "Marketing/Newsletter/CodePen",
    "Newsletters/Press": "Marketing/Newsletter/Press",
    "Promotions/OnePay": "Finance/Payments/OnePay",
    "Promotions/Sezzle": "Finance/Payments/Sezzle",
}


def get_service():
    return gmail_auth.build_gmail_service()


def main():
    svc = get_service()
    labels = svc.users().labels().list(userId="me").execute().get("labels", [])
    name_to_meta = {l["name"]: l for l in labels}

    for old, new in RENAMES.items():
        meta = name_to_meta.get(old)
        if not meta:
            print(f"[skip] missing label: {old}")
            continue
        if meta.get("type") != "user":
            print(f"[skip] system label: {old}")
            continue
        if old == new:
            print(f"[ok] no change needed: {old}")
            continue

        target = name_to_meta.get(new)
        if target and target["id"] != meta["id"]:
            print(f"[conflict] target exists with different id: {new}; skipping rename of {old}")
            continue

        body = {
            "name": new,
            "labelListVisibility": meta.get("labelListVisibility", "labelShow"),
            "messageListVisibility": meta.get("messageListVisibility", "show"),
        }

        try:
            svc.users().labels().update(userId="me", id=meta["id"], body=body).execute()
            print(f"[renamed] {old} -> {new}")
            name_to_meta[new] = meta
        except HttpError as e:
            print(f"[error] {old} -> {new}: {e}")
        time.sleep(0.2)

    print("Done. Review labels in Gmail/IMAP clients and rebuild/refresh folders if needed.")


if __name__ == "__main__":
    main()
