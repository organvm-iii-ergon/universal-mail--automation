#!/usr/bin/env python3
"""
Unified CLI for multi-provider email automation.

Usage:
    python cli.py label --provider gmail --query "has:nouserlabels"
    python cli.py label --provider imap --host imap.gmail.com
    python cli.py label --provider mailapp
    python cli.py label --provider outlook
    python cli.py report --provider gmail

Environment:
    See CLAUDE.md for required environment variables per provider.
"""

import argparse
import dataclasses
import logging
import json
import os
import secrets
import sys
import time
from pathlib import Path
from typing import Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.audit import AuditLog

from core.rules import (
    LABEL_RULES,
    categorize_with_tier,
    should_star,
    should_keep_in_inbox,
    is_vip_sender,
    is_protected_sender,
    escalate_by_age,
    calculate_email_age_hours,
    get_tier_config,
)
from core import __version__
from core.state import StateManager
from core.models import EmailMessage, LabelAction, ProcessingResult, FlagColor
from core.config import load_config, apply_vip_senders_from_config
from providers.base import EmailProvider, ProviderCapabilities


def _positive_int_arg(value: str) -> int:
    """Argparse type for bounds that must never produce empty/future scans."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"expected a positive integer, got {value!r}"
        ) from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError(
            f"expected a positive integer, got {value!r}"
        )
    return parsed


def _first_canary_limit_arg(value: str) -> int:
    """Argparse type for the permanently bounded first activation path."""
    parsed = _positive_int_arg(value)
    if parsed > 3:
        raise argparse.ArgumentTypeError(
            f"first activation canary limit must be within [1,3], got {value!r}"
        )
    return parsed


def _nonempty_arg(value: str) -> str:
    """Argparse type for scope components that must identify a real value."""
    if not value.strip():
        raise argparse.ArgumentTypeError("expected a non-empty value")
    return value


def _require_flags_mailbox(args: argparse.Namespace, command: str) -> bool:
    """Defense-in-depth for direct handler calls that bypass argparse."""
    mailbox = getattr(args, "mailbox", None)
    if not isinstance(mailbox, str) or not mailbox.strip():
        print(f"flags {command}: --mailbox must be non-empty", file=sys.stderr)
        return False
    return True

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)


def _record_dry_run_intent(
    provider: EmailProvider,
    actions: list[LabelAction],
    audit: "AuditLog",
) -> None:
    """Record the disposition that would be attempted in a dry-run preview.

    Live receipts stay post-hoc witnesses recorded by provider.apply_actions().
    In dry-run, no provider operation executes, so the preview records the
    intended, gate-respecting disposition and the audit entry is tagged
    ``dry_run=True``.
    """
    is_folder = bool(provider.capabilities & ProviderCapabilities.FOLDERS)
    label_is_move = bool(getattr(provider, "LABEL_IS_MOVE", False))

    for action in actions:
        protected = is_protected_sender(action.sender)
        labels_added = [] if protected and label_is_move else list(action.add_labels)
        would_leave_inbox = bool(action.archive) or any(
            label.upper() in ("INBOX", "\\INBOX") for label in action.remove_labels
        )
        would_label_move = bool(labels_added) and label_is_move

        audit.record(
            message_id=action.message_id,
            sender=action.sender,
            protected=protected,
            archived=(not protected and not is_folder and would_leave_inbox),
            moved=(
                not protected
                and is_folder
                and (would_leave_inbox or would_label_move or bool(action.target_folder))
            ),
            labels_added=labels_added,
        )


def get_provider(
    provider_name: str,
    host: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,  # allow-secret
    account: Optional[str] = None,
    use_gmail_extensions: bool = False,
) -> EmailProvider:
    """
    Factory function to create the appropriate provider.

    Args:
        provider_name: One of 'gmail', 'imap', 'mailapp', 'outlook'
        host: IMAP host (for imap provider)
        user: IMAP username (for imap provider)
        password: IMAP password (for imap provider)  # allow-secret
        account: Mail.app account name (for mailapp provider)
        use_gmail_extensions: Use Gmail IMAP extensions (for imap provider)

    Returns:
        Configured EmailProvider instance
    """
    if provider_name == "gmail":
        from providers.gmail import GmailProvider
        return GmailProvider()

    elif provider_name == "imap":
        from providers.imap import IMAPProvider
        return IMAPProvider(
            host=host,
            user=user,
            password=password,  # allow-secret
            use_gmail_extensions=use_gmail_extensions,
        )

    elif provider_name == "mailapp":
        from providers.mailapp import MailAppProvider
        return MailAppProvider(account=account)

    elif provider_name == "outlook":
        from providers.outlook import OutlookProvider
        return OutlookProvider()

    else:
        raise ValueError(f"Unknown provider: {provider_name}")


def _load_message_details(
    provider: EmailProvider,
    messages: list[EmailMessage],
) -> Dict[str, EmailMessage]:
    """Fetch message details while excluding provider-level misses."""
    message_ids = [message.id for message in messages]
    if hasattr(provider, "batch_get_details"):
        return {
            message_id: detail
            for message_id, detail in provider.batch_get_details(
                message_ids
            ).items()
            if detail is not None
        }
    details: Dict[str, EmailMessage] = {}
    for message in messages:
        detail = provider.get_message_details(message.id)
        if detail is not None:
            details[message.id] = detail
    return details


def run_labeler(
    provider: EmailProvider,
    query: str,
    limit: int,
    dry_run: bool,
    remove_label: Optional[str],
    state_file: Optional[str],
    tier_routing: bool = False,
    vip_only: bool = False,
    audit: Optional["AuditLog"] = None,
) -> ProcessingResult:
    """
    Run the labeling process on the given provider.

    Args:
        provider: Connected email provider
        query: Provider-specific query string
        limit: Max messages to process per run
        dry_run: If True, don't actually apply changes
        remove_label: Label to remove if a new category is found
        state_file: Path to state file for resumption
        tier_routing: If True, apply Eisenhower tier-based routing (categories + folders)
        vip_only: If True, only process emails from VIP senders

    Returns:
        ProcessingResult with statistics
    """
    has_categories = provider.capabilities & ProviderCapabilities.CATEGORIES
    can_star = bool(provider.capabilities & ProviderCapabilities.STAR)
    vip_count = 0
    non_vip_skipped = 0
    protected_count = 0  # trust receipt: protected senders skipped (never archived)
    result = ProcessingResult()
    state = StateManager(state_file) if state_file else None
    page_token = state.get_token() if state else None
    total_processed = state.get_total() if state else 0
    stats = state.get_history() if state else {}

    logger.info(f"Starting labeler with query: {query}")
    logger.info(f"Dry run: {dry_run}, Limit: {limit}")

    processed_this_run = 0
    start_time = time.time()

    try:
        while processed_this_run < limit:
            # List messages
            batch_limit = min(limit - processed_this_run, 100)
            list_result = provider.list_messages(
                query=query,
                limit=batch_limit,
                page_token=page_token,
            )

            if not list_result.messages:
                logger.info("No more messages found matching query.")
                break

            # Get message details
            details = _load_message_details(
                provider, list_result.messages
            )

            # Categorize and prepare actions
            actions = []
            for msg_id, msg in details.items():
                if not msg:
                    continue

                # PROTECTED-SENDER GATE (decision-layer short-circuit, mirrors
                # icloud_triage.py): a protected sender is dropped from the action
                # set entirely, so it never even gets archive=True. Defense in depth
                # — the provider chokepoint (apply_actions) enforces it again.
                if is_protected_sender(msg.sender):
                    protected_count += 1
                    # Record the held-in-inbox decision HERE — this is the first
                    # (decision-layer) place protection fires, before any action is
                    # built, so the receipt's protected_held count is complete and
                    # not just whatever happened to reach the provider chokepoint.
                    if audit is not None:
                        audit.record(
                            message_id=msg_id,
                            sender=msg.sender,
                            protected=True,
                        )
                    continue

                # VIP-only mode: skip non-VIP senders
                if vip_only and not is_vip_sender(msg.sender):
                    non_vip_skipped += 1
                    continue

                # Categorize with tier information
                cat_result = categorize_with_tier(msg.sender, msg.subject)

                if cat_result.is_vip:
                    vip_count += 1
                label = cat_result.label
                stats[label] = stats.get(label, 0) + 1
                result.add_label_stat(label)

                # Build action — carry the sender so the provider chokepoint can
                # re-verify the protected gate before any archive/move.
                action = LabelAction(message_id=msg_id, sender=msg.sender)
                action.add_labels.append(label)

                if tier_routing:
                    # Apply tier-based routing
                    tier_config = cat_result.tier_config

                    # Set category (for providers that support it)
                    if has_categories:
                        action.category = tier_config.name
                        action.category_color = tier_config.color

                    # Set target folder for tier routing
                    if tier_config.folder:
                        action.target_folder = tier_config.folder

                    # Star based on tier config
                    if tier_config.star and can_star:
                        action.star = True

                    # Archive based on tier config
                    if not tier_config.keep_in_inbox:
                        action.archive = True
                else:
                    # Legacy behavior
                    if should_star(label) and can_star:
                        action.star = True

                    if not should_keep_in_inbox(label):
                        action.archive = True

                if remove_label and label != remove_label:
                    action.remove_labels.append(remove_label)

                actions.append(action)
                tier_info = f" [Tier {cat_result.tier}]" if tier_routing else ""
                vip_info = f" [VIP: {cat_result.vip_note}]" if cat_result.is_vip else ""
                logger.debug(f"Message {msg_id}: {msg.sender[:30]}... -> {label}{tier_info}{vip_info}")

            # Apply actions
            if actions and not dry_run:
                batch_result = provider.apply_actions(actions, audit=audit)
                result.success_count += batch_result.success_count
                result.error_count += batch_result.error_count
                result.errors.extend(batch_result.errors)
            else:
                if actions and dry_run and audit is not None:
                    _record_dry_run_intent(provider, actions, audit)
                result.success_count += len(actions)

            processed_this_run += len(actions)
            result.processed_count += len(actions)
            total_processed += len(actions)

            # Update state
            page_token = list_result.next_page_token
            if state:
                state.save(page_token, total_processed, stats, provider=provider.name)

            # Log progress
            elapsed = time.time() - start_time
            rate = processed_this_run / elapsed if elapsed > 0 else 0
            logger.info(
                f"Processed {len(actions)} messages. "
                f"Total: {processed_this_run}/{limit} (Rate: {rate:.1f} msg/s)"
            )

            # Throttle
            time.sleep(1.0)

            if not page_token:
                break

    except KeyboardInterrupt:
        logger.warning("Interrupted by user. Saving state...")
        if state:
            state.save(page_token, total_processed, stats, provider=provider.name)
    except Exception as e:
        logger.error(f"Error during processing: {e}", exc_info=True)
        if state:
            state.save(page_token, total_processed, stats, provider=provider.name)
        raise

    result.label_counts = stats
    logger.info(
        f"Protected senders skipped (never archived): {protected_count}"
        + (f" | VIP: {vip_count}" if vip_count else "")
        + (f" | non-VIP skipped: {non_vip_skipped}" if non_vip_skipped else "")
    )
    return result


def print_stats(result: ProcessingResult) -> None:
    """Print processing statistics."""
    print("\n" + "=" * 50)
    print("PROCESSING STATISTICS")
    print("=" * 50)
    print(f"Total Processed: {result.processed_count}")
    print(f"Successful: {result.success_count}")
    print(f"Errors: {result.error_count}")
    print("\nLabel Distribution:")
    sorted_stats = sorted(result.label_counts.items(), key=lambda x: x[1], reverse=True)
    for label, count in sorted_stats:
        if count > 0:
            print(f"  {label:<30}: {count}")
    if result.errors:
        print(f"\nErrors ({len(result.errors)}):")
        for err in result.errors[:10]:
            print(f"  - {err}")
        if len(result.errors) > 10:
            print(f"  ... and {len(result.errors) - 10} more")
    print("=" * 50 + "\n")


def _make_audit(args: argparse.Namespace, kind: str) -> "Optional[AuditLog]":
    """Build the trust receipt for an apply run, or None when disabled / dry-run.

    ``kind`` selects the default filename (``audit/<provider>-<kind>.jsonl``). When
    senders are recorded un-redacted, warn about the PII — and warn harder when the
    chosen path is OUTSIDE the gitignored ``audit/`` directory, since that file is
    not auto-ignored and the repo's history has held real addresses before.
    """
    if getattr(args, "no_audit", False) or getattr(args, "dry_run", False):
        return None
    from core.audit import AuditLog

    default_path = f"audit/{args.provider}-{kind}.jsonl"
    audit_path = getattr(args, "audit_file", None) or default_path
    redact = getattr(args, "redact_audit", False)

    if not redact:
        norm = os.path.normpath(audit_path)
        in_audit_dir = norm == "audit" or norm.startswith("audit" + os.sep)
        if in_audit_dir:
            logger.warning(
                "Triage receipt %s will contain REAL sender addresses (PII). The "
                "audit/ directory is gitignored — do not commit it, or pass "
                "--redact-audit for a shareable domain-only receipt.", audit_path,
            )
        else:
            logger.warning(
                "Triage receipt %s is OUTSIDE the gitignored audit/ directory and "
                "will contain REAL sender addresses (PII). It is NOT auto-ignored by "
                "git — add it to .gitignore or pass --redact-audit before committing.",
                audit_path,
            )
    return AuditLog(path=audit_path, provider=args.provider, redact=redact)


def _report_audit(audit: "Optional[AuditLog]") -> bool:
    """Print the receipt line + path; return True if the invariant was violated.

    Also surfaces a degraded write (disk-full / unwritable path): the invariant is
    still checked in memory, but the caller is told no file was persisted.
    """
    if audit is None:
        return False
    print(audit.receipt_line())
    if audit.write_error:
        print(
            f"⚠ Audit receipt could NOT be written to {audit.path} "
            f"({audit.write_error}); invariant was still checked in-memory."
        )
    else:
        print(f"Audit receipt appended to: {audit.path}")
    if audit.summary()["violations"]:
        # The gate and its independent audit disagree — treat the run as
        # untrustworthy. This should be unreachable; surfacing it is the point.
        logger.critical(
            "PROTECTED-SENDER GATE VIOLATION — a protected message was archived/moved. "
            "Review the receipt immediately."
        )
        return True
    return False


def cmd_label(args: argparse.Namespace) -> int:
    """Handle the 'label' subcommand."""
    # Load config and apply VIP senders
    config = load_config()
    apply_vip_senders_from_config(config)

    provider = get_provider(
        args.provider,
        host=args.host,
        user=args.user,
        password=args.password,  # allow-secret
        account=args.account,
        use_gmail_extensions=args.gmail_extensions,
    )

    # Trust receipt: on an APPLY run, record every post-gate disposition to an
    # append-only JSONL so the protected-sender guarantee is provable, not implicit.
    # Dry-run previews via print_stats below and writes no receipt.
    audit = _make_audit(args, kind="triage")

    with provider:
        result = run_labeler(
            provider=provider,
            query=args.query,
            limit=args.limit,
            dry_run=args.dry_run,
            remove_label=args.remove_label,
            state_file=args.state_file,
            tier_routing=args.tier_routing,
            vip_only=args.vip_only,
            audit=audit,
        )

    print_stats(result)

    violation = _report_audit(audit)
    if getattr(args, "intake_json", False):
        from core.intake import build_triage_intake_packet

        audit_payload = audit.summary() if audit is not None else {
            "total": 0,
            "protected_held": 0,
            "archived": 0,
            "moved": 0,
            "labeled": 0,
            "kept": 0,
            "violations": [],
        }
        packet = build_triage_intake_packet(
            surface="cli-label",
            run_id=f"cli_{secrets.token_hex(8)}",
            provider=args.provider,
            dry_run=args.dry_run,
            query=args.query,
            limit=args.limit,
            result={
                "dry_run": args.dry_run,
                "provider": args.provider,
                "receipt": audit.receipt_line() if audit is not None else "",
                "audit": audit_payload,
                "processed": dataclasses.asdict(result),
            },
            actor={"type": "cli", "command": "label"},
            auth={"mode": "tool"},
            extra={
                "state_file": args.state_file,
                "remove_label": args.remove_label,
                "redact_audit": bool(getattr(args, "redact_audit", False)),
            },
        )
        print(json.dumps(packet))

    if violation:
        return 2
    return 0 if result.error_count == 0 else 1


def cmd_report(args: argparse.Namespace) -> int:
    """Handle the 'report' subcommand."""
    provider = get_provider(
        args.provider,
        host=args.host,
        user=args.user,
        password=args.password,  # allow-secret
        account=args.account,
        use_gmail_extensions=args.gmail_extensions,
    )

    print(f"# Email Report - {provider.name}")
    print(f"Capabilities: {provider.capabilities}")
    print()

    with provider:
        # Count messages in each label
        print("## Label Counts")
        for label in sorted(LABEL_RULES.keys()):
            try:
                count: int | str
                if args.provider == "gmail":
                    result = provider.list_messages(f"label:{label}", limit=1)
                    count = result.total_estimate or 0
                else:
                    count = "N/A"
                print(f"- {label}: {count}")
            except Exception as e:
                print(f"- {label}: Error ({e})")

    return 0


def cmd_health(args: argparse.Namespace) -> int:
    """Handle the 'health' subcommand."""
    provider = get_provider(
        args.provider,
        host=args.host,
        user=args.user,
        password=args.password,  # allow-secret
        account=args.account,
        use_gmail_extensions=args.gmail_extensions,
    )

    print(f"Checking {provider.name} health...")
    try:
        provider.connect()
        healthy, message = provider.health_check()
        provider.disconnect()

        if healthy:
            print(f"✓ {provider.name}: {message}")
            return 0
        else:
            print(f"✗ {provider.name}: {message}")
            return 1
    except Exception as e:
        print(f"✗ {provider.name}: Connection failed - {e}")
        return 1


def cmd_summary(args: argparse.Namespace) -> int:
    """Handle the 'summary' subcommand - email summary by tier."""
    # Load config and apply VIP senders
    config = load_config()
    apply_vip_senders_from_config(config)

    provider = get_provider(
        args.provider,
        host=args.host,
        user=args.user,
        password=args.password,  # allow-secret
        account=args.account,
        use_gmail_extensions=args.gmail_extensions,
    )

    tier_counts = {1: 0, 2: 0, 3: 0, 4: 0}
    vip_count = 0
    time_sensitive_count = 0
    total = 0

    logger.info(f"Generating summary (provider: {provider.name})")

    with provider:
        list_result = provider.list_messages(
            query=args.query,
            limit=args.limit,
        )

        if not list_result.messages:
            print("No messages found.")
            return 0

        details = _load_message_details(provider, list_result.messages)

        for msg_id, msg in details.items():
            if not msg:
                continue

            total += 1
            cat_result = categorize_with_tier(msg.sender, msg.subject)
            tier_counts[cat_result.tier] = tier_counts.get(cat_result.tier, 0) + 1

            if cat_result.is_vip:
                vip_count += 1
            if cat_result.time_sensitive:
                time_sensitive_count += 1

    # Output based on format
    if args.format == "json":
        import json
        output = {
            "provider": provider.name,
            "total": total,
            "tiers": {
                str(tier): {"name": get_tier_config(tier).name, "count": count}
                for tier, count in tier_counts.items()
            },
            "vip_count": vip_count,
            "time_sensitive_count": time_sensitive_count,
        }
        print(json.dumps(output, indent=2))
    elif args.format == "markdown":
        print(f"# Email Summary - {provider.name}")
        print()
        print(f"**Total Messages:** {total}")
        print()
        print("## By Priority Tier")
        print()
        print("| Tier | Name | Count | % |")
        print("|------|------|-------|---|")
        for tier, count in sorted(tier_counts.items()):
            tier_cfg = get_tier_config(tier)
            pct = (count / total * 100) if total > 0 else 0
            print(f"| {tier} | {tier_cfg.name} | {count} | {pct:.1f}% |")
        print()
        print(f"**VIP Messages:** {vip_count}")
        print(f"**Time-Sensitive:** {time_sensitive_count}")
    else:
        # Default table format
        print("\n" + "=" * 50)
        print(f"EMAIL SUMMARY - {provider.name.upper()}")
        print("=" * 50)
        print(f"Total Messages: {total}")
        print()
        print("By Priority Tier:")
        for tier, count in sorted(tier_counts.items()):
            tier_cfg = get_tier_config(tier)
            pct = (count / total * 100) if total > 0 else 0
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            print(f"  Tier {tier} ({tier_cfg.name:10}): {count:5} {bar} {pct:5.1f}%")
        print()
        print(f"VIP Messages:      {vip_count}")
        print(f"Time-Sensitive:    {time_sensitive_count}")
        print("=" * 50 + "\n")

    return 0


def cmd_pending(args: argparse.Namespace) -> int:
    """Handle the 'pending' subcommand - list flagged/due items."""
    provider = get_provider(
        args.provider,
        host=args.host,
        user=args.user,
        password=args.password,  # allow-secret
        account=args.account,
        use_gmail_extensions=args.gmail_extensions,
    )

    logger.info(f"Listing pending items (provider: {provider.name})")

    pending_items = []

    with provider:
        # Query for flagged/starred items
        if args.provider == "gmail":
            query = "is:starred"
        elif args.provider == "outlook":
            query = "isRead eq false"  # Or flagStatus eq 'flagged' if supported
        else:
            query = ""

        list_result = provider.list_messages(
            query=query,
            limit=args.limit,
        )

        if not list_result.messages:
            print("No pending items found.")
            return 0

        details = _load_message_details(provider, list_result.messages)

        for msg_id, msg in details.items():
            if not msg:
                continue

            if msg.is_starred:
                cat_result = categorize_with_tier(msg.sender, msg.subject)
                age_hours = calculate_email_age_hours(msg.date)
                pending_items.append({
                    "id": msg_id,
                    "sender": msg.sender[:50],
                    "subject": msg.subject[:50],
                    "tier": cat_result.tier,
                    "tier_name": cat_result.tier_config.name,
                    "is_vip": cat_result.is_vip,
                    "age_hours": age_hours,
                    "date": msg.date,
                })

    # Sort by tier (ascending) then age (descending)
    pending_items.sort(key=lambda x: (x["tier"], -x["age_hours"]))

    # Output
    if args.format == "json":
        import json
        print(json.dumps(pending_items, indent=2, default=str))
    elif args.format == "markdown":
        print(f"# Pending Items - {provider.name}")
        print()
        print(f"**Total Pending:** {len(pending_items)}")
        print()
        print("| Tier | Sender | Subject | Age |")
        print("|------|--------|---------|-----|")
        for item in pending_items:
            age_str = f"{item['age_hours']:.0f}h"
            vip = "⭐ " if item["is_vip"] else ""
            print(f"| {item['tier']} | {vip}{item['sender'][:30]} | {item['subject'][:30]} | {age_str} |")
    else:
        print("\n" + "=" * 70)
        print(f"PENDING ITEMS - {provider.name.upper()}")
        print("=" * 70)
        print(f"Total: {len(pending_items)}")
        print()
        for item in pending_items:
            age_str = f"{item['age_hours']:.0f}h old"
            vip = "[VIP] " if item["is_vip"] else ""
            print(f"[Tier {item['tier']}] {vip}{item['sender'][:40]}")
            print(f"         Subject: {item['subject'][:50]}")
            print(f"         Age: {age_str}")
            print()
        print("=" * 70 + "\n")

    return 0


def cmd_vip(args: argparse.Namespace) -> int:
    """Handle the 'vip' subcommand - show VIP sender activity."""
    # Load config and apply VIP senders
    config = load_config()
    apply_vip_senders_from_config(config)

    from core.rules import get_vip_senders

    vip_senders = get_vip_senders()

    if not vip_senders:
        print("No VIP senders configured.")
        print("Add VIP senders to ~/.config/mail_automation/config.yaml")
        return 0

    provider = get_provider(
        args.provider,
        host=args.host,
        user=args.user,
        password=args.password,  # allow-secret
        account=args.account,
        use_gmail_extensions=args.gmail_extensions,
    )

    vip_activity = {key: {"config": vip, "messages": []} for key, vip in vip_senders.items()}

    logger.info(f"Checking VIP activity (provider: {provider.name})")

    with provider:
        list_result = provider.list_messages(
            query=args.query,
            limit=args.limit,
        )

        if list_result.messages:
            details = _load_message_details(
                provider, list_result.messages
            )

            for msg_id, msg in details.items():
                if not msg:
                    continue

                cat_result = categorize_with_tier(msg.sender, msg.subject)
                if cat_result.is_vip:
                    # Find which VIP matched
                    for key, vip in vip_senders.items():
                        import re
                        if re.search(vip.pattern, msg.sender, re.IGNORECASE):
                            vip_activity[key]["messages"].append({
                                "sender": msg.sender[:50],
                                "subject": msg.subject[:50],
                                "date": msg.date,
                                "is_read": msg.is_read,
                            })
                            break

    # Output
    if args.format == "json":
        import json
        output = {}
        for key, data in vip_activity.items():
            output[key] = {
                "note": data["config"].note,
                "tier": data["config"].tier,
                "message_count": len(data["messages"]),
                "messages": data["messages"],
            }
        print(json.dumps(output, indent=2, default=str))
    elif args.format == "markdown":
        print(f"# VIP Sender Activity - {provider.name}")
        print()
        for key, data in vip_activity.items():
            vip = data["config"]
            msgs = data["messages"]
            print(f"## {vip.note or key} (Tier {vip.tier})")
            print(f"Pattern: `{vip.pattern}`")
            print(f"Messages: {len(msgs)}")
            print()
            if msgs:
                print("| Date | Sender | Subject |")
                print("|------|--------|---------|")
                for m in msgs[:10]:
                    print(f"| {m['date']} | {m['sender'][:25]} | {m['subject'][:30]} |")
            print()
    else:
        print("\n" + "=" * 70)
        print(f"VIP SENDER ACTIVITY - {provider.name.upper()}")
        print("=" * 70)
        print(f"Configured VIPs: {len(vip_senders)}")
        print()
        for key, data in vip_activity.items():
            vip = data["config"]
            msgs = data["messages"]
            print(f"▶ {vip.note or key}")
            print(f"  Pattern: {vip.pattern}")
            print(f"  Tier: {vip.tier}, Star: {vip.star}")
            print(f"  Messages found: {len(msgs)}")
            if msgs:
                for m in msgs[:5]:
                    status = "📖" if m["is_read"] else "📬"
                    print(f"    {status} {m['subject'][:45]}")
            print()
        print("=" * 70 + "\n")

    return 0


def cmd_escalate(args: argparse.Namespace) -> int:
    """Handle the 'escalate' subcommand - re-triage emails based on age."""
    # Load config and apply VIP senders
    config = load_config()
    apply_vip_senders_from_config(config)

    provider = get_provider(
        args.provider,
        host=args.host,
        user=args.user,
        password=args.password,  # allow-secret
        account=args.account,
        use_gmail_extensions=args.gmail_extensions,
    )

    has_categories = provider.capabilities & ProviderCapabilities.CATEGORIES
    can_star = bool(provider.capabilities & ProviderCapabilities.STAR)
    # Trust receipt on the escalate path too: escalate only raises tier today, but
    # it funnels through apply_actions (the gate) and the receipt makes that
    # coverage provable — and future-proofs the path if target_folder ever moves
    # mail. Same gitignored default + PII handling as `label`.
    audit = _make_audit(args, kind="escalate")
    result = ProcessingResult()
    escalated_count = 0
    checked_count = 0

    logger.info(f"Starting escalation check (provider: {provider.name})")
    logger.info(f"Dry run: {args.dry_run}, Limit: {args.limit}")

    with provider:
        # List messages (optionally filtered by query)
        list_result = provider.list_messages(
            query=args.query,
            limit=args.limit,
        )

        if not list_result.messages:
            logger.info("No messages found matching query.")
            print("No messages to check for escalation.")
            return 0

        # Get message details
        details = _load_message_details(provider, list_result.messages)

        actions = []
        for msg_id, msg in details.items():
            if not msg:
                continue

            checked_count += 1

            # Get current categorization
            cat_result = categorize_with_tier(msg.sender, msg.subject)

            # Calculate email age
            age_hours = calculate_email_age_hours(msg.date)

            # Check if escalation is needed
            esc_result = escalate_by_age(
                current_tier=cat_result.tier,
                email_age_hours=age_hours,
                is_time_sensitive=cat_result.time_sensitive,
            )

            if esc_result.should_escalate:
                escalated_count += 1
                new_tier_config = get_tier_config(esc_result.escalated_tier)

                logger.info(
                    f"Escalating: {msg.sender[:40]}... "
                    f"Tier {esc_result.original_tier} -> {esc_result.escalated_tier} "
                    f"({esc_result.reason})"
                )

                if not args.dry_run:
                    # Build escalation action — carry the sender for the gate
                    # (escalate only raises tier today, but keep the From attached
                    # so the chokepoint stays safe if target_folder becomes a move).
                    action = LabelAction(message_id=msg_id, sender=msg.sender)

                    # Apply new tier category
                    if has_categories:
                        action.category = new_tier_config.name
                        action.category_color = new_tier_config.color

                    # Move to tier folder
                    if new_tier_config.folder:
                        action.target_folder = new_tier_config.folder

                    # Star if tier requires it
                    if new_tier_config.star and can_star:
                        action.star = True

                    actions.append(action)

        # Apply escalation actions
        if actions:
            batch_result = provider.apply_actions(actions, audit=audit)
            result.success_count += batch_result.success_count
            result.error_count += batch_result.error_count
            result.errors.extend(batch_result.errors)
        else:
            result.success_count = escalated_count

    # Print summary
    print("\n" + "=" * 50)
    print("ESCALATION SUMMARY")
    print("=" * 50)
    print(f"Messages checked: {checked_count}")
    print(f"Messages escalated: {escalated_count}")
    print(f"Dry run: {args.dry_run}")
    if result.errors:
        print(f"Errors: {len(result.errors)}")
        for err in result.errors[:5]:
            print(f"  - {err}")
    print("=" * 50 + "\n")

    if _report_audit(audit):
        return 2
    return 0 if result.error_count == 0 else 1


def cmd_triage(args: argparse.Namespace) -> int:
    """Handle the 'triage' subcommand.

    The end-to-end pipeline the project is built around: pull a batch of
    messages, run content & context research on each, score and sort them by
    priority, and (optionally) draft suggested replies in the user's own voice.
    """
    from pathlib import Path
    from core.triage import triage_messages, render_triage
    from core.voice import load_voice_profile

    config = load_config()
    apply_vip_senders_from_config(config)

    provider = get_provider(
        args.provider,
        host=args.host,
        user=args.user,
        password=args.password,  # allow-secret
        account=args.account,
        use_gmail_extensions=args.gmail_extensions,
    )

    voice = None
    if args.draft:
        voice = load_voice_profile(
            path=Path(args.voice_file).expanduser() if args.voice_file else None,
            samples_path=Path(args.samples_file).expanduser() if args.samples_file else None,
            name=args.name or "",
        )

    logger.info(f"Triaging mailbox (provider: {provider.name})")

    with provider:
        list_result = provider.list_messages(query=args.query, limit=args.limit)
        if not list_result.messages:
            print("No messages found.")
            return 0

        details = _load_message_details(provider, list_result.messages)

        messages = [m for m in details.values() if m]

    # Bodies are sourced from whatever the provider populated (snippet/body);
    # research degrades gracefully to subject-only when none is available.
    items = triage_messages(messages, voice=voice, draft=args.draft)

    if args.top and args.top > 0:
        items = items[: args.top]
        for i, item in enumerate(items, start=1):
            item.rank = i

    print(render_triage(items, fmt=args.format))
    return 0


def cmd_ops_summary(args: argparse.Namespace) -> int:
    """Emit the canonical redacted operator dashboard summary."""
    import json

    from core.ops_summary import OpsReportError, build_ops_snapshot

    raw_report = args.report or os.environ.get("UMA_OPS_REPORT_PATH")
    if not raw_report:
        print("ops-summary: --report or UMA_OPS_REPORT_PATH is required", file=sys.stderr)
        return 1

    try:
        snapshot = build_ops_snapshot(
            Path(raw_report).expanduser(),
            max_age_hours=args.max_age_hours,
        )
    except OpsReportError as e:
        print(f"ops-summary: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(snapshot, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_ops_refresh(args: argparse.Namespace) -> int:
    """Build and persist the redacted operator summary plus bounded history."""
    import json
    import subprocess

    from core.ops_summary import OpsReportError, build_ops_snapshot, write_ops_snapshot

    raw_report = args.report or os.environ.get("UMA_OPS_REPORT_PATH")
    report_dir = Path(
        args.report_dir
        or os.environ.get("UMA_OPS_REPORT_DIR")
        or (Path(raw_report).expanduser().parent if raw_report else "~/System/Reports/mail-triage")
    ).expanduser()

    if args.run_mail_triage:
        if not args.since or not args.until:
            print("ops-refresh: --run-mail-triage requires --since and --until", file=sys.stderr)
            return 1
        mail_triage_bin = (
            args.mail_triage_bin
            or os.environ.get("UMA_MAIL_TRIAGE_BIN")
            or "/Users/4jp/.local/bin/mail-triage"
        )
        command = [
            str(Path(mail_triage_bin).expanduser()),
            "--since",
            args.since,
            "--until",
            args.until,
            "--report-dir",
            str(report_dir),
            "--apply",
        ]
        if args.mail_index:
            command.extend(["--index", str(Path(args.mail_index).expanduser())])
        try:
            completed = subprocess.run(
                command,
                cwd=os.getcwd(),
                text=True,
                capture_output=True,
                check=False,
            )
        except OSError as e:
            print(f"ops-refresh: could not run mail-triage producer: {e}", file=sys.stderr)
            return 1
        if completed.returncode != 0:
            print("ops-refresh: mail-triage producer failed", file=sys.stderr)
            if completed.stderr:
                print(completed.stderr.strip(), file=sys.stderr)
            return completed.returncode or 1
        if not raw_report:
            raw_report = str(report_dir / "latest.json")

    if not raw_report:
        print("ops-refresh: --report or UMA_OPS_REPORT_PATH is required", file=sys.stderr)
        return 1

    output_dir = (
        args.output_dir
        or os.environ.get("UMA_OPS_HISTORY_DIR")
        or "~/.local/state/universal-mail-automation/ops"
    )
    try:
        snapshot = build_ops_snapshot(
            Path(raw_report).expanduser(),
            max_age_hours=args.max_age_hours,
        )
        refresh = write_ops_snapshot(
            snapshot,
            Path(output_dir).expanduser(),
            history_limit=args.history_limit,
        )
    except OpsReportError as e:
        print(f"ops-refresh: {e.detail}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"ops-refresh: could not write operator snapshot: {e}", file=sys.stderr)
        return 1

    summary = {
        key: refresh[key]
        for key in ("schema", "status", "output_dir", "latest_summary", "history_index", "history_entry")
    }
    summary["freshness"] = snapshot.get("freshness")
    summary["kpis"] = snapshot.get("kpis")

    indent = 2 if args.pretty else None
    print(json.dumps(summary, indent=indent, sort_keys=args.sort_keys))
    if args.require_fresh and (snapshot.get("freshness") or {}).get("is_stale"):
        return 2
    return 0


def cmd_mail_intel(args: argparse.Namespace) -> int:
    """Emit redacted historical mail intelligence and ops reconciliation."""
    import json

    from core.historical_intelligence import (
        HistoricalIntelligenceError,
        build_historical_intelligence,
    )

    raw_history = args.history or os.environ.get("UMA_HISTORICAL_MAIL_PATH")
    if not raw_history:
        print("mail-intel: --history or UMA_HISTORICAL_MAIL_PATH is required", file=sys.stderr)
        return 1

    ops_report = args.ops_report or os.environ.get("UMA_OPS_REPORT_PATH")
    try:
        snapshot = build_historical_intelligence(
            Path(raw_history).expanduser(),
            ops_report_path=Path(ops_report).expanduser() if ops_report else None,
            stale_days=args.stale_days,
        )
    except HistoricalIntelligenceError as e:
        print(f"mail-intel: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    if args.output:
        output_path = Path(args.output).expanduser()
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(snapshot, indent=indent, sort_keys=args.sort_keys) + "\n",
                encoding="utf-8",
            )
            stat = output_path.stat()
        except OSError as e:
            print(f"mail-intel: could not write output: {e}", file=sys.stderr)
            return 1
        receipt = {
            "schema": "uma.mail.intelligence.receipt.v1",
            "status": "ok",
            "output": {
                "filename": output_path.name,
                "bytes": stat.st_size,
                "schema": snapshot.get("schema"),
                "redacted": True,
                "message_count": (snapshot.get("source") or {}).get("message_count"),
                "opportunities": (snapshot.get("kpis") or {}).get("opportunities"),
                "risks": (snapshot.get("kpis") or {}).get("risks"),
                "not_represented_in_current_ops": (snapshot.get("kpis") or {}).get("not_represented_in_current_ops"),
            },
            "privacy": {
                "receipt_redacted": True,
                "raw_mail_printed_to_stdout": False,
                "output_redacted": True,
            },
            "source": snapshot.get("source"),
        }
        print(json.dumps(receipt, indent=indent, sort_keys=args.sort_keys))
        return 0

    print(json.dumps(snapshot, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_history_export(args: argparse.Namespace) -> int:
    """Write a private normalized historical mail export and print a safe receipt."""
    import json

    from core.mail_history_export import (
        MailHistoryExportError,
        build_mail_history_export,
        write_mail_history_export,
    )

    raw_source = args.source or os.environ.get("UMA_HISTORICAL_MAIL_SOURCE")
    if not raw_source:
        print("mail-history-export: --source or UMA_HISTORICAL_MAIL_SOURCE is required", file=sys.stderr)
        return 1

    raw_output = (
        args.output
        or os.environ.get("UMA_HISTORICAL_MAIL_PATH")
        or "~/System/Reports/mail-history/latest.json"
    )
    try:
        export = build_mail_history_export(
            Path(raw_source).expanduser(),
            source_type=args.source_type,
            since=args.since,
            until_exclusive=args.until,
            limit=args.limit,
            body_char_limit=args.body_char_limit,
            self_addresses=args.self_address or [],
            mailbox_hint=args.mailbox_hint,
        )
        receipt = write_mail_history_export(
            export,
            Path(raw_output).expanduser(),
            pretty=args.pretty_export,
            sort_keys=args.sort_keys,
        )
    except MailHistoryExportError as e:
        print(f"mail-history-export: {e.detail}", file=sys.stderr)
        return 1
    except OSError as e:
        print(f"mail-history-export: could not write export: {e}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(receipt, indent=indent, sort_keys=args.sort_keys))
    return 0


def _default_ops_report_path() -> str:
    return "~/System/Reports/mail-triage/latest.json"


def _default_history_path() -> str:
    return "~/System/Reports/mail-history/latest.json"


def _optional_cli_path(value: Optional[str]) -> Optional[Path]:
    return Path(value).expanduser() if value else None


def cmd_mail_historical_crosswalk(args: argparse.Namespace) -> int:
    """Emit terminal accounting over every historical mail evidence item."""
    import json

    from core.mail_status import MailStatusError, build_historical_crosswalk

    raw_history = args.history or os.environ.get("UMA_HISTORICAL_MAIL_PATH")
    if not raw_history:
        print("mail-historical-crosswalk: --history or UMA_HISTORICAL_MAIL_PATH is required", file=sys.stderr)
        return 1
    raw_ops = args.ops_report or os.environ.get("UMA_OPS_REPORT_PATH")
    raw_actions = args.action_ledger or os.environ.get("UMA_MAIL_ACTION_LEDGER_PATH") or _default_action_ledger_path()
    raw_resolver = args.resolver_ledger or os.environ.get("UMA_MAIL_RESOLVER_LEDGER_PATH") or _default_resolver_ledger_path()
    raw_drafts = args.draft_approvals or os.environ.get("UMA_MAIL_DRAFT_APPROVAL_PATH") or _default_draft_approval_path()
    raw_delivery = args.delivery_ledger or os.environ.get("UMA_MAIL_DELIVERY_LEDGER_PATH") or _default_delivery_ledger_path()

    try:
        crosswalk = build_historical_crosswalk(
            Path(raw_history).expanduser(),
            ops_report_path=_optional_cli_path(raw_ops),
            action_ledger_path=_optional_cli_path(raw_actions),
            resolver_ledger_path=_optional_cli_path(raw_resolver),
            draft_approval_path=_optional_cli_path(raw_drafts),
            delivery_path=_optional_cli_path(raw_delivery),
            stale_days=args.stale_days,
            max_items=args.max_items,
        )
    except MailStatusError as e:
        print(f"mail-historical-crosswalk: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(crosswalk, indent=indent, sort_keys=args.sort_keys))
    if args.require_reconciled and not (crosswalk.get("kpis") or {}).get("reconciled"):
        return 2
    return 0


def cmd_mail_status(args: argparse.Namespace) -> int:
    """Emit the unified UMA mail status receipt."""
    import json

    from core.mail_status import build_mail_status

    raw_ops = args.ops_report or os.environ.get("UMA_OPS_REPORT_PATH") or _default_ops_report_path()
    raw_history = args.history or os.environ.get("UMA_HISTORICAL_MAIL_PATH") or _default_history_path()
    raw_actions = args.action_ledger or os.environ.get("UMA_MAIL_ACTION_LEDGER_PATH") or _default_action_ledger_path()
    raw_resolver = args.resolver_ledger or os.environ.get("UMA_MAIL_RESOLVER_LEDGER_PATH") or _default_resolver_ledger_path()
    raw_drafts = args.draft_approvals or os.environ.get("UMA_MAIL_DRAFT_APPROVAL_PATH") or _default_draft_approval_path()
    raw_delivery = args.delivery_ledger or os.environ.get("UMA_MAIL_DELIVERY_LEDGER_PATH") or _default_delivery_ledger_path()

    status = build_mail_status(
        ops_report_path=_optional_cli_path(raw_ops),
        history_path=_optional_cli_path(raw_history),
        action_ledger_path=_optional_cli_path(raw_actions),
        resolver_ledger_path=_optional_cli_path(raw_resolver),
        draft_approval_path=_optional_cli_path(raw_drafts),
        delivery_path=_optional_cli_path(raw_delivery),
        stale_days=args.stale_days,
        max_age_hours=args.max_age_hours,
        max_items=args.max_items,
    )

    indent = 2 if args.pretty else None
    if args.output:
        output_path = Path(args.output).expanduser()
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(
                json.dumps(status, indent=indent, sort_keys=args.sort_keys) + "\n",
                encoding="utf-8",
            )
        except OSError as e:
            print(f"mail-status: could not write output: {e}", file=sys.stderr)
            return 1

    print(json.dumps(status, indent=indent, sort_keys=args.sort_keys))
    if args.require_complete and status.get("status") != "ok":
        return 2
    return 0


def cmd_mail_action_plan(args: argparse.Namespace) -> int:
    """Emit a redacted, approval-aware action plan from intelligence output."""
    import json

    from core.mail_action_plan import MailActionPlanError, build_action_plan

    raw_intelligence = args.intelligence or os.environ.get("UMA_HISTORICAL_INTELLIGENCE_PATH")
    if not raw_intelligence:
        print("mail-action-plan: --intelligence or UMA_HISTORICAL_INTELLIGENCE_PATH is required", file=sys.stderr)
        return 1

    try:
        plan = build_action_plan(
            Path(raw_intelligence).expanduser(),
            max_items=args.max_items,
        )
    except MailActionPlanError as e:
        print(f"mail-action-plan: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(plan, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_resolver_plan(args: argparse.Namespace) -> int:
    """Emit redacted lane-specific resolver plans from intelligence output."""
    import json

    from core.mail_action_ledger import MailActionLedgerError, build_action_plan_for_ledger
    from core.mail_resolver_plan import MailResolverPlanError, build_resolver_plan

    raw_intelligence = args.intelligence or os.environ.get("UMA_HISTORICAL_INTELLIGENCE_PATH")
    if not raw_intelligence:
        print("mail-resolver-plan: --intelligence or UMA_HISTORICAL_INTELLIGENCE_PATH is required", file=sys.stderr)
        return 1

    try:
        plan = build_action_plan_for_ledger(
            Path(raw_intelligence).expanduser(),
            max_items=max(args.max_items, 10000),
        )
        resolver_plan = build_resolver_plan(
            plan,
            max_items=args.max_items,
        )
    except (MailActionLedgerError, MailResolverPlanError) as e:
        print(f"mail-resolver-plan: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(resolver_plan, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_provider_surface_plan(args: argparse.Namespace) -> int:
    """Emit a redacted provider-surface resolver frontier plan."""
    import json

    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_resolver_plan import MailResolverPlanError
    from core.provider_surface_plan import ProviderSurfacePlanError, build_provider_surface_plan

    try:
        resolver_plan = _build_resolver_plan_for_cli(args)
        plan = build_provider_surface_plan(
            resolver_plan,
            max_items=args.max_items,
        )
    except ValueError as e:
        print(f"mail-provider-surface-plan: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailResolverPlanError, ProviderSurfacePlanError) as e:
        print(f"mail-provider-surface-plan: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(plan, indent=indent, sort_keys=args.sort_keys))
    return 0


def _build_resolver_plan_for_cli(args: argparse.Namespace, *, min_items: int = 10000) -> dict:
    from core.mail_action_ledger import build_action_plan_for_ledger
    from core.mail_resolver_plan import build_resolver_plan

    raw_intelligence = args.intelligence or os.environ.get("UMA_HISTORICAL_INTELLIGENCE_PATH")
    if not raw_intelligence:
        raise ValueError("--intelligence or UMA_HISTORICAL_INTELLIGENCE_PATH is required")
    action_plan = build_action_plan_for_ledger(
        Path(raw_intelligence).expanduser(),
        max_items=max(args.max_items, min_items),
    )
    return build_resolver_plan(action_plan, max_items=max(args.max_items, min_items))


def _default_action_ledger_path() -> str:
    return "~/.local/state/universal-mail-automation/mail-action-ledger.jsonl"


def _default_resolver_ledger_path() -> str:
    return "~/.local/state/universal-mail-automation/mail-resolver-ledger.jsonl"


def _default_draft_approval_path() -> str:
    return "~/.local/state/universal-mail-automation/mail-draft-approvals.jsonl"


def _default_delivery_ledger_path() -> str:
    return "~/.local/state/universal-mail-automation/mail-delivery-ledger.jsonl"


def cmd_mail_action_ledger(args: argparse.Namespace) -> int:
    """Emit redacted action status merged with local receipts."""
    import json

    from core.mail_action_ledger import (
        MailActionLedgerError,
        build_action_ledger,
        build_action_plan_for_ledger,
    )

    raw_intelligence = args.intelligence or os.environ.get("UMA_HISTORICAL_INTELLIGENCE_PATH")
    if not raw_intelligence:
        print("mail-action-ledger: --intelligence or UMA_HISTORICAL_INTELLIGENCE_PATH is required", file=sys.stderr)
        return 1
    raw_ledger = args.ledger or os.environ.get("UMA_MAIL_ACTION_LEDGER_PATH") or _default_action_ledger_path()

    try:
        plan = build_action_plan_for_ledger(
            Path(raw_intelligence).expanduser(),
            max_items=args.max_items,
        )
        ledger = build_action_ledger(
            plan,
            receipt_path=Path(raw_ledger).expanduser(),
            max_items=args.max_items,
            max_receipts=args.max_receipts,
        )
    except MailActionLedgerError as e:
        print(f"mail-action-ledger: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(ledger, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_resolver_ledger(args: argparse.Namespace) -> int:
    """Emit redacted resolver proof state merged with local receipts."""
    import json

    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_resolver_plan import MailResolverPlanError
    from core.mail_resolver_receipt import MailResolverReceiptError, build_resolver_ledger

    raw_ledger = args.ledger or os.environ.get("UMA_MAIL_RESOLVER_LEDGER_PATH") or _default_resolver_ledger_path()
    try:
        resolver_plan = _build_resolver_plan_for_cli(args)
        ledger = build_resolver_ledger(
            resolver_plan,
            receipt_path=Path(raw_ledger).expanduser(),
            max_items=args.max_items,
            max_receipts=args.max_receipts,
        )
    except ValueError as e:
        print(f"mail-resolver-ledger: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailResolverPlanError, MailResolverReceiptError) as e:
        print(f"mail-resolver-ledger: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(ledger, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_github_resolver(args: argparse.Namespace) -> int:
    """Emit a redacted read-only GitHub official-surface resolver snapshot."""
    import json

    from core.github_resolver import GitHubResolverError, build_github_resolver_snapshot
    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_resolver_plan import MailResolverPlanError

    try:
        resolver_plan = _build_resolver_plan_for_cli(args)
        snapshot = build_github_resolver_snapshot(
            resolver_plan,
            gh_bin=args.gh_bin,
            query_limit=args.query_limit,
            max_items=args.max_items,
            include_provider_queries=not args.skip_provider_queries,
        )
    except ValueError as e:
        print(f"mail-github-resolver: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailResolverPlanError, GitHubResolverError) as e:
        print(f"mail-github-resolver: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(snapshot, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_github_resolver_receipts(args: argparse.Namespace) -> int:
    """Record redacted resolver receipts from a GitHub resolver snapshot."""
    import json

    from core.github_resolver import (
        GitHubResolverError,
        build_github_resolver_receipts,
        build_github_resolver_snapshot,
    )
    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_resolver_plan import MailResolverPlanError
    from core.mail_resolver_receipt import MailResolverReceiptError

    raw_ledger = args.ledger or os.environ.get("UMA_MAIL_RESOLVER_LEDGER_PATH") or _default_resolver_ledger_path()
    try:
        resolver_plan = _build_resolver_plan_for_cli(args)
        snapshot = build_github_resolver_snapshot(
            resolver_plan,
            gh_bin=args.gh_bin,
            query_limit=args.query_limit,
            max_items=args.max_items,
            include_provider_queries=not args.skip_provider_queries,
        )
        receipts = build_github_resolver_receipts(
            snapshot,
            resolver_plan,
            receipt_path=Path(raw_ledger).expanduser(),
            max_receipts=args.max_receipts,
        )
    except ValueError as e:
        print(f"mail-github-resolver-receipts: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailResolverPlanError, GitHubResolverError, MailResolverReceiptError) as e:
        print(f"mail-github-resolver-receipts: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(receipts, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_followup_resolver(args: argparse.Namespace) -> int:
    """Emit a redacted mail/LinkedIn follow-up resolver snapshot."""
    import json

    from core.followup_resolver import FollowupResolverError, build_followup_resolver_snapshot
    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_resolver_plan import MailResolverPlanError

    raw_approvals = (
        args.draft_approvals
        or os.environ.get("UMA_MAIL_DRAFT_APPROVAL_PATH")
        or _default_draft_approval_path()
    )
    raw_delivery = args.delivery_ledger or os.environ.get("UMA_MAIL_DELIVERY_LEDGER_PATH") or _default_delivery_ledger_path()
    try:
        resolver_plan = _build_resolver_plan_for_cli(args)
        snapshot = build_followup_resolver_snapshot(
            resolver_plan,
            draft_approval_receipt_path=Path(raw_approvals).expanduser(),
            delivery_receipt_path=Path(raw_delivery).expanduser(),
            max_items=args.max_items,
        )
    except ValueError as e:
        print(f"mail-followup-resolver: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailResolverPlanError, FollowupResolverError) as e:
        print(f"mail-followup-resolver: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(snapshot, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_followup_resolver_receipts(args: argparse.Namespace) -> int:
    """Record redacted resolver receipts from mail/LinkedIn follow-up proof."""
    import json

    from core.followup_resolver import (
        FollowupResolverError,
        build_followup_resolver_receipts,
        build_followup_resolver_snapshot,
    )
    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_resolver_plan import MailResolverPlanError
    from core.mail_resolver_receipt import MailResolverReceiptError

    raw_approvals = (
        args.draft_approvals
        or os.environ.get("UMA_MAIL_DRAFT_APPROVAL_PATH")
        or _default_draft_approval_path()
    )
    raw_delivery = args.delivery_ledger or os.environ.get("UMA_MAIL_DELIVERY_LEDGER_PATH") or _default_delivery_ledger_path()
    raw_ledger = args.ledger or os.environ.get("UMA_MAIL_RESOLVER_LEDGER_PATH") or _default_resolver_ledger_path()
    try:
        resolver_plan = _build_resolver_plan_for_cli(args)
        snapshot = build_followup_resolver_snapshot(
            resolver_plan,
            draft_approval_receipt_path=Path(raw_approvals).expanduser(),
            delivery_receipt_path=Path(raw_delivery).expanduser(),
            max_items=args.max_items,
        )
        receipts = build_followup_resolver_receipts(
            snapshot,
            resolver_plan,
            receipt_path=Path(raw_ledger).expanduser(),
            max_receipts=args.max_receipts,
        )
    except ValueError as e:
        print(f"mail-followup-resolver-receipts: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailResolverPlanError, FollowupResolverError, MailResolverReceiptError) as e:
        print(f"mail-followup-resolver-receipts: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(receipts, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_external_resolver(args: argparse.Namespace) -> int:
    """Emit a redacted external-surface resolver snapshot."""
    import json

    from core.external_resolver import ExternalResolverError, build_external_resolver_snapshot
    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_resolver_plan import MailResolverPlanError

    raw_ledger = args.ledger or os.environ.get("UMA_MAIL_RESOLVER_LEDGER_PATH") or _default_resolver_ledger_path()
    try:
        resolver_plan = _build_resolver_plan_for_cli(args)
        snapshot = build_external_resolver_snapshot(
            resolver_plan,
            receipt_path=Path(raw_ledger).expanduser(),
            max_items=args.max_items,
            operator_attestation_requested=False,
        )
    except ValueError as e:
        print(f"mail-external-resolver: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailResolverPlanError, ExternalResolverError) as e:
        print(f"mail-external-resolver: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(snapshot, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_external_resolver_receipts(args: argparse.Namespace) -> int:
    """Record redacted resolver receipts from explicit external-lane attestations."""
    import json

    from core.external_resolver import (
        ExternalResolverError,
        build_external_resolver_receipts,
        build_external_resolver_snapshot,
    )
    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_resolver_plan import MailResolverPlanError
    from core.mail_resolver_receipt import MailResolverReceiptError

    raw_ledger = args.ledger or os.environ.get("UMA_MAIL_RESOLVER_LEDGER_PATH") or _default_resolver_ledger_path()
    try:
        resolver_plan = _build_resolver_plan_for_cli(args)
        snapshot = build_external_resolver_snapshot(
            resolver_plan,
            receipt_path=Path(raw_ledger).expanduser(),
            max_items=args.max_items,
            operator_attestation_requested=args.attest_blockers,
        )
        receipts = build_external_resolver_receipts(
            snapshot,
            resolver_plan,
            receipt_path=Path(raw_ledger).expanduser(),
            max_receipts=args.max_receipts,
        )
    except ValueError as e:
        print(f"mail-external-resolver-receipts: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailResolverPlanError, ExternalResolverError, MailResolverReceiptError) as e:
        print(f"mail-external-resolver-receipts: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(receipts, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_resolver_receipt(args: argparse.Namespace) -> int:
    """Append a redacted official-surface resolver receipt."""
    import json

    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_resolver_plan import MailResolverPlanError
    from core.mail_resolver_receipt import MailResolverReceiptError, build_resolver_receipt

    raw_ledger = args.ledger or os.environ.get("UMA_MAIL_RESOLVER_LEDGER_PATH") or _default_resolver_ledger_path()
    try:
        resolver_plan = _build_resolver_plan_for_cli(args)
        receipt = build_resolver_receipt(
            resolver_plan,
            action_id=args.action_id,
            resolver_status=args.resolver_status,
            reason_code=args.reason_code,
            proof_type=args.proof_type,
            provider=args.provider,
            external_reference=args.external_reference,
            receipt_path=Path(raw_ledger).expanduser(),
        )
    except ValueError as e:
        print(f"mail-resolver-receipt: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailResolverPlanError, MailResolverReceiptError) as e:
        print(f"mail-resolver-receipt: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(receipt, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_action_receipt(args: argparse.Namespace) -> int:
    """Append a redacted local receipt for an action-plan item."""
    import json

    from core.mail_action_ledger import (
        MailActionLedgerError,
        build_action_plan_for_ledger,
        build_action_receipt,
    )

    raw_intelligence = args.intelligence or os.environ.get("UMA_HISTORICAL_INTELLIGENCE_PATH")
    if not raw_intelligence:
        print("mail-action-receipt: --intelligence or UMA_HISTORICAL_INTELLIGENCE_PATH is required", file=sys.stderr)
        return 1
    raw_ledger = args.ledger or os.environ.get("UMA_MAIL_ACTION_LEDGER_PATH") or _default_action_ledger_path()

    try:
        plan = build_action_plan_for_ledger(
            Path(raw_intelligence).expanduser(),
            max_items=args.max_items,
        )
        receipt = build_action_receipt(
            plan,
            action_id=args.action_id,
            action_status=args.action_status,
            reason_code=args.reason_code,
            evidence_ids=args.evidence_id or [],
            receipt_path=Path(raw_ledger).expanduser(),
        )
    except MailActionLedgerError as e:
        print(f"mail-action-receipt: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(receipt, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_evidence_review(args: argparse.Namespace) -> int:
    """Open a gated private source message for a redacted evidence id."""
    import json

    from core.mail_evidence_review import MailEvidenceReviewError, build_evidence_review

    raw_history = args.history or os.environ.get("UMA_HISTORICAL_MAIL_PATH")
    if not raw_history:
        print("mail-evidence-review: --history or UMA_HISTORICAL_MAIL_PATH is required", file=sys.stderr)
        return 1

    try:
        review = build_evidence_review(
            Path(raw_history).expanduser(),
            args.evidence_id,
            ack_private=args.ack_private,
            body_char_limit=args.body_char_limit,
            context_limit=args.context_limit,
        )
    except MailEvidenceReviewError as e:
        print(f"mail-evidence-review: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(review, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_draft_package(args: argparse.Namespace) -> int:
    """Build private approval-gated draft candidates for an action id."""
    import json

    from core.mail_action_ledger import MailActionLedgerError, build_action_plan_for_ledger
    from core.mail_draft_package import MailDraftPackageError, build_draft_package

    raw_intelligence = args.intelligence or os.environ.get("UMA_HISTORICAL_INTELLIGENCE_PATH")
    if not raw_intelligence:
        print("mail-draft-package: --intelligence or UMA_HISTORICAL_INTELLIGENCE_PATH is required", file=sys.stderr)
        return 1
    raw_history = args.history or os.environ.get("UMA_HISTORICAL_MAIL_PATH")
    if not raw_history:
        print("mail-draft-package: --history or UMA_HISTORICAL_MAIL_PATH is required", file=sys.stderr)
        return 1

    try:
        plan = build_action_plan_for_ledger(
            Path(raw_intelligence).expanduser(),
            max_items=args.max_items,
        )
        package = build_draft_package(
            plan,
            Path(raw_history).expanduser(),
            args.action_id,
            ack_private=args.ack_private,
            user_name=args.user_name,
            max_drafts=args.max_drafts,
            body_char_limit=args.body_char_limit,
        )
    except (MailActionLedgerError, MailDraftPackageError) as e:
        print(f"mail-draft-package: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(package, indent=indent, sort_keys=args.sort_keys))
    return 0


def _build_private_draft_package_for_cli(args: argparse.Namespace) -> dict:
    from core.mail_action_ledger import build_action_plan_for_ledger
    from core.mail_draft_package import build_draft_package

    raw_intelligence = args.intelligence or os.environ.get("UMA_HISTORICAL_INTELLIGENCE_PATH")
    if not raw_intelligence:
        raise ValueError("--intelligence or UMA_HISTORICAL_INTELLIGENCE_PATH is required")
    raw_history = args.history or os.environ.get("UMA_HISTORICAL_MAIL_PATH")
    if not raw_history:
        raise ValueError("--history or UMA_HISTORICAL_MAIL_PATH is required")

    plan = build_action_plan_for_ledger(
        Path(raw_intelligence).expanduser(),
        max_items=args.max_items,
    )
    return build_draft_package(
        plan,
        Path(raw_history).expanduser(),
        args.action_id,
        ack_private=args.ack_private,
        user_name=args.user_name,
        max_drafts=args.max_drafts,
        body_char_limit=args.body_char_limit,
    )


def cmd_mail_draft_approvals(args: argparse.Namespace) -> int:
    """Emit redacted approval status for private draft candidates."""
    import json

    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_draft_package import MailDraftPackageError
    from core.mail_draft_approval import MailDraftApprovalError, build_draft_approval_ledger

    raw_approvals = (
        args.approvals
        or os.environ.get("UMA_MAIL_DRAFT_APPROVAL_PATH")
        or _default_draft_approval_path()
    )
    try:
        package = _build_private_draft_package_for_cli(args)
        ledger = build_draft_approval_ledger(
            package,
            receipt_path=Path(raw_approvals).expanduser(),
            max_items=args.max_items,
            max_receipts=args.max_receipts,
        )
    except ValueError as e:
        print(f"mail-draft-approvals: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailDraftPackageError, MailDraftApprovalError) as e:
        print(f"mail-draft-approvals: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(ledger, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_draft_approval_receipt(args: argparse.Namespace) -> int:
    """Append a redacted local approval receipt for a draft candidate."""
    import json

    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_draft_package import MailDraftPackageError
    from core.mail_draft_approval import MailDraftApprovalError, build_draft_approval_receipt

    raw_approvals = (
        args.approvals
        or os.environ.get("UMA_MAIL_DRAFT_APPROVAL_PATH")
        or _default_draft_approval_path()
    )
    try:
        package = _build_private_draft_package_for_cli(args)
        receipt = build_draft_approval_receipt(
            package,
            draft_id=args.draft_id,
            decision=args.decision,
            reason_code=args.reason_code,
            ack_private=args.ack_private,
            receipt_path=Path(raw_approvals).expanduser(),
        )
    except ValueError as e:
        print(f"mail-draft-approval: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailDraftPackageError, MailDraftApprovalError) as e:
        print(f"mail-draft-approval: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(receipt, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_delivery_ledger(args: argparse.Namespace) -> int:
    """Emit redacted delivery intent/status for approved draft candidates."""
    import json

    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_draft_approval import MailDraftApprovalError
    from core.mail_draft_package import MailDraftPackageError
    from core.mail_delivery import MailDeliveryError, build_delivery_ledger

    raw_approvals = (
        args.approvals
        or os.environ.get("UMA_MAIL_DRAFT_APPROVAL_PATH")
        or _default_draft_approval_path()
    )
    raw_delivery = (
        args.delivery
        or os.environ.get("UMA_MAIL_DELIVERY_LEDGER_PATH")
        or _default_delivery_ledger_path()
    )
    try:
        package = _build_private_draft_package_for_cli(args)
        ledger = build_delivery_ledger(
            package,
            approval_receipt_path=Path(raw_approvals).expanduser(),
            delivery_receipt_path=Path(raw_delivery).expanduser(),
            max_items=args.max_items,
            max_receipts=args.max_receipts,
        )
    except ValueError as e:
        print(f"mail-delivery-ledger: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailDraftPackageError, MailDraftApprovalError, MailDeliveryError) as e:
        print(f"mail-delivery-ledger: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(ledger, indent=indent, sort_keys=args.sort_keys))
    return 0


def cmd_mail_delivery_receipt(args: argparse.Namespace) -> int:
    """Append a redacted local delivery receipt for an approved draft candidate."""
    import json

    from core.mail_action_ledger import MailActionLedgerError
    from core.mail_draft_approval import MailDraftApprovalError
    from core.mail_draft_package import MailDraftPackageError
    from core.mail_delivery import MailDeliveryError, build_delivery_receipt

    raw_approvals = (
        args.approvals
        or os.environ.get("UMA_MAIL_DRAFT_APPROVAL_PATH")
        or _default_draft_approval_path()
    )
    raw_delivery = (
        args.delivery
        or os.environ.get("UMA_MAIL_DELIVERY_LEDGER_PATH")
        or _default_delivery_ledger_path()
    )
    try:
        package = _build_private_draft_package_for_cli(args)
        receipt = build_delivery_receipt(
            package,
            draft_id=args.draft_id,
            delivery_status=args.delivery_status,
            reason_code=args.reason_code,
            provider=args.provider,
            external_reference=args.external_reference,
            ack_private=args.ack_private,
            approval_receipt_path=Path(raw_approvals).expanduser(),
            receipt_path=Path(raw_delivery).expanduser(),
        )
    except ValueError as e:
        print(f"mail-delivery-receipt: {e}", file=sys.stderr)
        return 1
    except (MailActionLedgerError, MailDraftPackageError, MailDraftApprovalError, MailDeliveryError) as e:
        print(f"mail-delivery-receipt: {e.detail}", file=sys.stderr)
        return 1

    indent = 2 if args.pretty else None
    print(json.dumps(receipt, indent=indent, sort_keys=args.sort_keys))
    return 0


# =============================================================================
# FLAGS COMMAND HANDLERS — Seven-color workflow state for Mail.app
# =============================================================================

def cmd_flags_doctor(args: argparse.Namespace) -> int:
    """Diagnose Mail.app colored flag capability and configuration.

    Read-only. Does NOT call the unbounded list_messages path.
    Reports: scripting property detection, read capability (inferred from
    provider construction), native mapping source, write capability
    (implemented but not live-tested), and live round-trip status.
    """
    if args.provider != "mailapp":
        print("flags doctor: only supported for mailapp provider", file=sys.stderr)
        return 1

    try:
        provider = get_provider(
            args.provider,
            account=args.account,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"flags doctor: provider unavailable: {exc}", file=sys.stderr)
        return 1

    try:
        with provider:
            # 1. Scripting property detection
            if not (
                provider.capabilities & ProviderCapabilities.COLORED_FLAGS
            ):
                print("✗ COLORED_FLAGS capability not declared by provider")
                return 1
            print("✓ Scripting property: COLORED_FLAGS declared")
            print(f"  Provider: {provider.name}")
            print(f"  Capabilities: {provider.capabilities}")

            # 2. Read capability — inferred from provider construction, NOT
            # by calling the unbounded list_messages path.
            print(
                "✓ Read capability: implemented "
                "(provider constructed successfully)"
            )

            # 3. Native mapping source
            print(
                "\n  Native mapping source: "
                "providers/flag_codecs.py MAILAPP_INDEX_TO_FLAG"
            )
            print("  Flag Color Mapping (Mail.app flag index):")
            from providers.flag_codecs import MAILAPP_INDEX_TO_FLAG
            for index in sorted(MAILAPP_INDEX_TO_FLAG):
                fc = MAILAPP_INDEX_TO_FLAG[index]
                print(
                    f"    {index:>3} = {fc.name_str:<12} "
                    f"({fc.operator_posture})"
                )

            # 4. Write capability — implemented but NOT live-tested
            print("\n  Write capability: implemented (not live-tested)")
            print("  Clear/unflag capability: implemented (not live-tested)")

            # 5. Live round-trip status
            print("  Live round-trip: NOT performed (doctor is read-only)")
            print(
                "\n  To test read capability live, use: "
                "flags audit --flagged-only"
            )
            print(
                "  To prepare the bounded write canary, use: flags apply "
                "--canary --dry-run with exact plan, snapshot, and approval "
                "artifacts (unrestricted apply remains disabled)"
            )
            return 0
    except (OSError, RuntimeError) as exc:
        print(f"flags doctor: connection failed: {exc}", file=sys.stderr)
        return 1


def cmd_flags_audit(args: argparse.Namespace) -> int:
    """Read-only inventory of flagged messages.

    Delegates ALL enumeration to the provider and ALL artifact handling to
    core.flag_workflow. A private snapshot (mode 0600) is ALWAYS written —
    including for failed/incomplete scans, so failure evidence is durable.
    --receipt writes the PUBLIC-SAFE projection only (allowlist fields).

    Exit codes: 0 complete (or partial accepted via --allow-partial) |
    20 incomplete without --allow-partial | 1 provider/config error.

    Rendering is mutually exclusive: json OR csv OR table — never mixed,
    so machine-readable output stays parseable.
    """
    if args.provider != "mailapp":
        print("flags audit: only supported for mailapp provider", file=sys.stderr)
        return 1
    if not _require_flags_mailbox(args, "audit"):
        return 2

    estate_mode = bool(getattr(args, "estate", False))
    account = getattr(args, "account", None)
    if not estate_mode and (
        not isinstance(account, str) or not account.strip()
    ):
        print(
            "flags audit: --account is required unless --estate is used",
            file=sys.stderr,
        )
        return 2

    from providers.mailapp import MailAppProvider
    from core import flag_workflow

    logger.info(
        f"Auditing mailbox {args.mailbox} "
        f"(flagged_only={args.flagged_only}, limit={args.limit})"
    )

    def failed_snapshot(error: str) -> flag_workflow.FlagSnapshot:
        """Durable private evidence for failures before enumeration returns."""
        return flag_workflow.build_snapshot(
            provider_name=args.provider,
            account="<estate>" if estate_mode else (account or "<missing>"),
            mailbox="unavailable estate" if estate_mode else args.mailbox,
            rows=[],
            complete=False,
            scope_complete=False,
            status="failed",
            errors=[error],
            inaccessible_count=0,
            timeout_count=0,
            unknown_index_count=0,
            limit=args.limit,
            since_days=args.since_days,
            total_matched=0,
            returned_count=0,
            hidden_by_limit=0,
        )

    try:
        provider = get_provider(args.provider, account=args.account)
    except (OSError, RuntimeError, ValueError) as exc:
        snapshot = failed_snapshot(f"provider construction failed: {exc}")
    else:
        if not isinstance(provider, MailAppProvider):
            print("flags audit: mailapp provider required", file=sys.stderr)
            return 1
        try:
            with provider:
                if estate_mode:
                    # Estate mode returns a typed aggregate even when
                    # discovery or an individual surface fails.
                    estate = flag_workflow.enumerate_estate(
                        provider,
                        per_surface_limit=args.limit,
                        since_days=args.since_days,
                    )
                else:
                    result = provider.enumerate_flagged(
                        mailbox=args.mailbox,
                        limit=args.limit,
                        since_days=args.since_days,
                    )
        except (OSError, RuntimeError) as exc:
            snapshot = failed_snapshot(f"provider connection failed: {exc}")
        else:
            try:
                if estate_mode:
                    snapshot = flag_workflow.build_estate_snapshot(
                        estate, provider_name=provider.name
                    )
                else:
                    snapshot = flag_workflow.build_snapshot(
                        provider_name=provider.name,
                        account=account or "<missing>",
                        mailbox=args.mailbox,
                        rows=result.rows,
                        complete=result.complete,
                        scope_complete=result.scope_complete,
                        status=result.status,
                        errors=result.errors,
                        inaccessible_count=result.inaccessible_count,
                        timeout_count=result.timeout_count,
                        unknown_index_count=result.unknown_index_count,
                        limit=args.limit,
                        since_days=args.since_days,
                        total_matched=result.scanned_boundary.get(
                            "total_flagged_seen", len(result.rows)
                        ),
                        returned_count=len(result.rows),
                        hidden_by_limit=result.scanned_boundary.get(
                            "hidden_by_limit", 0
                        ),
                        next_cursor=result.next_cursor,
                    )
            except flag_workflow.FlagWorkflowError as exc:
                print(f"flags audit: invalid scan evidence: {exc}", file=sys.stderr)
                return 20
    snap_dir = Path(
        os.environ.get(
            "UMA_FLAGS_STATE_DIR",
            str(Path.home() / ".local" / "share" / "uma" / "flags"),
        )
    ) / "snapshots"
    try:
        snap_path = flag_workflow.write_private_snapshot(snapshot, snap_dir)
    except (flag_workflow.FlagWorkflowError, OSError) as exc:
        print(
            f"flags audit: private evidence could not be persisted: {exc}",
            file=sys.stderr,
        )
        return 1

    # ALL completeness decisions derive uniformly from the SNAPSHOT —
    # identical code path for single-surface and estate modes.
    incomplete = not snapshot.complete
    if incomplete and not getattr(args, "allow_partial", False):
        print(
            f"flags audit: {snapshot.status.upper()} scan "
            f"({len(snapshot.errors)} errors, "
            f"{snapshot.inaccessible_count} inaccessible rows, "
            f"{snapshot.timeout_count} timeouts, "
            f"{snapshot.hidden_by_limit} hidden by limit). "
            "Private evidence snapshot was still written. This is NOT a "
            "full inventory and MUST NOT be treated as an empty mailbox. "
            "Re-run with --allow-partial to accept the partial report.",
            file=sys.stderr,
        )
        for err in snapshot.errors:
            print(f"  error: {err}", file=sys.stderr)
        print(f"  snapshot: {snap_path}", file=sys.stderr)
        return 20

    # Operational metadata goes to STDERR so --output json/csv stays pure
    # machine-readable output on STDOUT.
    print(f"Private snapshot (mode 0600): {snap_path}", file=sys.stderr)
    print(f"Snapshot id: {snapshot.snapshot_id}  status: {snapshot.status}",
          file=sys.stderr)
    print(f"Content hash: {snapshot.content_hash}", file=sys.stderr)
    if snapshot.next_cursor:
        print(f"Resume cursor: {snapshot.next_cursor}", file=sys.stderr)

    # Prepare the optional public projection before rendering stdout. A
    # receipt failure therefore cannot leave apparently successful machine
    # output behind.
    if args.receipt:
        try:
            public = snapshot.to_public_safe()
            receipt_path = Path(args.receipt).expanduser()
            receipt_path.parent.mkdir(parents=True, exist_ok=True)
            with open(receipt_path, "w") as receipt_file:
                json.dump(public, receipt_file, indent=2, allow_nan=False)
        except (flag_workflow.FlagWorkflowError, OSError, TypeError, ValueError) as exc:
            print(f"flags audit: public receipt failed: {exc}", file=sys.stderr)
            return 1
        print(
            f"Public-safe receipt written to: {args.receipt}",
            file=sys.stderr,
        )

    # Display layer — MUTUALLY EXCLUSIVE rendering.
    display_rows = [
        {
            "id": m.provider_id,
            "sender": m.sender,
            "subject": m.subject,
            "flag_index": m.native_index,
            "flag_color": m.observed_flag.name_str,
            "operator_posture": m.observed_flag.operator_posture,
        }
        for m in snapshot.messages
    ]
    if args.output == "json":
        print(json.dumps(snapshot.to_dict(), indent=2, allow_nan=False))
    elif args.output == "csv":
        _print_csv(display_rows)
    else:
        if not display_rows and snapshot.complete:
            print("No flagged messages found in scope.")
        elif display_rows:
            _print_audit_table(display_rows, args.flagged_only)

    return 0


def _print_audit_table(rows: list, flagged_only: bool):
    """Print audit results as a table."""
    if not rows:
        print("No messages found.")
        return

    title = "FLAGGED MESSAGES AUDIT" if flagged_only else "MAILBOX AUDIT"
    print(f"\n{'=' * 80}")
    print(f"{title} — {len(rows)} messages")
    print(f"{'=' * 80}")

    from collections import Counter
    color_counts = Counter(r.get("flag_color", "unknown") for r in rows)
    for color, count in sorted(color_counts.items(), key=lambda x: -x[1]):
        print(f"  {color}: {count}")

    print()
    for r in rows:
        flag = r.get("flag_color", "?")
        sender = r.get("sender", "")[:40]
        subject = r.get("subject", "")[:50]
        print(f"  [{flag:<12}] {sender:<40} {subject}")

    print(f"{'=' * 80}\n")


def _print_csv(rows: list):
    """Print audit results as CSV."""
    import csv
    import sys
    writer = csv.writer(sys.stdout)
    writer.writerow([
        "id", "sender", "subject", "flag_color", "operator_posture",
    ])
    for r in rows:
        writer.writerow([
            r.get("id", ""),
            r.get("sender", ""),
            r.get("subject", ""),
            r.get("flag_color", ""),
            r.get("operator_posture", ""),
        ])


def cmd_flags_plan(args: argparse.Namespace) -> int:
    """Generate migration/reclassification plan — ARTIFACT-ONLY.

    Commit 5 contract: this command REQUIRES --snapshot <private.json> and
    NEVER instantiates or connects a provider. There is NO live-rescan
    fallback; planning from a live Mail.app scan is structurally impossible
    here (the provider/enumeration symbols are not referenced at all).

    The snapshot is revalidated semantically on load (a valid hash over
    impossible content is rejected), and the produced plan is bound to the
    full snapshot hash plus the policy digest.
    """
    if not args.output:
        print("flags plan: --output is required", file=sys.stderr)
        return 1

    from core import flag_workflow

    snap_arg = getattr(args, "snapshot", None)
    if not snap_arg:
        # argparse enforces required=True; this is defense in depth.
        print("flags plan: --snapshot is required "
              "(planning never rescans Mail.app)", file=sys.stderr)
        return 2
    snap_path = Path(snap_arg).expanduser()
    if not snap_path.is_file():
        print(f"flags plan: snapshot not found: {snap_path}",
              file=sys.stderr)
        return 1

    try:
        snapshot = flag_workflow.load_snapshot(snap_path)
        plan = flag_workflow.build_plan(snapshot)
        plan_path = flag_workflow.write_private_plan(
            plan,
            Path(args.output).expanduser(),
        )
    except flag_workflow.FlagWorkflowError as e:
        # Tampered hashes, semantically invalid snapshots, and incomplete
        # snapshots are all structurally plan-ineligible.
        print(f"flags plan: {e}", file=sys.stderr)
        return 20

    mutations = plan["mutations"]
    review_only = sum(1 for m in mutations if m["review_required"])
    auto_eligible = sum(1 for m in mutations if m["auto_eligible"])
    print(f"\nMigration Plan Generated: {plan_path}")
    print(f"  Plan Hash (full sha256): {plan['plan_hash']}")
    print(f"  Snapshot Hash (full sha256): {plan['snapshot_sha256']}")
    print(f"  Policy Version: {plan['policy_version']}")
    print(f"  Policy Digest (sha256): {plan['policy_sha256']}")
    print(f"  Total Scanned: {plan['total_scanned']}")
    print(f"  Unchanged: {plan['unchanged_count']}")
    print(f"  To Recolor: {len(mutations)}")
    print(f"  Review-only (apply-ineligible): {review_only}/{len(mutations)}")
    print(f"  Auto-classified (Commit 6 approval+preflight gate applies): "
          f"{auto_eligible}/{len(mutations)}")
    print("  NOTE: planning performs zero writes. Only the explicit "
          "1..3-message --canary path can consume an exact current approval; "
          "unrestricted apply remains disabled (exit 89).")
    return 0


def cmd_flags_queue(args: argparse.Namespace) -> int:
    """Show the seven queues plus an explicit UNKNOWN evidence surface."""
    if args.provider != "mailapp":
        print("flags queue: only supported for mailapp provider", file=sys.stderr)
        return 1
    if not _require_flags_mailbox(args, "queue"):
        return 2
    account = getattr(args, "account", None)
    if not isinstance(account, str) or not account.strip():
        print("flags queue: --account is required", file=sys.stderr)
        return 2

    from providers.mailapp import MailAppProvider

    try:
        provider = get_provider(args.provider, account=args.account)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"flags queue: provider unavailable: {exc}", file=sys.stderr)
        return 1
    if not isinstance(provider, MailAppProvider):
        print("flags queue: mailapp provider required", file=sys.stderr)
        return 1

    logger.info(f"Building flags queue for {args.mailbox} (limit={args.limit})")

    try:
        with provider:
            result = provider.enumerate_flagged(
                mailbox=args.mailbox,
                limit=args.limit,
            )
    except (OSError, RuntimeError) as exc:
        print(f"flags queue: enumeration failed: {exc}", file=sys.stderr)
        return 1

    if not result.complete:
        print(
            f"flags queue: refusing {result.status} enumeration "
            f"({len(result.errors)} errors, "
            f"{result.inaccessible_count} inaccessible rows, "
            f"{result.timeout_count} timeouts, "
            f"{result.scanned_boundary.get('hidden_by_limit', 0)} hidden "
            "by limit)",
            file=sys.stderr,
        )
        return 20

    queue_order = [
        FlagColor.RED,
        FlagColor.ORANGE,
        FlagColor.YELLOW,
        FlagColor.GREEN,
        FlagColor.BLUE,
        FlagColor.PURPLE,
        FlagColor.GRAY,
        FlagColor.UNKNOWN,
    ]
    queue_data: Dict[FlagColor, list] = {fc: [] for fc in queue_order}

    for r in result.rows:
        fc = r.flag_color
        if fc in queue_data:
            queue_data[fc].append(r)

    if args.output == "json":
        import json
        output = {
            fc.queue_label: [
                {
                    "id": row.provider_id,
                    "account": row.account,
                    "mailbox": row.mailbox,
                    "sender": row.sender,
                    "subject": row.subject,
                    "native_index": row.native_index,
                    "flag_color": row.flag_color.value,
                    "received_iso": row.received_iso,
                }
                for row in queue_data[fc]
            ]
            for fc in queue_order
        }
        print(json.dumps(output, indent=2))
        return 0

    print(f"\n{'=' * 80}")
    print(f"FLAGS QUEUE — {args.mailbox} ({sum(len(v) for v in queue_data.values())} flagged)")
    print(f"{'=' * 80}")

    for fc in queue_order:
        items = queue_data[fc]
        if not items:
            continue
        print(f"\n  {fc.queue_label} ({fc.name_str}) — {len(items)}")
        print(f"  {'-' * 76}")
        for r in items[:20]:
            sender = (r.sender or "")[:35]
            subject = (r.subject or "")[:45]
            print(f"    {sender:<35} {subject}")
        if len(items) > 20:
            print(f"    ... +{len(items) - 20} more")

    print(f"\n{'=' * 80}\n")
    return 0


def cmd_flags_apply(args: argparse.Namespace) -> int:
    """Prepare or execute one explicitly approved Mail.app canary."""
    if getattr(args, "canary", False) is not True:
        print(
            "NOT_READY: unrestricted flags apply is disabled; explicit "
            "--canary is required and no provider was constructed.",
            file=sys.stderr,
        )
        return 89
    if getattr(args, "provider", None) != "mailapp":
        print(
            "flags apply: canary activation supports only mailapp",
            file=sys.stderr,
        )
        return 20

    from core.flag_activation import (
        CanaryRollbackBundle,
        default_flags_state_dir,
        load_canary_activation,
        make_transaction_engine,
        persist_canary_material,
        redacted_canary_proposal,
        validate_canary_output_paths,
        write_public_canary_proposal,
    )
    from core.flag_workflow import FlagWorkflowError

    required = ("plan", "snapshot", "approval")
    missing = [
        f"--{name}" for name in required
        if not getattr(args, name, None)
    ]
    if missing:
        print(
            f"flags apply: missing required artifact(s): {', '.join(missing)}",
            file=sys.stderr,
        )
        return 20

    try:
        activation = load_canary_activation(
            plan_path=Path(args.plan).expanduser(),
            snapshot_path=Path(args.snapshot).expanduser(),
            approval_path=Path(args.approval).expanduser(),
            cli_limit=getattr(args, "limit", 3),
        )
        requested_account = getattr(args, "account", None)
        if requested_account is not None \
                and requested_account != activation.scope[1]:
            raise FlagWorkflowError(
                "CLI account does not match the approved plan scope"
            )
        bundle = CanaryRollbackBundle.create(activation)
        state_dir = default_flags_state_dir()
        receipt_output = (
            Path(args.receipt_output).expanduser()
            if getattr(args, "receipt_output", None)
            else None
        )
        proposal_output = (
            Path(args.proposal_output).expanduser()
            if getattr(args, "proposal_output", None)
            else None
        )
        validate_canary_output_paths(
            activation=activation,
            bundle=bundle,
            state_dir=state_dir,
            plan_input=Path(args.plan).expanduser(),
            snapshot_input=Path(args.snapshot).expanduser(),
            approval_input=Path(args.approval).expanduser(),
            receipt_output=receipt_output,
            proposal_output=proposal_output,
        )
        material = persist_canary_material(
            activation,
            bundle,
            state_dir,
            receipt_output,
        )
        engine, _ledger = make_transaction_engine(state_dir)
    except (FlagWorkflowError, OSError, TypeError, ValueError) as exc:
        print(f"flags apply: activation refused: {exc}", file=sys.stderr)
        return 20

    print(
        f"Private rollback bundle: {material['rollback']}",
        file=sys.stderr,
    )

    try:
        provider = get_provider("mailapp", account=activation.scope[1])
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"flags apply: provider unavailable: {exc}", file=sys.stderr)
        return 1

    try:
        with provider:
            preflight = engine.preflight_transaction(
                plan=activation.plan,
                approval=activation.approval,
                provider=provider,
            )
            proposal = redacted_canary_proposal(activation, bundle)
            proposal["preflight_status"] = preflight.status
            proposal["preflight_target_count"] = len(preflight.verified)
            proposal["writes_performed"] = 0
            if preflight.status != "preflight_passed":
                proposal["error_code"] = "canary_preflight_refused"
                print(json.dumps(proposal, indent=2, sort_keys=True))
                return 20

            if proposal_output is not None:
                write_public_canary_proposal(
                    proposal, proposal_output
                )

            if getattr(args, "dry_run", False):
                proposal["status"] = "canary_ready_for_approval"
                proposal["rollback_receipt_ready"] = True
                print(json.dumps(proposal, indent=2, sort_keys=True))
                return 0

            result = engine.apply_canary_transaction(
                plan=activation.plan,
                approval=activation.approval,
                provider=provider,
                max_count=activation.cli_limit,
            )
    except FlagWorkflowError as exc:
        print(f"flags apply: activation refused: {exc}", file=sys.stderr)
        return 20
    except (OSError, RuntimeError) as exc:
        print(f"flags apply: provider failure: {exc}", file=sys.stderr)
        return 1

    output = redacted_canary_proposal(activation, bundle)
    output["status"] = result.status
    output["writes_performed"] = result.writes_performed
    output["verified_count"] = len(result.verified)
    output["error_code"] = (
        None if result.status == "applied"
        else "canary_apply_not_verified"
    )
    output["rollback_receipt_ready"] = True
    print(json.dumps(output, indent=2, sort_keys=True))
    if (
        result.status != "applied"
        or result.writes_performed != len(activation.selected)
        or len(result.verified) != len(activation.selected)
    ):
        return 20
    return 0


def cmd_flags_rollback(args: argparse.Namespace) -> int:
    """Prepare or execute rollback for one exact canary bundle."""
    if getattr(args, "canary", False) is not True:
        print(
            "NOT_READY: unrestricted flags rollback is disabled; explicit "
            "--canary is required and no provider was constructed.",
            file=sys.stderr,
        )
        return 89
    if getattr(args, "provider", None) != "mailapp":
        print(
            "flags rollback: canary rollback supports only mailapp",
            file=sys.stderr,
        )
        return 20

    from core.flag_activation import (
        default_flags_state_dir,
        load_canary_rollback,
        make_rollback_engine,
    )
    from core.flag_workflow import FlagWorkflowError, validate_plan_schema

    required = ("plan", "snapshot", "approval", "receipt")
    missing = [
        f"--{name}" for name in required
        if not getattr(args, name, None)
    ]
    if missing:
        print(
            "flags rollback: missing required artifact(s): "
            f"{', '.join(missing)}",
            file=sys.stderr,
        )
        return 20
    try:
        plan, _snapshot, bundle = load_canary_rollback(
            plan_path=Path(args.plan).expanduser(),
            snapshot_path=Path(args.snapshot).expanduser(),
            approval_path=Path(args.approval).expanduser(),
            receipt_path=Path(args.receipt).expanduser(),
        )
        mutations = {
            mutation.mutation_id: mutation
            for mutation in validate_plan_schema(plan)
        }
        first = mutations[bundle.receipts[0].mutation_id]
        requested_account = getattr(args, "account", None)
        if requested_account is not None \
                and requested_account != first.account:
            raise FlagWorkflowError(
                "CLI account does not match the rollback plan scope"
            )
        engine = make_rollback_engine(default_flags_state_dir(), plan)
    except (FlagWorkflowError, OSError, TypeError, ValueError) as exc:
        print(f"flags rollback: refused: {exc}", file=sys.stderr)
        return 20

    try:
        provider = get_provider("mailapp", account=first.account)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"flags rollback: provider unavailable: {exc}", file=sys.stderr)
        return 1
    try:
        with provider:
            result = engine.rollback_transactions(
                receipts=bundle.receipts,
                provider=provider,
                max_count=3,
                preflight_only=getattr(args, "dry_run", False),
            )
    except FlagWorkflowError as exc:
        print(f"flags rollback: refused: {exc}", file=sys.stderr)
        return 20
    except (OSError, RuntimeError) as exc:
        print(f"flags rollback: provider failure: {exc}", file=sys.stderr)
        return 1

    output = {
        "schema": "uma.flags.canary.rollback_result.public.v1",
        "canary_id": bundle.canary_id,
        "message_count": len(bundle.receipts),
        "plan_sha256": bundle.plan_sha256,
        "snapshot_sha256": bundle.snapshot_sha256,
        "policy_sha256": bundle.policy_sha256,
        "approval_sha256": bundle.approval_sha256,
        "rollback_bundle_sha256": bundle.content_hash,
        "status": result.status,
        "writes_performed": result.writes_performed,
        "verified_restored_count": sum(
            row.get("status") == "rolled_back"
            for row in result.results
        ),
        "already_rolled_back_count": sum(
            row.get("status") == "already_rolled_back"
            for row in result.results
        ),
        "not_applied_count": sum(
            row.get("status") == "not_applied"
            for row in result.results
        ),
        "failed_count": len(result.failed),
        "unattempted_count": len(result.unattempted),
        "error_code": (
            None
            if result.status in {
                "preflight_passed", "rolled_back", "already_rolled_back",
                "rollback_not_required",
            }
            else "canary_rollback_not_verified"
        ),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    accepted = (
        {
            "preflight_passed", "already_rolled_back",
            "rollback_not_required",
        }
        if getattr(args, "dry_run", False)
        else {
            "rolled_back", "already_rolled_back",
            "rollback_not_required",
        }
    )
    return 0 if result.status in accepted else 20


def cmd_flags_overrides(args: argparse.Namespace) -> int:
    """List POLICY DISAGREEMENTS between legacy policy and current state.

    HONEST LABELING: this is a heuristic policy-disagreement preview, NOT
    human-override detection. True override detection requires persisted
    automation state (core.flag_workflow.OverrideStore) and lands with the
    apply/ledger work.
    """
    if args.provider != "mailapp":
        print("flags overrides: only supported for mailapp provider", file=sys.stderr)
        return 1
    if not _require_flags_mailbox(args, "overrides"):
        return 2
    account = getattr(args, "account", None)
    if not isinstance(account, str) or not account.strip():
        print("flags overrides: --account is required", file=sys.stderr)
        return 2

    from providers.mailapp import MailAppProvider
    from core import flag_policy

    try:
        provider = get_provider(args.provider, account=args.account)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"flags overrides: provider unavailable: {exc}", file=sys.stderr)
        return 1
    if not isinstance(provider, MailAppProvider):
        print("flags overrides: mailapp provider required", file=sys.stderr)
        return 1

    try:
        with provider:
            result = provider.enumerate_flagged(
                mailbox=args.mailbox,
                limit=args.limit,
            )
    except (OSError, RuntimeError) as exc:
        print(f"flags overrides: enumeration failed: {exc}", file=sys.stderr)
        return 1

    if not result.complete:
        print(
            f"flags overrides: refusing {result.status} enumeration "
            f"({len(result.errors)} errors, "
            f"{result.inaccessible_count} inaccessible rows, "
            f"{result.timeout_count} timeouts, "
            f"{result.scanned_boundary.get('hidden_by_limit', 0)} hidden "
            "by limit)",
            file=sys.stderr,
        )
        return 20

    disagreements = []
    for r in result.rows:
        proposal = flag_policy.propose(r.sender, r.subject, r.flag_color)
        if not proposal.is_identity and proposal.reason_code != "purple_review":
            disagreements.append({
                "id": r.provider_id,
                "sender": r.sender,
                "subject": r.subject[:60],
                "observed_flag": r.flag_color.name_str,
                "policy_proposes": proposal.proposed_flag.name_str,
                "reason_code": proposal.reason_code,
            })

    print(f"\n{'=' * 80}")
    print(f"POLICY DISAGREEMENT PREVIEW — {len(disagreements)} messages")
    print("(NOT human-override detection; no persisted automation state yet.)")
    print(f"{'=' * 80}")
    for o in disagreements:
        print(
            f"  [{o['observed_flag']} -> {o['policy_proposes']}] "
            f"{o['sender'][:35]} {o['subject']}  ({o['reason_code']})"
        )
    if not disagreements:
        print("  No policy disagreements in scope.")
    print("\nNote: heuristic comparison only. True override detection "
          "requires persisted last-automation state.")
    return 0


def cmd_flags_explain(args: argparse.Namespace) -> int:
    """Explain the flag classification for a specific message."""
    if args.provider != "mailapp":
        print("flags explain: only supported for mailapp provider", file=sys.stderr)
        return 1
    if not _require_flags_mailbox(args, "explain"):
        return 2
    account = getattr(args, "account", None)
    if not isinstance(account, str) or not account.strip():
        print("flags explain: --account is required", file=sys.stderr)
        return 2

    message_id = str(args.message_ref)
    if (
        not message_id
        or not message_id.isascii()
        or not message_id.isdigit()
        or message_id[0] == "0"
    ):
        print(
            "flags explain: message reference must be a numeric Mail.app id: "
            f"{message_id!r}",
            file=sys.stderr,
        )
        return 1

    from core.models import MessageReference
    from providers.mailapp import MailAppProvider

    try:
        provider = get_provider(
            args.provider,
            account=args.account,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"flags explain: provider unavailable: {exc}", file=sys.stderr)
        return 1
    if not isinstance(provider, MailAppProvider):
        print("flags explain: mailapp provider required", file=sys.stderr)
        return 1
    message_ref = MessageReference(
        provider="mailapp",
        account=args.account,
        mailbox=args.mailbox,
        provider_id=message_id,
    )

    try:
        with provider:
            msg = provider.get_message_details_ref(message_ref)
    except (OSError, RuntimeError) as exc:
        print(f"flags explain: scoped lookup failed: {exc}", file=sys.stderr)
        return 1
    if not msg:
        print(f"Message not found: {message_ref}", file=sys.stderr)
        return 1

    flag_color = getattr(msg, 'flag_color', FlagColor.NO_FLAG)
    is_starred = msg.is_starred

    print(f"\n{'=' * 60}")
    print("MESSAGE EXPLANATION")
    print(f"{'=' * 60}")
    print(f"ID:          {msg.id}")
    print(f"Sender:      {msg.sender}")
    print(f"Subject:     {msg.subject}")
    print(f"Date:        {msg.date}")
    print(f"Read:        {msg.is_read}")
    print(f"Starred:     {is_starred} (boolean)")
    print(f"Flag Color:  {flag_color.name_str} ({flag_color.operator_posture})")

    from core import flag_policy
    proposal = flag_policy.propose(msg.sender, msg.subject, flag_color)
    if not proposal.is_identity:
        review_note = (
            " [review-only]" if proposal.review_required else ""
        )
        print(
            f"Policy proposes: {proposal.proposed_flag.name_str} "
            f"({proposal.proposed_flag.operator_posture}) "
            f"[{proposal.reason_code}]{review_note}"
        )
    else:
        print(f"Policy agrees: {proposal.proposed_flag.name_str}")

    combined = f"{msg.sender} {msg.subject}".lower()
    signals = []
    for rule_name, rule in LABEL_RULES.items():
        for pattern in rule["patterns"]:
            import re
            if re.search(pattern, combined, re.IGNORECASE):
                signals.append(f"  Rule match: {rule_name} (tier {rule.get('tier', 4)})")
                break
    if signals:
        print("\nClassification signals:")
        for s in signals[:10]:
            print(s)

    print(f"{'=' * 60}\n")
    return 0


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Multi-provider email automation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s label --provider gmail --query "has:nouserlabels"
  %(prog)s label --provider gmail --query "label:Misc/Other" --remove-label "Misc/Other"
  %(prog)s label --provider imap --host imap.gmail.com --gmail-extensions
  %(prog)s label --provider mailapp --account "iCloud"
  %(prog)s label --provider outlook --dry-run
  %(prog)s report --provider gmail
  %(prog)s health --provider gmail
  %(prog)s triage --provider gmail --top 20 --draft --name "Anthony"
  %(prog)s ops-summary --report ~/System/Reports/mail-triage/latest.json
  %(prog)s ops-refresh --report ~/System/Reports/mail-triage/latest.json
  %(prog)s mail-history-export --source ~/Library/Mail --since 2024-01-01 --until 2026-06-16
  %(prog)s mail-intel --history ~/System/Reports/mail-history/latest.json --ops-report ~/System/Reports/mail-triage/latest.json
  %(prog)s mail-historical-crosswalk --history ~/System/Reports/mail-history/latest.json --ops-report ~/System/Reports/mail-triage/latest.json
  %(prog)s mail-status --ops-report ~/System/Reports/mail-triage/latest.json --history ~/System/Reports/mail-history/latest.json
  %(prog)s mail-action-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json
  %(prog)s mail-resolver-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json
  %(prog)s mail-provider-surface-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json
  %(prog)s mail-resolver-ledger --intelligence ~/System/Reports/mail-history/latest-intelligence.json
  %(prog)s mail-github-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json
  %(prog)s mail-github-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json --ledger ~/.local/state/universal-mail-automation/mail-resolver-ledger.jsonl
  %(prog)s mail-followup-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json
  %(prog)s mail-followup-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json --ledger ~/.local/state/universal-mail-automation/mail-resolver-ledger.jsonl
  %(prog)s mail-external-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json
  %(prog)s mail-external-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json --attest-blockers
  %(prog)s mail-resolver-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --action-id action_... --resolver-status verified_resolved --reason-code github_reconciled --proof-type github_issue_pr_billing_or_security_state --provider github
  %(prog)s mail-action-ledger --intelligence ~/System/Reports/mail-history/latest-intelligence.json
  %(prog)s mail-action-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --action-id action_... --status waiting --reason-code awaiting_reply
  %(prog)s mail-evidence-review --history ~/System/Reports/mail-history/latest.json --evidence-id ev_... --ack-private
  %(prog)s mail-draft-package --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --ack-private
  %(prog)s mail-draft-approval --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --draft-id draft_... --decision approved --reason-code ready_to_send --ack-private
  %(prog)s mail-delivery-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --draft-id draft_... --delivery-status provider_draft_requested --reason-code approved_for_provider_draft --ack-private
        """,
    )

    # Global options
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--intake-json",
        action="store_true",
        help="Also emit UMA intake packet JSON for machine consumption",
    )

    # Provider options (shared across subcommands).  The flags group accepts
    # these on EITHER side of its nested subcommand.  Its child parser uses
    # suppressed defaults so an omitted child option cannot overwrite a value
    # already parsed by the parent (for example, ``flags --provider mailapp
    # audit``).
    def add_provider_options(
        target: argparse.ArgumentParser,
        *,
        suppress_defaults: bool = False,
    ) -> None:
        optional_default = (
            argparse.SUPPRESS if suppress_defaults else None
        )
        target.add_argument(
            "--provider", "-p",
            choices=["gmail", "imap", "mailapp", "outlook"],
            default=(
                argparse.SUPPRESS if suppress_defaults else "gmail"
            ),
            help="Email provider (default: gmail)",
        )
        target.add_argument(
            "--host",
            default=optional_default,
            help="IMAP host (for imap provider)",
        )
        target.add_argument(
            "--user",
            default=optional_default,
            help="IMAP username (for imap provider)",
        )
        target.add_argument(
            "--password",
            default=optional_default,
            help="IMAP password (for imap provider)",
        )
        target.add_argument(
            "--account",
            default=optional_default,
            help="Mail.app account name (for mailapp provider)",
        )
        target.add_argument(
            "--gmail-extensions",
            action="store_true",
            default=(argparse.SUPPRESS if suppress_defaults else False),
            help="Use Gmail IMAP extensions (for imap provider)",
        )

    provider_group = argparse.ArgumentParser(add_help=False)
    add_provider_options(provider_group)
    flags_provider_group = argparse.ArgumentParser(add_help=False)
    add_provider_options(flags_provider_group, suppress_defaults=True)

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Label command
    label_parser = subparsers.add_parser(
        "label",
        parents=[provider_group],
        help="Categorize and label emails",
    )
    label_parser.add_argument(
        "--query", "-q",
        default="has:nouserlabels",
        help="Query to filter messages (default: has:nouserlabels for Gmail)",
    )
    label_parser.add_argument(
        "--limit", "-l",
        type=int,
        default=1000,
        help="Maximum messages to process (default: 1000)",
    )
    label_parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Don't actually apply changes",
    )
    label_parser.add_argument(
        "--remove-label",
        help="Label to remove if a new category is found",
    )
    label_parser.add_argument(
        "--state-file",
        help="State file for resumption (default: none)",
    )
    label_parser.add_argument(
        "--tier-routing",
        action="store_true",
        help="Enable Eisenhower tier-based routing (categories + Action folders)",
    )
    label_parser.add_argument(
        "--vip-only",
        action="store_true",
        help="Only process emails from VIP senders (defined in config)",
    )
    label_parser.add_argument(
        "--audit-file",
        help="Path for the append-only triage receipt "
             "(default: audit/<provider>-triage.jsonl). Only the default audit/ "
             "directory is gitignored; a custom path is NOT auto-ignored and may "
             "contain real senders — see --redact-audit.",
    )
    label_parser.add_argument(
        "--no-audit",
        action="store_true",
        help="Disable the trust receipt (not recommended for apply runs)",
    )
    label_parser.add_argument(
        "--redact-audit",
        action="store_true",
        help="Record sender DOMAIN only (no local-part) — produces a shareable receipt",
    )
    label_parser.set_defaults(func=cmd_label)

    # Report command
    report_parser = subparsers.add_parser(
        "report",
        parents=[provider_group],
        help="Generate label statistics report",
    )
    report_parser.set_defaults(func=cmd_report)

    # Health command
    health_parser = subparsers.add_parser(
        "health",
        parents=[provider_group],
        help="Check provider connection health",
    )
    health_parser.set_defaults(func=cmd_health)

    # Escalate command
    escalate_parser = subparsers.add_parser(
        "escalate",
        parents=[provider_group],
        help="Re-triage emails based on age (escalate stale emails)",
    )
    escalate_parser.add_argument(
        "--query", "-q",
        default="",
        help="Query to filter messages for escalation check",
    )
    escalate_parser.add_argument(
        "--limit", "-l",
        type=int,
        default=500,
        help="Maximum messages to check (default: 500)",
    )
    escalate_parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Don't actually apply changes",
    )
    escalate_parser.add_argument(
        "--audit-file",
        help="Path for the append-only triage receipt "
             "(default: audit/<provider>-escalate.jsonl). Only the default audit/ "
             "directory is gitignored; a custom path is NOT auto-ignored and may "
             "contain real senders — see --redact-audit.",
    )
    escalate_parser.add_argument(
        "--no-audit",
        action="store_true",
        help="Disable the trust receipt (not recommended for apply runs)",
    )
    escalate_parser.add_argument(
        "--redact-audit",
        action="store_true",
        help="Record sender DOMAIN only (no local-part) — produces a shareable receipt",
    )
    escalate_parser.set_defaults(func=cmd_escalate)

    # Summary command
    summary_parser = subparsers.add_parser(
        "summary",
        parents=[provider_group],
        help="Generate email summary by priority tier",
    )
    summary_parser.add_argument(
        "--query", "-q",
        default="",
        help="Query to filter messages",
    )
    summary_parser.add_argument(
        "--limit", "-l",
        type=int,
        default=500,
        help="Maximum messages to analyze (default: 500)",
    )
    summary_parser.add_argument(
        "--format", "-f",
        choices=["table", "markdown", "json"],
        default="table",
        help="Output format (default: table)",
    )
    summary_parser.set_defaults(func=cmd_summary)

    # Pending command
    pending_parser = subparsers.add_parser(
        "pending",
        parents=[provider_group],
        help="List flagged/starred items needing action",
    )
    pending_parser.add_argument(
        "--limit", "-l",
        type=int,
        default=100,
        help="Maximum items to show (default: 100)",
    )
    pending_parser.add_argument(
        "--format", "-f",
        choices=["table", "markdown", "json"],
        default="table",
        help="Output format (default: table)",
    )
    pending_parser.set_defaults(func=cmd_pending)

    # VIP command
    vip_parser = subparsers.add_parser(
        "vip",
        parents=[provider_group],
        help="Show VIP sender activity",
    )
    vip_parser.add_argument(
        "--query", "-q",
        default="",
        help="Query to filter messages",
    )
    vip_parser.add_argument(
        "--limit", "-l",
        type=int,
        default=500,
        help="Maximum messages to scan (default: 500)",
    )
    vip_parser.add_argument(
        "--format", "-f",
        choices=["table", "markdown", "json"],
        default="table",
        help="Output format (default: table)",
    )
    vip_parser.set_defaults(func=cmd_vip)

    # Triage command — research + prioritization sort + voice-matched drafts
    triage_parser = subparsers.add_parser(
        "triage",
        parents=[provider_group],
        help="Research, prioritize and (optionally) draft replies for the mailbox",
    )
    triage_parser.add_argument(
        "--query", "-q",
        default="",
        help="Query to filter messages",
    )
    triage_parser.add_argument(
        "--limit", "-l",
        type=int,
        default=200,
        help="Maximum messages to triage (default: 200)",
    )
    triage_parser.add_argument(
        "--top", "-t",
        type=int,
        default=0,
        help="Show only the top N highest-priority items (default: all)",
    )
    triage_parser.add_argument(
        "--format", "-f",
        choices=["text", "markdown", "json"],
        default="text",
        help="Output format (default: text)",
    )
    triage_parser.add_argument(
        "--draft",
        action="store_true",
        help="Generate suggested replies in the user's voice for items needing a response",
    )
    triage_parser.add_argument(
        "--voice-file",
        help="Path to a saved voice profile JSON "
             "(default: ~/.config/mail_automation/voice.json)",
    )
    triage_parser.add_argument(
        "--samples-file",
        help="Path to a corpus of the user's sent messages to learn voice from "
             "(default: ~/.config/mail_automation/sent_samples.txt)",
    )
    triage_parser.add_argument(
        "--name",
        help="User's name for the draft signature",
    )
    triage_parser.set_defaults(func=cmd_triage)

    # Flags command group — seven-color workflow state for Mail.app
    flags_parser = subparsers.add_parser(
        "flags",
        parents=[provider_group],
        help="Seven-color flag workflow state operations (Mail.app only)",
    )
    flags_parser.set_defaults(provider="mailapp")
    flags_subparsers = flags_parser.add_subparsers(
        dest="flags_command",
        help="Flags subcommands",
        required=True,
    )

    # flags doctor
    flags_doctor_parser = flags_subparsers.add_parser(
        "doctor",
        parents=[flags_provider_group],
        help="Diagnose Mail.app colored flag capability and configuration",
    )
    flags_doctor_parser.set_defaults(func=cmd_flags_doctor)

    # flags audit
    flags_audit_parser = flags_subparsers.add_parser(
        "audit",
        parents=[flags_provider_group],
        help="Read-only inventory of flagged messages",
    )
    flags_audit_parser.add_argument(
        "--mailbox", "-m",
        type=_nonempty_arg,
        default="INBOX",
        help="Mailbox to audit (default: INBOX)",
    )
    flags_audit_parser.add_argument(
        "--limit", "-l",
        type=_positive_int_arg,
        default=500,
        help="Maximum messages to scan (default: 500)",
    )
    flags_audit_parser.add_argument(
        "--since-days",
        type=_positive_int_arg,
        default=None,
        help="Bound scan to messages received in last N days",
    )
    flags_audit_parser.add_argument(
        "--flagged-only",
        action="store_true",
        help="Only enumerate currently flagged messages",
    )
    flags_audit_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry run (no mutations, implied for audit)",
    )
    flags_audit_parser.add_argument(
        "--output", "-o",
        choices=["table", "json", "csv"],
        default="table",
        help="Output format (default: table)",
    )
    flags_audit_parser.add_argument(
        "--receipt",
        help="Path to write PUBLIC-SAFE (redacted) JSON receipt of audit results",
    )
    flags_audit_parser.add_argument(
        "--estate",
        action="store_true",
        help="Discover ALL account/mailbox surfaces and scan each "
             "(read-only). Per-surface limits apply; any failed surface "
             "breaks estate completeness.",
    )
    flags_audit_parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Emit a read-only partial report when the scan is incomplete "
             "(default: exit 20 on incomplete scans)",
    )
    flags_audit_parser.set_defaults(func=cmd_flags_audit)

    # flags plan — ARTIFACT-ONLY since Commit 5: requires a private
    # snapshot; no provider args, no mailbox/limit/since-days, no rescan.
    flags_plan_parser = flags_subparsers.add_parser(
        "plan",
        help="Generate migration plan from a PRIVATE SNAPSHOT (artifact-only)",
    )
    flags_plan_parser.add_argument(
        "--snapshot",
        required=True,
        help="Path to a private snapshot JSON (mode 0600 artifact of "
             "`flags audit`); REQUIRED — planning never rescans Mail.app",
    )
    flags_plan_parser.add_argument(
        "--output", "-o",
        help="Path to write immutable plan JSON (required)",
    )
    flags_plan_parser.set_defaults(func=cmd_flags_plan)

    # flags queue
    flags_queue_parser = flags_subparsers.add_parser(
        "queue",
        parents=[flags_provider_group],
        help=(
            "Show NOW/ACTION/WAITING/SCHEDULED/REVIEW/REFERENCE/LATER "
            "plus UNKNOWN evidence"
        ),
    )
    flags_queue_parser.add_argument(
        "--mailbox", "-m",
        type=_nonempty_arg,
        default="INBOX",
        help="Mailbox to scan (default: INBOX)",
    )
    flags_queue_parser.add_argument(
        "--limit", "-l",
        type=_positive_int_arg,
        default=200,
        help="Maximum messages to show (default: 200)",
    )
    flags_queue_parser.add_argument(
        "--output", "-o",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )
    flags_queue_parser.set_defaults(func=cmd_flags_queue)

    # flags apply
    flags_apply_parser = flags_subparsers.add_parser(
        "apply",
        parents=[flags_provider_group],
        help="Apply a flag mutation plan from a receipt",
    )
    flags_apply_parser.add_argument(
        "--plan",
        help="Path to the complete private plan JSON",
    )
    flags_apply_parser.add_argument(
        "--snapshot",
        help="Path to the complete private source snapshot JSON",
    )
    flags_apply_parser.add_argument(
        "--approval",
        help="Path to the exact private approval JSON",
    )
    flags_apply_parser.add_argument(
        "--canary",
        action="store_true",
        help="Enable only the bounded first-activation canary path",
    )
    flags_apply_parser.add_argument(
        "--limit", "-l",
        type=_first_canary_limit_arg,
        default=3,
        help="Maximum approved mutations; hard bounded to 1..3 (default: 3)",
    )
    flags_apply_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run full locked preflight and persist rollback material; write no flags",
    )
    flags_apply_parser.add_argument(
        "--receipt-output",
        help="Optional private output path for the rollback bundle",
    )
    flags_apply_parser.add_argument(
        "--proposal-output",
        help="Optional output path for the redacted canary proposal",
    )
    flags_apply_parser.set_defaults(func=cmd_flags_apply)

    # flags rollback
    flags_rollback_parser = flags_subparsers.add_parser(
        "rollback",
        parents=[flags_provider_group],
        help="Rollback a previously applied flag mutation plan",
    )
    flags_rollback_parser.add_argument(
        "--receipt",
        help="Path to the exact private canary rollback bundle JSON",
    )
    flags_rollback_parser.add_argument(
        "--plan",
        help="Path to the complete private plan JSON",
    )
    flags_rollback_parser.add_argument(
        "--snapshot",
        help="Path to the complete private source snapshot JSON",
    )
    flags_rollback_parser.add_argument(
        "--approval",
        help="Path to the exact private approval JSON used for apply",
    )
    flags_rollback_parser.add_argument(
        "--canary",
        action="store_true",
        help="Enable only the bounded canary rollback path",
    )
    flags_rollback_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run whole-canary rollback preflight with zero writes",
    )
    flags_rollback_parser.set_defaults(func=cmd_flags_rollback)

    # flags overrides
    flags_overrides_parser = flags_subparsers.add_parser(
        "overrides",
        parents=[flags_provider_group],
        help="Preview policy disagreements (not human-override detection)",
    )
    flags_overrides_parser.add_argument(
        "--mailbox", "-m",
        type=_nonempty_arg,
        default="INBOX",
        help="Mailbox to scan (default: INBOX)",
    )
    flags_overrides_parser.add_argument(
        "--limit", "-l",
        type=_positive_int_arg,
        default=200,
        help="Maximum messages to scan (default: 200)",
    )
    flags_overrides_parser.set_defaults(func=cmd_flags_overrides)

    # flags explain
    flags_explain_parser = flags_subparsers.add_parser(
        "explain",
        parents=[flags_provider_group],
        help="Explain the flag classification for a specific message",
    )
    flags_explain_parser.add_argument(
        "message_ref",
        help="Numeric Mail.app message ID within the requested scope",
    )
    flags_explain_parser.add_argument(
        "--mailbox", "-m",
        type=_nonempty_arg,
        default="INBOX",
        help="Mailbox containing the message (default: INBOX)",
    )
    flags_explain_parser.set_defaults(func=cmd_flags_explain)

    # Operator summary command - local report to canonical dashboard payload.
    ops_parser = subparsers.add_parser(
        "ops-summary",
        help="Emit the redacted UMA operator summary JSON",
    )
    ops_parser.add_argument(
        "--report",
        help="Path to latest.json (defaults to UMA_OPS_REPORT_PATH)",
    )
    ops_parser.add_argument(
        "--max-age-hours",
        type=float,
        default=None,
        help="Freshness threshold for the report (default: 12)",
    )
    ops_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    ops_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    ops_parser.set_defaults(func=cmd_ops_summary)

    # Operator refresh command - persist redacted summary and history.
    ops_refresh_parser = subparsers.add_parser(
        "ops-refresh",
        help="Persist the redacted UMA operator summary and history",
    )
    ops_refresh_parser.add_argument(
        "--report",
        help="Path to latest.json (defaults to UMA_OPS_REPORT_PATH)",
    )
    ops_refresh_parser.add_argument(
        "--run-mail-triage",
        action="store_true",
        help="Run the local read-only mail-triage producer before summarizing",
    )
    ops_refresh_parser.add_argument(
        "--mail-triage-bin",
        help="Path to mail-triage producer (defaults to UMA_MAIL_TRIAGE_BIN or user-local bin)",
    )
    ops_refresh_parser.add_argument(
        "--since",
        help="Inclusive YYYY-MM-DD passed to mail-triage when --run-mail-triage is set",
    )
    ops_refresh_parser.add_argument(
        "--until",
        help="Exclusive YYYY-MM-DD passed to mail-triage when --run-mail-triage is set",
    )
    ops_refresh_parser.add_argument(
        "--report-dir",
        help="Report directory passed to mail-triage and used for latest.json discovery",
    )
    ops_refresh_parser.add_argument(
        "--mail-index",
        help="Optional Apple Mail Envelope Index path passed to mail-triage",
    )
    ops_refresh_parser.add_argument(
        "--output-dir",
        help="Output directory for latest-summary.json and history "
             "(defaults to UMA_OPS_HISTORY_DIR or user-local state)",
    )
    ops_refresh_parser.add_argument(
        "--history-limit",
        type=int,
        default=100,
        help="Maximum history entries to keep in index.json (default: 100)",
    )
    ops_refresh_parser.add_argument(
        "--max-age-hours",
        type=float,
        default=None,
        help="Freshness threshold for the report (default: 12)",
    )
    ops_refresh_parser.add_argument(
        "--require-fresh",
        action="store_true",
        help="Exit 2 after writing if the report is stale",
    )
    ops_refresh_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    ops_refresh_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    ops_refresh_parser.set_defaults(func=cmd_ops_refresh)

    # Historical intelligence command - read-only past-mail mining.
    mail_intel_parser = subparsers.add_parser(
        "mail-intel",
        help="Emit redacted historical mail intelligence and ops reconciliation",
    )
    mail_intel_parser.add_argument(
        "--history",
        help="Path to historical mail export JSON (defaults to UMA_HISTORICAL_MAIL_PATH)",
    )
    mail_intel_parser.add_argument(
        "--ops-report",
        help="Optional latest.json ops report used to reconcile current lane visibility "
             "(defaults to UMA_OPS_REPORT_PATH)",
    )
    mail_intel_parser.add_argument(
        "--stale-days",
        type=int,
        default=14,
        help="Minimum age for stale missed-lead candidates (default: 14)",
    )
    mail_intel_parser.add_argument(
        "--output",
        help="Optional redacted intelligence output file; stdout becomes a safe receipt",
    )
    mail_intel_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_intel_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_intel_parser.set_defaults(func=cmd_mail_intel)

    # Historical export command - private raw-ish input for mail-intel.
    mail_history_export_parser = subparsers.add_parser(
        "mail-history-export",
        help="Write a private normalized historical mail export and print a safe receipt",
    )
    mail_history_export_parser.add_argument(
        "--source",
        help="Source file or directory (defaults to UMA_HISTORICAL_MAIL_SOURCE)",
    )
    mail_history_export_parser.add_argument(
        "--output",
        help="Private export path (defaults to UMA_HISTORICAL_MAIL_PATH or ~/System/Reports/mail-history/latest.json)",
    )
    mail_history_export_parser.add_argument(
        "--source-type",
        choices=["auto", "json", "jsonl", "mbox", "eml", "emlx", "emlx_dir"],
        default="auto",
        help="Source parser to use (default: auto)",
    )
    mail_history_export_parser.add_argument(
        "--since",
        help="Inclusive lower bound for received_at/date filtering, e.g. 2024-01-01",
    )
    mail_history_export_parser.add_argument(
        "--until",
        help="Exclusive upper bound for received_at/date filtering, e.g. 2026-06-16",
    )
    mail_history_export_parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum messages to write after date filtering",
    )
    mail_history_export_parser.add_argument(
        "--body-char-limit",
        type=int,
        default=4000,
        help="Maximum text/plain body characters copied per message (default: 4000)",
    )
    mail_history_export_parser.add_argument(
        "--mailbox-hint",
        help="Optional scope override such as Inbox, Archive, Sent, or All Mail",
    )
    mail_history_export_parser.add_argument(
        "--self-address",
        action="append",
        default=[],
        help="Address treated as outbound; may be repeated",
    )
    mail_history_export_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the receipt JSON",
    )
    mail_history_export_parser.add_argument(
        "--pretty-export",
        action="store_true",
        help="Pretty-print the private export file",
    )
    mail_history_export_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_history_export_parser.set_defaults(func=cmd_mail_history_export)

    # Historical crosswalk command - terminal accounting over all evidence.
    mail_crosswalk_parser = subparsers.add_parser(
        "mail-historical-crosswalk",
        help="Assign terminal statuses to every historical mail evidence item",
    )
    mail_crosswalk_parser.add_argument(
        "--history",
        help="Path to historical mail export JSON (defaults to UMA_HISTORICAL_MAIL_PATH)",
    )
    mail_crosswalk_parser.add_argument(
        "--ops-report",
        help="Optional latest.json ops report used to mark represented_in_ops",
    )
    mail_crosswalk_parser.add_argument(
        "--action-ledger",
        help="Optional JSONL action receipt ledger",
    )
    mail_crosswalk_parser.add_argument(
        "--resolver-ledger",
        help="Optional JSONL resolver receipt ledger",
    )
    mail_crosswalk_parser.add_argument(
        "--draft-approvals",
        help="Optional JSONL draft approval receipt ledger",
    )
    mail_crosswalk_parser.add_argument(
        "--delivery-ledger",
        help="Optional JSONL delivery receipt ledger",
    )
    mail_crosswalk_parser.add_argument(
        "--stale-days",
        type=int,
        default=14,
        help="Minimum age for stale missed-lead candidates (default: 14)",
    )
    mail_crosswalk_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum crosswalk items to include while keeping full counts (default: 100)",
    )
    mail_crosswalk_parser.add_argument(
        "--require-reconciled",
        action="store_true",
        help="Exit 2 if source messages do not reconcile to terminal statuses plus exclusions",
    )
    mail_crosswalk_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_crosswalk_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_crosswalk_parser.set_defaults(func=cmd_mail_historical_crosswalk)

    # Unified status command - public-safe UMA mail receipt.
    mail_status_parser = subparsers.add_parser(
        "mail-status",
        help="Emit the unified UMA mail status receipt",
    )
    mail_status_parser.add_argument(
        "--ops-report",
        help="Path to latest.json ops report (defaults to UMA_OPS_REPORT_PATH or user report path)",
    )
    mail_status_parser.add_argument(
        "--history",
        help="Path to historical mail export JSON (defaults to UMA_HISTORICAL_MAIL_PATH or user report path)",
    )
    mail_status_parser.add_argument(
        "--action-ledger",
        help="Optional JSONL action receipt ledger",
    )
    mail_status_parser.add_argument(
        "--resolver-ledger",
        help="Optional JSONL resolver receipt ledger",
    )
    mail_status_parser.add_argument(
        "--draft-approvals",
        help="Optional JSONL draft approval receipt ledger",
    )
    mail_status_parser.add_argument(
        "--delivery-ledger",
        help="Optional JSONL delivery receipt ledger",
    )
    mail_status_parser.add_argument(
        "--stale-days",
        type=int,
        default=14,
        help="Minimum age for stale missed-lead candidates (default: 14)",
    )
    mail_status_parser.add_argument(
        "--max-age-hours",
        type=float,
        default=None,
        help="Freshness threshold for the ops report (default: 12)",
    )
    mail_status_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum queue/crosswalk items to include while keeping full counts (default: 100)",
    )
    mail_status_parser.add_argument(
        "--output",
        help="Optional path to write the redacted status receipt",
    )
    mail_status_parser.add_argument(
        "--require-complete",
        action="store_true",
        help="Exit 2 if the status is not ok",
    )
    mail_status_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_status_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_status_parser.set_defaults(func=cmd_mail_status)

    # Action plan command - redacted next-action reducer over intelligence.
    mail_action_plan_parser = subparsers.add_parser(
        "mail-action-plan",
        help="Emit a redacted, approval-aware action plan from historical intelligence",
    )
    mail_action_plan_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_action_plan_parser.add_argument(
        "--max-items",
        type=int,
        default=40,
        help="Maximum action groups to include (default: 40)",
    )
    mail_action_plan_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_action_plan_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_action_plan_parser.set_defaults(func=cmd_mail_action_plan)

    # Resolver plan command - lane-specific official surface reducer.
    mail_resolver_plan_parser = subparsers.add_parser(
        "mail-resolver-plan",
        help="Emit redacted lane-specific resolver plans from historical intelligence",
    )
    mail_resolver_plan_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_resolver_plan_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum resolver groups to include (default: 100)",
    )
    mail_resolver_plan_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_resolver_plan_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_resolver_plan_parser.set_defaults(func=cmd_mail_resolver_plan)

    # Provider-surface plan command - next official provider/API resolver frontier.
    mail_provider_surface_plan_parser = subparsers.add_parser(
        "mail-provider-surface-plan",
        help="Emit a redacted provider-surface resolver frontier plan",
    )
    mail_provider_surface_plan_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_provider_surface_plan_parser.add_argument(
        "--max-items",
        type=int,
        default=20,
        help="Maximum provider surfaces to include (default: 20)",
    )
    mail_provider_surface_plan_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_provider_surface_plan_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_provider_surface_plan_parser.set_defaults(func=cmd_mail_provider_surface_plan)

    # Resolver ledger command - redacted official-surface proof state.
    mail_resolver_ledger_parser = subparsers.add_parser(
        "mail-resolver-ledger",
        help="Emit redacted resolver proof state merged with local receipts",
    )
    mail_resolver_ledger_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_resolver_ledger_parser.add_argument(
        "--ledger",
        help="Path to JSONL resolver receipt ledger (defaults to UMA_MAIL_RESOLVER_LEDGER_PATH or user-local state)",
    )
    mail_resolver_ledger_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum resolver groups to include (default: 100)",
    )
    mail_resolver_ledger_parser.add_argument(
        "--max-receipts",
        type=int,
        default=40,
        help="Maximum recent receipts to include (default: 40)",
    )
    mail_resolver_ledger_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_resolver_ledger_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_resolver_ledger_parser.set_defaults(func=cmd_mail_resolver_ledger)

    # GitHub resolver command - read-only official-surface snapshot.
    mail_github_resolver_parser = subparsers.add_parser(
        "mail-github-resolver",
        help="Emit a redacted read-only GitHub official-surface resolver snapshot",
    )
    mail_github_resolver_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_github_resolver_parser.add_argument(
        "--gh-bin",
        default="gh",
        help="GitHub CLI executable to use for read-only official-surface checks (default: gh)",
    )
    mail_github_resolver_parser.add_argument(
        "--query-limit",
        type=int,
        default=50,
        help="Bounded per-surface GitHub query limit (default: 50)",
    )
    mail_github_resolver_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum GitHub resolver action groups to include (default: 100)",
    )
    mail_github_resolver_parser.add_argument(
        "--skip-provider-queries",
        action="store_true",
        help="Build only the planned GitHub resolver mapping without calling gh",
    )
    mail_github_resolver_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_github_resolver_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_github_resolver_parser.set_defaults(func=cmd_mail_github_resolver)

    # GitHub resolver receipts command - local proof from read-only snapshot.
    mail_github_receipts_parser = subparsers.add_parser(
        "mail-github-resolver-receipts",
        help="Record redacted resolver receipts from a GitHub resolver snapshot",
    )
    mail_github_receipts_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_github_receipts_parser.add_argument(
        "--ledger",
        help="Path to JSONL resolver receipt ledger (defaults to UMA_MAIL_RESOLVER_LEDGER_PATH or user-local state)",
    )
    mail_github_receipts_parser.add_argument(
        "--gh-bin",
        default="gh",
        help="GitHub CLI executable to use for read-only official-surface checks (default: gh)",
    )
    mail_github_receipts_parser.add_argument(
        "--query-limit",
        type=int,
        default=50,
        help="Bounded per-surface GitHub query limit (default: 50)",
    )
    mail_github_receipts_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum GitHub resolver action groups to include (default: 100)",
    )
    mail_github_receipts_parser.add_argument(
        "--max-receipts",
        type=int,
        default=100,
        help="Maximum receipt candidates to record (default: 100)",
    )
    mail_github_receipts_parser.add_argument(
        "--skip-provider-queries",
        action="store_true",
        help="Build only the planned GitHub resolver mapping without calling gh; records no receipts",
    )
    mail_github_receipts_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_github_receipts_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_github_receipts_parser.set_defaults(func=cmd_mail_github_resolver_receipts)

    # Follow-up resolver command - read-only mail/LinkedIn follow-up snapshot.
    mail_followup_resolver_parser = subparsers.add_parser(
        "mail-followup-resolver",
        help="Emit a redacted mail/LinkedIn follow-up resolver snapshot",
    )
    mail_followup_resolver_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_followup_resolver_parser.add_argument(
        "--draft-approvals",
        help="Path to JSONL draft approval receipts (defaults to UMA_MAIL_DRAFT_APPROVAL_PATH or user-local state)",
    )
    mail_followup_resolver_parser.add_argument(
        "--delivery-ledger",
        help="Path to JSONL delivery receipts (defaults to UMA_MAIL_DELIVERY_LEDGER_PATH or user-local state)",
    )
    mail_followup_resolver_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum follow-up resolver action groups to include (default: 100)",
    )
    mail_followup_resolver_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_followup_resolver_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_followup_resolver_parser.set_defaults(func=cmd_mail_followup_resolver)

    # Follow-up resolver receipts command - local proof from approval/delivery receipts.
    mail_followup_receipts_parser = subparsers.add_parser(
        "mail-followup-resolver-receipts",
        help="Record resolver receipts from mail/LinkedIn follow-up proof",
    )
    mail_followup_receipts_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_followup_receipts_parser.add_argument(
        "--ledger",
        help="Path to JSONL resolver receipt ledger (defaults to UMA_MAIL_RESOLVER_LEDGER_PATH or user-local state)",
    )
    mail_followup_receipts_parser.add_argument(
        "--draft-approvals",
        help="Path to JSONL draft approval receipts (defaults to UMA_MAIL_DRAFT_APPROVAL_PATH or user-local state)",
    )
    mail_followup_receipts_parser.add_argument(
        "--delivery-ledger",
        help="Path to JSONL delivery receipts (defaults to UMA_MAIL_DELIVERY_LEDGER_PATH or user-local state)",
    )
    mail_followup_receipts_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum follow-up resolver action groups to include (default: 100)",
    )
    mail_followup_receipts_parser.add_argument(
        "--max-receipts",
        type=int,
        default=100,
        help="Maximum receipt candidates to record (default: 100)",
    )
    mail_followup_receipts_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_followup_receipts_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_followup_receipts_parser.set_defaults(func=cmd_mail_followup_resolver_receipts)

    # External resolver command - read-only official-surface lane snapshot.
    mail_external_resolver_parser = subparsers.add_parser(
        "mail-external-resolver",
        help="Emit a redacted external-surface resolver snapshot",
    )
    mail_external_resolver_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_external_resolver_parser.add_argument(
        "--ledger",
        help="Path to JSONL resolver receipt ledger (defaults to UMA_MAIL_RESOLVER_LEDGER_PATH or user-local state)",
    )
    mail_external_resolver_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum external resolver action groups to include (default: 100)",
    )
    mail_external_resolver_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_external_resolver_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_external_resolver_parser.set_defaults(func=cmd_mail_external_resolver)

    # External resolver receipts command - explicit local blocker attestations.
    mail_external_receipts_parser = subparsers.add_parser(
        "mail-external-resolver-receipts",
        help="Record resolver receipts from explicit external-surface attestations",
    )
    mail_external_receipts_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_external_receipts_parser.add_argument(
        "--ledger",
        help="Path to JSONL resolver receipt ledger (defaults to UMA_MAIL_RESOLVER_LEDGER_PATH or user-local state)",
    )
    mail_external_receipts_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum external resolver action groups to include (default: 100)",
    )
    mail_external_receipts_parser.add_argument(
        "--max-receipts",
        type=int,
        default=100,
        help="Maximum receipt candidates to record (default: 100)",
    )
    mail_external_receipts_parser.add_argument(
        "--attest-blockers",
        action="store_true",
        help="Explicitly record local blocker attestations for visible external actions",
    )
    mail_external_receipts_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_external_receipts_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_external_receipts_parser.set_defaults(func=cmd_mail_external_resolver_receipts)

    # Resolver receipt command - local redacted official-surface receipt.
    mail_resolver_receipt_parser = subparsers.add_parser(
        "mail-resolver-receipt",
        help="Append a redacted official-surface resolver receipt",
    )
    mail_resolver_receipt_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_resolver_receipt_parser.add_argument(
        "--ledger",
        help="Path to JSONL resolver receipt ledger (defaults to UMA_MAIL_RESOLVER_LEDGER_PATH or user-local state)",
    )
    mail_resolver_receipt_parser.add_argument("--action-id", required=True, help="Action id from the resolver plan")
    mail_resolver_receipt_parser.add_argument(
        "--resolver-status",
        required=True,
        choices=[
            "verified_waiting",
            "verified_blocked",
            "verified_resolved",
            "needs_follow_up",
            "not_found",
            "not_applicable",
        ],
        help="Resolver status to record",
    )
    mail_resolver_receipt_parser.add_argument(
        "--reason-code",
        required=True,
        choices=[
            "official_surface_checked",
            "external_state_matches_mail",
            "external_state_differs",
            "awaiting_provider",
            "awaiting_reply",
            "legal_review_complete",
            "billing_verified",
            "security_reviewed",
            "github_reconciled",
            "subscription_decision_recorded",
            "blocked_no_auth",
            "blocked_provider_unavailable",
            "duplicate",
            "not_actionable",
        ],
        help="Redacted reason code for the resolver status",
    )
    mail_resolver_receipt_parser.add_argument(
        "--proof-type",
        required=True,
        choices=[
            "action_receipt",
            "delivery_receipt",
            "draft_approval_receipt",
            "future_provider_send_receipt",
            "future_send_receipt_if_reply_needed",
            "github_issue_pr_billing_or_security_state",
            "legal_review_receipt",
            "manual_review_receipt",
            "official_payment_or_invoice_verification",
            "official_provider_status",
            "official_provider_verification",
            "official_subscription_status",
            "operator_decision",
        ],
        help="Proof type required by the current resolver plan",
    )
    mail_resolver_receipt_parser.add_argument(
        "--provider",
        default="manual",
        help="Redacted provider label, e.g. github, gmail, cloudflare, bank",
    )
    mail_resolver_receipt_parser.add_argument(
        "--external-reference",
        help="Optional external reference; only a hash is stored",
    )
    mail_resolver_receipt_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum resolver groups to load while validating action id (default: 100)",
    )
    mail_resolver_receipt_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_resolver_receipt_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_resolver_receipt_parser.set_defaults(func=cmd_mail_resolver_receipt)

    # Action ledger command - redacted status/proof over the action plan.
    mail_action_ledger_parser = subparsers.add_parser(
        "mail-action-ledger",
        help="Emit redacted action status merged with local receipts",
    )
    mail_action_ledger_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_action_ledger_parser.add_argument(
        "--ledger",
        help="Path to JSONL receipt ledger (defaults to UMA_MAIL_ACTION_LEDGER_PATH or user-local state)",
    )
    mail_action_ledger_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum action groups to include (default: 100)",
    )
    mail_action_ledger_parser.add_argument(
        "--max-receipts",
        type=int,
        default=40,
        help="Maximum recent receipts to include (default: 40)",
    )
    mail_action_ledger_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_action_ledger_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_action_ledger_parser.set_defaults(func=cmd_mail_action_ledger)

    # Action receipt command - append a local proof receipt.
    mail_action_receipt_parser = subparsers.add_parser(
        "mail-action-receipt",
        help="Append a redacted local receipt for an action-plan item",
    )
    mail_action_receipt_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_action_receipt_parser.add_argument(
        "--ledger",
        help="Path to JSONL receipt ledger (defaults to UMA_MAIL_ACTION_LEDGER_PATH or user-local state)",
    )
    mail_action_receipt_parser.add_argument(
        "--action-id",
        required=True,
        help="Redacted action id from uma.mail.action_plan.v1 or uma.mail.action_ledger.v1",
    )
    mail_action_receipt_parser.add_argument(
        "--status",
        dest="action_status",
        choices=["open", "reviewing", "waiting", "blocked", "resolved", "ignored"],
        required=True,
        help="New local action status",
    )
    mail_action_receipt_parser.add_argument(
        "--reason-code",
        choices=[
            "evidence_reviewed",
            "draft_prepared",
            "awaiting_reply",
            "portal_verified",
            "legal_waiting",
            "provider_blocked",
            "needs_human",
            "not_actionable",
            "duplicate",
            "reopened",
        ],
        required=True,
        help="Redacted reason code for the receipt",
    )
    mail_action_receipt_parser.add_argument(
        "--evidence-id",
        action="append",
        default=[],
        help="Optional redacted evidence id included in the receipt; may be repeated",
    )
    mail_action_receipt_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum action groups used to validate action id (default: 100)",
    )
    mail_action_receipt_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_action_receipt_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_action_receipt_parser.set_defaults(func=cmd_mail_action_receipt)

    # Evidence review command - private raw source lookup.
    mail_evidence_review_parser = subparsers.add_parser(
        "mail-evidence-review",
        help="Open a gated private source message for a redacted evidence id",
    )
    mail_evidence_review_parser.add_argument(
        "--history",
        help="Path to private historical mail export JSON (defaults to UMA_HISTORICAL_MAIL_PATH)",
    )
    mail_evidence_review_parser.add_argument(
        "--evidence-id",
        required=True,
        help="Redacted evidence id from uma.mail.intelligence.v1 or uma.mail.action_plan.v1",
    )
    mail_evidence_review_parser.add_argument(
        "--ack-private",
        action="store_true",
        help="Required acknowledgment that stdout will contain private source mail",
    )
    mail_evidence_review_parser.add_argument(
        "--body-char-limit",
        type=int,
        default=6000,
        help="Maximum body characters to include (default: 6000)",
    )
    mail_evidence_review_parser.add_argument(
        "--context-limit",
        type=int,
        default=6,
        help="Maximum same-thread context rows to include (default: 6)",
    )
    mail_evidence_review_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_evidence_review_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_evidence_review_parser.set_defaults(func=cmd_mail_evidence_review)

    # Draft package command - private draft candidates from verified evidence.
    mail_draft_package_parser = subparsers.add_parser(
        "mail-draft-package",
        help="Build private approval-gated draft candidates for an action id",
    )
    mail_draft_package_parser.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    mail_draft_package_parser.add_argument(
        "--history",
        help="Path to private historical mail export JSON (defaults to UMA_HISTORICAL_MAIL_PATH)",
    )
    mail_draft_package_parser.add_argument(
        "--action-id",
        required=True,
        help="Redacted draft_approval action id from uma.mail.action_plan.v1",
    )
    mail_draft_package_parser.add_argument(
        "--ack-private",
        action="store_true",
        help="Required acknowledgment that stdout will contain private draft content",
    )
    mail_draft_package_parser.add_argument(
        "--user-name",
        default="Anthony",
        help="Name used for the draft signature (default: Anthony)",
    )
    mail_draft_package_parser.add_argument(
        "--max-drafts",
        type=int,
        default=3,
        help="Maximum draft candidates to include (default: 3)",
    )
    mail_draft_package_parser.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum action groups used to validate action id (default: 100)",
    )
    mail_draft_package_parser.add_argument(
        "--body-char-limit",
        type=int,
        default=3000,
        help="Maximum source body characters inspected per evidence id (default: 3000)",
    )
    mail_draft_package_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_draft_package_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_draft_package_parser.set_defaults(func=cmd_mail_draft_package)

    draft_common = argparse.ArgumentParser(add_help=False)
    draft_common.add_argument(
        "--intelligence",
        help="Path to redacted intelligence JSON (defaults to UMA_HISTORICAL_INTELLIGENCE_PATH)",
    )
    draft_common.add_argument(
        "--history",
        help="Path to private historical mail export JSON (defaults to UMA_HISTORICAL_MAIL_PATH)",
    )
    draft_common.add_argument(
        "--approvals",
        help="Path to JSONL draft approval receipt ledger (defaults to UMA_MAIL_DRAFT_APPROVAL_PATH or user-local state)",
    )
    draft_common.add_argument(
        "--action-id",
        required=True,
        help="Redacted draft_approval action id from uma.mail.action_plan.v1",
    )
    draft_common.add_argument(
        "--ack-private",
        action="store_true",
        help="Required acknowledgment that private draft content will be validated",
    )
    draft_common.add_argument(
        "--user-name",
        default="Anthony",
        help="Name used for the draft signature (default: Anthony)",
    )
    draft_common.add_argument(
        "--max-drafts",
        type=int,
        default=3,
        help="Maximum draft candidates to build for validation (default: 3)",
    )
    draft_common.add_argument(
        "--max-items",
        type=int,
        default=100,
        help="Maximum action groups used to validate action id (default: 100)",
    )
    draft_common.add_argument(
        "--body-char-limit",
        type=int,
        default=3000,
        help="Maximum source body characters inspected per evidence id (default: 3000)",
    )

    mail_draft_approvals_parser = subparsers.add_parser(
        "mail-draft-approvals",
        parents=[draft_common],
        help="Emit redacted approval status for private draft candidates",
    )
    mail_draft_approvals_parser.add_argument(
        "--max-receipts",
        type=int,
        default=40,
        help="Maximum recent approval receipts to include (default: 40)",
    )
    mail_draft_approvals_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_draft_approvals_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_draft_approvals_parser.set_defaults(func=cmd_mail_draft_approvals)

    mail_draft_approval_parser = subparsers.add_parser(
        "mail-draft-approval",
        parents=[draft_common],
        help="Append a redacted local approval receipt for a draft candidate",
    )
    mail_draft_approval_parser.add_argument(
        "--draft-id",
        required=True,
        help="Draft id from uma.mail.draft_package.v1",
    )
    mail_draft_approval_parser.add_argument(
        "--decision",
        choices=["approved", "rejected", "revise"],
        required=True,
        help="Approval decision for the draft candidate",
    )
    mail_draft_approval_parser.add_argument(
        "--reason-code",
        choices=[
            "ready_to_send",
            "needs_edit",
            "fact_issue",
            "wrong_recipient",
            "stale_context",
            "legal_review",
            "duplicate",
            "not_actionable",
        ],
        required=True,
        help="Redacted reason code for the approval decision",
    )
    mail_draft_approval_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_draft_approval_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_draft_approval_parser.set_defaults(func=cmd_mail_draft_approval_receipt)

    mail_delivery_ledger_parser = subparsers.add_parser(
        "mail-delivery-ledger",
        parents=[draft_common],
        help="Emit redacted delivery intent/status for approved draft candidates",
    )
    mail_delivery_ledger_parser.add_argument(
        "--delivery",
        help="Path to JSONL delivery receipt ledger (defaults to UMA_MAIL_DELIVERY_LEDGER_PATH or user-local state)",
    )
    mail_delivery_ledger_parser.add_argument(
        "--max-receipts",
        type=int,
        default=40,
        help="Maximum recent delivery receipts to include (default: 40)",
    )
    mail_delivery_ledger_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_delivery_ledger_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_delivery_ledger_parser.set_defaults(func=cmd_mail_delivery_ledger)

    mail_delivery_receipt_parser = subparsers.add_parser(
        "mail-delivery-receipt",
        parents=[draft_common],
        help="Append a redacted local delivery receipt for an approved draft candidate",
    )
    mail_delivery_receipt_parser.add_argument(
        "--delivery",
        help="Path to JSONL delivery receipt ledger (defaults to UMA_MAIL_DELIVERY_LEDGER_PATH or user-local state)",
    )
    mail_delivery_receipt_parser.add_argument(
        "--draft-id",
        required=True,
        help="Draft id from uma.mail.draft_package.v1",
    )
    mail_delivery_receipt_parser.add_argument(
        "--delivery-status",
        choices=[
            "provider_draft_requested",
            "provider_draft_recorded",
            "send_requested",
            "sent_recorded",
            "blocked",
            "canceled",
        ],
        required=True,
        help="Redacted delivery status to record",
    )
    mail_delivery_receipt_parser.add_argument(
        "--reason-code",
        choices=[
            "approved_for_provider_draft",
            "operator_confirmed_external_draft",
            "operator_confirmed_external_send",
            "final_review_required",
            "provider_unavailable",
            "portal_required",
            "not_current",
            "duplicate",
            "policy_blocked",
        ],
        required=True,
        help="Redacted reason code for the delivery status",
    )
    mail_delivery_receipt_parser.add_argument(
        "--provider",
        default="manual",
        help="Provider/source label, e.g. gmail, mailapp, outlook, imap, or manual",
    )
    mail_delivery_receipt_parser.add_argument(
        "--external-reference",
        help="Optional provider/reference id; stored only as a hash in the receipt",
    )
    mail_delivery_receipt_parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    mail_delivery_receipt_parser.add_argument(
        "--sort-keys",
        action="store_true",
        help="Sort JSON object keys for stable diffing",
    )
    mail_delivery_receipt_parser.set_defaults(func=cmd_mail_delivery_receipt)

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
