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
import logging
import sys
import time
from typing import Optional

from core.rules import (
    LABEL_RULES,
    PRIORITY_LABELS,
    KEEP_IN_INBOX,
    PRIORITY_TIERS,
    categorize_message,
    categorize_with_tier,
    should_star,
    should_keep_in_inbox,
    is_vip_sender,
    is_time_sensitive,
    escalate_by_age,
    calculate_email_age_hours,
    get_tier_config,
)
from core.state import StateManager
from core.models import LabelAction, ProcessingResult
from core.config import load_config, apply_vip_senders_from_config
from providers.base import EmailProvider, ProviderCapabilities

# Logging setup
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)


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


def run_labeler(
    provider: EmailProvider,
    query: str,
    limit: int,
    dry_run: bool,
    remove_label: Optional[str],
    state_file: Optional[str],
    tier_routing: bool = False,
    vip_only: bool = False,
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
    vip_count = 0
    non_vip_skipped = 0
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
            msg_ids = [m.id for m in list_result.messages]
            if hasattr(provider, 'batch_get_details'):
                details = provider.batch_get_details(msg_ids)
            else:
                details = {m.id: provider.get_message_details(m.id) for m in list_result.messages}

            # Categorize and prepare actions
            actions = []
            for msg_id, msg in details.items():
                if not msg:
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

                # Build action
                action = LabelAction(message_id=msg_id)
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
                    if tier_config.star:
                        action.star = True

                    # Archive based on tier config
                    if not tier_config.keep_in_inbox:
                        action.archive = True
                else:
                    # Legacy behavior
                    if should_star(label):
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
                batch_result = provider.apply_actions(actions)
                result.success_count += batch_result.success_count
                result.error_count += batch_result.error_count
                result.errors.extend(batch_result.errors)
            else:
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
        )

    print_stats(result)
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

        msg_ids = [m.id for m in list_result.messages]
        if hasattr(provider, 'batch_get_details'):
            details = provider.batch_get_details(msg_ids)
        else:
            details = {m.id: provider.get_message_details(m.id) for m in list_result.messages}

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

        msg_ids = [m.id for m in list_result.messages]
        if hasattr(provider, 'batch_get_details'):
            details = provider.batch_get_details(msg_ids)
        else:
            details = {m.id: provider.get_message_details(m.id) for m in list_result.messages}

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
            msg_ids = [m.id for m in list_result.messages]
            if hasattr(provider, 'batch_get_details'):
                details = provider.batch_get_details(msg_ids)
            else:
                details = {m.id: provider.get_message_details(m.id) for m in list_result.messages}

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
        msg_ids = [m.id for m in list_result.messages]
        if hasattr(provider, 'batch_get_details'):
            details = provider.batch_get_details(msg_ids)
        else:
            details = {m.id: provider.get_message_details(m.id) for m in list_result.messages}

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
                    # Build escalation action
                    action = LabelAction(message_id=msg_id)

                    # Apply new tier category
                    if has_categories:
                        action.category = new_tier_config.name
                        action.category_color = new_tier_config.color

                    # Move to tier folder
                    if new_tier_config.folder:
                        action.target_folder = new_tier_config.folder

                    # Star if tier requires it
                    if new_tier_config.star:
                        action.star = True

                    actions.append(action)

        # Apply escalation actions
        if actions:
            batch_result = provider.apply_actions(actions)
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

    return 0 if result.error_count == 0 else 1


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
        """,
    )

    # Global options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging",
    )

    # Provider options (shared across subcommands)
    provider_group = argparse.ArgumentParser(add_help=False)
    provider_group.add_argument(
        "--provider", "-p",
        choices=["gmail", "imap", "mailapp", "outlook"],
        default="gmail",
        help="Email provider (default: gmail)",
    )
    provider_group.add_argument(
        "--host",
        help="IMAP host (for imap provider)",
    )
    provider_group.add_argument(
        "--user",
        help="IMAP username (for imap provider)",
    )
    provider_group.add_argument(
        "--password",
        help="IMAP password (for imap provider)",
    )
    provider_group.add_argument(
        "--account",
        help="Mail.app account name (for mailapp provider)",
    )
    provider_group.add_argument(
        "--gmail-extensions",
        action="store_true",
        help="Use Gmail IMAP extensions (for imap provider)",
    )

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

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
