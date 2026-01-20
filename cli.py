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
    categorize_message,
    should_star,
    should_keep_in_inbox,
)
from core.state import StateManager
from core.models import LabelAction, ProcessingResult
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

    Returns:
        ProcessingResult with statistics
    """
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

                # Convert to headers format for categorization
                headers = [
                    {"name": "From", "value": msg.sender},
                    {"name": "Subject", "value": msg.subject},
                ]
                label = categorize_message(headers)
                stats[label] = stats.get(label, 0) + 1
                result.add_label_stat(label)

                # Build action
                action = LabelAction(message_id=msg_id)
                action.add_labels.append(label)

                if should_star(label):
                    action.star = True

                if not should_keep_in_inbox(label):
                    action.archive = True

                if remove_label and label != remove_label:
                    action.remove_labels.append(remove_label)

                actions.append(action)
                logger.debug(f"Message {msg_id}: {msg.sender[:30]}... -> {label}")

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

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.command:
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
