"""
Gmail Archive Labeling Automation
Author: Comprehensive Email Organization System
Purpose: Exhaustively label all emails in Gmail with semantic categories
"""

import re
import time
import socket
from collections import defaultdict
from datetime import datetime
import importlib.metadata as importlib_metadata

# Ensure packages_distributions is available on Python <3.10
if not hasattr(importlib_metadata, "packages_distributions"):
    try:
        import importlib_metadata as backport

        importlib_metadata.packages_distributions = backport.packages_distributions  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

from googleapiclient.errors import HttpError

import gmail_auth

# Gmail API scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# ============================================================================
# LABEL TAXONOMY - Comprehensive categorization rules
# ============================================================================

LABEL_RULES = {
    # Development & Code
    "Dev/GitHub": {
        "patterns": [
            r"github\.com",
            r"notifications@github",
            r"@reply\.github\.com",
            r"copilot",
            r"ivi374forivi",
        ],
        "priority": 1,
    },
    "Dev/Code-Review": {
        "patterns": [r"coderabb", r"sourcery", r"qodo", r"codacy", r"copilot", r"llamapre"],
        "priority": 2,
    },
    "Dev/Infrastructure": {
        "patterns": [
            r"cloudflare",
            r"vercel",
            r"netlify",
            r"digitalocean",
            r"railway",
            r"render\\.com",
            r"newrelic",
            r"pieces\\.app",
        ],
        "priority": 3,
    },
    # AI Services
    "AI/Services": {
        "patterns": [
            r"openai",
            r"anthropic",
            r"claude",
            r"x\.ai",
            r"xai\.com",
            r"xAI LLC",
            r"perplexity",
            r"meta\\.com",
            r"ollama",
        ],
        "priority": 4,
    },
    "AI/Grok": {"patterns": [r"grok", r"x\.ai.*grok"], "priority": 5},
    "AI/Data Exports": {"patterns": [r"data export", r"export is ready", r"download.*data"], "priority": 6},
    # Finance & Payments
    "Finance/Banking": {
        "patterns": [
            r"chase",
            r"capital.?one",
            r"verizon",
            r"gemini",
            r"experian",
            r"chime",
            r"kikoff",
            r"self\\.inc",
            r"nav\\.com",
            r"bankofamerica",
            r"wellsfargo",
            r"citi",
            r"usbank",
            r"ally",
            r"marcus",
            r"regions",
            r"pnc",
        ],
        "priority": 7,
    },
    "Finance/Payments": {
        "patterns": [
            r"paypal",
            r"stripe",
            r"kovo",
            r"cash.?app",
            r"true.?finance",
            r"square",
            r"braintree",
            r"plaid",
            r"capitalone",
            r"joingerald",
            r"vola",
            r"venmo",
            r"zelle",
            r"att",
            r"xfinity",
            r"spectrum",
            r"conedison",
            r"discover",
            r"american.?express",
            r"barclaycard",
            r"statement",
            r"invoice",
            r"payment.*due",
        ],
        "priority": 8,
    },
    # Subscriptions & Services
    "Tech/Security": {
        "patterns": [
            r"1password",
            r"security.*alert",
            r"login.*detected",
            r"new.*device",
            r"password.*reset",
            r"verification.*code",
            r"dropbox",
            r"todoist",
        ],
        "priority": 9,
    },
    # Commerce & Shopping
    "Shopping": {
        "patterns": [
            r"uber",
            r"amazon",
            r"ebay",
            r"etsy",
            r"walmart",
            r"target",
            r"deepview",
            r"squarespace",
            r"lafitness",
            r"bestbuy",
            r"costco",
            r"wayfair",
            r"chewy",
            r"zara",
            r"hm\.com",
            r"gap\.com",
            r"oldnavy",
            r"nike",
            r"adidas",
            r"nordstrom",
            r"macys",
            r"uniqlo",
            r"lululemon",
            r"order.*confirm",
            r"shipped",
            r"tracking",
        ],
        "priority": 10,
    },
    # Travel
    "Travel": {
        "patterns": [
            r"united\.com",
            r"aa\.com",
            r"delta\.com",
            r"southwest",
            r"jetblue",
            r"alaskaair",
            r"spirit",
            r"flyfrontier",
            r"marriott",
            r"hilton",
            r"hyatt",
            r"ihg",
            r"airbnb",
            r"vrbo",
            r"booking\.com",
            r"hotels\.com",
            r"expedia",
            r"kayak",
            r"priceline",
            r"orbitz",
            r"hotwire",
            r"itinerary",
            r"boarding.*pass",
            r"flight.*confirm",
        ],
        "priority": 11,
    },
    # Entertainment & Media
    "Entertainment": {
        "patterns": [r"fandango", r"audible", r"netflix", r"spotify", r"letterboxd", r"popcorn.?frights", r"warprecords"],
        "priority": 12,
    },
    # Education
    "Education/Research": {
        "patterns": [
            r"coursera",
            r"udemy",
            r"skillshare",
            r"edx",
            r"khanacademy",
            r"scholar\.google",
            r"researchgate",
            r"arxiv",
            r"academia\.edu",
            r"learning",
        ],
        "priority": 13,
    },
    # Professional Services
    "Professional/Jobs": {
        "patterns": [r"higheredjobs", r"indeed", r"linkedin.*jobs", r"glassdoor", r"jobot", r"builtin\\.com", r"ziprecruiter", r"monster"],
        "priority": 14,
    },
    # Domain Services
    "Services/Domain": {"patterns": [r"namecheap", r"godaddy", r"domain.*renew", r"dns", r"e\\.godaddy\\.com"], "priority": 15},
    # Notifications (catch-all for services)
    "Notification": {
        "patterns": [
            r"notification",
            r"alert",
            r"reminder",
            r"automatic.?appointment",
            r"udemy.*instructor",
            r"google.*workspace",
            r"trinity-health",
            r"deepview",
            r"todoist",
        ],
        "priority": 16,
    },
    # Marketing
    "Marketing": {
        "patterns": [
            r"unsubscribe",
            r"newsletter",
            r"promo",
            r"special.*offer",
            r"offer",
            r"discount",
            r"sale",
            r"hims",
            r"substack",
            r"scaleclients",
            r"collabwriting",
            r"beehiiv",
            r"coursera",
            r"jupitrr",
            r"myhumandesign",
            r"ibo\\.org",
        ],
        "priority": 17,
    },
    # Personal
    "Personal": {"patterns": [r"padavano\.anthony", r"family", r"mom", r"dad"], "priority": 18},
    # Awaiting Action
    "Awaiting Reply": {"patterns": [r"awaiting.*reply", r"pending.*response"], "priority": 19},
    # Default catch-all
    "Uncategorized": {"patterns": [r".*"], "priority": 999},
}


# ============================================================================
# AUTHENTICATION
# ============================================================================

def get_gmail_service():
    """Authenticate and return Gmail API service."""
    return gmail_auth.build_gmail_service(scopes=SCOPES)


# ============================================================================
# LABEL MANAGEMENT
# ============================================================================

def execute_with_retry(request, retries=4, base_sleep=1.0):
    """Execute a Google API request with simple exponential backoff."""
    for attempt in range(retries):
        try:
            return request.execute()
        except (HttpError, OSError, socket.error) as exc:  # noqa: B902
            if attempt == retries - 1:
                raise
            delay = base_sleep * (2 ** attempt)
            print(f"  ✗ Retryable error ({exc}); retrying in {delay:.1f}s...")
            time.sleep(delay)
        except Exception as exc:  # noqa: BLE001
            if attempt == retries - 1:
                raise
            delay = base_sleep * (2 ** attempt)
            print(f"  ✗ Retryable error ({exc}); retrying in {delay:.1f}s...")
            time.sleep(delay)


def get_or_create_label(service, label_name):
    """Get label ID, create if it doesn't exist."""
    try:
        results = execute_with_retry(service.users().labels().list(userId="me"))
        labels = results.get("labels", [])
        for label in labels:
            if label["name"] == label_name:
                return label["id"]

        label_object = {"name": label_name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
        created_label = execute_with_retry(service.users().labels().create(userId="me", body=label_object))
        print(f"✓ Created label: {label_name}")
        return created_label["id"]
    except Exception as exc:  # noqa: BLE001
        print(f"✗ Error with label {label_name}: {exc}")
        return None


# ============================================================================
# EMAIL CATEGORIZATION
# ============================================================================

def categorize_email(email_data):
    """Determine best label for an email based on sender/subject."""
    headers = email_data["payload"]["headers"]
    sender = ""
    subject = ""
    for header in headers:
        name = header["name"].lower()
        if name == "from":
            sender = header["value"]
        elif name == "subject":
            subject = header["value"]

    combined_text = f"{sender} {subject}".lower()

    best_match = None
    best_priority = 9999
    for label_name, rule_config in LABEL_RULES.items():
        for pattern in rule_config["patterns"]:
            if re.search(pattern, combined_text, re.IGNORECASE):
                if rule_config["priority"] < best_priority:
                    best_match = label_name
                    best_priority = rule_config["priority"]
                    break

    return best_match or "Uncategorized"


# ============================================================================
# BULK LABELING ENGINE
# ============================================================================

def label_all_unlabeled_emails(service, batch_size=500, max_emails=None, query="has:nouserlabels"):
    """
    Exhaustively label emails matching the query (default: no user labels).

    Args:
        service: Gmail API service.
        batch_size: Number of emails to process per batch (max 500).
        max_emails: Maximum total emails to process (None = all).
        query: Gmail search query to select messages (defaults to has:nouserlabels).
    """
    label_id_cache = {}
    for label_name in LABEL_RULES.keys():
        label_id = get_or_create_label(service, label_name)
        if label_id:
            label_id_cache[label_name] = label_id
    uncategorized_id = label_id_cache.get("Uncategorized")

    print(f"\n{'='*70}")
    print("Gmail Archive Exhaustive Labeling - Started")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Query: {query}")
    print(f"{'='*70}\n")

    stats = defaultdict(int)
    total_processed = 0
    page_token = None

    try:
        while True:
            results = execute_with_retry(
                service.users().messages().list(
                    userId="me",
                    q=query,
                    maxResults=min(batch_size, 500),
                    pageToken=page_token,
                )
            )
            messages = results.get("messages", [])
            if not messages:
                print("\n✓ No more unlabeled emails found!")
                break

            print(f"\n📧 Processing batch of {len(messages)} emails...")

            for idx, message in enumerate(messages, 1):
                try:
                    email_data = execute_with_retry(
                        service.users().messages().get(
                            userId="me",
                            id=message["id"],
                            format="metadata",
                            metadataHeaders=["From", "Subject"],
                        )
                    )

                    label_name = categorize_email(email_data)
                    label_id = label_id_cache.get(label_name)
                    if label_id:
                        body = {"addLabelIds": [label_id]}
                        if uncategorized_id and label_name != "Uncategorized":
                            body["removeLabelIds"] = [uncategorized_id]
                        execute_with_retry(service.users().messages().modify(userId="me", id=message["id"], body=body))

                        stats[label_name] += 1
                        total_processed += 1
                        if idx % 50 == 0:
                            print(f"  ⚡ Processed {idx}/{len(messages)} in batch...")

                    if idx % 100 == 0:
                        time.sleep(1)
                except Exception as exc:  # noqa: BLE001
                    print(f"  ✗ Error processing email {message['id']}: {exc}")
                    continue

            if max_emails and total_processed >= max_emails:
                print(f"\n⚠️  Reached maximum of {max_emails} emails")
                break

            page_token = results.get("nextPageToken")
            if not page_token:
                break

            print(f"\n📊 Progress: {total_processed} emails labeled so far")
            print("Current distribution:")
            for label, count in sorted(stats.items(), key=lambda item: item[1], reverse=True)[:5]:
                print(f"  • {label}: {count}")

    except KeyboardInterrupt:
        print("\n\n⚠️  Process interrupted by user")
    except Exception as exc:  # noqa: BLE001
        print(f"\n✗ Fatal error: {exc}")
    finally:
        print(f"\n{'='*70}")
        print("FINAL STATISTICS")
        print(f"{'='*70}")
        print(f"Total emails processed: {total_processed:,}")
        print("\nLabel distribution:")
        for label, count in sorted(stats.items(), key=lambda item: item[1], reverse=True):
            percentage = (count / total_processed * 100) if total_processed else 0
            print(f"  {label:30} {count:6,} ({percentage:5.1f}%)")
        print(f"\n{'='*70}")
        print(f"Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*70}\n")
        return stats


# ============================================================================
# VERIFICATION
# ============================================================================

def verify_labeling_complete(service):
    """Check how many unlabeled emails remain."""
    try:
        results = service.users().messages().list(userId="me", q="has:nouserlabels", maxResults=1).execute()
        remaining = results.get("resultSizeEstimate", 0)
        if remaining == 0:
            print("\n✓✓✓ SUCCESS: All emails are now labeled! ✓✓✓")
            return True

        print(f"\n⚠️  {remaining:,} unlabeled emails still remain")
        return False
    except Exception as exc:  # noqa: BLE001
        print(f"✗ Error checking status: {exc}")
        return False


# ============================================================================
# MAIN EXECUTION
# ============================================================================

def main():
    """Main execution function."""
    print("=" * 70)
    print(" Gmail Archive Exhaustive Labeling System")
    print(" Purpose: Label all emails systematically")
    print("=" * 70)

    print("\n🔐 Authenticating with Gmail API...")
    service = get_gmail_service()
    print("✓ Authentication successful!")

    print("\n🚀 Starting exhaustive labeling process...")
    print("   This will process ALL unlabeled emails in your archive")
    print("   Press Ctrl+C at any time to pause\n")

    label_all_unlabeled_emails(service, batch_size=500, max_emails=None)

    print("\n🔍 Verifying labeling completeness...")
    verify_labeling_complete(service)

    print("\n✓ Labeling run complete.")


if __name__ == "__main__":
    main()
