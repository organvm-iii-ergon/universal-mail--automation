"""
Email categorization rules and matching logic.

This module contains the shared LABEL_RULES taxonomy and categorization
function used across all email providers. Rules are applied in priority
order (lower number = higher priority).

Usage:
    from core.rules import categorize_message, LABEL_RULES

    headers = [{"name": "From", "value": "github.com"}, {"name": "Subject", "value": "PR Review"}]
    label = categorize_message(headers)  # Returns "Work/Dev/GitHub"
"""

import re
from typing import Dict, List, Union, Optional

# Labels that should also be flagged/starred for priority handling in clients.
PRIORITY_LABELS = {
    "Work/Dev/GitHub",
    "Work/Dev/Code-Review",
    "Work/Dev/Infrastructure",
    "Tech/Security",
    "Finance/Payments",
    "Finance/Banking",
    "Awaiting Reply",
    "Personal",
}

# Labels that should REMAIN in the Inbox (High Priority / Human).
# Everything else will be Archived (removed from INBOX).
KEEP_IN_INBOX = {
    "Personal",
    "Awaiting Reply",
    "To Do",
    "To Respond",
}

# Label rules taxonomy with regex patterns and priorities.
# Lower priority number = higher precedence (matched first).
LABEL_RULES: Dict[str, Dict[str, Union[List[str], int]]] = {
    # Work / Development
    "Work/Dev/GitHub": {
        "patterns": [
            r"github\.com",
            r"notifications@github",
            r"@reply\.github\.com",
            r"copilot",
            r"ivi374forivi",
        ],
        "priority": 1,
    },
    "Work/Dev/Code-Review": {
        "patterns": [r"coderabb", r"sourcery", r"qodo", r"codacy", r"copilot", r"llamapre", r"pieces"],
        "priority": 2,
    },
    "Work/Dev/Infrastructure": {
        "patterns": [
            r"cloudflare",
            r"vercel",
            r"netlify",
            r"digitalocean",
            r"railway",
            r"render\\.com",
            r"newrelic",
            r"pieces\\.app",
            r"render",
            r"gitkraken",
            r"notion\\.so",
            r"backblaze",
            r"termius",
        ],
        "priority": 3,
    },
    # Real Estate / Projects
    "Work/RealEstate": {
        "patterns": [
            r"permit application",
            r"majesticbuilds",
            r"unit s",
            r"elv fr",
            r"tenant",
            r"lease",
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
            r"nav\.com",
            r"bankofamerica",
            r"wellsfargo",
            r"citi",
            r"usbank",
            r"ally",
            r"marcus",
            r"regions",
            r"pnc",
            r"lendingtree",
            r"trueaccord",
            r"moneylion",
            r"dave\\.com",
            r"nelnet",
            r"studentaid",
            r"loan",
            r"credit score",
            r"credit card",
            r"apr",
            r"refinance",
            r"overdraft",
            r"missionlane",
            r"lenme",
            r"credit report",
            r"collections",
            r"settle",
            r"settlement",
            r"debt",
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
            r"floatme",
            r"taxrise",
            r"beem",
            r"onepay",
            r"facebook.*receipt",
            r"meta.*receipt",
            r"ads receipt",
            r"billing issue",
            r"adobe",
            r"past due",
            r"overdue",
            r"declined",
            r"failed payment",
            r"autopay",
            r"renewal",
            r"subscription",
            r"paid",
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
            r"geico",
            r"facebook",
            r"support\\.facebook\\.com",
            r"business-updates\\.facebook\\.com",
            r"confirming.*login",
            r"google data.*download",
            r"security",
            r"sign in",
            r"unusual activity",
            r"suspicious",
            r"two[- ]factor",
            r"2fa",
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
            r"flash sale",
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
        "patterns": [
            r"fandango",
            r"audible",
            r"netflix",
            r"spotify",
            r"letterboxd",
            r"popcorn.?frights",
            r"warprecords",
            r"pluto",
            r"rotten.?tomato",
        ],
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
            r"ibo\\.org",
        ],
        "priority": 13,
    },
    # Professional Services
    "Professional/Jobs": {
        "patterns": [
            r"higheredjobs",
            r"indeed",
            r"linkedin.*jobs",
            r"glassdoor",
            r"jobot",
            r"builtin\.com",
            r"ziprecruiter",
            r"monster",
            r"justinwelsh",
            r"training overdue",
            r"compliance",
            r"training",
            r"ppe",
            r"course",
        ],
        "priority": 14,
    },
    # Domain Services
    "Services/Domain": {
        "patterns": [r"namecheap", r"godaddy", r"domain.*renew", r"dns", r"e\\.godaddy\\.com"],
        "priority": 15,
    },
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
            r"automatic reply",
            r"auto-reply",
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
            r"personal loan",
            r"credit card.*waiting",
            r"deal",
            r"last chance",
            r"save",
            r"coupon",
            r"offer ends",
            r"free shipping",
            r"clearance",
        ],
        "priority": 17,
    },
    # Personal
    "Personal": {
        "patterns": [
            r"padavano\.anthony",
            r"a\.j\.?\.?padavano@outlook\.com",
            r"a\.j\.?\.?padavano@icloud\.com",
            r"family",
            r"mom",
            r"dad",
        ],
        "priority": 18,
    },
    # Awaiting Action
    "Awaiting Reply": {
        "patterns": [r"awaiting.*reply", r"pending.*response"],
        "priority": 19,
    },
    # Default catch-all routed to a generic folder
    "Misc/Other": {"patterns": [r".*"], "priority": 999},
}


def categorize_message(
    headers: List[Dict[str, str]],
    rules: Optional[Dict[str, Dict[str, Union[List[str], int]]]] = None,
) -> str:
    """
    Categorize an email message based on headers.

    Matches sender and subject against LABEL_RULES patterns, returning the
    highest-priority (lowest number) matching label.

    Args:
        headers: List of header dicts with 'name' and 'value' keys.
                 Expected headers: 'From', 'Subject'
        rules: Optional custom rules dict. Defaults to LABEL_RULES.

    Returns:
        The best-matching label name, or "Misc/Other" if no match.

    Example:
        >>> headers = [{"name": "From", "value": "notifications@github.com"}]
        >>> categorize_message(headers)
        'Work/Dev/GitHub'
    """
    if rules is None:
        rules = LABEL_RULES

    sender = ""
    subject = ""
    for h in headers:
        name = h.get("name", "").lower()
        if name == "from":
            sender = h.get("value", "")
        if name == "subject":
            subject = h.get("value", "")

    combined_text = f"{sender} {subject}".lower()

    best_match = None
    best_priority = 9999

    for label_name, rule in rules.items():
        for pattern in rule["patterns"]:
            if re.search(pattern, combined_text, re.IGNORECASE):
                if rule["priority"] < best_priority:
                    best_match = label_name
                    best_priority = rule["priority"]
                    break  # Found match for this label, check next label

    return best_match or "Misc/Other"


def categorize_from_strings(sender: str, subject: str) -> str:
    """
    Convenience function to categorize from sender/subject strings directly.

    Args:
        sender: The 'From' header value
        subject: The 'Subject' header value

    Returns:
        The best-matching label name, or "Misc/Other" if no match.
    """
    headers = [
        {"name": "From", "value": sender},
        {"name": "Subject", "value": subject},
    ]
    return categorize_message(headers)


def get_label_priority(label: str) -> int:
    """Get the priority of a label. Returns 9999 if not found."""
    rule = LABEL_RULES.get(label)
    if rule:
        return rule["priority"]
    return 9999


def should_star(label: str) -> bool:
    """Check if a label should trigger starring/flagging."""
    return label in PRIORITY_LABELS


def should_keep_in_inbox(label: str) -> bool:
    """Check if a label should remain in inbox (not archived)."""
    return label in KEEP_IN_INBOX
