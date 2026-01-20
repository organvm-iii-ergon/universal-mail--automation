"""
Shared email categorization rules.

Defines the LABEL_RULES taxonomy, priority labels, priority tiers (Eisenhower matrix),
and categorization functions used across all email providers.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple


# ============================================================================
# PRIORITY TIER SYSTEM (Eisenhower Matrix)
# ============================================================================

@dataclass(frozen=True)
class PriorityTier:
    """Configuration for a priority tier."""
    number: int
    name: str
    color: str
    folder: Optional[str]
    keep_in_inbox: bool
    star: bool


PRIORITY_TIERS: Dict[int, PriorityTier] = {
    1: PriorityTier(
        number=1,
        name="Critical",
        color="red",
        folder="Action/Critical",
        keep_in_inbox=True,
        star=True,
    ),
    2: PriorityTier(
        number=2,
        name="Important",
        color="yellow",
        folder="Action/Important",
        keep_in_inbox=True,
        star=False,
    ),
    3: PriorityTier(
        number=3,
        name="Delegate",
        color="blue",
        folder="Action/Delegate",
        keep_in_inbox=False,
        star=False,
    ),
    4: PriorityTier(
        number=4,
        name="Reference",
        color="green",
        folder=None,  # Just categorize, archive
        keep_in_inbox=False,
        star=False,
    ),
}

# ============================================================================
# LABEL TAXONOMY - Comprehensive categorization rules
# ============================================================================

LABEL_RULES: Dict[str, Dict[str, Any]] = {
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
        "tier": 2,  # Important - code reviews may need attention
        "time_sensitive": False,
    },
    "Dev/Code-Review": {
        "patterns": [r"coderabb", r"sourcery", r"qodo", r"codacy", r"copilot", r"llamapre"],
        "priority": 2,
        "tier": 2,  # Important - reviews need response
        "time_sensitive": True,
    },
    "Dev/Infrastructure": {
        "patterns": [
            r"cloudflare",
            r"vercel",
            r"netlify",
            r"digitalocean",
            r"railway",
            r"render\.com",
            r"newrelic",
            r"pieces\.app",
            r"hashicorp",
        ],
        "priority": 3,
        "tier": 3,  # Delegate/Monitor - alerts can be checked later
        "time_sensitive": False,
    },
    "Dev/GameDev": {
        "patterns": [r"unity3d\.com", r"unity\.com", r"unrealengine", r"godotengine"],
        "priority": 3,
        "tier": 3,
        "time_sensitive": False,
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
            r"meta\.com",
            r"ollama",
            r"sudowrite",
        ],
        "priority": 4,
        "tier": 3,  # Delegate - informational
        "time_sensitive": False,
    },
    "AI/Grok": {
        "patterns": [r"grok", r"x\.ai.*grok"],
        "priority": 5,
        "tier": 3,
        "time_sensitive": False,
    },
    "AI/Data Exports": {
        "patterns": [r"data export", r"export is ready", r"download.*data"],
        "priority": 6,
        "tier": 2,  # Important - exports may expire
        "time_sensitive": True,
    },
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
            r"self\.inc",
            r"nav\.com",
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
        "tier": 1,  # Critical - financial alerts
        "time_sensitive": True,
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
        "tier": 2,  # Important - bills and payments
        "time_sensitive": True,
    },
    "Finance/Tax": {
        "patterns": [
            r"intuit",
            r"turbotax",
            r"hrblock",
            r"taxact",
            r"taxslayer",
            r"irs\.gov",
            r"taxrise",
        ],
        "priority": 8,
        "tier": 2,  # Important - tax deadlines
        "time_sensitive": True,
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
            r"login\.gov",
        ],
        "priority": 9,
        "tier": 1,  # Critical - security alerts
        "time_sensitive": True,
    },
    "Tech/Google": {
        "patterns": [
            r"@google\.com",
            r"cloudsupport@",
            r"google.*cloud",
            r"gcp",
            r"workspace",
            r"payments\.google\.com",
        ],
        "priority": 9,
        "tier": 2,  # Important - support cases
        "time_sensitive": True,
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
            r"fjallraven",
        ],
        "priority": 10,
        "tier": 4,  # Reference - order confirmations
        "time_sensitive": False,
    },
    # Health & Pharmacy
    "Personal/Health": {
        "patterns": [
            r"walgreens",
            r"cvs",
            r"pharmacy",
            r"prescription",
            r"health\.nyc\.gov",
            r"trinity-health",
            r"myhealth",
        ],
        "priority": 10,
        "tier": 2,  # Important - health matters
        "time_sensitive": True,
    },
    # Social Networks
    "Social/LinkedIn": {
        "patterns": [
            r"linkedin\.com",
            r"linkedin.*network",
            r"linkedin.*job",
        ],
        "priority": 11,
        "tier": 3,  # Delegate - social can wait
        "time_sensitive": False,
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
        "tier": 2,  # Important - travel may need action
        "time_sensitive": True,
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
            r"musescore",
            r"justwatch",
            r"thefilmjunkies",
            r"louisck",
        ],
        "priority": 12,
        "tier": 4,  # Reference
        "time_sensitive": False,
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
            r"orcid\.org",
        ],
        "priority": 13,
        "tier": 3,  # Delegate - can be reviewed later
        "time_sensitive": False,
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
            r"recruiterflow",
        ],
        "priority": 14,
        "tier": 2,  # Important - job opportunities
        "time_sensitive": True,
    },
    "Professional/Legal": {
        "patterns": [
            r"legalzoom",
            r"longofirm",
            r"law\.com",
            r"attorney",
            r"legal.*notice",
        ],
        "priority": 14,
        "tier": 2,  # Important - legal matters
        "time_sensitive": True,
    },
    # Domain Services
    "Services/Domain": {
        "patterns": [r"namecheap", r"godaddy", r"domain.*renew", r"dns", r"e\.godaddy\.com"],
        "priority": 15,
        "tier": 2,  # Important - domain renewals critical
        "time_sensitive": True,
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
        ],
        "priority": 16,
        "tier": 3,  # Delegate - informational
        "time_sensitive": False,
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
            r"ibo\.org",
            r"sendfox",
        ],
        "priority": 17,
        "tier": 4,  # Reference - archive
        "time_sensitive": False,
    },
    # Cloud Storage & Files
    "Tech/Storage": {
        "patterns": [
            r"filerev",
            r"box\.com",
            r"onedrive",
            r"gdrive",
            r"icloud",
            r"sync\.com",
        ],
        "priority": 17,
        "tier": 3,  # Delegate
        "time_sensitive": False,
    },
    # Government & Official
    "Personal/Government": {
        "patterns": [
            r"\.gov$",
            r"@.*\.gov",
            r"flhsmv",
            r"passport",
            r"social.*security",
            r"ssa\.gov",
            r"irs\.gov",
            r"dmv",
            r"state\.fl\.us",
        ],
        "priority": 17,
        "tier": 1,  # Critical - government matters
        "time_sensitive": True,
    },
    # Personal
    "Personal": {
        "patterns": [r"padavano\.anthony", r"family", r"mom", r"dad"],
        "priority": 18,
        "tier": 1,  # Critical - personal emails
        "time_sensitive": True,
    },
    # Awaiting Action
    "Awaiting Reply": {
        "patterns": [r"awaiting.*reply", r"pending.*response"],
        "priority": 19,
        "tier": 2,  # Important - needs follow-up
        "time_sensitive": True,
    },
    # Default catch-all
    "Misc/Other": {
        "patterns": [r".*"],
        "priority": 999,
        "tier": 4,  # Reference - uncategorized
        "time_sensitive": False,
    },
}

# Labels that should trigger starring (high priority)
PRIORITY_LABELS = {
    "Finance/Banking",
    "Tech/Security",
}

# Labels that should remain in inbox (not archived)
KEEP_IN_INBOX = {
    "Finance/Banking",
    "Tech/Security",
    "Personal",
    "Awaiting Reply",
}


# ============================================================================
# VIP SENDER SYSTEM
# ============================================================================

@dataclass
class VIPSender:
    """Configuration for a VIP sender."""
    pattern: str
    tier: int
    star: bool
    label_override: Optional[str] = None  # Override the matched label
    note: str = ""  # Human-readable note


# VIP senders always get priority treatment regardless of category
# Patterns are matched against the sender (From header)
VIP_SENDERS: Dict[str, VIPSender] = {
    # Example VIP patterns (customize for your use case)
    # "ceo@company.com": VIPSender(
    #     pattern=r"ceo@company\.com",
    #     tier=1,
    #     star=True,
    #     note="CEO",
    # ),
    # ".*@important-client.com": VIPSender(
    #     pattern=r".*@important-client\.com",
    #     tier=1,
    #     star=True,
    #     note="Important client domain",
    # ),
}


# ============================================================================
# CATEGORIZATION FUNCTIONS
# ============================================================================

@dataclass
class CategorizationResult:
    """Result of categorizing an email."""
    label: str
    tier: int
    time_sensitive: bool
    tier_config: PriorityTier
    is_vip: bool = False
    vip_note: str = ""


def check_vip_sender(sender: str) -> Optional[Tuple[VIPSender, str]]:
    """
    Check if a sender matches a VIP pattern.

    Args:
        sender: The From header value

    Returns:
        Tuple of (VIPSender, matched_key) if VIP, None otherwise
    """
    sender_lower = sender.lower()
    for key, vip in VIP_SENDERS.items():
        if re.search(vip.pattern, sender_lower, re.IGNORECASE):
            return (vip, key)
    return None


def is_vip_sender(sender: str) -> bool:
    """Check if a sender is a VIP."""
    return check_vip_sender(sender) is not None


def get_vip_senders() -> Dict[str, VIPSender]:
    """Get the current VIP senders dict."""
    return VIP_SENDERS.copy()


def add_vip_sender(
    key: str,
    pattern: str,
    tier: int = 1,
    star: bool = True,
    label_override: Optional[str] = None,
    note: str = "",
) -> None:
    """
    Add a VIP sender at runtime.

    Args:
        key: Unique key for this VIP (usually the pattern or email)
        pattern: Regex pattern to match sender
        tier: Priority tier (1=Critical, 2=Important)
        star: Whether to star messages from this sender
        label_override: Optional label to use instead of categorization
        note: Human-readable note about this VIP
    """
    VIP_SENDERS[key] = VIPSender(
        pattern=pattern,
        tier=tier,
        star=star,
        label_override=label_override,
        note=note,
    )


def categorize_message(headers: List[Dict[str, str]]) -> str:
    """
    Categorize an email based on headers.

    Args:
        headers: List of header dicts with 'name' and 'value' keys

    Returns:
        Label name from LABEL_RULES
    """
    sender = ""
    subject = ""
    for header in headers:
        name = header.get("name", "").lower()
        if name == "from":
            sender = header.get("value", "")
        elif name == "subject":
            subject = header.get("value", "")

    return categorize_from_strings(sender, subject)


def categorize_from_strings(sender: str, subject: str) -> str:
    """
    Categorize an email based on sender and subject strings.

    Args:
        sender: The From header value
        subject: The Subject header value

    Returns:
        Label name from LABEL_RULES
    """
    result = categorize_with_tier(sender, subject)
    return result.label


def categorize_with_tier(sender: str, subject: str) -> CategorizationResult:
    """
    Categorize an email and return full tier information.

    VIP senders are checked first and override normal categorization rules.

    Args:
        sender: The From header value
        subject: The Subject header value

    Returns:
        CategorizationResult with label, tier, time_sensitive, and VIP info
    """
    # Check VIP senders first - they get priority treatment
    vip_match = check_vip_sender(sender)
    if vip_match:
        vip, vip_key = vip_match
        tier = vip.tier
        tier_config = PRIORITY_TIERS.get(tier, PRIORITY_TIERS[1])

        # Use label override if specified, otherwise do normal categorization
        if vip.label_override:
            label = vip.label_override
            rule = LABEL_RULES.get(label, {"time_sensitive": True})
            time_sensitive = rule.get("time_sensitive", True)
        else:
            # Still categorize normally but use VIP tier
            combined_text = f"{sender} {subject}".lower()
            label = _find_best_label(combined_text)
            rule = LABEL_RULES.get(label, {})
            time_sensitive = rule.get("time_sensitive", True)  # VIP is time-sensitive

        return CategorizationResult(
            label=label,
            tier=tier,
            time_sensitive=time_sensitive,
            tier_config=tier_config,
            is_vip=True,
            vip_note=vip.note,
        )

    # Normal categorization
    combined_text = f"{sender} {subject}".lower()
    label = _find_best_label(combined_text)

    rule = LABEL_RULES[label]
    tier = rule.get("tier", 4)
    time_sensitive = rule.get("time_sensitive", False)
    tier_config = PRIORITY_TIERS.get(tier, PRIORITY_TIERS[4])

    return CategorizationResult(
        label=label,
        tier=tier,
        time_sensitive=time_sensitive,
        tier_config=tier_config,
        is_vip=False,
        vip_note="",
    )


def _find_best_label(combined_text: str) -> str:
    """Find the best matching label for combined sender+subject text."""
    best_match = None
    best_priority = 9999

    for label_name, rule_config in LABEL_RULES.items():
        for pattern in rule_config["patterns"]:
            if re.search(pattern, combined_text, re.IGNORECASE):
                if rule_config["priority"] < best_priority:
                    best_match = label_name
                    best_priority = rule_config["priority"]
                    break

    return best_match or "Misc/Other"


def get_tier_for_label(label: str) -> int:
    """Get the priority tier for a label."""
    rule = LABEL_RULES.get(label, {})
    return rule.get("tier", 4)


def get_tier_config(tier: int) -> PriorityTier:
    """Get the configuration for a priority tier."""
    return PRIORITY_TIERS.get(tier, PRIORITY_TIERS[4])


def should_star(label: str) -> bool:
    """Check if a label should trigger starring."""
    # Check both legacy PRIORITY_LABELS and new tier-based starring
    if label in PRIORITY_LABELS:
        return True
    tier = get_tier_for_label(label)
    tier_config = get_tier_config(tier)
    return tier_config.star


def should_keep_in_inbox(label: str) -> bool:
    """Check if a label should remain in inbox."""
    # Check both legacy KEEP_IN_INBOX and new tier-based inbox retention
    if label in KEEP_IN_INBOX:
        return True
    tier = get_tier_for_label(label)
    tier_config = get_tier_config(tier)
    return tier_config.keep_in_inbox


def is_time_sensitive(label: str) -> bool:
    """Check if a label is time-sensitive (should escalate with age)."""
    rule = LABEL_RULES.get(label, {})
    return rule.get("time_sensitive", False)


# ============================================================================
# TIME-BASED ESCALATION
# ============================================================================

@dataclass
class EscalationResult:
    """Result of checking if an email should be escalated."""
    should_escalate: bool
    original_tier: int
    escalated_tier: int
    reason: str


def escalate_by_age(
    current_tier: int,
    email_age_hours: float,
    is_time_sensitive: bool = False,
) -> EscalationResult:
    """
    Determine if an email should be escalated based on age.

    Escalation rules:
    - < 24 hours: Keep current tier
    - 24-72 hours: Tier 3-4 -> Tier 2 (if time-sensitive)
    - > 72 hours: Tier 2-4 -> Tier 1 (always escalate old emails)

    Args:
        current_tier: Current priority tier (1-4)
        email_age_hours: Age of the email in hours
        is_time_sensitive: Whether the email's category is time-sensitive

    Returns:
        EscalationResult with escalation details
    """
    # Tier 1 (Critical) cannot be escalated further
    if current_tier == 1:
        return EscalationResult(
            should_escalate=False,
            original_tier=1,
            escalated_tier=1,
            reason="Already at highest priority",
        )

    # < 24 hours: no escalation
    if email_age_hours < 24:
        return EscalationResult(
            should_escalate=False,
            original_tier=current_tier,
            escalated_tier=current_tier,
            reason="Email is less than 24 hours old",
        )

    # 24-72 hours: escalate Tier 3-4 to Tier 2 (if time-sensitive)
    if 24 <= email_age_hours < 72:
        if is_time_sensitive and current_tier >= 3:
            return EscalationResult(
                should_escalate=True,
                original_tier=current_tier,
                escalated_tier=2,
                reason=f"Time-sensitive email is {email_age_hours:.0f} hours old",
            )
        return EscalationResult(
            should_escalate=False,
            original_tier=current_tier,
            escalated_tier=current_tier,
            reason="Not time-sensitive or already Important tier",
        )

    # > 72 hours: escalate anything below Tier 1 to Tier 1
    if email_age_hours >= 72:
        return EscalationResult(
            should_escalate=True,
            original_tier=current_tier,
            escalated_tier=1,
            reason=f"Email is {email_age_hours:.0f} hours old (>72h)",
        )

    return EscalationResult(
        should_escalate=False,
        original_tier=current_tier,
        escalated_tier=current_tier,
        reason="No escalation rule matched",
    )


def calculate_email_age_hours(email_date: Optional["datetime"]) -> float:
    """
    Calculate the age of an email in hours.

    Args:
        email_date: The email's received date

    Returns:
        Age in hours, or 0 if date is None
    """
    if email_date is None:
        return 0

    from datetime import datetime, timezone

    # Ensure we compare timezone-aware datetimes
    now = datetime.now(timezone.utc)
    if email_date.tzinfo is None:
        # Assume UTC if no timezone
        email_date = email_date.replace(tzinfo=timezone.utc)

    age = now - email_date
    return age.total_seconds() / 3600
