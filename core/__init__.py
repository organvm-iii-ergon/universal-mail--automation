"""
Core email automation module.

Provides shared categorization rules, state management, and data models
used across all email providers (Gmail, IMAP, Mail.app, Outlook).
"""

from core.models import EmailMessage, LabelAction, ProcessingResult
from core.rules import (
    LABEL_RULES,
    PRIORITY_LABELS,
    KEEP_IN_INBOX,
    PRIORITY_TIERS,
    VIP_SENDERS,
    PriorityTier,
    VIPSender,
    CategorizationResult,
    EscalationResult,
    categorize_message,
    categorize_from_strings,
    categorize_with_tier,
    get_tier_for_label,
    get_tier_config,
    should_star,
    should_keep_in_inbox,
    is_time_sensitive,
    is_vip_sender,
    check_vip_sender,
    get_vip_senders,
    add_vip_sender,
    escalate_by_age,
    calculate_email_age_hours,
)
from core.state import StateManager
from core.config import Config, load_config, create_sample_config

__all__ = [
    "EmailMessage",
    "LabelAction",
    "ProcessingResult",
    "LABEL_RULES",
    "PRIORITY_LABELS",
    "KEEP_IN_INBOX",
    "PRIORITY_TIERS",
    "VIP_SENDERS",
    "PriorityTier",
    "VIPSender",
    "CategorizationResult",
    "categorize_message",
    "categorize_from_strings",
    "categorize_with_tier",
    "get_tier_for_label",
    "get_tier_config",
    "should_star",
    "should_keep_in_inbox",
    "is_time_sensitive",
    "is_vip_sender",
    "check_vip_sender",
    "get_vip_senders",
    "add_vip_sender",
    "EscalationResult",
    "escalate_by_age",
    "calculate_email_age_hours",
    "StateManager",
    "Config",
    "load_config",
    "create_sample_config",
]
