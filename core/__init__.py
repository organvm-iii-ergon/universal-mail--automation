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
    categorize_message,
    categorize_from_strings,
    should_star,
    should_keep_in_inbox,
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
    "categorize_message",
    "categorize_from_strings",
    "should_star",
    "should_keep_in_inbox",
    "StateManager",
    "Config",
    "load_config",
    "create_sample_config",
]
