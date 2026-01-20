"""
Email provider implementations.

This package contains adapters for different email services, all implementing
the abstract EmailProvider interface for consistent behavior.

Supported Providers:
    - GmailProvider: Gmail API (google-api-python-client)
    - IMAPProvider: Generic IMAP (with Gmail extensions support)
    - MailAppProvider: macOS Mail.app (AppleScript bridge)
    - OutlookProvider: Microsoft Graph API (Outlook.com)
"""

from providers.base import EmailProvider, ProviderCapabilities

__all__ = [
    "EmailProvider",
    "ProviderCapabilities",
]

# Lazy imports to avoid dependency issues
def get_gmail_provider():
    from providers.gmail import GmailProvider
    return GmailProvider

def get_imap_provider():
    from providers.imap import IMAPProvider
    return IMAPProvider

def get_mailapp_provider():
    from providers.mailapp import MailAppProvider
    return MailAppProvider

def get_outlook_provider():
    from providers.outlook import OutlookProvider
    return OutlookProvider
