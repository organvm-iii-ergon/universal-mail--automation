"""
Authentication utilities for email providers.

Provides OAuth2 helpers and 1Password credential loading for
multi-provider authentication.
"""

from auth.onepassword import load_secret, load_json_secret

__all__ = [
    "load_secret",
    "load_json_secret",
]
