"""
Multi-provider configuration system.

Loads configuration from YAML file, environment variables, and CLI arguments
with proper precedence: CLI > env > config file > defaults.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Default config file locations (checked in order)
DEFAULT_CONFIG_PATHS = [
    Path("~/.config/mail_automation/config.yaml").expanduser(),
    Path("~/.mail_automation.yaml").expanduser(),
    Path("mail_automation.yaml"),
]


@dataclass
class ProviderConfig:
    """Configuration for a specific email provider."""
    name: str
    enabled: bool = True
    default_query: str = ""
    state_file: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GmailConfig(ProviderConfig):
    """Gmail-specific configuration."""
    name: str = "gmail"
    default_query: str = "has:nouserlabels"
    state_file: str = "gmail_state.json"
    scopes: List[str] = field(default_factory=lambda: ["https://www.googleapis.com/auth/gmail.modify"])


@dataclass
class IMAPConfig(ProviderConfig):
    """IMAP-specific configuration."""
    name: str = "imap"
    default_query: str = "ALL"
    state_file: str = "imap_state.json"
    host: str = "imap.gmail.com"
    port: int = 993
    user: Optional[str] = None
    use_gmail_extensions: bool = False


@dataclass
class MailAppConfig(ProviderConfig):
    """Mail.app-specific configuration."""
    name: str = "mailapp"
    default_query: str = ""
    state_file: str = "mailapp_state.json"
    account: Optional[str] = None
    default_mailbox: str = "INBOX"


@dataclass
class OutlookConfig(ProviderConfig):
    """Outlook-specific configuration."""
    name: str = "outlook"
    default_query: str = ""
    state_file: str = "outlook_state.json"
    client_id: Optional[str] = None
    token_cache_path: Optional[str] = None


@dataclass
class Config:
    """
    Main configuration container.

    Holds settings for all providers and general automation options.
    """
    # General settings
    default_provider: str = "gmail"
    log_level: str = "INFO"
    dry_run: bool = False
    batch_size: int = 100
    throttle_seconds: float = 1.0

    # Provider configurations
    gmail: GmailConfig = field(default_factory=GmailConfig)
    imap: IMAPConfig = field(default_factory=IMAPConfig)
    mailapp: MailAppConfig = field(default_factory=MailAppConfig)
    outlook: OutlookConfig = field(default_factory=OutlookConfig)

    # Custom rules (override default LABEL_RULES)
    custom_rules: Dict[str, Dict] = field(default_factory=dict)

    # Priority labels (additions to default)
    extra_priority_labels: List[str] = field(default_factory=list)

    # Keep in inbox (additions to default)
    extra_keep_in_inbox: List[str] = field(default_factory=list)

    # VIP senders configuration
    vip_senders: Dict[str, Dict] = field(default_factory=dict)


def load_yaml_config(path: Path) -> Dict[str, Any]:
    """Load configuration from a YAML file."""
    try:
        import yaml
    except ImportError:
        logger.warning("pyyaml not installed, skipping config file")
        return {}

    if not path.exists():
        return {}

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
            logger.info(f"Loaded config from {path}")
            return data
    except Exception as e:
        logger.warning(f"Failed to load config from {path}: {e}")
        return {}


def find_config_file() -> Optional[Path]:
    """Find the first existing config file."""
    # Check environment variable first
    env_path = os.getenv("MAIL_AUTOMATION_CONFIG")
    if env_path:
        path = Path(env_path).expanduser()
        if path.exists():
            return path

    # Check default locations
    for path in DEFAULT_CONFIG_PATHS:
        if path.exists():
            return path

    return None


def load_config(
    config_path: Optional[Path] = None,
    env_prefix: str = "MAIL_AUTO_",
) -> Config:
    """
    Load configuration with proper precedence.

    Priority (highest to lowest):
    1. Environment variables (MAIL_AUTO_*)
    2. Config file
    3. Defaults

    Args:
        config_path: Explicit config file path (optional)
        env_prefix: Prefix for environment variables

    Returns:
        Populated Config object
    """
    # Start with defaults
    config = Config()

    # Load from config file
    if config_path is None:
        config_path = find_config_file()

    if config_path:
        yaml_data = load_yaml_config(config_path)
        _apply_yaml_config(config, yaml_data)

    # Override with environment variables
    _apply_env_config(config, env_prefix)

    return config


def _apply_yaml_config(config: Config, data: Dict[str, Any]) -> None:
    """Apply YAML configuration data to config object."""
    if not data:
        return

    # General settings
    if "default_provider" in data:
        config.default_provider = data["default_provider"]
    if "log_level" in data:
        config.log_level = data["log_level"]
    if "dry_run" in data:
        config.dry_run = data["dry_run"]
    if "batch_size" in data:
        config.batch_size = data["batch_size"]
    if "throttle_seconds" in data:
        config.throttle_seconds = data["throttle_seconds"]

    # Provider configs
    if "gmail" in data and isinstance(data["gmail"], dict):
        gmail = data["gmail"]
        if "enabled" in gmail:
            config.gmail.enabled = gmail["enabled"]
        if "default_query" in gmail:
            config.gmail.default_query = gmail["default_query"]
        if "state_file" in gmail:
            config.gmail.state_file = gmail["state_file"]
        if "scopes" in gmail:
            config.gmail.scopes = gmail["scopes"]

    if "imap" in data and isinstance(data["imap"], dict):
        imap = data["imap"]
        if "enabled" in imap:
            config.imap.enabled = imap["enabled"]
        if "host" in imap:
            config.imap.host = imap["host"]
        if "port" in imap:
            config.imap.port = imap["port"]
        if "user" in imap:
            config.imap.user = imap["user"]
        if "use_gmail_extensions" in imap:
            config.imap.use_gmail_extensions = imap["use_gmail_extensions"]
        if "state_file" in imap:
            config.imap.state_file = imap["state_file"]

    if "mailapp" in data and isinstance(data["mailapp"], dict):
        mailapp = data["mailapp"]
        if "enabled" in mailapp:
            config.mailapp.enabled = mailapp["enabled"]
        if "account" in mailapp:
            config.mailapp.account = mailapp["account"]
        if "default_mailbox" in mailapp:
            config.mailapp.default_mailbox = mailapp["default_mailbox"]
        if "state_file" in mailapp:
            config.mailapp.state_file = mailapp["state_file"]

    if "outlook" in data and isinstance(data["outlook"], dict):
        outlook = data["outlook"]
        if "enabled" in outlook:
            config.outlook.enabled = outlook["enabled"]
        if "client_id" in outlook:
            config.outlook.client_id = outlook["client_id"]
        if "token_cache_path" in outlook:
            config.outlook.token_cache_path = outlook["token_cache_path"]
        if "state_file" in outlook:
            config.outlook.state_file = outlook["state_file"]

    # Custom rules
    if "custom_rules" in data:
        config.custom_rules = data["custom_rules"]

    # Extra labels
    if "extra_priority_labels" in data:
        config.extra_priority_labels = data["extra_priority_labels"]
    if "extra_keep_in_inbox" in data:
        config.extra_keep_in_inbox = data["extra_keep_in_inbox"]

    # VIP senders
    if "vip_senders" in data:
        config.vip_senders = data["vip_senders"]


def _apply_env_config(config: Config, prefix: str) -> None:
    """Apply environment variable overrides to config object."""
    # General settings
    if os.getenv(f"{prefix}DEFAULT_PROVIDER"):
        config.default_provider = os.getenv(f"{prefix}DEFAULT_PROVIDER")
    if os.getenv(f"{prefix}LOG_LEVEL"):
        config.log_level = os.getenv(f"{prefix}LOG_LEVEL")
    if os.getenv(f"{prefix}DRY_RUN"):
        config.dry_run = os.getenv(f"{prefix}DRY_RUN", "").lower() in ("1", "true", "yes")
    if os.getenv(f"{prefix}BATCH_SIZE"):
        config.batch_size = int(os.getenv(f"{prefix}BATCH_SIZE"))

    # Gmail
    if os.getenv(f"{prefix}GMAIL_QUERY"):
        config.gmail.default_query = os.getenv(f"{prefix}GMAIL_QUERY")
    if os.getenv(f"{prefix}GMAIL_STATE_FILE"):
        config.gmail.state_file = os.getenv(f"{prefix}GMAIL_STATE_FILE")

    # IMAP
    if os.getenv("IMAP_HOST"):
        config.imap.host = os.getenv("IMAP_HOST")
    if os.getenv("IMAP_USER"):
        config.imap.user = os.getenv("IMAP_USER")
    if os.getenv(f"{prefix}IMAP_GMAIL_EXTENSIONS"):
        config.imap.use_gmail_extensions = os.getenv(f"{prefix}IMAP_GMAIL_EXTENSIONS", "").lower() in ("1", "true", "yes")

    # Mail.app
    if os.getenv(f"{prefix}MAILAPP_ACCOUNT"):
        config.mailapp.account = os.getenv(f"{prefix}MAILAPP_ACCOUNT")

    # Outlook
    if os.getenv("OUTLOOK_CLIENT_ID"):
        config.outlook.client_id = os.getenv("OUTLOOK_CLIENT_ID")
    if os.getenv("OUTLOOK_TOKEN_CACHE"):
        config.outlook.token_cache_path = os.getenv("OUTLOOK_TOKEN_CACHE")


def apply_vip_senders_from_config(config: Config) -> int:
    """
    Apply VIP senders from config to the rules module.

    Args:
        config: Loaded configuration

    Returns:
        Number of VIP senders added
    """
    from core.rules import add_vip_sender

    count = 0
    for key, vip_data in config.vip_senders.items():
        if isinstance(vip_data, dict) and "pattern" in vip_data:
            add_vip_sender(
                key=key,
                pattern=vip_data["pattern"],
                tier=vip_data.get("tier", 1),
                star=vip_data.get("star", True),
                label_override=vip_data.get("label_override"),
                note=vip_data.get("note", ""),
            )
            count += 1
            logger.debug(f"Added VIP sender: {key}")

    if count > 0:
        logger.info(f"Loaded {count} VIP senders from config")

    return count


def create_sample_config(path: Optional[Path] = None) -> str:
    """
    Generate a sample configuration file.

    Args:
        path: Optional path to write the config file

    Returns:
        Sample YAML configuration string
    """
    sample = '''# Mail Automation Configuration
# Place this file at ~/.config/mail_automation/config.yaml

# Default provider to use when not specified
default_provider: gmail

# Logging level (DEBUG, INFO, WARNING, ERROR)
log_level: INFO

# Default batch size for processing
batch_size: 100

# Throttle between batches (seconds)
throttle_seconds: 1.0

# Gmail provider settings
gmail:
  enabled: true
  default_query: "has:nouserlabels"
  state_file: "gmail_state.json"
  # scopes:
  #   - "https://www.googleapis.com/auth/gmail.modify"

# IMAP provider settings
imap:
  enabled: true
  host: imap.gmail.com
  port: 993
  # user: your-email@example.com
  use_gmail_extensions: false
  state_file: "imap_state.json"

# macOS Mail.app settings
mailapp:
  enabled: true
  # account: "iCloud"
  default_mailbox: "INBOX"
  state_file: "mailapp_state.json"

# Outlook.com settings
outlook:
  enabled: true
  # client_id: "your-azure-app-client-id"
  # token_cache_path: "~/.outlook_token_cache.json"
  state_file: "outlook_state.json"

# Custom rules to add or override (merged with defaults)
# custom_rules:
#   "CustomCategory/Subcategory":
#     patterns:
#       - "custom-pattern"
#       - "another-pattern"
#     priority: 5

# Additional labels to star/flag
# extra_priority_labels:
#   - "Important/Category"

# Additional labels to keep in inbox (not archive)
# extra_keep_in_inbox:
#   - "Urgent/Category"

# VIP senders - always get priority treatment
# vip_senders:
#   "ceo@company.com":
#     pattern: "ceo@company\\.com"
#     tier: 1  # Critical
#     star: true
#     note: "CEO"
#   "important-client":
#     pattern: ".*@important-client\\.com"
#     tier: 1
#     star: true
#     label_override: "Personal"  # Optional: override categorization
#     note: "Important client domain"
'''

    if path:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            f.write(sample)
        logger.info(f"Created sample config at {path}")

    return sample
