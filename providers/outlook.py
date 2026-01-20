"""
Microsoft Outlook.com provider implementation.

Uses Microsoft Graph API with MSAL for consumer (MSA) authentication
to access Outlook.com mailboxes.
"""

import json
import logging
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

from providers.base import (
    EmailProvider,
    ProviderCapabilities,
    ListMessagesResult,
)
from core.models import EmailMessage, LabelAction, ProcessingResult

logger = logging.getLogger(__name__)

# Microsoft Graph API endpoints
GRAPH_API_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_API_MESSAGES = f"{GRAPH_API_BASE}/me/mailFolders/inbox/messages"
GRAPH_API_FOLDERS = f"{GRAPH_API_BASE}/me/mailFolders"
GRAPH_API_CATEGORIES = f"{GRAPH_API_BASE}/me/outlook/masterCategories"

# Outlook category color presets (Graph API enum values)
CATEGORY_COLORS = {
    "red": "preset0",
    "orange": "preset1",
    "brown": "preset2",
    "yellow": "preset3",
    "green": "preset4",
    "teal": "preset5",
    "olive": "preset6",
    "blue": "preset7",
    "purple": "preset8",
    "cranberry": "preset9",
    "steel": "preset10",
    "darkSteel": "preset11",
    "gray": "preset12",
    "darkGray": "preset13",
    "black": "preset14",
    "darkRed": "preset15",
    "darkOrange": "preset16",
    "darkBrown": "preset17",
    "darkYellow": "preset18",
    "darkGreen": "preset19",
    "darkTeal": "preset20",
    "darkOlive": "preset21",
    "darkBlue": "preset22",
    "darkPurple": "preset23",
    "darkCranberry": "preset24",
}

# Default OAuth scopes for Outlook
DEFAULT_SCOPES = ["Mail.ReadWrite", "MailboxSettings.ReadWrite"]

# Default client ID for personal Microsoft accounts
# Users should register their own app at portal.azure.com
DEFAULT_CLIENT_ID = os.getenv("OUTLOOK_CLIENT_ID", "")


class OutlookProvider(EmailProvider):
    """
    Microsoft Outlook.com provider using Graph API.

    Uses MSAL (Microsoft Authentication Library) for OAuth2 authentication
    with consumer Microsoft accounts (Outlook.com, Hotmail, Live).

    Configuration via environment variables:
        OUTLOOK_CLIENT_ID: Azure app registration client ID
        OUTLOOK_TOKEN_CACHE: Path to token cache file (default: ~/.outlook_token_cache.json)

    Example:
        provider = OutlookProvider(client_id="your-app-client-id")
        with provider:
            result = provider.list_messages(limit=100)
            for msg in result.messages:
                details = provider.get_message_details(msg.id)
                provider.apply_label(msg.id, "Work/Dev/GitHub")

    Notes:
        - Requires `msal` and `requests` packages
        - First run will prompt for interactive authentication
        - Token is cached for subsequent runs
    """

    name = "outlook"
    capabilities = (
        ProviderCapabilities.FOLDERS |
        ProviderCapabilities.SEARCH_QUERY |
        ProviderCapabilities.STAR |
        ProviderCapabilities.ARCHIVE |
        ProviderCapabilities.CATEGORIES
    )

    def __init__(
        self,
        client_id: Optional[str] = None,
        token_cache_path: Optional[str] = None,
        scopes: Optional[List[str]] = None,
    ):
        """
        Initialize Outlook provider.

        Args:
            client_id: Azure AD app registration client ID
                       (or OUTLOOK_CLIENT_ID env var)
            token_cache_path: Path to token cache file
                              (or OUTLOOK_TOKEN_CACHE env var)
            scopes: OAuth scopes (defaults to Mail.ReadWrite)
        """
        self.client_id = client_id or os.getenv("OUTLOOK_CLIENT_ID")
        self.token_cache_path = token_cache_path or os.getenv(
            "OUTLOOK_TOKEN_CACHE",
            os.path.expanduser("~/.outlook_token_cache.json"),
        )
        self.scopes = scopes or DEFAULT_SCOPES
        self._access_token: Optional[str] = None
        self._folder_cache: Dict[str, str] = {}
        self._category_cache: Dict[str, str] = {}  # name -> id
        self._msal_app = None
        self._session = None

    def _get_msal_app(self):
        """Get or create MSAL PublicClientApplication."""
        if self._msal_app:
            return self._msal_app

        try:
            import msal
        except ImportError:
            raise RuntimeError(
                "msal package not installed. Run: pip install msal"
            )

        if not self.client_id:
            raise ValueError(
                "Outlook client_id not configured. Set OUTLOOK_CLIENT_ID "
                "or register an app at portal.azure.com"
            )

        # Load token cache
        cache = msal.SerializableTokenCache()
        if os.path.exists(self.token_cache_path):
            with open(self.token_cache_path, "r") as f:
                cache.deserialize(f.read())

        self._msal_app = msal.PublicClientApplication(
            self.client_id,
            authority="https://login.microsoftonline.com/consumers",
            token_cache=cache,
        )
        return self._msal_app

    def _save_token_cache(self):
        """Save MSAL token cache to disk."""
        app = self._get_msal_app()
        if app.token_cache.has_state_changed:
            with open(self.token_cache_path, "w") as f:
                f.write(app.token_cache.serialize())

    def _acquire_token(self) -> str:
        """Acquire access token via MSAL."""
        app = self._get_msal_app()

        # Try to get token silently from cache
        accounts = app.get_accounts()
        if accounts:
            result = app.acquire_token_silent(self.scopes, account=accounts[0])
            if result and "access_token" in result:
                self._save_token_cache()
                return result["access_token"]

        # Fall back to interactive authentication
        logger.info("No cached token found, starting interactive authentication...")
        result = app.acquire_token_interactive(
            scopes=self.scopes,
            prompt="select_account",
        )

        if "access_token" not in result:
            error = result.get("error_description", result.get("error", "Unknown error"))
            raise RuntimeError(f"Failed to acquire token: {error}")  # allow-secret

        self._save_token_cache()
        return result["access_token"]

    def _get_session(self):
        """Get or create requests session with auth headers."""
        if self._session:
            return self._session

        try:
            import requests
        except ImportError:
            raise RuntimeError("requests package not installed. Run: pip install requests")

        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self._access_token}",
            "Content-Type": "application/json",
        })
        return self._session

    def _api_get(self, url: str, params: Optional[Dict] = None) -> Dict:
        """Make GET request to Graph API."""
        session = self._get_session()
        response = session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def _api_post(self, url: str, data: Dict) -> Dict:
        """Make POST request to Graph API."""
        session = self._get_session()
        response = session.post(url, json=data)
        response.raise_for_status()
        return response.json()

    def _api_patch(self, url: str, data: Dict) -> Dict:
        """Make PATCH request to Graph API."""
        session = self._get_session()
        response = session.patch(url, json=data)
        response.raise_for_status()
        return response.json()

    def connect(self) -> None:
        """Establish connection via OAuth."""
        self._access_token = self._acquire_token()
        self._init_folder_cache()
        self._init_category_cache()
        logger.info("Outlook provider connected")

    def disconnect(self) -> None:
        """Close connection."""
        if self._session:
            self._session.close()
            self._session = None
        self._access_token = None
        logger.debug("Outlook provider disconnected")

    def _init_folder_cache(self) -> None:
        """Pre-fetch folder IDs."""
        logger.info("Initializing Outlook folder cache...")
        try:
            result = self._api_get(GRAPH_API_FOLDERS, params={"$top": 100})
            for folder in result.get("value", []):
                self._folder_cache[folder["displayName"]] = folder["id"]

            # Also get child folders recursively
            for folder in result.get("value", []):
                self._fetch_child_folders(folder["id"], folder["displayName"])

        except Exception as e:
            logger.warning(f"Failed to cache folders: {e}")

    def _fetch_child_folders(self, parent_id: str, parent_name: str) -> None:
        """Recursively fetch child folders."""
        try:
            url = f"{GRAPH_API_FOLDERS}/{parent_id}/childFolders"
            result = self._api_get(url, params={"$top": 100})
            for folder in result.get("value", []):
                full_name = f"{parent_name}/{folder['displayName']}"
                self._folder_cache[full_name] = folder["id"]
                self._fetch_child_folders(folder["id"], full_name)
        except Exception:
            pass  # Ignore errors for child folders

    def _init_category_cache(self) -> None:
        """Pre-fetch master categories."""
        logger.info("Initializing Outlook category cache...")
        try:
            result = self._api_get(GRAPH_API_CATEGORIES)
            for cat in result.get("value", []):
                self._category_cache[cat["displayName"]] = cat["id"]
            logger.debug(f"Cached {len(self._category_cache)} categories")
        except Exception as e:
            logger.warning(f"Failed to cache categories: {e}")

    def ensure_category_exists(self, name: str, color: str = "blue") -> str:
        """
        Ensure a category exists, creating if necessary.

        Args:
            name: Category display name (e.g., "Critical", "Important")
            color: Color name from CATEGORY_COLORS (default: blue)

        Returns:
            The category ID
        """
        if name in self._category_cache:
            return self._category_cache[name]

        # Resolve color preset
        color_preset = CATEGORY_COLORS.get(color.lower(), "preset7")  # default blue

        data = {
            "displayName": name,
            "color": color_preset,
        }

        try:
            result = self._api_post(GRAPH_API_CATEGORIES, data)
            self._category_cache[name] = result["id"]
            logger.info(f"Created category: {name} ({color})")
            return result["id"]
        except Exception as e:
            # Category might already exist (race condition)
            logger.debug(f"Category create for {name}: {e}")
            # Refresh cache and check again
            self._init_category_cache()
            if name in self._category_cache:
                return self._category_cache[name]
            raise RuntimeError(f"Failed to create category: {name}")

    def apply_category(
        self,
        message_id: str,
        category: str,
        color: str = "blue",
    ) -> bool:
        """
        Apply a color category to a message.

        Args:
            message_id: Message to categorize
            category: Category name to apply
            color: Color for category (if creating new)

        Returns:
            True if successful
        """
        # Ensure category exists
        self.ensure_category_exists(category, color)

        url = f"{GRAPH_API_BASE}/me/messages/{message_id}"

        # Get current categories first
        try:
            msg = self._api_get(url, params={"$select": "categories"})
            current_cats = msg.get("categories", [])
        except Exception:
            current_cats = []

        # Add new category if not already present
        if category not in current_cats:
            current_cats.append(category)

        data = {"categories": current_cats}

        try:
            self._api_patch(url, data)
            logger.debug(f"Applied category '{category}' to message {message_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to apply category: {e}")
            return False

    def remove_category(self, message_id: str, category: str) -> bool:
        """
        Remove a category from a message.

        Args:
            message_id: Message to modify
            category: Category name to remove

        Returns:
            True if successful
        """
        url = f"{GRAPH_API_BASE}/me/messages/{message_id}"

        try:
            msg = self._api_get(url, params={"$select": "categories"})
            current_cats = msg.get("categories", [])

            if category in current_cats:
                current_cats.remove(category)
                data = {"categories": current_cats}
                self._api_patch(url, data)
                logger.debug(f"Removed category '{category}' from message {message_id}")

            return True
        except Exception as e:
            logger.error(f"Failed to remove category: {e}")
            return False

    def get_category_cache(self) -> Dict[str, str]:
        """Return the category name -> ID cache."""
        return self._category_cache.copy()

    def list_messages(
        self,
        query: str = "",
        limit: int = 100,
        page_token: Optional[str] = None,
        folder: str = "inbox",
    ) -> ListMessagesResult:
        """
        List messages from Outlook.

        Args:
            query: OData filter query (e.g., "isRead eq false")
            limit: Maximum messages to return
            page_token: URL for next page (from previous result)
            folder: Folder name to search in (default inbox)

        Returns:
            ListMessagesResult with messages
        """
        if page_token:
            # Use skiptoken URL directly
            url = page_token
            params = None
        else:
            folder_id = self._folder_cache.get(folder)
            if folder_id:
                url = f"{GRAPH_API_FOLDERS}/{folder_id}/messages"
            else:
                url = f"{GRAPH_API_BASE}/me/mailFolders/{folder}/messages"

            params = {
                "$top": limit,
                "$select": "id,subject,from,isRead,flag,receivedDateTime",
                "$orderby": "receivedDateTime desc",
            }
            if query:
                params["$filter"] = query

        try:
            result = self._api_get(url, params=params)
        except Exception as e:
            logger.error(f"Failed to list messages: {e}")
            return ListMessagesResult(messages=[])

        messages = []
        for msg in result.get("value", []):
            sender = ""
            if msg.get("from", {}).get("emailAddress"):
                email_addr = msg["from"]["emailAddress"]
                sender = f"{email_addr.get('name', '')} <{email_addr.get('address', '')}>"

            is_flagged = msg.get("flag", {}).get("flagStatus") == "flagged"

            received = None
            if msg.get("receivedDateTime"):
                try:
                    received = datetime.fromisoformat(
                        msg["receivedDateTime"].replace("Z", "+00:00")
                    )
                except ValueError:
                    pass

            messages.append(EmailMessage(
                id=msg["id"],
                sender=sender,
                subject=msg.get("subject", ""),
                date=received,
                is_read=msg.get("isRead", False),
                is_starred=is_flagged,
            ))

        next_link = result.get("@odata.nextLink")
        return ListMessagesResult(
            messages=messages,
            next_page_token=next_link,
        )

    def get_message_details(self, message_id: str) -> Optional[EmailMessage]:
        """Fetch message details by ID."""
        url = f"{GRAPH_API_BASE}/me/messages/{message_id}"
        params = {"$select": "id,subject,from,isRead,flag,receivedDateTime,parentFolderId"}

        try:
            msg = self._api_get(url, params=params)
        except Exception as e:
            logger.error(f"Failed to get message {message_id}: {e}")
            return None

        sender = ""
        if msg.get("from", {}).get("emailAddress"):
            email_addr = msg["from"]["emailAddress"]
            sender = f"{email_addr.get('name', '')} <{email_addr.get('address', '')}>"

        is_flagged = msg.get("flag", {}).get("flagStatus") == "flagged"

        # Get folder name
        labels = set()
        folder_id = msg.get("parentFolderId")
        if folder_id:
            for name, fid in self._folder_cache.items():
                if fid == folder_id:
                    labels.add(name)
                    break

        received = None
        if msg.get("receivedDateTime"):
            try:
                received = datetime.fromisoformat(
                    msg["receivedDateTime"].replace("Z", "+00:00")
                )
            except ValueError:
                pass

        return EmailMessage(
            id=message_id,
            sender=sender,
            subject=msg.get("subject", ""),
            date=received,
            labels=labels,
            is_read=msg.get("isRead", False),
            is_starred=is_flagged,
        )

    def apply_label(self, message_id: str, label: str) -> bool:
        """
        Move message to a folder.

        Outlook uses folders, so this moves the message to the target folder.
        """
        folder_id = self.ensure_label_exists(label)

        url = f"{GRAPH_API_BASE}/me/messages/{message_id}/move"
        data = {"destinationId": folder_id}

        try:
            self._api_post(url, data)
            return True
        except Exception as e:
            logger.error(f"Failed to move message to {label}: {e}")
            return False

    def remove_label(self, message_id: str, label: str) -> bool:
        """Not directly supported (Outlook uses folders)."""
        logger.warning("remove_label not supported for Outlook (folder-based)")
        return False

    def archive(self, message_id: str) -> bool:
        """Move message to Archive folder."""
        return self.apply_label(message_id, "Archive")

    def star(self, message_id: str, due_date: Optional[datetime] = None) -> bool:
        """
        Flag a message, optionally with a due date for Microsoft To Do.

        Args:
            message_id: Message to flag
            due_date: Optional due date (syncs to Microsoft To Do)

        Returns:
            True if successful
        """
        url = f"{GRAPH_API_BASE}/me/messages/{message_id}"

        flag_data: Dict[str, Any] = {"flagStatus": "flagged"}

        if due_date:
            # Format as ISO 8601 date for Graph API
            due_str = due_date.strftime("%Y-%m-%dT00:00:00Z")
            flag_data["dueDateTime"] = {
                "dateTime": due_str,
                "timeZone": "UTC",
            }

        data = {"flag": flag_data}

        try:
            self._api_patch(url, data)
            return True
        except Exception as e:
            logger.error(f"Failed to flag message: {e}")
            return False

    def unstar(self, message_id: str) -> bool:
        """Unflag a message."""
        url = f"{GRAPH_API_BASE}/me/messages/{message_id}"
        data = {"flag": {"flagStatus": "notFlagged"}}

        try:
            self._api_patch(url, data)
            return True
        except Exception as e:
            logger.error(f"Failed to unflag message: {e}")
            return False

    def ensure_label_exists(self, label: str) -> str:
        """Ensure folder exists, creating if necessary."""
        if label in self._folder_cache:
            return self._folder_cache[label]

        # Handle hierarchical folder names (Work/Dev/GitHub -> nested folders)
        parts = label.split("/")
        parent_id = None

        for i, part in enumerate(parts):
            partial_path = "/".join(parts[:i + 1])

            if partial_path in self._folder_cache:
                parent_id = self._folder_cache[partial_path]
                continue

            # Create folder
            if parent_id:
                url = f"{GRAPH_API_FOLDERS}/{parent_id}/childFolders"
            else:
                url = GRAPH_API_FOLDERS

            data = {"displayName": part}

            try:
                result = self._api_post(url, data)
                folder_id = result["id"]
                self._folder_cache[partial_path] = folder_id
                parent_id = folder_id
                logger.info(f"Created folder: {partial_path}")
            except Exception as e:
                # Folder might already exist
                logger.debug(f"Folder create for {part}: {e}")
                # Try to find it
                try:
                    if parent_id:
                        child_url = f"{GRAPH_API_FOLDERS}/{parent_id}/childFolders"
                    else:
                        child_url = GRAPH_API_FOLDERS

                    result = self._api_get(child_url, params={
                        "$filter": f"displayName eq '{part}'"
                    })
                    if result.get("value"):
                        folder_id = result["value"][0]["id"]
                        self._folder_cache[partial_path] = folder_id
                        parent_id = folder_id
                except Exception:
                    raise RuntimeError(f"Failed to create or find folder: {label}")

        return self._folder_cache.get(label, label)

    def mark_read(self, message_id: str) -> bool:
        """Mark message as read."""
        url = f"{GRAPH_API_BASE}/me/messages/{message_id}"
        data = {"isRead": True}

        try:
            self._api_patch(url, data)
            return True
        except Exception as e:
            logger.error(f"Failed to mark read: {e}")
            return False

    def mark_unread(self, message_id: str) -> bool:
        """Mark message as unread."""
        url = f"{GRAPH_API_BASE}/me/messages/{message_id}"
        data = {"isRead": False}

        try:
            self._api_patch(url, data)
            return True
        except Exception as e:
            logger.error(f"Failed to mark unread: {e}")
            return False
