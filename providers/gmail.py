"""
Gmail API provider implementation.

Wraps the Gmail API (google-api-python-client) to implement the EmailProvider
interface for consistent behavior with other providers.
"""

import logging
import time
from typing import Dict, List, Optional, Callable, Any

from googleapiclient.errors import HttpError

from providers.base import (
    EmailProvider,
    ProviderCapabilities,
    ListMessagesResult,
)
from core.models import EmailMessage, LabelAction, ProcessingResult

logger = logging.getLogger(__name__)

# Default API scopes
DEFAULT_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

# Performance tuning
BATCH_GET_SIZE = 20        # Messages per batch get request
BATCH_MODIFY_SIZE = 1000   # Max IDs per batchModify (API limit)
LIST_PAGE_SIZE = 500       # Max messages per list page (API max)
BASE_BACKOFF_SECONDS = 10  # Initial backoff delay for rate limits


class GmailProvider(EmailProvider):
    """
    Gmail API provider implementation.

    Uses the Gmail REST API with batch operations for efficient processing.
    Supports labels (not just folders), starring, and server-side search.

    Example:
        from providers.gmail import GmailProvider

        with GmailProvider() as gmail:
            result = gmail.list_messages("has:nouserlabels", limit=100)
            for msg in result.messages:
                details = gmail.get_message_details(msg.id)
                gmail.apply_label(msg.id, "Work/Dev/GitHub")
                gmail.archive(msg.id)
    """

    name = "gmail"
    capabilities = (
        ProviderCapabilities.TRUE_LABELS |
        ProviderCapabilities.STAR |
        ProviderCapabilities.ARCHIVE |
        ProviderCapabilities.BATCH_OPERATIONS |
        ProviderCapabilities.SEARCH_QUERY
    )

    def __init__(
        self,
        scopes: Optional[List[str]] = None,
        service: Optional[Any] = None,
    ):
        """
        Initialize Gmail provider.

        Args:
            scopes: OAuth scopes (defaults to gmail.modify)
            service: Optional pre-built Gmail service for testing
        """
        self.scopes = scopes or DEFAULT_SCOPES
        self._service = service
        self._label_cache: Dict[str, str] = {}
        self._connected = False

    def connect(self) -> None:
        """Establish connection via OAuth."""
        if self._service is not None:
            self._connected = True
            return

        import gmail_auth
        self._service = gmail_auth.build_gmail_service(scopes=self.scopes)
        self._connected = True
        self._init_label_cache()
        logger.info("Gmail provider connected")

    def disconnect(self) -> None:
        """Disconnect (no-op for Gmail API)."""
        self._connected = False
        logger.debug("Gmail provider disconnected")

    def _execute_with_backoff(
        self,
        func: Callable[[], Any],
        description: str,
        max_retries: int = 5,
    ) -> Any:
        """Execute an API call with exponential backoff on rate limits."""
        delay = BASE_BACKOFF_SECONDS
        for attempt in range(1, max_retries + 1):
            try:
                return func()
            except HttpError as e:
                message = str(e)
                status = getattr(e.resp, "status", None)
                rate_limited = status in (403, 429) and any(
                    tag in message for tag in (
                        "rateLimitExceeded",
                        "userRateLimitExceeded",
                        "quotaExceeded",
                    )
                )
                if rate_limited:
                    logger.warning(
                        f"{description} rate limited (attempt {attempt}/{max_retries}); "
                        f"sleeping {delay:.1f}s"
                    )
                    time.sleep(delay)
                    delay *= 2
                    continue
                raise
        raise RuntimeError(f"{description} failed after {max_retries} retries due to rate limits.")

    def _init_label_cache(self) -> None:
        """Pre-fetch all label IDs to avoid API calls during processing."""
        logger.info("Initializing Gmail label cache...")
        results = self._service.users().labels().list(userId="me").execute()
        for label in results.get("labels", []):
            self._label_cache[label["name"]] = label["id"]
        logger.debug(f"Cached {len(self._label_cache)} labels")

    def list_messages(
        self,
        query: str = "",
        limit: int = 100,
        page_token: Optional[str] = None,
    ) -> ListMessagesResult:
        """List messages matching Gmail search query."""
        page_size = min(limit, LIST_PAGE_SIZE)
        results = self._execute_with_backoff(
            lambda: self._service.users().messages().list(
                userId="me",
                q=query,
                maxResults=page_size,
                pageToken=page_token,
            ).execute(),
            "list messages"
        )

        messages = []
        for msg in results.get("messages", []):
            messages.append(EmailMessage(
                id=msg["id"],
                sender="",  # Populated by get_message_details
                subject="",
            ))

        return ListMessagesResult(
            messages=messages,
            next_page_token=results.get("nextPageToken"),
            total_estimate=results.get("resultSizeEstimate"),
        )

    def get_message_details(self, message_id: str) -> Optional[EmailMessage]:
        """Fetch message headers."""
        try:
            data = self._execute_with_backoff(
                lambda: self._service.users().messages().get(
                    userId="me",
                    id=message_id,
                    format="metadata",
                    metadataHeaders=["From", "Subject"],
                ).execute(),
                f"get message {message_id}"
            )
        except HttpError as e:
            if e.resp.status == 404:
                return None
            raise

        headers = data.get("payload", {}).get("headers", [])
        sender = ""
        subject = ""
        for h in headers:
            name = h.get("name", "").lower()
            if name == "from":
                sender = h.get("value", "")
            elif name == "subject":
                subject = h.get("value", "")

        label_ids = data.get("labelIds", [])
        labels = set()
        for lid in label_ids:
            for name, id_ in self._label_cache.items():
                if id_ == lid:
                    labels.add(name)
                    break

        return EmailMessage(
            id=message_id,
            sender=sender,
            subject=subject,
            labels=labels,
            is_starred="STARRED" in label_ids,
            is_read="UNREAD" not in label_ids,
        )

    def batch_get_details(
        self,
        message_ids: List[str],
    ) -> Dict[str, EmailMessage]:
        """Fetch details for multiple messages using batch API."""
        results: Dict[str, EmailMessage] = {}
        chunks = [
            message_ids[i:i + BATCH_GET_SIZE]
            for i in range(0, len(message_ids), BATCH_GET_SIZE)
        ]

        for chunk in chunks:
            failed_ids: List[str] = []

            def callback(request_id: str, response: dict, exception: Exception):
                if exception:
                    failed_ids.append(request_id)
                    logger.warning(f"Error fetching message {request_id}: {exception}")
                else:
                    msg = self._parse_message_response(request_id, response)
                    if msg:
                        results[request_id] = msg

            batch = self._service.new_batch_http_request(callback=callback)
            for msg_id in chunk:
                batch.add(
                    self._service.users().messages().get(
                        userId="me",
                        id=msg_id,
                        format="metadata",
                        metadataHeaders=["From", "Subject"],
                    ),
                    request_id=msg_id,
                )

            self._execute_with_backoff(batch.execute, "batch get")
            time.sleep(2.0)  # Throttle between batches

            # Retry failed fetches individually
            for msg_id in failed_ids:
                msg = self.get_message_details(msg_id)
                if msg:
                    results[msg_id] = msg

        return results

    def _parse_message_response(
        self,
        message_id: str,
        data: dict,
    ) -> Optional[EmailMessage]:
        """Parse a Gmail message response into EmailMessage."""
        if not data:
            return None

        headers = data.get("payload", {}).get("headers", [])
        sender = ""
        subject = ""
        for h in headers:
            name = h.get("name", "").lower()
            if name == "from":
                sender = h.get("value", "")
            elif name == "subject":
                subject = h.get("value", "")

        label_ids = data.get("labelIds", [])
        labels = set()
        for lid in label_ids:
            for name, id_ in self._label_cache.items():
                if id_ == lid:
                    labels.add(name)
                    break

        return EmailMessage(
            id=message_id,
            sender=sender,
            subject=subject,
            labels=labels,
            is_starred="STARRED" in label_ids,
            is_read="UNREAD" not in label_ids,
        )

    def apply_label(self, message_id: str, label: str) -> bool:
        """Add a label to a message."""
        label_id = self._label_cache.get(label)
        if not label_id:
            label_id = self.ensure_label_exists(label)

        try:
            self._execute_with_backoff(
                lambda: self._service.users().messages().modify(
                    userId="me",
                    id=message_id,
                    body={"addLabelIds": [label_id]},
                ).execute(),
                f"apply label {label}"
            )
            return True
        except HttpError as e:
            logger.error(f"Failed to apply label {label} to {message_id}: {e}")
            return False

    def remove_label(self, message_id: str, label: str) -> bool:
        """Remove a label from a message."""
        label_id = self._label_cache.get(label) or label
        try:
            self._execute_with_backoff(
                lambda: self._service.users().messages().modify(
                    userId="me",
                    id=message_id,
                    body={"removeLabelIds": [label_id]},
                ).execute(),
                f"remove label {label}"
            )
            return True
        except HttpError as e:
            logger.error(f"Failed to remove label {label} from {message_id}: {e}")
            return False

    def archive(self, message_id: str) -> bool:
        """Archive a message (remove from INBOX)."""
        return self.remove_label(message_id, "INBOX")

    def star(self, message_id: str, due_date: Any = None) -> bool:
        """Star a message. due_date is ignored (Gmail doesn't support it)."""
        return self.apply_label(message_id, "STARRED")

    def unstar(self, message_id: str) -> bool:
        """Unstar a message."""
        return self.remove_label(message_id, "STARRED")

    def ensure_label_exists(self, label: str) -> str:
        """Ensure label exists, creating if necessary."""
        if label in self._label_cache:
            return self._label_cache[label]

        # Check if it's a system label
        system_labels = {"INBOX", "STARRED", "SENT", "DRAFT", "TRASH", "SPAM"}
        if label in system_labels:
            self._label_cache[label] = label
            return label

        logger.info(f"Creating missing label: {label}")
        label_object = {
            "name": label,
            "labelListVisibility": "labelShow",
            "messageListVisibility": "show",
        }
        try:
            created = self._execute_with_backoff(
                lambda: self._service.users().labels().create(
                    userId="me",
                    body=label_object,
                ).execute(),
                f"create label {label}"
            )
            self._label_cache[label] = created["id"]
            return created["id"]
        except HttpError as e:
            logger.error(f"Failed to create label {label}: {e}")
            raise

    def apply_actions(self, actions: List[LabelAction]) -> ProcessingResult:
        """Apply actions using batch modify for efficiency."""
        result = ProcessingResult()

        # Group actions by (add_labels, remove_labels) for batch processing
        from collections import defaultdict
        batches: Dict[tuple, List[str]] = defaultdict(list)

        for action in actions:
            # Ensure labels exist
            add_ids = []
            for label in action.add_labels:
                label_id = self.ensure_label_exists(label)
                add_ids.append(label_id)

            remove_ids = []
            for label in action.remove_labels:
                label_id = self._label_cache.get(label) or label
                remove_ids.append(label_id)

            if action.archive:
                remove_ids.append("INBOX")

            if action.star:
                star_id = self._label_cache.get("STARRED", "STARRED")
                add_ids.append(star_id)

            key = (tuple(sorted(add_ids)), tuple(sorted(remove_ids)))
            batches[key].append(action.message_id)

            # Track stats
            for label in action.add_labels:
                result.add_label_stat(label)

        # Execute batch modifications
        for (add_ids, remove_ids), msg_ids in batches.items():
            # Chunk by batch modify limit
            for i in range(0, len(msg_ids), BATCH_MODIFY_SIZE):
                chunk = msg_ids[i:i + BATCH_MODIFY_SIZE]
                body = {
                    "ids": chunk,
                    "addLabelIds": list(add_ids),
                    "removeLabelIds": list(remove_ids),
                }
                try:
                    self._execute_with_backoff(
                        lambda: self._service.users().messages().batchModify(
                            userId="me",
                            body=body,
                        ).execute(),
                        "batch modify"
                    )
                    result.success_count += len(chunk)
                except HttpError as e:
                    logger.error(f"Batch modify failed: {e}")
                    result.error_count += len(chunk)
                    result.errors.append(str(e))

                result.processed_count += len(chunk)
                time.sleep(0.5)  # Throttle

        return result

    def get_label_cache(self) -> Dict[str, str]:
        """Get the label name to ID mapping."""
        return self._label_cache.copy()
