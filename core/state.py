"""
State management for email automation processing.

Provides persistence of processing state for crash recovery and resumption
of interrupted runs.
"""

import json
import logging
import os
from collections import defaultdict
from typing import Any, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class StateManager:
    """
    Handles persistence of the processing state.

    Saves page tokens, processed counts, and label statistics to a JSON file
    for crash recovery. Each provider can use its own state file.

    Attributes:
        filename: Path to the state JSON file
        state: Current state dictionary

    Example:
        state = StateManager("gmail_state.json")
        token = state.get_token()  # allow-secret
        # ... process messages ...
        state.save(next_token, processed_count, label_stats)
    """

    def __init__(self, filename: str):
        """
        Initialize the state manager.

        Args:
            filename: Path to the state file (JSON)
        """
        self.filename = filename
        self.state = self._load()

    def _load(self) -> Dict[str, Any]:
        """Load state from file, or return default state if not found."""
        if os.path.exists(self.filename):
            try:
                with open(self.filename, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse state file {self.filename}: {e}")
            except Exception as e:
                logger.error(f"Failed to load state file {self.filename}: {e}")
        return self._default_state()

    def _default_state(self) -> Dict[str, Any]:
        """Return the default state structure."""
        return {
            "next_page_token": None,
            "total_processed": 0,
            "history": {},
            "last_run": None,
            "provider": None,
        }

    def save(
        self,
        page_token: Optional[str],
        processed_count: int,
        history: Dict[str, int],
        provider: Optional[str] = None,
    ) -> None:
        """
        Save current processing state.

        Args:
            page_token: The next page token for resumption (or None if complete)
            processed_count: Total number of messages processed
            history: Dict mapping label names to counts
            provider: Optional provider identifier (gmail, imap, etc.)
        """
        self.state["next_page_token"] = page_token
        self.state["total_processed"] = processed_count
        self.state["history"] = dict(history)  # Convert defaultdict to dict
        self.state["last_run"] = datetime.now().isoformat()
        if provider:
            self.state["provider"] = provider

        try:
            with open(self.filename, "w") as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state to {self.filename}: {e}")

    def get_token(self) -> Optional[str]:
        """Get the saved page token for resumption."""
        return self.state.get("next_page_token")

    def get_total(self) -> int:
        """Get the total number of processed messages."""
        return self.state.get("total_processed", 0)

    def get_history(self) -> defaultdict:
        """
        Get the label statistics history.

        Returns:
            defaultdict(int) with label counts
        """
        return defaultdict(int, self.state.get("history", {}))

    def get_last_run(self) -> Optional[str]:
        """Get the timestamp of the last run."""
        return self.state.get("last_run")

    def get_provider(self) -> Optional[str]:
        """Get the provider identifier from the last run."""
        return self.state.get("provider")

    def clear(self) -> None:
        """Clear the state file (reset to defaults)."""
        self.state = self._default_state()
        try:
            if os.path.exists(self.filename):
                os.remove(self.filename)
        except Exception as e:
            logger.error(f"Failed to clear state file {self.filename}: {e}")

    def is_resumable(self) -> bool:
        """Check if there's a valid state to resume from."""
        return self.state.get("next_page_token") is not None
