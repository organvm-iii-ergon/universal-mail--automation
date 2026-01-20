import os
from collections import defaultdict

from gmail_labeler import GmailLabeler

# Run an explicit pass over messages tagged "Uncategorized".
if __name__ == "__main__":
    app = GmailLabeler()
    reset_state = os.getenv("RESET_STATE", "true").lower() == "true"
    if reset_state:
        # Reset state to avoid stale page tokens from other queries.
        app.state_manager.save(None, 0, {})
        app.total_processed = 0
        app.stats = defaultdict(int)
    else:
        # Preserve page token to resume a prior pass; keep fresh stats display.
        app.stats = defaultdict(int)
    app.run(query="label:Uncategorized")
