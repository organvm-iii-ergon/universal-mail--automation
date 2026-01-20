# Mail Automation Project

This directory contains a suite of tools for automating email organization, primarily focused on Gmail but also including AppleScript tools for the macOS Mail app. The project aims to exhaustively label, archive, and organize emails based on semantic categories.

## 📂 Project Structure

### Core Python Tools
*   **`gmail_labeler.py`**: The main automation script. It uses the Gmail API to:
    *   Fetch unlabeled emails (`has:nouserlabels`).
    *   Apply labels based on a comprehensive set of regex rules (defined in `LABEL_RULES`).
    *   Categories include Development, AI Services, Finance, Shopping, etc.
    *   Handles authentication via OAuth2 (client config + token loaded from 1Password-backed env).
*   **`final_sweep.py` / `recount.py`**: Helper scripts for secondary passes or statistical counting (likely similar logic to the main labeler).

### AppleScript Tools (macOS Mail)
*   **`archive_old_inbox.applescript`**: Moves messages older than a specified threshold (default 90 days) from Inbox to Archive.
*   **`export_mail_snapshot.applescript`**: Exports mail data, likely to `mail_export.tsv`.
*   **`flag_important_senders.applescript`**: Flags messages from key senders.
*   **`route_bulk_senders.applescript`**: Moves bulk/newsletter emails to specific folders.

### Data & Configuration
*   OAuth client JSON and token JSON are loaded from 1Password-backed env variables (see Authentication).
*   **`*.log`**: Execution logs from the labeling scripts.
*   **`mail_report.md`**: Summary report of email statistics (senders, domains, age).

## 🚀 Setup & Usage

### 1. Python Environment
Ensure you have Python installed. It is recommended to use a virtual environment.

**Install Dependencies:**
The scripts require the Google API client libraries.
```bash
pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

**Authentication:**
1.  Store the OAuth client JSON and token JSON in 1Password.
2.  Load env vars using `~/.config/op/load-env.sh` and a per-project env script.
3.  The first time you run `gmail_labeler.py`, a browser window will open for you to authorize access, then the token is written back to 1Password.

Example env entries (replace placeholders):
```bash
export GMAIL_OAUTH_OP_REF="op://Vault/Gmail OAuth/client_json"
export GMAIL_TOKEN_OP_REF="op://Vault/Gmail OAuth/token_json"
export OP_GMAIL_TOKEN_ITEM="Gmail OAuth"
export OP_GMAIL_TOKEN_FIELD="token_json"
export OP_GMAIL_TOKEN_VAULT="Vault"
```
*   Note: scheduled runs require an active 1Password CLI session (`op signin`).

**Running the Labeler:**
```bash
python3 gmail_labeler.py
```
*   **Note:** The script runs in batches (default 500 emails) and includes retry logic for API rate limits.

### 2. AppleScript usage
These scripts are designed to run locally on macOS with the Mail app open.
*   **Run via Command Line:** `osascript archive_old_inbox.applescript`
*   **Run via Editor:** Open the file in **Script Editor.app** and click the "Run" (Play) button.

## ⚙️ Configuration

### Modifying Label Rules
The categorization logic is defined in the `LABEL_RULES` dictionary within `gmail_labeler.py`. Each category has:
*   **`patterns`**: A list of regex strings to match against the Sender and Subject.
*   **`priority`**: Lower numbers are higher priority (e.g., "Dev/GitHub" checks before "Notification").

Example:
```python
"Dev/GitHub": {
    "patterns": [r"github\.com", r"notifications@github"],
    "priority": 1,
}
```

## 📝 Logs & Troubleshooting
*   Check `gmail_labeler.log` (or `relabel_*.log`) for execution details.
*   If authentication fails, clear the token field in 1Password and run the script again to re-authenticate.
