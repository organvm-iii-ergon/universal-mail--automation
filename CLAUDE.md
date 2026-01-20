# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Gmail inbox automation system that categorizes and archives emails using the Gmail API. Also includes AppleScript utilities for macOS Mail integration.

## Commands

### Setup
```bash
# Create venv and install dependencies
./deploy.sh

# Or manually:
python3 -m venv .venv
.venv/bin/pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

### Running
```bash
# Load 1Password secrets first
source ~/.config/op/mail_automation.env.op.sh

# Primary labeler (unlabeled emails)
python3 gmail_labeler.py

# With custom query
python3 gmail_labeler.py --query "label:Misc/Other" --remove-label "Misc/Other"

# Bulk re-labeling pass
python3 bulk_sweeper.py

# Generate label counts report
python3 recount.py > mail_report.md

# Full daily automation
./run_automation.sh
```

### Scheduling
```bash
# Deploy launchd job (runs daily at 9 AM)
./deploy.sh

# Check scheduler status
launchctl list | grep com.user.gmail_labeler
```

## Architecture

### Core Pipeline
```
gmail_auth.py        Authentication via 1Password CLI
      ↓
gmail_labeler.py     Main labeler: fetch → categorize → batchModify
      ↓
bulk_sweeper.py      Secondary pass: query-based bulk relabeling
      ↓
recount.py           Statistics reporter
```

### Key Components

**gmail_labeler.py** - Central orchestrator
- `LABEL_RULES` dict: regex patterns with priority ordering (lower = higher priority)
- `StateManager`: persists progress to `labeler_state.json` for crash recovery
- `GmailLabeler.categorize_message()`: matches sender+subject against rules
- Archives all labeled mail except `KEEP_IN_INBOX` categories (Personal, Awaiting Reply, etc.)
- Stars messages in `PRIORITY_LABELS` categories

**gmail_auth.py** - 1Password-backed OAuth
- Reads client config from `GMAIL_OAUTH_OP_REF` or `GMAIL_OAUTH_JSON`
- Reads/writes token via `GMAIL_TOKEN_OP_REF` or `OP_GMAIL_TOKEN_ITEM`/`OP_GMAIL_TOKEN_FIELD`
- Auto-refreshes expired tokens and writes back to 1Password

**bulk_sweeper.py** - Query-based sweeps
- `SWEEP_RULES` list: sender-specific corrections for `Misc/Other` cleanup
- More efficient than client-side iteration for known patterns

### Label Taxonomy
Hierarchical labels with `/` separator: `Work/Dev/GitHub`, `Finance/Banking`, `AI/Services`, etc. The `Misc/Other` label is the catch-all (priority 999).

### AppleScript Tools (macOS Mail)
- `archive_old_inbox.applescript` - Archive messages >90 days old
- `export_mail_snapshot.applescript` - Export to `mail_export.tsv`
- `flag_important_senders.applescript` - Flag VIP senders
- `route_bulk_senders.applescript` - Move newsletters to folders

## Configuration

### Environment Variables (1Password)
```bash
GMAIL_OAUTH_OP_REF="op://Vault/Gmail OAuth/client_json"
GMAIL_TOKEN_OP_REF="op://Vault/Gmail OAuth/token_json"
# Or use item/field/vault triplets:
OP_GMAIL_TOKEN_ITEM="Gmail OAuth"
OP_GMAIL_TOKEN_FIELD="token_json"
OP_GMAIL_TOKEN_VAULT="Vault"
```

### Adding New Rules
Edit `LABEL_RULES` in `gmail_labeler.py`:
```python
"NewCategory/Subcategory": {
    "patterns": [r"sender\.com", r"keyword.*pattern"],
    "priority": 10,  # Lower = higher priority
}
```

For bulk corrections of existing `Misc/Other` items, add to `SWEEP_RULES` in `bulk_sweeper.py`.

## Coding Conventions

- Python 3, 4-space indents
- Structured logging via `logger` (avoid print statements)
- Regex patterns: escape dots (`\.`) and use raw strings (`r"..."`)
- Label names: hierarchical with `/` (e.g., `Work/Dev/GitHub`)

## Files to Avoid Modifying
- `credentials.json`, `client_secret_*.json` (secrets - gitignored)
- `*.log` files (generated output)
- `labeler_state.json` (runtime state for resumption)
