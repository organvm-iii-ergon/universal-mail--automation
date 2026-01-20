#!/bin/bash
# Universal Mail Automation - Daily Runner
# Processes emails across Gmail, Outlook, and iCloud

set -euo pipefail

REPO_DIR="/Users/4jp/Workspace/universal-mail--automation"
cd "$REPO_DIR"

VENV_DIR="$REPO_DIR/.venv"
PYTHON_BIN="$VENV_DIR/bin/python"

if [ ! -x "$PYTHON_BIN" ]; then
  echo "ERROR: Python not found at $PYTHON_BIN" >&2
  exit 1
fi

# Load secrets from 1Password
if [ -f "$HOME/.config/op/mail_automation.env.op.sh" ]; then
  source "$HOME/.config/op/mail_automation.env.op.sh"
else
  echo "ERROR: Env file not found at ~/.config/op/mail_automation.env.op.sh" >&2
  exit 1
fi

echo "========================================"
echo "Universal Mail Automation - $(date)"
echo "========================================"

# Gmail
echo ""
echo "[Gmail] Processing unlabeled emails..."
"$PYTHON_BIN" cli.py label --provider gmail --query "has:nouserlabels" || echo "Gmail failed"

echo ""
echo "[Gmail] Re-processing Misc/Other..."
"$PYTHON_BIN" cli.py label --provider gmail --query "label:Misc/Other" --remove-label "Misc/Other" || echo "Gmail sweep failed"

# Outlook
echo ""
echo "[Outlook] Processing inbox..."
"$PYTHON_BIN" cli.py label --provider outlook --query "" || echo "Outlook failed"

# iCloud
echo ""
echo "[iCloud] Processing inbox..."
IMAP_HOST="$ICLOUD_IMAP_HOST" \
IMAP_USER="$ICLOUD_IMAP_USER" \
IMAP_PASS="$ICLOUD_IMAP_PASS" \
"$PYTHON_BIN" cli.py label --provider imap --query "ALL" || echo "iCloud failed"

echo ""
echo "========================================"
echo "Automation Complete - $(date)"
echo "========================================"
