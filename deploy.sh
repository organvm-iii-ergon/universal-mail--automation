#!/usr/bin/env bash

# Deploy and schedule the Gmail labeling automation on macOS.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-$REPO_DIR/.venv}"
PLIST_SRC="$REPO_DIR/com.user.gmail_labeler.plist"
PLIST_DEST="$HOME/Library/LaunchAgents/com.user.gmail_labeler.plist"

echo "Deploying mail automation from $REPO_DIR"
echo "Using Python: $PYTHON_BIN"
echo "Virtualenv: $VENV_DIR"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "Python interpreter not found: $PYTHON_BIN" >&2
  exit 1
fi

# Create or reuse the virtual environment.
if [ ! -d "$VENV_DIR" ]; then
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi
VENV_PY="$VENV_DIR/bin/python"

# Install Python dependencies.
"$VENV_PY" -m pip install --upgrade pip
"$VENV_PY" -m pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib

# Ensure automation script is executable.
chmod +x "$REPO_DIR/run_automation.sh"

# Quick env reminder.
if [ -z "${GMAIL_OAUTH_OP_REF:-}" ] && [ -z "${GMAIL_OAUTH_JSON:-}" ]; then
  echo "Reminder: load Gmail OAuth secrets from 1Password before running the labeler." >&2
fi

# Install and load the launchd job for hourly runs.
if [ -f "$PLIST_SRC" ]; then
  mkdir -p "$(dirname "$PLIST_DEST")"
  cp "$PLIST_SRC" "$PLIST_DEST"
  AGENT_ID="gui/$(id -u)"
  LABEL="com.user.gmail_labeler"
  launchctl bootout "$AGENT_ID/$LABEL" >/dev/null 2>&1 || true
  launchctl bootstrap "$AGENT_ID" "$PLIST_DEST"
  launchctl kickstart -k "$AGENT_ID/$LABEL"
  echo "LaunchAgent loaded and started: $PLIST_DEST"
else
  echo "Launchd plist not found at $PLIST_SRC; skipping scheduler setup." >&2
fi

echo "Deployment complete. To run once manually:"
echo "  \"$VENV_PY\" -m pip install --upgrade pip"
echo "  \"$VENV_PY\" -m pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib"
echo "  source \"$HOME/.config/op/mail_automation.env.op.sh\""
echo "  \"$VENV_PY\" gmail_labeler.py"
echo "To check status: launchctl list | grep com.user.gmail_labeler"
