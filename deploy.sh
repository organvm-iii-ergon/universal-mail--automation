#!/usr/bin/env bash
# Deploy and schedule Universal Mail Automation on macOS.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-$REPO_DIR/.venv}"
PLIST_SRC="$REPO_DIR/com.user.mail_automation.plist"
PLIST_DEST="$HOME/Library/LaunchAgents/com.user.mail_automation.plist"
LOG_DIR="$HOME/System/Logs/mail_automation"

echo "Deploying Universal Mail Automation from $REPO_DIR"
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
echo "Installing dependencies..."
"$VENV_PY" -m pip install --upgrade pip -q
"$VENV_PY" -m pip install -r "$REPO_DIR/requirements.txt" -q
"$VENV_PY" -m pip install msal requests -q

# Ensure automation script is executable.
chmod +x "$REPO_DIR/run_automation.sh"

# Create log directory.
mkdir -p "$LOG_DIR"

# Quick env reminder.
if [ ! -f "$HOME/.config/op/mail_automation.env.op.sh" ]; then
  echo "WARNING: Env file not found at ~/.config/op/mail_automation.env.op.sh" >&2
fi

# Install and load the launchd job.
if [ -f "$PLIST_SRC" ]; then
  mkdir -p "$(dirname "$PLIST_DEST")"
  cp "$PLIST_SRC" "$PLIST_DEST"

  AGENT_ID="gui/$(id -u)"
  LABEL="com.user.mail_automation"

  # Unload old job if exists
  launchctl bootout "$AGENT_ID/$LABEL" 2>/dev/null || true

  # Also unload the old gmail_labeler job
  launchctl bootout "$AGENT_ID/com.user.gmail_labeler" 2>/dev/null || true

  # Load new job
  launchctl bootstrap "$AGENT_ID" "$PLIST_DEST"

  echo "LaunchAgent installed: $PLIST_DEST"
  echo "Scheduled to run daily at 9:00 AM"
else
  echo "Launchd plist not found at $PLIST_SRC; skipping scheduler setup." >&2
fi

echo ""
echo "Deployment complete!"
echo ""
echo "Commands:"
echo "  Run now:     $REPO_DIR/run_automation.sh"
echo "  Check logs:  tail -f $LOG_DIR/launchd.stdout.log"
echo "  Status:      launchctl list | grep mail_automation"
echo "  Unload:      launchctl bootout gui/\$(id -u)/com.user.mail_automation"
