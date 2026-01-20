#!/bin/bash
cd /Users/4jp/Workspace/mail_automation
VENV_DIR="$PWD/.venv"
PYTHON_BIN="$VENV_DIR/bin/python"
if [ ! -x "$PYTHON_BIN" ]; then
  PYTHON_BIN="python3"
fi
if [ -f "$HOME/.config/op/mail_automation.env.op.sh" ]; then
  source "$HOME/.config/op/mail_automation.env.op.sh"
fi

echo "🚀 Starting Daily Mail Automation..."
"$PYTHON_BIN" gmail_labeler.py --query "has:nouserlabels"
echo "✅ Labeling Complete."

echo "🧹 Running Bulk Sweeper..."
"$PYTHON_BIN" bulk_sweeper.py
echo "✅ Sweeper Complete."

echo "📊 Generating Report..."
"$PYTHON_BIN" recount.py > mail_report.md
echo "✅ Done."
