# Repository Guidelines

Global policy: /Users/4jp/AGENTS.md applies and cannot be overridden.

## Project Structure & Module Organization
- Python automation lives at `gmail_labeler.py` (core labeling logic), with helpers `final_sweep.py` (follow-up pass) and `recount.py` (label counts). Logs such as `gmail_labeler.log` and `relabel_*.log` track runs.
- macOS Mail support is in `*.applescript` (archiving, exporting snapshots, routing bulk senders).
- Automation entry point `run_automation.sh` runs the labeler on a schedule; OAuth client and token material must be loaded from 1Password-backed env and stay out of the repo.
- Reference docs: `GEMINI.md` (overview) and `PROCESS.md` (rule-mapping plan).

## Build, Test, and Development Commands
- Install deps once: `pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib`.
- Run primary labeler: `python3 gmail_labeler.py` (auths via 1Password-backed env variables).
- Second-pass sweep: `python3 final_sweep.py` (targets `label:Uncategorized`).
- Count remaining uncategorized: `python3 recount.py`.
- Scheduled run log: `bash run_automation.sh` (writes `automation.log`).
- AppleScript utilities (macOS Mail): `osascript archive_old_inbox.applescript`.

## Coding Style & Naming Conventions
- Python 3, 4-space indents, standard library first then third-party imports.
- Keep regex patterns in `LABEL_RULES` precise and escaped; note `priority` ordering (lower = earlier match).
- Name labels with hierarchical slashes (e.g., `Dev/GitHub`, `Finance/Payments`) and keep new categories consistent.
- Prefer structured logging via the existing `logger`; avoid ad-hoc prints except for short utilities.

## Testing & Validation
- No unit test suite; validate by running `gmail_labeler.py` on a small query (e.g., set `query='label:Uncategorized'` temporarily) and reviewing `gmail_labeler.log`.
- After rule changes, run `final_sweep.py` then `recount.py` to confirm uncategorized counts drop.
- Spot-check Gmail labels in the UI for false positives; revert by removing the applied label in Gmail if needed.

## Commit & Pull Request Guidelines
- Commit messages: short, imperative subjects (e.g., `refine travel regex`) with optional body listing changes and validation commands run.
- Pull requests should describe rule changes, new patterns, and any operational impacts (rate limits, scope changes). Link to issue or email sample if available.
- Include a brief "Testing" note (commands run, log files inspected). Screenshots of Gmail label diffs are helpful when UI verification was done.

## Security & Configuration
- Keep OAuth client JSON, token data, and log files out of commits; rotate tokens if shared externally.
- Gmail scope is `https://www.googleapis.com/auth/gmail.modify`; do not widen without review.
- AppleScript tools operate on the local Mail app—close or pause them when running Gmail scripts to avoid conflicts.
