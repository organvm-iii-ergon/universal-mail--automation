# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Multi-provider email automation system that categorizes and archives emails using Gmail API, IMAP, macOS Mail.app, or Outlook.com. Features a unified CLI with shared categorization rules across all providers.

## Commands

### Setup
```bash
# Create venv and install dependencies
./deploy.sh

# Or manually:
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# For Outlook support:
.venv/bin/pip install msal requests

# For YAML config support:
.venv/bin/pip install pyyaml
```

### Sending mail (interactive lane) — mail_send.py

`mail_send.py` is the INTERACTIVE, headless send CLI (keyed Gmail SMTP + built-in
[Gmail]/Sent Mail verification; loud VERIFIED/UNVERIFIED, non-zero exit if unverified).
It is a SEPARATE lane from `send_drafts.py` (the autonomic beat sender, which stays
tier-locked behind LIMEN_MAIL_SEND). `mail_send` is zero-write by default. Invocation
is not authorization: every transmission requires explicit `--apply` plus an unexpired
`uma.mail_send_authorization.v1` receipt bound to the attempt ID, sender, normalized
To/Cc/Bcc recipients, SMTP envelope, subject, Message-ID, thread/source UID, body
digest, and attachment digests. The receipt must be authenticated with the separately
custodied Ed25519 private key, may live for at most 15 minutes, and each attempt ID
is durably one-shot even after an SMTP/verification failure. The sender only reads
the fixed public key at `/etc/universal-mail-automation/mail-send-authorization.pub`;
neither the verifier path nor the attempt store is caller-selectable. Never wire
`mail_send` into the beat.

```bash
# creds: GMAIL_USER/GMAIL_APP_PASSWORD (limen creds-hydrate), or use
# --credentials-file ~/.config/mail_automation/credentials.env (parsed as data;
# never source/eval the file)

python3 mail_send.py --self-test --attempt-id selftest-20260716-a  # deterministic zero-write request
python3 mail_send.py --attempt-id send-20260716-a --to a@b.c --subject "Hi" --body-file body.txt
python3 mail_send.py --attempt-id reply-20260716-a --reply-to-search "subject fragment" --body-file body.txt
python3 mail_send.py --attempt-id draft-20260716-a --from-draft "subject fragment"

# Only after an independent authority copies the preview binding into an
# authorized=true, authorized_by, issued_at/expires_at (<=15m) JSON receipt,
# adds key_id/signature_algorithm, and Ed25519-signs the canonical receipt using
# private key material unavailable to the mail-send process:
python3 mail_send.py ... --apply \
  --authorization-receipt /private/path/authorization.json

# Never retry an apply with the same attempt ID. Its durable claim is consumed
# before SMTP; use a fresh preview, receipt, and attempt ID after any ambiguity.
```

### Running (Unified CLI)
```bash
# Load 1Password secrets first
source ~/.config/op/mail_automation.env.op.sh

# Gmail provider (default)
python3 cli.py label --provider gmail --query "has:nouserlabels"
python3 cli.py label --provider gmail --query "label:Misc/Other" --remove-label "Misc/Other"

# IMAP provider (with Gmail extensions)
python3 cli.py label --provider imap --host imap.gmail.com --gmail-extensions

# macOS Mail.app provider
python3 cli.py label --provider mailapp --account "iCloud"

# Outlook.com provider
python3 cli.py label --provider outlook

# Dry run (don't apply changes)
python3 cli.py label --provider gmail --dry-run

# Tier-based routing (Eisenhower matrix with categories + Action folders)
python3 cli.py label --provider outlook --tier-routing

# Process only VIP sender emails
python3 cli.py label --provider gmail --vip-only

# Health check
python3 cli.py health --provider gmail

# Report (label counts)
python3 cli.py report --provider gmail

# Redacted private operator-dashboard payload
python3 cli.py ops-summary --report ~/System/Reports/mail-triage/latest.json --pretty
python3 cli.py ops-refresh --report ~/System/Reports/mail-triage/latest.json --pretty
python3 cli.py mail-history-export --source ~/Library/Mail --output ~/System/Reports/mail-history/latest.json --since 2024-01-01 --until 2026-06-16 --pretty
python3 cli.py mail-intel --history ~/System/Reports/mail-history/latest.json --ops-report ~/System/Reports/mail-triage/latest.json --output ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-action-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-resolver-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-provider-surface-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-resolver-ledger --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-github-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-github-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-followup-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-followup-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-external-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-external-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json --attest-blockers --pretty
python3 cli.py mail-resolver-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --action-id action_... --resolver-status verified_resolved --reason-code github_reconciled --proof-type github_issue_pr_billing_or_security_state --provider github --pretty
python3 cli.py mail-action-ledger --intelligence ~/System/Reports/mail-history/latest-intelligence.json --pretty
python3 cli.py mail-action-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --action-id action_... --status waiting --reason-code awaiting_reply --pretty
python3 cli.py mail-evidence-review --history ~/System/Reports/mail-history/latest.json --evidence-id ev_... --ack-private --pretty
python3 cli.py mail-draft-package --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --ack-private --pretty
python3 cli.py mail-draft-approval --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --draft-id draft_... --decision approved --reason-code ready_to_send --ack-private --pretty
python3 cli.py mail-delivery-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --draft-id draft_... --delivery-status provider_draft_requested --reason-code approved_for_provider_draft --ack-private --pretty
```

### Triage & Reporting Commands
```bash
# Summary by priority tier
python3 cli.py summary --provider outlook
python3 cli.py summary --provider gmail --format json

# List pending/flagged items needing action
python3 cli.py pending --provider gmail
python3 cli.py pending --format markdown

# Show VIP sender activity
python3 cli.py vip --provider outlook
python3 cli.py vip --format json

# Escalate stale emails (re-triage based on age)
python3 cli.py escalate --provider outlook --dry-run
python3 cli.py escalate --provider gmail --limit 500

# Operator summary for /ops and Data Analytics handoff
python3 cli.py ops-summary --report ~/System/Reports/mail-triage/latest.json

# Persist redacted latest summary + bounded history for /ops
python3 cli.py ops-refresh --report ~/System/Reports/mail-triage/latest.json
python3 cli.py ops-refresh --run-mail-triage --since 2026-05-01 --until 2026-06-16 --report-dir ~/System/Reports/mail-triage

# Normalize local historical mail into a private export for intelligence mining
python3 cli.py mail-history-export --source ~/Library/Mail --output ~/System/Reports/mail-history/latest.json --since 2024-01-01 --until 2026-06-16

# Mine historical mail into redacted opportunities, risks, evidence, and ops reconciliation
python3 cli.py mail-intel --history ~/System/Reports/mail-history/latest.json --ops-report ~/System/Reports/mail-triage/latest.json --output ~/System/Reports/mail-history/latest-intelligence.json

# Group redacted intelligence into approval-aware next actions
python3 cli.py mail-action-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json

# Map actions to official surfaces, blockers, safe local prep, and required proof
python3 cli.py mail-resolver-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json

# Rank controlled provider hints into future resolver/API/CLI build frontier
python3 cli.py mail-provider-surface-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json

# Read GitHub official surfaces without mutating GitHub or mail
python3 cli.py mail-github-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json

# Record GitHub provider-read or blocker proof into the resolver ledger
python3 cli.py mail-github-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json

# Reconcile and record mail/LinkedIn follow-up proof from approval/delivery receipts
python3 cli.py mail-followup-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json
python3 cli.py mail-followup-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json

# Inspect and explicitly attest provider/security/billing/subscription/legal blockers
python3 cli.py mail-external-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json
python3 cli.py mail-external-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json --attest-blockers

# Show and record redacted official-surface resolver proof
python3 cli.py mail-resolver-ledger --intelligence ~/System/Reports/mail-history/latest-intelligence.json
python3 cli.py mail-resolver-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --action-id action_... --resolver-status verified_resolved --reason-code github_reconciled --proof-type github_issue_pr_billing_or_security_state --provider github

# Show local action status and proof receipts
python3 cli.py mail-action-ledger --intelligence ~/System/Reports/mail-history/latest-intelligence.json

# Record a local redacted proof receipt
python3 cli.py mail-action-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --action-id action_... --status waiting --reason-code awaiting_reply

# Open a single private source message for fact checking
python3 cli.py mail-evidence-review --history ~/System/Reports/mail-history/latest.json --evidence-id ev_... --ack-private

# Build private draft candidates for approval
python3 cli.py mail-draft-package --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --ack-private

# Record redacted local approval for a draft candidate
python3 cli.py mail-draft-approval --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --draft-id draft_... --decision approved --reason-code ready_to_send --ack-private

# Record redacted local delivery intent/status after approval
python3 cli.py mail-delivery-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --draft-id draft_... --delivery-status provider_draft_requested --reason-code approved_for_provider_draft --ack-private
```

### Triage Command (research + prioritization + voice-matched drafts)
End-to-end pipeline: research each item's content/context, score and sort the
mailbox by priority, and optionally draft replies in the user's own voice.
```bash
# Priority-sorted triage of the mailbox (research + scoring)
python3 cli.py triage --provider gmail --top 20

# Markdown / JSON output
python3 cli.py triage --provider outlook --format markdown
python3 cli.py triage --provider gmail --format json --limit 100

# Generate suggested replies in the user's voice for items needing a response
python3 cli.py triage --provider gmail --draft --name "Anthony"

# Use an explicit voice profile, or learn it from a corpus of sent messages
python3 cli.py triage --draft --voice-file ~/.config/mail_automation/voice.json
python3 cli.py triage --draft --samples-file ~/.config/mail_automation/sent_samples.txt
```

### Legacy Commands (Backward Compatible)
```bash
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

### Module Structure
```
mail_automation/
├── core/                    # Shared components
│   ├── rules.py            # LABEL_RULES, categorize_message()
│   ├── research.py         # Per-item content & context research (ResearchDossier)
│   ├── voice.py            # Learn & apply the user's speech patterns (VoiceProfile)
│   ├── triage.py           # Prioritization scoring + orchestration (triage_messages)
│   ├── ops_summary.py      # Redacted UMA operator summary contract
│   ├── state.py            # StateManager for crash recovery
│   ├── models.py           # EmailMessage, LabelAction dataclasses
│   └── config.py           # Multi-provider configuration
├── providers/              # Email service adapters
│   ├── base.py             # Abstract EmailProvider interface
│   ├── gmail.py            # Gmail API provider
│   ├── imap.py             # Generic IMAP provider
│   ├── mailapp.py          # macOS Mail.app (AppleScript)
│   └── outlook.py          # Microsoft Graph API
├── auth/                   # Authentication utilities
│   └── onepassword.py      # 1Password CLI integration
├── cli.py                  # Unified CLI entry point
├── gmail_labeler.py        # Legacy entry point (backward compat)
├── gmail_auth.py           # Legacy Gmail auth
└── imap_rules.py           # Legacy IMAP script
```

### Provider Capabilities

| Provider | Labels | Folders | Star | Archive | Batch API | Search | Categories |
|----------|--------|---------|------|---------|-----------|--------|------------|
| Gmail    | ✓      |         | ✓    | ✓       | ✓         | ✓      |            |
| IMAP     | ✓*     | ✓       | ✓    | ✓       |           | ✓      |            |
| Mail.app |        | ✓       | ✓    | ✓       |           |        |            |
| Outlook  |        | ✓       | ✓    | ✓       |           | ✓      | ✓          |

*IMAP with `--gmail-extensions` flag

### Core Pipeline
```
core/rules.py        Shared LABEL_RULES taxonomy
      ↓
providers/*.py       Provider-specific fetch & apply
      ↓
core/state.py        Progress persistence for resumption
```

### Key Components

**core/rules.py** - Shared categorization
- `LABEL_RULES` dict: regex patterns with priority, tier, and time_sensitive fields
- `PRIORITY_TIERS`: Eisenhower matrix (1=Critical, 2=Important, 3=Delegate, 4=Reference)
- `VIP_SENDERS`: High-priority senders that override normal categorization
- `categorize_message()`: matches sender+subject against rules
- `categorize_with_tier()`: returns full tier info with `CategorizationResult`
- `escalate_by_age()`: determines if email should be escalated based on age
- `PRIORITY_LABELS`: labels that trigger starring
- `KEEP_IN_INBOX`: labels that remain in inbox (not archived)

**core/research.py** - Content & context research (offline, deterministic)
- `ResearchDossier`: per-message extraction — summary, action items, questions,
  deadlines, links, monetary amounts, entities, urgency, `requires_reply`
- `research_message(message, body=None)`: mines `EmailMessage.content_text`
  (subject + body/snippet), degrading gracefully to subject-only

**core/voice.py** - User speech-pattern modelling (no LLM dependency)
- `VoiceProfile`: greeting, sign-off, signature, formality, cadence, contractions, phrases
- `learn_voice_profile(samples)`: derive a profile from the user's sent messages
- `load_voice_profile()`: resolve from saved JSON → learn-from-corpus → neutral default
  (default paths under `~/.config/mail_automation/`)
- `VoiceProfile.draft_reply(dossier)`: compose a reply matching the user's voice
  (learned openers are kept as a style signal but never pasted verbatim)

**core/triage.py** - Prioritization + orchestration
- `triage_messages(messages, voice=None, draft=False)`: categorize → escalate by
  age → research → score → sort; returns ranked `TriageItem`s
- `score_priority(...)`: transparent composite of tier, VIP, urgency, deadlines,
  requires-reply, escalation, unread/starred and age
- `render_triage(items, fmt)`: `text` / `markdown` / `json`

**providers/base.py** - Abstract interface
- `EmailProvider`: base class all providers implement
- `ProviderCapabilities`: flags for feature detection
- `ListMessagesResult`: pagination support

**core/state.py** - Crash recovery
- `StateManager`: persists progress to JSON for resumption
- Supports page tokens, processed counts, label statistics

**gmail_auth.py** - 1Password-backed OAuth
- Reads client config from `GMAIL_OAUTH_OP_REF` or `GMAIL_OAUTH_JSON`
- Reads/writes token via `GMAIL_TOKEN_OP_REF` or `OP_GMAIL_TOKEN_ITEM`/`OP_GMAIL_TOKEN_FIELD`
- Auto-refreshes expired tokens and writes back to 1Password

### Label Taxonomy
Hierarchical labels with `/` separator: `Work/Dev/GitHub`, `Finance/Banking`, `AI/Services`, etc. The `Misc/Other` label is the catch-all (priority 999).

### AppleScript Tools (macOS Mail)
- `archive_old_inbox.applescript` - Archive messages >90 days old
- `export_mail_snapshot.applescript` - Export to `mail_export.tsv`
- `flag_important_senders.applescript` - Flag VIP senders
- `route_bulk_senders.applescript` - Move newsletters to folders

## Configuration

### Environment Variables (1Password - Gmail)
```bash
GMAIL_OAUTH_OP_REF="op://Vault/Gmail OAuth/client_json"
GMAIL_TOKEN_OP_REF="op://Vault/Gmail OAuth/token_json"
# Or use item/field/vault triplets:
OP_GMAIL_TOKEN_ITEM="Gmail OAuth"
OP_GMAIL_TOKEN_FIELD="token_json"
OP_GMAIL_TOKEN_VAULT="Vault"
```

### Environment Variables (IMAP)
```bash
IMAP_HOST="imap.gmail.com"
IMAP_USER="user@gmail.com"
IMAP_PASS="app-password"  # Or use 1Password
OP_ACCOUNT="my.op.com"
OP_ITEM="IMAP Password"
OP_FIELD="password"
```

### Environment Variables (Outlook)
```bash
OUTLOOK_CLIENT_ID="your-azure-app-client-id"
OUTLOOK_TOKEN_CACHE="~/.outlook_token_cache.json"
```

### Environment Variables (Operator Dashboard)
```bash
UMA_OPS_REPORT_PATH="~/System/Reports/mail-triage/latest.json"
UMA_OPS_REPORT_DIR="~/System/Reports/mail-triage"
UMA_OPS_HISTORY_DIR="~/.local/state/universal-mail-automation/ops"
UMA_OPS_MAX_AGE_HOURS="12"
UMA_MAIL_TRIAGE_BIN="/Users/4jp/.local/bin/mail-triage"
UMA_OPS_TOKEN="optional-local-bearer-token"
UMA_HISTORICAL_MAIL_PATH="~/System/Reports/mail-history/latest.json"
UMA_HISTORICAL_STALE_DAYS="14"
UMA_MAIL_RESOLVER_LEDGER_PATH="~/.local/state/universal-mail-automation/mail-resolver-ledger.jsonl"
```

`/ops` is the private operator dashboard. It fetches `/v1/ops/summary`, which is
disabled unless `UMA_OPS_REPORT_PATH` is set. The payload is
`uma.ops.summary.v1` and must not expose raw senders, addresses, subjects,
bodies, or full local report paths. Run `ops-refresh` to write the redacted
`latest-summary.json`, `history/`, and `index.json` consumed by `/v1/ops/history`.
`/v1/ops/intelligence` emits `uma.mail.intelligence.v1` from
`UMA_HISTORICAL_MAIL_PATH` and reconciles missed historical opportunities and
risks against current `/ops` lanes without mutating the mailbox. It may include
controlled provider/surface hint slugs for routing; those hints are not raw
provider identity and are not provider proof.
Generate that input with `mail-history-export`; it writes a private
`uma.mail.history_export.v1` file and prints only a redacted
`uma.mail.history_export.receipt.v1` receipt.
For large histories, use `mail-intel --output` and set
`UMA_HISTORICAL_INTELLIGENCE_PATH` so `/v1/ops/intelligence` serves the
precomputed redacted cache instead of recomputing from raw export every load.
`/v1/ops/action-plan` emits `uma.mail.action_plan.v1`, grouping the redacted
findings into priority, lane, approval, automation-boundary, and provider-hint
clusters.
`/v1/ops/resolver-plan` emits `uma.mail.resolver_plan.v1`, mapping those
clusters to official surfaces such as mail or LinkedIn inboxes, GitHub API/CLI,
provider security dashboards, billing portals, legal review, blockers, safe
local prep, controlled provider hints, and required proof. It is plan-only and
performs no portal, send, or mailbox mutation.
`/v1/ops/provider-surface-plan` emits `uma.provider.surface_plan.v1`, ranking
controlled provider/surface hints into the next provider/API/CLI resolver
frontier. It is plan-only and performs no provider reads, portal automation,
sends, provider-draft creation, or mailbox mutation.
`/v1/ops/resolver-ledger` emits `uma.mail.resolver_ledger.v1`, merging resolver
plan items with local `uma.mail.resolver_receipt.v1` official-surface
attestations. `POST /v1/ops/resolver-receipts` requires `UMA_OPS_TOKEN`, hashes
external references, and still performs no portal, send, provider-draft, or
mailbox mutation.
`/v1/ops/github-resolver` emits `uma.github.resolver_snapshot.v1`, a bounded
read-only GitHub CLI/API snapshot for GitHub resolver actions. It hashes repo
references, omits notification/issue/PR titles and URLs, and creates receipt
candidates without mutating GitHub, mailboxes, portals, drafts, or sends.
`/v1/ops/github-resolver-receipts` requires `UMA_OPS_TOKEN` and records those
provider-read or blocker candidates into the redacted resolver ledger as
`uma.mail.resolver_receipt.v1` receipts; provider-backed read is distinct from
provider-backed automation, which remains false.
`/v1/ops/followup-resolver` emits `uma.followup.resolver_snapshot.v1`, a
redacted mail/LinkedIn follow-up snapshot over local draft approval and delivery
receipts. `/v1/ops/followup-resolver-receipts` requires `UMA_OPS_TOKEN` and
records resolver receipts only when those approval/delivery receipts already
provide local proof. It does not read LinkedIn, create drafts, send, archive,
label, mark read, or mutate mail.
`/v1/ops/external-resolver` emits `uma.external.resolver_snapshot.v1`, a
redacted planned view of provider, security, billing, subscription, and legal
official-surface lanes with controlled provider hint counts.
`/v1/ops/external-resolver-receipts` requires
`UMA_OPS_TOKEN` and records local blocker attestations only when explicitly
requested. Provider hints are not provider reads. It does not read providers,
open portals, send, archive, label, mark read, or mutate accounts.
`/v1/ops/action-ledger` emits `uma.mail.action_ledger.v1`, merging those action
groups with local `uma.mail.action_receipt.v1` proof receipts. `POST
/v1/ops/action-receipts` requires `UMA_OPS_TOKEN` and writes only redacted local
receipt state.
`/v1/ops/draft-package/{action_id}?ack_private=true` emits private
`uma.mail.draft_package.v1` candidates for `missed_lead` / `draft_approval`
actions; it requires `UMA_OPS_TOKEN` and still permits no sends or mailbox
mutations.
`/v1/ops/draft-approvals/{action_id}?ack_private=true` emits redacted
`uma.mail.draft_approval_ledger.v1`; `POST /v1/ops/draft-approvals/{action_id}`
records `uma.mail.draft_approval_receipt.v1` and still sends nothing.
`/v1/ops/delivery/{action_id}?ack_private=true` emits redacted
`uma.mail.delivery_ledger.v1`; `POST /v1/ops/delivery/{action_id}` records
`uma.mail.delivery_receipt.v1` and still creates no provider draft and sends
nothing.
`/v1/ops/evidence/{evidence_id}?ack_private=true` emits gated private
`uma.mail.evidence_review.v1`; it requires `UMA_OPS_TOKEN` and can include raw
source sender, subject, and bounded body text for fact checking only.

### Configuration File (Optional)
Create `~/.config/mail_automation/config.yaml`:
```yaml
default_provider: gmail
log_level: INFO
batch_size: 100

gmail:
  default_query: "has:nouserlabels"
  state_file: "gmail_state.json"

imap:
  host: imap.gmail.com
  use_gmail_extensions: true

mailapp:
  account: "iCloud"

outlook:
  client_id: "your-app-id"

# VIP senders - always get priority treatment
vip_senders:
  "ceo@company.com":
    pattern: "ceo@company\\.com"
    tier: 1  # Critical
    star: true
    note: "CEO"
  "important-client":
    pattern: ".*@important-client\\.com"
    tier: 1
    star: true
    label_override: "Personal"  # Optional: override categorization
    note: "Important client domain"
```

### Adding New Rules
Edit `core/rules.py` or add to config file:
```python
"NewCategory/Subcategory": {
    "patterns": [r"sender\.com", r"keyword.*pattern"],
    "priority": 10,  # Lower = higher priority
    "tier": 2,       # 1=Critical, 2=Important, 3=Delegate, 4=Reference
    "time_sensitive": True,  # Escalate if email gets old
}
```

For bulk corrections of existing `Misc/Other` items, add to `SWEEP_RULES` in `bulk_sweeper.py`.

### Priority Tier System (Eisenhower Matrix)
| Tier | Name | Color | Behavior |
|------|------|-------|----------|
| 1 | Critical | Red | Star, keep in inbox, Action/Critical folder |
| 2 | Important | Yellow | Keep in inbox, Action/Important folder |
| 3 | Delegate | Blue | Archive, Action/Delegate folder |
| 4 | Reference | Green | Archive, categorize only |

### Time-Based Escalation Rules
- < 24 hours: No escalation
- 24-72 hours: Tier 3-4 → Tier 2 (if time_sensitive=True)
- > 72 hours: Tier 2-4 → Tier 1 (always escalate)

## Coding Conventions

- Python 3.9+, 4-space indents
- Structured logging via `logger` (avoid print statements)
- Regex patterns: escape dots (`\.`) and use raw strings (`r"..."`)
- Label names: hierarchical with `/` (e.g., `Work/Dev/GitHub`)
- Providers implement `EmailProvider` abstract base class
- Use dataclasses for DTOs (`EmailMessage`, `LabelAction`)

## Files to Avoid Modifying
- `credentials.json`, `client_secret_*.json` (secrets - gitignored)
- `*.log` files (generated output)
- `*_state.json` (runtime state for resumption)
- `~/.outlook_token_cache.json` (OAuth token cache)

## Testing

```bash
# Verify imports
python3 -c "from core import LABEL_RULES, categorize_message, PRIORITY_TIERS"
python3 -c "from core import categorize_with_tier, escalate_by_age"
python3 -c "from core import research_message, learn_voice_profile, triage_messages, render_triage"
python3 -c "from providers.gmail import GmailProvider"
python3 -c "from providers.outlook import OutlookProvider, CATEGORY_COLORS"

# Unit tests for the triage pipeline (offline, no accounts needed)
python3 -m pytest tests/test_research.py tests/test_voice.py tests/test_triage.py -q

# Operator dashboard/API/CLI redaction contract
python3 -m pytest tests/test_ops.py -q

# Dry run test
python3 cli.py label --provider gmail --dry-run --limit 10

# Test tier routing (Outlook)
python3 cli.py label --provider outlook --tier-routing --dry-run --limit 5

# Test escalation
python3 cli.py escalate --provider gmail --dry-run --limit 10

# Health check
python3 cli.py health --provider gmail

# Generate summary
python3 cli.py summary --provider gmail --limit 100

# Triage pipeline (research + prioritization + voice-matched drafts)
python3 cli.py triage --provider gmail --top 20 --draft --name "Anthony"
```

## Web Dashboard

`web/index.html` is a single-file static dashboard (deployed at uma.4444j99.dev) with
sender-check and triage-preview panels backed by the `/v1/senders/check` and
`/v1/triage/preview` API endpoints.

**Provider brand theming:** the dashboard shifts in phase with the interfaced mailbox.
`html[data-provider="gmail|outlook|icloud|imap"]` swaps the `--accent`/`--accent-rgb`
CSS token family to the provider's brand palette, with a 700ms cross-fade
(`prefers-reduced-motion` respected). Three control surfaces stay in sync: the nav
theme dial, the provider chips, and the `#provider` triage select (CLI key `mailapp`
maps to visual identity `icloud`). Choice persists via localStorage
(`uma-provider-theme`).

```bash
# Visual proof: brand accents, dial↔select sync, reload persistence
npx playwright install chromium   # once
node tests/theme_proof.mjs [output-dir]

# Static assertions on the dashboard markup
python3 -m pytest tests/test_web.py -q
```

<!-- ORGANVM:AUTO:START -->
## System Context (auto-generated — do not edit)

**Organ:** ORGAN-III (Commerce) | **Tier:** standard | **Status:** PUBLIC_PROCESS
**Org:** `organvm-iii-ergon` | **Repo:** `universal-mail--automation`

### Edges
- **Produces** → `unspecified`: artifact
- **Produces** → `unspecified`: artifact
- **Produces** → `unspecified`: artifact

### Siblings in Commerce
`classroom-rpg-aetheria`, `gamified-coach-interface`, `trade-perpetual-future`, `fetch-familiar-friends`, `sovereign-ecosystem--real-estate-luxury`, `public-record-data-scrapper`, `search-local--happy-hour`, `multi-camera--livestream--framework`, `mirror-mirror`, `the-invisible-ledger`, `enterprise-plugin`, `virgil-training-overlay`, `tab-bookmark-manager`, `a-i-chat--exporter`, `.github` ... and 16 more

### Governance
- Strictly unidirectional flow: I→II→III. No dependencies on Theory (I).

*Last synced: 2026-06-08T16:26:25Z*

## Active Handoff Protocol

If `.conductor/active-handoff.md` exists, **READ IT FIRST** before doing any work.
It contains constraints, locked files, conventions, and completed work from the
originating agent. You MUST honor all constraints listed there.

If the handoff says "CROSS-VERIFICATION REQUIRED", your self-assessment will
NOT be trusted. A different agent will verify your output against these constraints.

## Session Review Protocol

At the end of each session that produces or modifies files:
1. Run `organvm session review --latest` to get a session summary
2. Check for unimplemented plans: `organvm session plans --project .`
3. Export significant sessions: `organvm session export <id> --slug <slug>`
4. Run `organvm prompts distill --dry-run` to detect uncovered operational patterns

Transcripts are on-demand (never committed):
- `organvm session transcript <id>` — conversation summary
- `organvm session transcript <id> --unabridged` — full audit trail
- `organvm session prompts <id>` — human prompts only


## System Library

Plans: 269 indexed | Chains: 5 available | SOPs: 18 active
Discover: `organvm plans search <query>` | `organvm chains list` | `organvm sop lifecycle`
Library: `/Users/4jp/Code/organvm/praxis-perpetua/library`


## Active Directives

| Scope | Phase | Name | Description |
|-------|-------|------|-------------|
| system | any | atomic-clock | The Atomic Clock |
| system | any | execution-sequence | Execution Sequence |
| system | any | multi-agent-dispatch | Multi-Agent Dispatch |
| system | any | session-handoff-avalanche | Session Handoff Avalanche |
| system | any | system-loops | System Loops |
| system | any | prompting-standards | Prompting Standards |
| system | any | prompting-standards | Prompting Standards |
| system | any | prompting-standards | Prompting Standards |
| system | any | background-task-resilience | background-task-resilience |
| system | any | context-window-conservation | context-window-conservation |
| system | any | session-self-critique | session-self-critique |
| system | any | the-descent-protocol | the-descent-protocol |
| system | any | the-membrane-protocol | the-membrane-protocol |
| system | any | theory-to-concrete-gate | theory-to-concrete-gate |
| system | any | triangulation-protocol | triangulation-protocol |

Linked skills: SOP-TRIADIC-REVIEW-PROTOCOL, cicd-resilience-and-recovery, continuous-learning-agent, evaluation-to-growth, genesis-dna, multi-agent-workforce-planner, promotion-and-state-transitions, quality-gate-baseline-calibration, repo-onboarding-and-habitat-creation, session-self-critique, structural-integrity-audit, the-membrane-protocol, triple-reference


**Prompting (Anthropic)**: context 200K tokens, format: XML tags, thinking: extended thinking (budget_tokens)


## Atomization Pipeline

Run `organvm atoms pipeline --write && organvm atoms fanout --write` to generate task queue.


## System Density (auto-generated)

AMMOI: 25% | Edges: 0 | Tensions: 0 | Clusters: 0 | Adv: 27 | Events(24h): 41370
Structure: 8 organs / 149 repos / 1654 components (depth 17) | Inference: 0% | Organs: META-ORGANVM:63%, ORGAN-I:53%, ORGAN-II:48%, ORGAN-III:55% +5 more
Last pulse: 2026-06-08T16:26:13 | Δ24h: 0.0% | Δ7d: vacuum


## Dialect Identity (Trivium)

**Dialect:** EXECUTABLE_ALGORITHM | **Classical Parallel:** Arithmetic | **Translation Role:** The Engineering — proves that proofs compute

Strongest translations: I (formal), II (structural), VII (structural)

Scan: `organvm trivium scan III <OTHER>` | Matrix: `organvm trivium matrix` | Synthesize: `organvm trivium synthesize`


## Logos Documentation Layer

**Status:** ACTIVE | **Symmetry:** 1.0 (SYMMETRIC)

Nature demands a documentation counterpart. This formation maintains its narrative record in `docs/logos/`.

### The Tetradic Counterpart
- **[Telos (Idealized Form)](../docs/logos/telos.md)** — The dream and theoretical grounding.
- **[Pragma (Concrete State)](../docs/logos/pragma.md)** — The honest account of what exists.
- **[Praxis (Remediation Plan)](../docs/logos/praxis.md)** — The attack vectors for evolution.
- **[Receptio (Reception)](../docs/logos/receptio.md)** — The account of the constructed polis.

### Alchemical I/O
- **[Source & Transmutation](../docs/logos/alchemical-io.md)** — Narrative of inputs, process, and returns.



*Compliance: Nature and Counterpart are in balance.*

<!-- ORGANVM:AUTO:END -->









## ⚡ Conductor OS Integration
This repository is a managed component of the ORGANVM meta-workspace.
- **Orchestration:** Use `conductor patch` for system status and work queue.
- **Lifecycle:** Follow the `FRAME -> SHAPE -> BUILD -> PROVE` workflow.
- **Governance:** Promotions are managed via `conductor wip promote`.
- **Intelligence:** Conductor MCP tools are available for routing and mission synthesis.
