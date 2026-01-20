# Universal Mail Automation

Automated inbox triage across Gmail, Outlook, and iCloud using shared categorization rules and Eisenhower priority tiers.

---

## The Problem

**Email chaos is universal.** Multiple accounts across different providers, inconsistent organization, and important messages buried under newsletters.

- **Manual methods don't scale** — "Touch It Once" and Inbox Zero require human decisions on every email
- **Provider tools are fragmented** — Gmail filters, Outlook rules, and iCloud rules can't share logic
- **Important emails get buried** — Without systematic triage, urgent items hide among noise
- **No cross-provider consistency** — Different organization schemes per account

---

## The Approach

### Unified Rules Engine
One set of regex patterns works across all providers. Define a rule once, apply everywhere.

### Eisenhower Matrix Prioritization
Every email gets assigned to one of four tiers:

| Tier | Name | Action |
|------|------|--------|
| 1 | Critical | Star, keep in inbox |
| 2 | Important | Keep in inbox |
| 3 | Delegate | Archive, route to Action folder |
| 4 | Reference | Archive, categorize only |

### Pattern Matching
Categorize by sender domain, subject keywords, or both. Rules have priority ordering—first match wins.

### VIP Detection
Always-important senders bypass normal categorization. CEO email? Goes straight to Critical.

### Time-Based Escalation
Emails age into higher priority:
- < 24 hours: No escalation
- 24–72 hours: Tier 3–4 → Tier 2 (if time-sensitive)
- > 72 hours: Any tier → Tier 1

### Provider Capabilities

| Provider | Labels | Folders | Categories | Star | Archive | Batch API |
|----------|:------:|:-------:|:----------:|:----:|:-------:|:---------:|
| Gmail    | ✓      |         |            | ✓    | ✓       | ✓         |
| Outlook  |        | ✓       | ✓ (colors) | ✓    | ✓       |           |
| IMAP     | ✓*     | ✓       |            | ✓    | ✓       |           |
| Mail.app |        | ✓       |            | ✓    | ✓       |           |

*IMAP with `--gmail-extensions` flag

---

## The Outcome

- **28 categories** with hierarchical labels (`Work/Dev/GitHub`, `Finance/Banking`, `AI/Services`)
- **Consistent organization** across all email accounts
- **Automated daily triage** — emails sorted without thinking
- **Crash recovery** — state files for resuming interrupted runs
- **Reporting** — summary by tier, pending actions, VIP activity

---

## Quick Start

```bash
# Setup
./deploy.sh

# Load secrets (1Password integration)
source ~/.config/op/mail_automation.env.op.sh

# Run on all providers
./run_automation.sh

# Or run individually
python3 cli.py label --provider gmail --dry-run
python3 cli.py label --provider outlook --tier-routing
python3 cli.py label --provider imap --host imap.mail.me.com
```

---

## CLI Commands

### Labeling
```bash
# Label unlabeled emails
python3 cli.py label --provider gmail

# With tier routing (Outlook categories + Action folders)
python3 cli.py label --provider outlook --tier-routing

# VIP senders only
python3 cli.py label --provider gmail --vip-only

# Dry run (preview changes)
python3 cli.py label --provider outlook --dry-run
```

### Reporting
```bash
# Summary by priority tier
python3 cli.py summary --provider gmail

# Pending items needing action
python3 cli.py pending --provider outlook

# VIP sender activity
python3 cli.py vip --provider gmail

# Re-triage stale emails
python3 cli.py escalate --provider outlook --dry-run
```

### Health & Diagnostics
```bash
python3 cli.py health --provider gmail
python3 cli.py report --provider outlook
```

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    cli.py                           │
└─────────────────────┬───────────────────────────────┘
                      │
┌─────────────────────┴───────────────────────────────┐
│                 core/rules.py                       │
│   LABEL_RULES · PRIORITY_TIERS · VIP_SENDERS        │
└─────────────────────┬───────────────────────────────┘
                      │
    ┌─────────────────┼─────────────────┐
    │                 │                 │
    ▼                 ▼                 ▼
┌─────────┐     ┌──────────┐     ┌──────────┐
│  Gmail  │     │ Outlook  │     │   IMAP   │
│   API   │     │  Graph   │     │ (iCloud) │
└─────────┘     └──────────┘     └──────────┘
```

### Module Structure
```
mail_automation/
├── core/                    # Shared components
│   ├── rules.py            # LABEL_RULES, categorize_message()
│   ├── state.py            # StateManager for crash recovery
│   └── models.py           # EmailMessage, LabelAction dataclasses
├── providers/              # Email service adapters
│   ├── base.py             # Abstract EmailProvider interface
│   ├── gmail.py            # Gmail API provider
│   ├── imap.py             # Generic IMAP provider
│   ├── mailapp.py          # macOS Mail.app (AppleScript)
│   └── outlook.py          # Microsoft Graph API
└── cli.py                  # Unified CLI entry point
```

---

## Configuration

### 1Password Integration
Secrets are loaded from 1Password via environment variables:

```bash
# Gmail
GMAIL_OAUTH_OP_REF="op://Vault/Gmail OAuth/client_json"
GMAIL_TOKEN_OP_REF="op://Vault/Gmail OAuth/token_json"

# Outlook
OUTLOOK_CLIENT_ID="your-azure-app-client-id"
```

### VIP Senders
Add to `~/.config/mail_automation/config.yaml`:

```yaml
vip_senders:
  "ceo@company.com":
    pattern: "ceo@company\\.com"
    tier: 1
    star: true
    note: "CEO"
```

### Adding Rules
Edit `core/rules.py`:

```python
"NewCategory/Subcategory": {
    "patterns": [r"sender\.com", r"keyword.*pattern"],
    "priority": 10,
    "tier": 2,
    "time_sensitive": True,
}
```

---

## Detailed Documentation

- **[CLAUDE.md](CLAUDE.md)** — Full configuration reference, all CLI options, coding conventions
- **[PROCESS.md](PROCESS.md)** — Historical context and design decisions
