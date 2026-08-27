[![ORGAN-III: Ergon](https://img.shields.io/badge/ORGAN--III-Ergon-1b5e20?style=flat-square)](https://github.com/organvm-iii-ergon)
[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

# Universal Mail Automation

[![CI](https://github.com/organvm-iii-ergon/universal-mail--automation/actions/workflows/ci.yml/badge.svg)](https://github.com/organvm-iii-ergon/universal-mail--automation/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-pending-lightgrey)](https://github.com/organvm-iii-ergon/universal-mail--automation)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/organvm-iii-ergon/universal-mail--automation/blob/main/LICENSE)
[![Organ III](https://img.shields.io/badge/Organ-III%20Ergon-F59E0B)](https://github.com/organvm-iii-ergon)
[![Status](https://img.shields.io/badge/status-active-brightgreen)](https://github.com/organvm-iii-ergon/universal-mail--automation)
[![Python](https://img.shields.io/badge/lang-Python-informational)](https://github.com/organvm-iii-ergon/universal-mail--automation)


**Automated inbox triage across Gmail, Outlook, and iCloud using a shared categorization engine, Eisenhower priority tiers, and time-based escalation — unified behind a single CLI.**

---

## Table of Contents

- [The Problem](#the-problem)
- [Product Overview](#product-overview)
- [Cloudflare Share Demo](#cloudflare-share-demo)
- [Operator Dashboard](#operator-dashboard)
- [Technical Architecture](#technical-architecture)
  - [System Diagram](#system-diagram)
  - [Module Structure](#module-structure)
  - [Provider Abstraction Layer](#provider-abstraction-layer)
  - [Rules Engine](#rules-engine)
  - [Eisenhower Priority Tier System](#eisenhower-priority-tier-system)
  - [VIP Sender System](#vip-sender-system)
  - [Time-Based Escalation](#time-based-escalation)
  - [State Management and Crash Recovery](#state-management-and-crash-recovery)
  - [Data Models](#data-models)
- [Installation and Quick Start](#installation-and-quick-start)
  - [Prerequisites](#prerequisites)
  - [Automated Deployment](#automated-deployment)
  - [Manual Setup](#manual-setup)
  - [First Run](#first-run)
- [CLI Reference](#cli-reference)
  - [Labeling Commands](#labeling-commands)
  - [Reporting Commands](#reporting-commands)
  - [Triage Commands](#triage-commands)
  - [Operator Summary Command](#operator-summary-command)
  - [Health and Diagnostics](#health-and-diagnostics)
- [Configuration](#configuration)
  - [Configuration Precedence](#configuration-precedence)
  - [YAML Configuration File](#yaml-configuration-file)
  - [Environment Variables](#environment-variables)
  - [1Password Integration](#1password-integration)
  - [Adding Custom Rules](#adding-custom-rules)
  - [Configuring VIP Senders](#configuring-vip-senders)
- [Provider Capabilities Matrix](#provider-capabilities-matrix)
- [Label Taxonomy](#label-taxonomy)
- [Scheduling and Daily Automation](#scheduling-and-daily-automation)
- [Cross-Organ Context](#cross-organ-context)
- [Related Work](#related-work)
- [Contributing](#contributing)
- [License](#license)
- [Author](#author)

---

## The Problem

**Email chaos is universal.** Anyone who operates across multiple accounts — a personal Gmail, a work Outlook, an iCloud account for Apple devices — knows the friction. Important messages drown in newsletter noise. Financial alerts compete with marketing spam. Each provider offers its own filter system, but none of them talk to each other. The result is fragmented organization, duplicated effort, and the persistent anxiety of missing something critical.

Manual approaches fail at scale. "Touch It Once" and "Inbox Zero" philosophies demand a human decision on every single email, which breaks down above a few hundred messages per day. Gmail filters cannot share logic with Outlook rules. iCloud rules cannot reference Gmail labels. The organizational schemes diverge, and the user is left maintaining three separate systems that accomplish the same goal badly.

This project eliminates that fragmentation. One set of categorization rules. One priority system. One CLI. Every provider.

---

## Product Overview

Universal Mail Automation is a Python-based email triage system that applies a unified set of categorization rules across Gmail (via REST API), Outlook.com (via Microsoft Graph API), iCloud and any standard IMAP server, and macOS Mail.app (via AppleScript). The system operates on three coordinated principles:

1. **Unified Rules Engine** — A single taxonomy of 28 hierarchical categories (`Dev/GitHub`, `Finance/Banking`, `AI/Services`, `Travel`, `Marketing`, etc.) defined as regex patterns in `core/rules.py`. Define a rule once, and it applies to every provider.

2. **Eisenhower Matrix Prioritization** — Every email is assigned to one of four priority tiers (Critical, Important, Delegate, Reference) that determine whether it stays in the inbox, gets archived, gets starred, or simply gets categorized for later retrieval.

3. **Time-Based Escalation** — Emails that remain unprocessed age into higher priority tiers. A Tier 4 (Reference) email that sits for 72+ hours automatically escalates to Tier 1 (Critical), ensuring nothing falls through the cracks.

The system is designed for daily intake, but the primary local path is on-demand. Use `scripts/intake_now.sh` to create/reuse the venv, verify Gmail auth, and write private triage reports under user-local state. A macOS `launchd` job is available only as an explicit opt-in for machines where LaunchAgents are allowed.

---

## Cloudflare Share Demo

A public Cloudflare Worker demo is available for quick partner review:

- Live share URL: <https://uma.4444j99.dev>
- Deployment note: [docs/cloudflare-share-demo.md](docs/cloudflare-share-demo.md)

This share surface serves the dashboard and a minimal same-origin API. It is not the canonical product backend; the Python application remains authoritative for real provider operations.

---

## Operator Dashboard

UMA also includes a private operator dashboard for local mail-ops state:

- `GET /ops` serves the operator control tower.
- `GET /v1/ops/summary` returns the redacted `uma.ops.summary.v1` payload.
- `GET /v1/ops/history` returns the redacted bounded history index when configured.
- `GET /v1/ops/intelligence` returns the redacted `uma.mail.intelligence.v1` historical-intelligence payload, including controlled provider/surface hint slugs, when configured.
- `GET /v1/ops/action-plan` returns the redacted `uma.mail.action_plan.v1` next-action plan with controlled provider hint counts when intelligence is configured.
- `GET /v1/ops/resolver-plan` returns the redacted `uma.mail.resolver_plan.v1` official-surface, blocker, provider-hint, and proof plan when intelligence is configured.
- `GET /v1/ops/provider-surface-plan` returns the redacted `uma.provider.surface_plan.v1` provider resolver frontier from controlled provider hints.
- `GET /v1/ops/resolver-ledger` returns redacted resolver proof state merged with local `uma.mail.resolver_receipt.v1` receipts.
- `GET /v1/ops/github-resolver` returns a redacted `uma.github.resolver_snapshot.v1` read-only GitHub CLI/API snapshot for GitHub resolver actions.
- `POST /v1/ops/github-resolver-receipts` records redacted resolver receipts from GitHub provider-read or blocker snapshot candidates and always requires `UMA_OPS_TOKEN`.
- `GET /v1/ops/followup-resolver` returns a redacted `uma.followup.resolver_snapshot.v1` view of mail/LinkedIn follow-up proof from draft approval and delivery receipts.
- `POST /v1/ops/followup-resolver-receipts` records redacted resolver receipts from existing follow-up approval/delivery proof and always requires `UMA_OPS_TOKEN`.
- `GET /v1/ops/external-resolver` returns a redacted `uma.external.resolver_snapshot.v1` view of provider/security/billing/subscription/legal official-surface work with controlled provider hint counts.
- `POST /v1/ops/external-resolver-receipts` records local blocker attestations only when explicitly requested and always requires `UMA_OPS_TOKEN`.
- `POST /v1/ops/resolver-receipts` appends a redacted resolver proof receipt and always requires `UMA_OPS_TOKEN`.
- `GET /v1/ops/action-ledger` returns redacted action status merged with local `uma.mail.action_receipt.v1` proof receipts.
- `POST /v1/ops/action-receipts` appends a redacted local proof receipt and always requires `UMA_OPS_TOKEN`.
- `GET /v1/ops/draft-package/{action_id}?ack_private=true` builds a gated private draft package and always requires `UMA_OPS_TOKEN`.
- `GET /v1/ops/draft-approvals/{action_id}?ack_private=true` returns redacted local draft approval status.
- `POST /v1/ops/draft-approvals/{action_id}` appends a redacted local draft approval receipt and always requires `UMA_OPS_TOKEN`.
- `GET /v1/ops/delivery/{action_id}?ack_private=true` returns redacted delivery intent/status for approved draft candidates.
- `POST /v1/ops/delivery/{action_id}` appends a redacted local delivery receipt and always requires `UMA_OPS_TOKEN`.
- `GET /v1/ops/evidence/{evidence_id}?ack_private=true` opens gated private source evidence and always requires `UMA_OPS_TOKEN`.
- `python3 cli.py ops-summary --report ~/System/Reports/mail-triage/latest.json` emits the same contract without running the web app.
- `python3 cli.py ops-refresh --report ~/System/Reports/mail-triage/latest.json` writes `latest-summary.json`, `history/`, and `index.json` under user-local state.
- `python3 cli.py mail-history-export --source ~/Library/Mail --output ~/System/Reports/mail-history/latest.json` normalizes local JSON/JSONL/mbox/EML/EMLX sources into a private `uma.mail.history_export.v1` file and prints only a redacted receipt.
- `python3 cli.py mail-intel --history ~/System/Reports/mail-history/latest.json` mines a read-only historical export into redacted opportunities, risks, evidence, controlled provider/surface hints, and `/ops` reconciliation.
- `python3 cli.py mail-intel --history ~/System/Reports/mail-history/latest.json --output ~/System/Reports/mail-history/latest-intelligence.json` precomputes the redacted intelligence cache and prints only a safe receipt.
- `python3 cli.py mail-action-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json` groups the redacted findings into approval-aware next actions with controlled provider hint counts.
- `python3 cli.py mail-resolver-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json` maps those actions to official surfaces, blockers, safe prep steps, provider hints, and required proof.
- `python3 cli.py mail-provider-surface-plan --intelligence ~/System/Reports/mail-history/latest-intelligence.json` ranks controlled provider hints into the next provider/API/CLI resolver frontier without provider reads.
- `python3 cli.py mail-resolver-ledger --intelligence ~/System/Reports/mail-history/latest-intelligence.json` shows official-surface resolver proof state from local receipts.
- `python3 cli.py mail-github-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json` runs a bounded read-only GitHub resolver snapshot through the GitHub CLI when authenticated.
- `python3 cli.py mail-github-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json` records provider-read or blocker GitHub snapshot candidates into the redacted resolver ledger.
- `python3 cli.py mail-followup-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json` shows mail/LinkedIn follow-up proof state from local approval and delivery receipts.
- `python3 cli.py mail-followup-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json` records resolver proof from existing follow-up approval/delivery receipts.
- `python3 cli.py mail-external-resolver --intelligence ~/System/Reports/mail-history/latest-intelligence.json` shows provider/security/billing/subscription/legal official-surface work and controlled provider hint counts without provider reads.
- `python3 cli.py mail-external-resolver-receipts --intelligence ~/System/Reports/mail-history/latest-intelligence.json --attest-blockers` records local blocker attestations without portal automation.
- `python3 cli.py mail-resolver-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --action-id action_... --resolver-status verified_resolved --reason-code github_reconciled --proof-type github_issue_pr_billing_or_security_state --provider github` records a redacted official-surface resolver receipt.
- `python3 cli.py mail-action-ledger --intelligence ~/System/Reports/mail-history/latest-intelligence.json` shows open/waiting/blocked/resolved action status from local receipts.
- `python3 cli.py mail-action-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --action-id action_... --status waiting --reason-code awaiting_reply` records a redacted local proof receipt.
- `python3 cli.py mail-evidence-review --history ~/System/Reports/mail-history/latest.json --evidence-id ev_... --ack-private` opens one private source message for fact checking.
- `python3 cli.py mail-draft-package --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --ack-private` builds private draft candidates for approval.
- `python3 cli.py mail-draft-approval --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --draft-id draft_... --decision approved --reason-code ready_to_send --ack-private` records a redacted local approval receipt.
- `python3 cli.py mail-delivery-receipt --intelligence ~/System/Reports/mail-history/latest-intelligence.json --history ~/System/Reports/mail-history/latest.json --action-id action_... --draft-id draft_... --delivery-status provider_draft_requested --reason-code approved_for_provider_draft --ack-private` records redacted post-approval delivery intent without creating a provider draft or sending.

Configure the API with `UMA_OPS_REPORT_PATH`. Set `UMA_OPS_TOKEN` to require a
bearer token for operator APIs; private evidence review and receipt writes
always require it. Redacted operator payloads intentionally omit raw senders,
email addresses, subjects, message bodies, and full local report paths.
See [docs/schemas/ops-summary-v1.md](docs/schemas/ops-summary-v1.md),
[docs/schemas/mail-history-export-v1.md](docs/schemas/mail-history-export-v1.md),
[docs/schemas/mail-action-plan-v1.md](docs/schemas/mail-action-plan-v1.md),
[docs/schemas/mail-resolver-plan-v1.md](docs/schemas/mail-resolver-plan-v1.md),
[docs/schemas/provider-surface-plan-v1.md](docs/schemas/provider-surface-plan-v1.md),
[docs/schemas/mail-resolver-ledger-v1.md](docs/schemas/mail-resolver-ledger-v1.md),
[docs/schemas/github-resolver-v1.md](docs/schemas/github-resolver-v1.md),
[docs/schemas/followup-resolver-v1.md](docs/schemas/followup-resolver-v1.md),
[docs/schemas/external-resolver-v1.md](docs/schemas/external-resolver-v1.md),
[docs/schemas/mail-action-ledger-v1.md](docs/schemas/mail-action-ledger-v1.md),
[docs/schemas/mail-evidence-review-v1.md](docs/schemas/mail-evidence-review-v1.md),
[docs/schemas/mail-draft-package-v1.md](docs/schemas/mail-draft-package-v1.md),
[docs/schemas/mail-draft-approval-v1.md](docs/schemas/mail-draft-approval-v1.md),
[docs/schemas/mail-delivery-v1.md](docs/schemas/mail-delivery-v1.md),
and
[docs/schemas/mail-intelligence-v1.md](docs/schemas/mail-intelligence-v1.md)
for the contracts.

This is separate from the public `/app` surface: `/app` proves the product and
safety gate, while `/ops` represents private triage queues, escaped-unread
checks, waiting lanes, closed/reviewed work, snapshot freshness, and redacted
history. When `UMA_HISTORICAL_MAIL_PATH` is configured, `/ops` also shows
historical missed leads, unresolved risks, redacted evidence counts, and which
findings are not represented in current operator lanes.

---

## How it works

Universal Mail Automation unifies email triage across Gmail, Outlook, and iCloud by applying one shared categorization engine with Eisenhower-based priority routing and time-aware escalation. Every message is matched against a taxonomy of 28 categories (Dev, Finance, AI, Travel, Marketing, etc.), assigned to one of four priority tiers, and routed to keep critical emails in your inbox while archiving routine updates. Old messages that go untouched automatically escalate to higher tiers, ensuring nothing is missed.

---

## Technical Architecture

### System Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                          cli.py                                  │
│    Unified CLI: label | summary | pending | vip | escalate       │
│    --provider {gmail,outlook,imap,mailapp}                       │
└──────────────────────────┬───────────────────────────────────────┘
                           │
┌──────────────────────────┴───────────────────────────────────────┐
│                       core/ layer                                │
│  ┌──────────────┐  ┌────────────┐  ┌──────────┐  ┌───────────┐  │
│  │  rules.py    │  │ config.py  │  │ state.py │  │ models.py │  │
│  │  LABEL_RULES │  │ YAML/env   │  │ crash    │  │ dataclass │  │
│  │  PRIORITY    │  │ precedence │  │ recovery │  │ contracts │  │
│  │  VIP_SENDERS │  │            │  │          │  │           │  │
│  └──────────────┘  └────────────┘  └──────────┘  └───────────┘  │
└──────────────────────────┬───────────────────────────────────────┘
                           │
    ┌──────────────────────┼───────────────────────┐
    │                      │                       │
    ▼                      ▼                       ▼
┌──────────┐       ┌────────────┐          ┌────────────┐
│  Gmail   │       │  Outlook   │          │ IMAP/Mail  │
│  REST    │       │  Graph     │          │  .app      │
│  API     │       │  API       │          │            │
│          │       │            │          │            │
│ Batch    │       │ Categories │          │ X-GM-LABELS│
│ Modify   │       │ Folders    │          │ AppleScript│
│ Labels   │       │ Flagging   │          │ Folders    │
└──────────┘       └────────────┘          └────────────┘
```

### Module Structure

```
universal-mail--automation/
├── cli.py                          # Unified CLI entry point (argparse)
├── core/                           # Shared components
│   ├── __init__.py
│   ├── rules.py                    # LABEL_RULES taxonomy, categorize_message(),
│   │                               #   PRIORITY_TIERS, VIP_SENDERS, escalation
│   ├── config.py                   # Multi-source config: YAML > env > defaults
│   ├── state.py                    # StateManager for crash recovery (JSON persistence)
│   └── models.py                   # EmailMessage, LabelAction, ProcessingResult dataclasses
├── providers/                      # Email service adapters
│   ├── __init__.py
│   ├── base.py                     # Abstract EmailProvider + ProviderCapabilities flags
│   ├── gmail.py                    # Gmail REST API with batch operations
│   ├── outlook.py                  # Microsoft Graph API with MSAL auth
│   ├── imap.py                     # Generic IMAP + Gmail X-GM-LABELS extension
│   └── mailapp.py                  # macOS Mail.app via AppleScript subprocess
├── auth/                           # Authentication helpers
│   ├── __init__.py
│   └── onepassword.py              # 1Password CLI integration for secrets
├── deploy.sh                       # macOS setup script (venv; launchd opt-in only)
├── scripts/intake_now.sh           # On-demand Gmail intake runner
├── run_automation.sh               # Daily runner script (all providers)
├── seed.yaml                       # Project metadata and AI agent contract
├── requirements.txt                # Python dependencies
├── com.user.mail_automation.plist  # macOS LaunchAgent schedule definition
└── *.py / *.applescript            # Legacy and utility scripts
```

### Provider Abstraction Layer

The architecture is built around an abstract `EmailProvider` base class (`providers/base.py`) that defines a uniform interface for all email services. Each provider implements the same set of methods — `connect()`, `disconnect()`, `list_messages()`, `get_message_details()`, `apply_label()`, `remove_label()`, `archive()`, `star()`, `ensure_label_exists()`, and `apply_actions()` — adapting them to the underlying API's semantics.

A `ProviderCapabilities` flag enum describes what each provider supports. This allows the core logic to make runtime decisions: Gmail supports true multi-label semantics and batch operations; Outlook supports color categories and folder hierarchies; IMAP supports Gmail extensions when configured; Mail.app supports folders and flagging via AppleScript.

The provider factory function in `cli.py` instantiates the correct provider from a `--provider` argument, and every provider supports the context manager protocol (`with provider:`) for clean connection lifecycle management.

### Rules Engine

The rules engine (`core/rules.py`) is the heart of the system. It defines a `LABEL_RULES` dictionary with 28 categories, each containing:

- **`patterns`** — A list of regex patterns matched against the combined sender + subject text of each email.
- **`priority`** — A numeric ordering (lower = matched first) that resolves conflicts when multiple rules match. First match wins.
- **`tier`** — The Eisenhower tier (1–4) assigned to emails matching this rule.
- **`time_sensitive`** — A boolean flag that determines whether the email is eligible for time-based escalation.

The `categorize_with_tier()` function is the primary entry point. It checks VIP senders first (always override normal rules), then performs pattern matching across all rules, returning a `CategorizationResult` dataclass that packages the label, tier, time sensitivity flag, and VIP metadata together.

Pattern matching uses `re.search` with `re.IGNORECASE` against a combined lowercase string of sender and subject, ensuring broad matching without requiring exact-match configurations.

### Eisenhower Priority Tier System

Every email receives one of four Eisenhower tiers, each with distinct behavioral consequences:

| Tier | Name | Color | Inbox | Star | Folder | Description |
|------|------|-------|:-----:|:----:|--------|-------------|
| 1 | Critical | Red | Yes | Yes | `Action/Critical` | Financial alerts, security notifications, government correspondence, personal/family emails. Demands immediate attention. |
| 2 | Important | Yellow | Yes | No | `Action/Important` | Code reviews, payment confirmations, health matters, job opportunities, domain renewals, travel confirmations. Should be addressed same-day. |
| 3 | Delegate | Blue | No | No | `Action/Delegate` | Infrastructure alerts, AI service notifications, social media, educational content. Can be reviewed during dedicated triage time. |
| 4 | Reference | Green | No | No | *(category only)* | Shopping confirmations, entertainment, marketing, newsletters. Archived and categorized for retrieval if needed. |

Each tier is encoded as a frozen `PriorityTier` dataclass with `keep_in_inbox`, `star`, `folder`, and `color` attributes. The provider implementations translate these into provider-specific actions: Gmail labels + archive, Outlook color categories + folder moves, IMAP flags + folder copies.

### VIP Sender System

VIP senders bypass the normal categorization pipeline entirely. When a sender matches a VIP pattern, the system uses the VIP's configured tier and starring behavior regardless of which category rule would normally match. VIP senders can optionally override the label assignment itself via `label_override`, or allow normal categorization to proceed while simply forcing the tier upward.

VIP senders are configured in two ways:
1. **At runtime** via `add_vip_sender()` in `core/rules.py` (for programmatic use).
2. **Via YAML config** at `~/.config/mail_automation/config.yaml` under the `vip_senders` key, loaded at startup by `apply_vip_senders_from_config()`.

### Time-Based Escalation

The `escalate_by_age()` function implements automatic priority escalation based on email age:

- **< 24 hours** — No escalation. The original tier stands.
- **24–72 hours** — Tier 3 and Tier 4 emails escalate to Tier 2, but only if their category is marked `time_sensitive`.
- **> 72 hours** — Any email below Tier 1 escalates to Tier 1 (Critical). If an email has been sitting for three days, something is wrong.

The `escalate` CLI command applies this logic across the inbox, re-triaging stale emails. It uses `calculate_email_age_hours()` to compute age from the message's received date, handling timezone-aware and timezone-naive datetimes.

### State Management and Crash Recovery

The `StateManager` class (`core/state.py`) persists processing state to a JSON file after each batch. It stores:

- **`next_page_token`** — The pagination token for resuming from the last processed page.
- **`total_processed`** — Running count of processed messages.
- **`history`** — A dictionary mapping label names to counts (for reporting).
- **`last_run`** — ISO 8601 timestamp of the last run.
- **`provider`** — Which provider was being processed.

If the automation crashes mid-run (network failure, API rate limit exhaustion, system sleep), the next invocation picks up from the saved page token. Each provider has its own state file (`gmail_state.json`, `outlook_state.json`, etc.), allowing independent recovery.

### Data Models

The `core/models.py` module defines three provider-agnostic dataclasses:

- **`EmailMessage`** — An immutable representation of an email with `id`, `sender`, `subject`, `date`, `labels`, `is_read`, `is_starred`, `priority_tier`, and `categories`. The `combined_text` property returns a lowercase concatenation of sender and subject for pattern matching.

- **`LabelAction`** — Accumulates multiple actions (add labels, remove labels, archive, star, set category, set folder, set due date) for a single message. Supports `merge()` for combining overlapping actions.

- **`ProcessingResult`** — Aggregates statistics from a batch operation: `processed_count`, `success_count`, `error_count`, `label_counts` dictionary, and an `errors` list.

---

## Installation and Quick Start

### Prerequisites

- Python 3.10 or later
- macOS (for Mail.app provider and launchd scheduling; Gmail/Outlook/IMAP work on any platform)
- Gmail API credentials (OAuth client JSON via Google Cloud Console)
- Outlook Azure app registration (for Outlook.com provider)
- 1Password CLI (`op`) for secrets management (recommended)

### Local On-Demand Intake

This machine's home-level agent policy forbids LaunchAgents. The safe default is
the on-demand intake runner:

```bash
cd ~/Code/organvm/universal-mail--automation
scripts/intake_now.sh
```

The runner:

1. Creates `.venv/` if it is missing
2. Installs the core, API, and MCP dependency sets
3. Loads `~/.config/op/mail_automation.env.op.sh`
4. Runs `cli.py health --provider gmail`
5. Writes private reports under `~/.local/state/universal-mail-automation/intake/`
6. Does **not** install, load, or modify LaunchAgents

The most useful output files are:

- `*-reply-needed.md` — recent human/action-oriented mail and suggested replies
- `*-drafts.md` — stuck drafts from the last 30 days
- `*-gmail-risk.md` — broader two-week risk/payment/security/provider queue

### Automated Setup

The `deploy.sh` script handles the complete setup:

```bash
git clone https://github.com/organvm-iii-ergon/universal-mail--automation.git
cd universal-mail--automation
./deploy.sh
```

This will:
1. Create a Python virtual environment at `.venv/`
2. Install all dependencies from `requirements.txt` (plus `msal` and `requests` for Outlook)
3. Make `run_automation.sh` executable
4. Create the log directory at `~/System/Logs/mail_automation/`
5. Skip LaunchAgent installation unless explicitly requested

To opt into launchd on a machine where that is allowed:

```bash
INSTALL_LAUNCH_AGENT=1 ./deploy.sh
```

### Manual Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt          # core + Gmail + Outlook + YAML config
pip install -r requirements-api.txt      # FastAPI server (optional)
pip install -r requirements-mcp.txt      # MCP server (optional, Python 3.10+)
```

### First Run

```bash
#Load secrets (1Password integration)
source ~/.config/op/mail_automation.env.op.sh

#Dry run to preview changes (no modifications made)
python3 cli.py label --provider gmail --dry-run

#Apply labels to unlabeled Gmail messages
python3 cli.py label --provider gmail --query "has:nouserlabels"

#Process Outlook inbox
python3 cli.py label --provider outlook

#Process iCloud via IMAP
python3 cli.py label --provider imap --host imap.mail.me.com

#Run all providers sequentially
./run_automation.sh
```

---

## CLI Reference

The CLI (`cli.py`) is built on `argparse` and provides eight subcommands — `label`, `report`, `health`, `escalate`, `summary`, `pending`, `vip`, and `triage` — each accepting a shared `--provider {gmail,imap,mailapp,outlook}` flag (default `gmail`) to target a specific email service. The global flag `-v/--verbose` enables debug logging and applies to every subcommand.

### Labeling Commands

```bash
#Label unlabeled Gmail emails
python3 cli.py label --provider gmail

#Label with a custom query
python3 cli.py label --provider gmail --query "from:important@example.com"

#With Eisenhower tier routing (Outlook categories + Action folders)
python3 cli.py label --provider outlook --tier-routing

#VIP senders only (skip normal categorization)
python3 cli.py label --provider gmail --vip-only

#Re-label emails currently tagged Misc/Other
python3 cli.py label --provider gmail --query "label:Misc/Other" --remove-label "Misc/Other"

#Dry run — preview all changes without applying them
python3 cli.py label --provider outlook --dry-run
```

`label` flags (defaults from `argparse`):

| Flag | Default | Purpose |
|------|---------|---------|
| `--query`, `-q` | `has:nouserlabels` | Provider query selecting messages to process |
| `--limit`, `-l` | `1000` | Max messages per run |
| `--dry-run`, `-n` | off | Preview decisions; apply nothing and write no receipt |
| `--remove-label` | none | Remove this label when a new category is assigned |
| `--state-file` | none | JSON state file for crash-recovery / resumption |
| `--tier-routing` | off | Eisenhower routing: categories + `Action/*` folders |
| `--vip-only` | off | Only process messages from configured VIP senders |
| `--audit-file` | `audit/<provider>-triage.jsonl` | Append-only trust receipt path |
| `--no-audit` | off | Disable the receipt (not recommended for apply runs) |
| `--redact-audit` | off | Record sender domain only — produces a shareable receipt |

### Reporting Commands

```bash
#Summary by priority tier
python3 cli.py summary --provider gmail

#Pending items needing action (Tier 1 and 2)
python3 cli.py pending --provider outlook

#VIP sender activity report
python3 cli.py vip --provider gmail

#Re-triage stale emails via time-based escalation (dry run)
python3 cli.py escalate --provider outlook --dry-run

#Re-triage and apply escalations
python3 cli.py escalate --provider gmail
```

Flags and defaults for the reporting commands:

| Command | Flags (default) |
|---------|-----------------|
| `summary` | `--query` (`""`), `--limit` (`500`), `--format {table,markdown,json}` (`table`) |
| `pending` | `--limit` (`100`), `--format {table,markdown,json}` (`table`) — no `--query` |
| `vip` | `--query` (`""`), `--limit` (`500`), `--format {table,markdown,json}` (`table`) |
| `escalate` | `--query` (`""`), `--limit` (`500`), `--dry-run`, `--audit-file` (`audit/<provider>-escalate.jsonl`), `--no-audit`, `--redact-audit` |
| `report` | shared `--provider` flags only (Gmail returns live label counts; other providers report `N/A`) |
| `health` | shared `--provider` flags only |

### Operator Summary Command

```bash
#Emit the redacted operator dashboard payload from a local report
python3 cli.py ops-summary --report ~/System/Reports/mail-triage/latest.json --pretty

#Persist a redacted latest summary and bounded history
python3 cli.py ops-refresh --report ~/System/Reports/mail-triage/latest.json --pretty

#Optionally run the local read-only macOS Mail report producer first
python3 cli.py ops-refresh \
  --run-mail-triage \
  --since 2026-05-01 \
  --until 2026-06-16 \
  --report-dir ~/System/Reports/mail-triage \
  --output-dir ~/.local/state/universal-mail-automation/ops

#Normalize local historical mail into the private export consumed by mail-intel
python3 cli.py mail-history-export \
  --source ~/Library/Mail \
  --output ~/System/Reports/mail-history/latest.json \
  --since 2024-01-01 \
  --until 2026-06-16 \
  --pretty

#Mine a read-only historical export and reconcile it against the current ops report
python3 cli.py mail-intel \
  --history ~/System/Reports/mail-history/latest.json \
  --ops-report ~/System/Reports/mail-triage/latest.json \
  --output ~/System/Reports/mail-history/latest-intelligence.json \
  --pretty

#Group the redacted intelligence into approval-aware action clusters
python3 cli.py mail-action-plan \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --pretty

#Map action clusters to official surfaces, blockers, and proof requirements
python3 cli.py mail-resolver-plan \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --pretty

#Rank controlled provider hints into the next provider/API/CLI resolver frontier
python3 cli.py mail-provider-surface-plan \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --pretty

#Show official-surface resolver proof state
python3 cli.py mail-resolver-ledger \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --pretty

#Read GitHub official surfaces without mutating GitHub or mail
python3 cli.py mail-github-resolver \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --pretty

#Record GitHub provider-read or blocker proof into the resolver ledger
python3 cli.py mail-github-resolver-receipts \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --ledger ~/.local/state/universal-mail-automation/mail-resolver-ledger.jsonl \
  --pretty

#Reconcile mail/LinkedIn follow-up state from approval and delivery receipts
python3 cli.py mail-followup-resolver \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --pretty

#Record mail/LinkedIn follow-up proof when approval or delivery receipts exist
python3 cli.py mail-followup-resolver-receipts \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --ledger ~/.local/state/universal-mail-automation/mail-resolver-ledger.jsonl \
  --pretty

#Inspect provider/security/billing/subscription/legal external-surface work
python3 cli.py mail-external-resolver \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --pretty

#Record local blocker attestations for visible external-surface actions
python3 cli.py mail-external-resolver-receipts \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --ledger ~/.local/state/universal-mail-automation/mail-resolver-ledger.jsonl \
  --attest-blockers \
  --pretty

#Record redacted official-surface resolver proof
python3 cli.py mail-resolver-receipt \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --action-id action_... \
  --resolver-status verified_resolved \
  --reason-code github_reconciled \
  --proof-type github_issue_pr_billing_or_security_state \
  --provider github \
  --pretty

#Show local action status and proof receipts
python3 cli.py mail-action-ledger \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --pretty

#Record a redacted local receipt for an action id
python3 cli.py mail-action-receipt \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --action-id action_... \
  --status waiting \
  --reason-code awaiting_reply \
  --pretty

#Open one private source message for fact checking before drafting/action
python3 cli.py mail-evidence-review \
  --history ~/System/Reports/mail-history/latest.json \
  --evidence-id ev_... \
  --ack-private \
  --pretty

#Build private draft candidates for approval before any send
python3 cli.py mail-draft-package \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --history ~/System/Reports/mail-history/latest.json \
  --action-id action_... \
  --ack-private \
  --pretty

#Record redacted local approval for a draft candidate
python3 cli.py mail-draft-approval \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --history ~/System/Reports/mail-history/latest.json \
  --action-id action_... \
  --draft-id draft_... \
  --decision approved \
  --reason-code ready_to_send \
  --ack-private \
  --pretty

#Record redacted local delivery intent/status after approval
python3 cli.py mail-delivery-receipt \
  --intelligence ~/System/Reports/mail-history/latest-intelligence.json \
  --history ~/System/Reports/mail-history/latest.json \
  --action-id action_... \
  --draft-id draft_... \
  --delivery-status provider_draft_requested \
  --reason-code approved_for_provider_draft \
  --ack-private \
  --pretty

#Or configure once and serve the private operator dashboard
export UMA_OPS_REPORT_PATH=~/System/Reports/mail-triage/latest.json
export UMA_OPS_HISTORY_DIR=~/.local/state/universal-mail-automation/ops
export UMA_HISTORICAL_MAIL_PATH=~/System/Reports/mail-history/latest.json
export UMA_HISTORICAL_INTELLIGENCE_PATH=~/System/Reports/mail-history/latest-intelligence.json
export UMA_MAIL_ACTION_LEDGER_PATH=~/.local/state/universal-mail-automation/mail-action-ledger.jsonl
export UMA_MAIL_RESOLVER_LEDGER_PATH=~/.local/state/universal-mail-automation/mail-resolver-ledger.jsonl
export UMA_MAIL_DRAFT_APPROVAL_PATH=~/.local/state/universal-mail-automation/mail-draft-approvals.jsonl
export UMA_MAIL_DELIVERY_LEDGER_PATH=~/.local/state/universal-mail-automation/mail-delivery-ledger.jsonl
export UMA_OPS_TOKEN="choose-a-local-token"
uvicorn api.app:app --reload
#open /ops and use the configured bearer token
```

### Triage Commands

```bash
#Research, prioritize, and rank the mailbox (top 20 items)
python3 cli.py triage --provider gmail --top 20

#Triage with voice-matched reply drafts for items needing a response
python3 cli.py triage --provider gmail --top 20 --draft --name "Anthony"

#On-demand recent intake reports for this local machine
scripts/intake_now.sh

#Use a saved voice profile / sent-mail corpus for drafting
python3 cli.py triage --provider gmail --draft \
    --voice-file ~/.config/mail_automation/voice.json \
    --samples-file ~/.config/mail_automation/sent_samples.txt

#Machine-readable output for downstream tooling
python3 cli.py triage --provider outlook --format json --limit 100
```

`triage` flags (defaults from `argparse`):

| Flag | Default | Purpose |
|------|---------|---------|
| `--query`, `-q` | `""` | Provider query selecting messages to triage |
| `--limit`, `-l` | `200` | Max messages to research and score |
| `--top`, `-t` | `0` (all) | Keep only the top N highest-priority items |
| `--format`, `-f` | `text` | Output format: `text`, `markdown`, or `json` |
| `--draft` | off | Generate voice-matched reply drafts for items needing a response |
| `--voice-file` | `~/.config/mail_automation/voice.json` | Saved voice profile JSON |
| `--samples-file` | `~/.config/mail_automation/sent_samples.txt` | Sent-mail corpus to learn voice from |
| `--name` | none | Name used in the draft signature |

`--draft`, `--voice-file`, `--samples-file`, and `--name` are inert without `--draft`; drafting runs fully offline (no LLM call).

### Health and Diagnostics

```bash
#Provider health check (verifies connection and credentials)
python3 cli.py health --provider gmail

#Per-label message counts (live counts on Gmail; N/A on other providers)
python3 cli.py report --provider outlook
```

---

## Configuration

### Configuration Precedence

The system loads configuration from multiple sources with clear precedence (highest wins):

1. **CLI arguments** — `--provider`, `--query`, `--dry-run`, etc.
2. **Environment variables** — Prefixed with `MAIL_AUTO_` (e.g., `MAIL_AUTO_DEFAULT_PROVIDER`)
3. **YAML config file** — `~/.config/mail_automation/config.yaml`
4. **Built-in defaults** — Defined in `core/config.py` dataclasses

The config file is located by checking, in order:
1. `MAIL_AUTOMATION_CONFIG` environment variable
2. `~/.config/mail_automation/config.yaml`
3. `~/.mail_automation.yaml`
4. `mail_automation.yaml` in the working directory

### YAML Configuration File

```yaml
#~/.config/mail_automation/config.yaml

default_provider: gmail
log_level: INFO
batch_size: 100
throttle_seconds: 1.0

gmail:
  enabled: true
  default_query: "has:nouserlabels"
  state_file: "gmail_state.json"

imap:
  enabled: true
  host: imap.mail.me.com
  port: 993
  use_gmail_extensions: false

outlook:
  enabled: true
  state_file: "outlook_state.json"

mailapp:
  enabled: true
  account: "iCloud"
  default_mailbox: "INBOX"
```

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `MAIL_AUTO_DEFAULT_PROVIDER` | Default provider when `--provider` is omitted | `gmail` |
| `MAIL_AUTO_LOG_LEVEL` | Logging verbosity | `INFO` |
| `MAIL_AUTO_DRY_RUN` | Enable dry-run mode globally | `false` |
| `MAIL_AUTO_BATCH_SIZE` | Messages per processing batch | `100` |
| `IMAP_HOST` | IMAP server hostname | `imap.gmail.com` |
| `IMAP_USER` | IMAP username | *(required)* |
| `IMAP_PASS` | IMAP password | *(via 1Password)* |
| `OUTLOOK_CLIENT_ID` | Azure app registration client ID | *(required)* |
| `OUTLOOK_TOKEN_CACHE` | Path to Outlook token cache file | `~/.outlook_token_cache.json` |
| `UMA_OPS_REPORT_PATH` | Local `latest.json` report used by `/v1/ops/summary` and `/ops` | *(unset; ops disabled)* |
| `UMA_OPS_REPORT_DIR` | Report directory used by `ops-refresh --run-mail-triage` | `~/System/Reports/mail-triage` |
| `UMA_OPS_HISTORY_DIR` | User-local directory containing `latest-summary.json`, `history/`, and `index.json` from `ops-refresh` | `~/.local/state/universal-mail-automation/ops` for CLI only |
| `UMA_OPS_MAX_AGE_HOURS` | Freshness threshold used by `/v1/ops/summary` | `12` |
| `UMA_OPS_TOKEN` | Optional bearer token required by `/v1/ops/summary` | *(unset; local unauthenticated)* |
| `UMA_MAIL_TRIAGE_BIN` | Optional path to the read-only local mail-triage producer | `/Users/4jp/.local/bin/mail-triage` |
| `UMA_HISTORICAL_MAIL_SOURCE` | Optional source path used by `mail-history-export` | *(unset; pass `--source`)* |
| `UMA_HISTORICAL_MAIL_PATH` | Local historical mail export used by `/v1/ops/intelligence` and optional `/ops` intelligence cards | *(unset; intelligence disabled)* |
| `UMA_HISTORICAL_INTELLIGENCE_PATH` | Optional precomputed redacted intelligence cache served by `/v1/ops/intelligence` instead of recomputing from raw export | *(unset; recompute from `UMA_HISTORICAL_MAIL_PATH`)* |
| `UMA_HISTORICAL_STALE_DAYS` | Stale threshold for missed-lead candidates | `14` |
| `UMA_MAIL_ACTION_LEDGER_PATH` | JSONL receipt ledger used by `/v1/ops/action-ledger`, `/v1/ops/action-receipts`, and action-ledger CLI commands | `~/.local/state/universal-mail-automation/mail-action-ledger.jsonl` |
| `UMA_MAIL_RESOLVER_LEDGER_PATH` | JSONL receipt ledger used by `/v1/ops/resolver-ledger`, `/v1/ops/resolver-receipts`, and resolver CLI commands | `~/.local/state/universal-mail-automation/mail-resolver-ledger.jsonl` |
| `UMA_MAIL_DRAFT_APPROVAL_PATH` | JSONL receipt ledger used by `/v1/ops/draft-approvals/{action_id}` and draft approval CLI commands | `~/.local/state/universal-mail-automation/mail-draft-approvals.jsonl` |
| `UMA_MAIL_DELIVERY_LEDGER_PATH` | JSONL receipt ledger used by `/v1/ops/delivery/{action_id}` and delivery CLI commands | `~/.local/state/universal-mail-automation/mail-delivery-ledger.jsonl` |

### 1Password Integration

Secrets are loaded from 1Password via environment variables, typically sourced from a shell script:

```bash
#~/.config/op/mail_automation.env.op.sh
export GMAIL_OAUTH_OP_REF="op://Vault/Gmail OAuth/client_json"
export GMAIL_TOKEN_OP_REF="op://Vault/Gmail OAuth/token_json"
export ICLOUD_IMAP_HOST="imap.mail.me.com"
export ICLOUD_IMAP_USER="user@icloud.com"
export ICLOUD_IMAP_PASS="op://Vault/iCloud App Password/password"
export OUTLOOK_CLIENT_ID="your-azure-app-client-id"
```

Values written as `op://...` references are resolved at load time with the
1Password CLI (`op read`), so no plaintext secret is committed. The IMAP provider
also supports direct 1Password CLI lookup via `OP_ACCOUNT`, `OP_ITEM`, and
`OP_FIELD` environment variables, calling `op item get` at connection time.

### Adding Custom Rules

Edit `core/rules.py` to add categories:

```python
"NewCategory/Subcategory": {
    "patterns": [r"sender\.com", r"keyword.*pattern"],
    "priority": 10,        # Lower = matched first
    "tier": 2,             # Eisenhower tier (1-4)
    "time_sensitive": True, # Eligible for escalation
}
```

Or add rules via YAML config without modifying source code:

```yaml
custom_rules:
  "Custom/Category":
    patterns:
      - "custom-pattern"
      - "another-pattern"
    priority: 5
    tier: 2
    time_sensitive: true
```

### Configuring VIP Senders

Via YAML config:

```yaml
vip_senders:
  "ceo@company.com":
    pattern: "ceo@company\\.com"
    tier: 1
    star: true
    note: "CEO"
  "important-client":
    pattern: ".*@important-client\\.com"
    tier: 1
    star: true
    label_override: "Personal"
    note: "Important client domain"
```

---

## Provider Capabilities Matrix

| Feature | Gmail API | Outlook Graph | IMAP (Standard) | IMAP (Gmail Ext.) | Mail.app |
|---------|:---------:|:------------:|:---------------:|:-----------------:|:--------:|
| True labels (multiple per message) | Yes | No | No | Yes | No |
| Folders | No | Yes | Yes | Yes | Yes |
| Color categories | No | Yes | No | No | No |
| Star / Flag | Yes | Yes (+ due dates) | Yes | Yes | Yes |
| Archive | Yes | Yes | Yes (copy + delete) | Yes | Yes |
| Batch operations | Yes (1000/batch) | No | No | No | No |
| Server-side search | Yes | Yes (OData) | Yes (IMAP SEARCH) | Yes | No |
| OAuth / modern auth | Yes | Yes (MSAL) | Varies | N/A | N/A |
| Context manager | Yes | Yes | Yes | Yes | Yes |

The Gmail provider is the most capable, supporting batch `batchModify` operations that can apply labels to up to 1,000 messages in a single API call. It also implements exponential backoff with retry logic for `rateLimitExceeded`, `userRateLimitExceeded`, and `quotaExceeded` errors, with a configurable base delay starting at 10 seconds.

The Outlook provider uniquely supports **color categories** (25 preset colors) and **due-date flagging** that syncs with Microsoft To Do, enabling task management integration. It handles hierarchical folder creation automatically, creating nested folder paths like `Action/Critical` by walking the path segments.

---

## Label Taxonomy

The 28 built-in categories span the full spectrum of email types:

| Category | Tier | Time-Sensitive | Example Patterns |
|----------|:----:|:--------------:|-----------------|
| `Dev/GitHub` | 2 | No | `github.com`, `notifications@github` |
| `Dev/Code-Review` | 2 | Yes | `coderabb`, `sourcery`, `copilot` |
| `Dev/Infrastructure` | 3 | No | `cloudflare`, `vercel`, `netlify` |
| `Dev/GameDev` | 3 | No | `unity3d.com`, `godotengine` |
| `AI/Services` | 3 | No | `openai`, `anthropic`, `claude` |
| `AI/Grok` | 3 | No | `grok`, `x.ai` |
| `AI/Data Exports` | 2 | Yes | `data export`, `export is ready` |
| `Finance/Banking` | 1 | Yes | `chase`, `capital one`, `experian` |
| `Finance/Payments` | 2 | Yes | `paypal`, `stripe`, `venmo` |
| `Finance/Tax` | 2 | Yes | `turbotax`, `irs.gov` |
| `Tech/Security` | 1 | Yes | `1password`, `security alert` |
| `Tech/Google` | 2 | Yes | `@google.com`, `google cloud` |
| `Shopping` | 4 | No | `amazon`, `ebay`, `walmart` |
| `Personal/Health` | 2 | Yes | `walgreens`, `cvs`, `pharmacy` |
| `Social/LinkedIn` | 3 | No | `linkedin.com` |
| `Travel` | 2 | Yes | `united.com`, `airbnb`, `booking.com` |
| `Entertainment` | 4 | No | `netflix`, `spotify`, `audible` |
| `Education/Research` | 3 | No | `coursera`, `arxiv`, `academia.edu` |
| `Professional/Jobs` | 2 | Yes | `indeed`, `glassdoor`, `linkedin jobs` |
| `Professional/Legal` | 2 | Yes | `legalzoom`, `attorney` |
| `Services/Domain` | 2 | Yes | `namecheap`, `godaddy` |
| `Tech/Storage` | 3 | No | `filerev`, `box.com`, `onedrive` |
| `Notification` | 3 | No | `notification`, `alert`, `reminder` |
| `Marketing` | 4 | No | `unsubscribe`, `newsletter`, `promo` |
| `Personal/Government` | 1 | Yes | `.gov`, `passport`, `dmv` |
| `Personal` | 1 | Yes | family-specific patterns |
| `Awaiting Reply` | 2 | Yes | `awaiting reply`, `pending response` |
| `Misc/Other` | 4 | No | `.*` (catch-all, priority 999) |

---

## Scheduling and Daily Automation

The system includes a macOS `LaunchAgent` plist (`com.user.mail_automation.plist`) that can schedule `run_automation.sh` to execute daily at 9:00 AM, but scheduler installation is opt-in. The default local workflow is `scripts/intake_now.sh`, which runs on demand and writes private reports under `~/.local/state/universal-mail-automation/intake/`.

The daily runner processes providers in sequence:

1. **Gmail** — Labels unlabeled emails, then sweeps `Misc/Other` for re-categorization.
2. **Outlook** — Processes the full inbox with tier routing.
3. **iCloud** — Processes all messages via IMAP.

Each step runs independently (failure in one provider does not block the others), with logs written to `~/System/Logs/mail_automation/`.

The `deploy.sh` script manages setup and optional scheduler install:

```bash
#Install and opt into scheduling
INSTALL_LAUNCH_AGENT=1 ./deploy.sh

#Preferred local on-demand intake
scripts/intake_now.sh

#Check scheduler status
launchctl list | grep mail_automation

#View logs
tail -f ~/System/Logs/mail_automation/launchd.stdout.log

#Unload scheduler (replace UID with your numeric user id from `id -u`)
launchctl bootout gui/UID/com.user.mail_automation
```

---

## Cross-Organ Context

Universal Mail Automation sits within **ORGAN-III (Ergon)** — the Commerce organ of the eight-organ creative-institutional system. ORGAN-III houses SaaS products, B2B/B2C tools, and internal productivity infrastructure. This project occupies the "internal tooling" category: a system built first for the operator's own workflow, with the architectural discipline to serve as a template or product if warranted.

**Connections across the organ system:**

- **ORGAN-I (Theoria)** — The provider abstraction pattern (abstract base class with capability flags, strategy-pattern dispatch) reflects the recursive architectural thinking documented in ORGAN-I's theory corpus. The `ProviderCapabilities` flag enum is a practical application of the compositional interface design explored in `recursive-engine`.
- **ORGAN-IV (Taxis)** — The daily scheduling via launchd, the state management for crash recovery, and the multi-source configuration precedence system are all orchestration patterns. The `StateManager` class embodies the same "resumable execution" principle that `agentic-titan` applies to AI agent workflows.
- **ORGAN-V (Logos)** — The design process behind this system — the gap analysis between iCloud filtering rules and Gmail patterns, the iterative refinement of the taxonomy, the decision to adopt the Eisenhower matrix — is documented in `PROCESS.md` and represents the kind of "building in public" narrative that ORGAN-V surfaces.

---

## Related Work

- [`organvm-iii-ergon/tab-bookmark-manager`](https://github.com/organvm-iii-ergon/tab-bookmark-manager) — Browser tab and bookmark organization (parallel information-triage problem in a different domain)
- [`organvm-iv-taxis/agentic-titan`](https://github.com/organvm-iv-taxis/agentic-titan) — AI agent orchestration framework (shares the abstract-provider + state-recovery architectural pattern)
- [`organvm-i-theoria/recursive-engine`](https://github.com/organvm-i-theoria/recursive-engine--generative-entity) — Recursive systems theory (the compositional interface pattern in `providers/base.py` is a direct descendant)

---

## Contributing

This repository is part of a coordinated multi-org system. Contributions are welcome, particularly:

- **New provider implementations** — Fastmail, ProtonMail, Yahoo Mail, or any IMAP-compatible service
- **Rule refinements** — More precise regex patterns, new categories, tier adjustments
- **Testing** — Unit tests for the rules engine and provider implementations
- **Documentation** — Usage guides, configuration examples, troubleshooting

Please open an issue before submitting large changes to discuss approach and scope.

### Dependency lock policy

`pyproject.toml` is the canonical declaration of package dependencies and
extras. The tracked `uv.lock` is the reproducibility receipt for that complete
environment; regenerate it with `uv lock` whenever a dependency constraint or
supported Python range changes, review the resolver diff, and commit both files
together. Do not edit the lockfile by hand.

The `requirements*.txt` files remain explicit compatibility and deployment
inputs. Keep their direct constraints aligned with the corresponding
`pyproject.toml` extras in the same change. The GitHub Python matrix installs
those inputs independently, so an up-to-date lockfile does not replace matrix
execution or package-build validation.

---

## Contact

For questions, issues, or contributions, visit the repository on GitHub: [@4444j99](https://github.com/4444j99)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Author

**[@4444j99](https://github.com/4444j99)**

Part of the [ORGAN-III: Ergon](https://github.com/organvm-iii-ergon) organization — Commerce, SaaS, and productivity tooling.
