# Agent commerce & agent tools: MCP + ACP

This product exposes two agent-facing surfaces. They are different protocols doing
different jobs, and "ACP" in particular is overloaded — read this before touching
either.

## MCP — Model Context Protocol (how agents *use* the tool)

Anthropic's tool-connectivity standard. Our MCP server (`mcp_server/`) exposes the
triage engine and redacted operator intelligence as tools an AI agent can call:

| Tool | Effect | Annotation |
|------|--------|------------|
| `check_protected_sender` | pure check, no mailbox | `readOnlyHint` |
| `triage_preview` | dry-run, touches nothing | `readOnlyHint` |
| `triage` | applies labels/archive; `dry_run=True` by default | `destructiveHint` |
| `mail_history_export` | normalizes local JSON/JSONL/mbox/EML/EMLX sources into a private export file and returns only a safe receipt | non-destructive file write |
| `mail_intelligence` | mines a local historical export into redacted opportunities, risks, evidence, and `/ops` reconciliation | `readOnlyHint` |
| `mail_action_plan` | groups redacted intelligence into ranked, approval-aware next actions | `readOnlyHint` |
| `mail_resolver_plan` | maps action groups to official surfaces, blockers, safe prep, and required proof | `readOnlyHint` |
| `mail_provider_surface_plan` | ranks controlled provider hints into the next official API/CLI/manual resolver frontier | `readOnlyHint` |
| `mail_resolver_ledger` | reads redacted official-surface resolver proof state | `readOnlyHint` |
| `mail_github_resolver` | reads a bounded redacted GitHub CLI/API snapshot for GitHub resolver actions | `readOnlyHint` |
| `mail_github_resolver_receipts` | records GitHub provider-read or blocker snapshot candidates into the local resolver ledger | non-destructive file write |
| `mail_followup_resolver` | reads redacted mail/LinkedIn follow-up state from local approval and delivery receipts | `readOnlyHint` |
| `mail_followup_resolver_receipts` | records follow-up resolver proof from existing approval or delivery receipts | non-destructive file write |
| `mail_external_resolver` | reads provider/security/billing/subscription/legal planned external-surface state | `readOnlyHint` |
| `mail_external_resolver_receipts` | records explicit local blocker attestations for external-surface lanes | non-destructive file write |
| `mail_resolver_receipt` | appends a redacted resolver receipt; no portal automation | non-destructive file write |
| `mail_action_ledger` | reads redacted local action status and proof receipts | `readOnlyHint` |
| `mail_action_receipt` | appends a redacted local action receipt; no mailbox mutation | non-destructive file write |
| `mail_draft_package` | builds private draft candidates for approval; requires `ack_private=True` | `readOnlyHint` |
| `mail_draft_approvals` | reads redacted local draft approval status | `readOnlyHint` |
| `mail_draft_approval` | appends a redacted local draft approval receipt; no send | non-destructive file write |
| `mail_delivery_ledger` | reads redacted post-approval delivery intent/status | `readOnlyHint` |
| `mail_delivery_receipt` | appends a redacted local delivery receipt; no provider draft or send | non-destructive file write |
| `mail_evidence_review` | opens one bounded private source message for an evidence id; requires `ack_private=True` | `readOnlyHint` |

Every tool delegates to `api.service`, so the fail-closed protected-sender gate and
the independent audit receipt apply to agent calls too: **an agent physically
cannot get a success result if a protected sender was archived.** That inverts the
68+ existing Gmail MCP servers, which expose raw archive/delete with no
decision-layer restraint.

Live MCP triage (`triage(dry_run=False)`) also requires `account_api_key`. It uses
the same account entitlement reservation as the HTTP API: monthly run allowance
first, prepaid run credits second, and rollback on provider or gate failure.

`mail_intelligence` is read-only and local-file based. It does not send, label,
archive, mark read, or mutate a mailbox; it returns `uma.mail.intelligence.v1`
from a historical export path and optional current ops report path.

`mail_history_export` is the private intake producer for that tool. It reads local
mail sources and writes `uma.mail.history_export.v1`; because that file can
contain raw subjects, snippets, and bounded bodies, the MCP tool returns only
`uma.mail.history_export.receipt.v1`.

`mail_action_plan` consumes the redacted intelligence cache and returns
`uma.mail.action_plan.v1`. It can tell an agent what should happen next, but it
does not grant send, archive, mark-read, or portal-action authority.

`mail_resolver_plan` consumes the same redacted intelligence cache and returns
`uma.mail.resolver_plan.v1`. It tells an agent which official surface is
required for each action group, including mail or LinkedIn inboxes, GitHub
API/CLI/web, provider security dashboards, billing portals, subscription
portals, or legal review. It is plan-only: no sends, provider drafts, portal
mutations, archive changes, labels, or mark-read operations.

`mail_resolver_ledger` and `mail_resolver_receipt` are the official-surface
proof-state layer. They read/write `uma.mail.resolver_ledger.v1` and
`uma.mail.resolver_receipt.v1` records for checks such as GitHub reconciliation,
security review, billing verification, subscription decisions, and legal review.
The receipts hash external references and remain operator attestations until a
future provider-backed resolver writes stronger proof.

`mail_github_resolver` is the first provider-specific official-surface reader.
It consumes the same redacted intelligence cache, builds the current resolver
plan, and uses the GitHub CLI for bounded read-only checks of notifications,
assigned issues, and open PR search when authenticated. It hashes repository
references, omits raw titles, URLs, subjects, command output, and login data,
and returns receipt candidates only. It never mutates GitHub, portals, mailboxes,
drafts, labels, or sends.

`mail_github_resolver_receipts` records those provider-read or blocker
candidates into the same redacted resolver ledger as
`mail_resolver_receipt`. It may read GitHub through the CLI/API, then writes
local proof only. `provider_backed_read` can be true for successful official
reads; `provider_backed_automation`, sends, portal mutations, and mailbox
mutations remain false.

`mail_followup_resolver` and `mail_followup_resolver_receipts` are the
mail/LinkedIn follow-up proof bridge. They reconcile `reply_follow_up` actions
against local draft approval and delivery receipts, then record resolver proof
only when those receipts already exist. They do not read LinkedIn, create
provider drafts, send, archive, label, mark read, or mutate a mailbox.

`mail_external_resolver` and `mail_external_resolver_receipts` cover the
provider/security/billing/subscription/legal lanes that still require official
surfaces. The snapshot is planned-only by default and may include controlled
provider/surface hint slugs for routing. Receipt writes require an explicit
blocker attestation and remain local proof state. Provider hints are not
provider reads. They do not read providers, open portals, mutate accounts, send,
archive, label, or mark read.

`mail_provider_surface_plan` is the provider resolver frontier. It ranks those
controlled provider/surface hint slugs into future official API/CLI/manual
resolver candidates, showing existing UMA coverage, proof goals, blockers, and
future intake detector candidates. It is read-only and plan-only: no provider
reads, portal automation, sends, or mailbox mutations.

`mail_action_ledger` and `mail_action_receipt` are the local proof layer.
`mail_action_ledger` returns `uma.mail.action_ledger.v1`, and
`mail_action_receipt` appends `uma.mail.action_receipt.v1` to a JSONL receipt
ledger. These tools record redacted status only; they do not send, archive,
label, mark read, or change provider state.

`mail_draft_package` is the gated private draft tool. It returns
`uma.mail.draft_package.v1` for `missed_lead` / `draft_approval` actions, with
private recipients, source-backed fact checks, and draft text. It requires
`ack_private=True`; every candidate remains `send_allowed=false`.

`mail_draft_approvals` and `mail_draft_approval` are the local approval layer.
They read/write redacted draft approval receipts. Approval does not send mail and
does not create provider drafts.

`mail_delivery_ledger` and `mail_delivery_receipt` are the post-approval local
delivery layer. They can record that a provider draft was requested, blocked, or
operator-attested externally, but they do not create provider drafts or send
mail. `provider_draft_recorded` and `sent_recorded` remain local attestations
until a provider-specific resolver writes official proof.

`mail_evidence_review` is the gated private review tool. It can return raw
sender, address, subject, snippet, and bounded body text for one evidence id, so
agents must pass `ack_private=True`. The tool remains read-only and grants no
send or mailbox-mutation authority.

The server uses the official Python SDK v2 `MCPServer` API. In v2, transport
configuration belongs on `run()` and the ASGI app builders; see the official
[v2 migration guide](https://github.com/modelcontextprotocol/python-sdk/blob/v2.0.0/docs/migration.md).

- **stdio** (local, Claude Desktop, any MCP client): `python -m mcp_server`
- **Streamable HTTP** (hosted): mounted at `/mcp` on the main app; also runnable
  standalone via `uvicorn mcp_server.server:http_app`. Set `MCP_ALLOWED_HOSTS` to
  your deploy host(s) (DNS-rebinding protection is on by default).

## ACP — Agentic Commerce Protocol (how agents *buy* the tool)

**The "ACP" we implement is the
[Agentic Commerce Protocol](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol)
(OpenAI + Stripe), spec version `2026-04-17`.** It is the agent→merchant checkout
standard. We chose it because it is the only "ACP" that is a *commerce/checkout*
protocol and the only one co-developed with Stripe (our billing processor).

It is explicitly **NOT**:

- **Zed's Agent Client Protocol** — editor ↔ coding-agent IPC. Wrong layer.
- **IBM/BeeAI Agent Communication Protocol** (Linux Foundation) — agent interop.
- **Google A2A / AP2** — agent-to-agent messaging / payment authorization mandates.

If a future contributor wires one of those expecting "buy this service," that is
the predictable error this document exists to prevent.

### Scope ruling: ACP and Stripe Billing are two surfaces, not one

Stripe **Shared Payment Tokens (SPT)** — the delegated-payment mechanism ACP uses —
are *one-time*-scoped (the delegated allowance reason is literally `one_time`).
There is no recurring/subscription path through SPT today. Therefore:

- **Recurring human subscriptions → `api/billing.py`** (Stripe Checkout + Customer
  Portal + a metered usage meter). This is the primary money path.
- **One-time agent purchases → `acp/`** — a single digital SKU: a credit pack of N
  triage runs. An agent buys a pack; runs are credited to the buyer's balance.

Conflating them (trying to run a subscription through ACP/SPT) is the second
predictable error. Don't.

### The ACP surface (`acp/`)

Five endpoints implement the verified Agentic Checkout spec:

```
POST   /acp/checkout_sessions              create
GET    /acp/checkout_sessions/{id}         retrieve
POST   /acp/checkout_sessions/{id}         update
POST   /acp/checkout_sessions/{id}/complete   charge (SPT) + fulfill
POST   /acp/checkout_sessions/{id}/cancel     cancel
GET    /acp/feed.json                      product feed (discovery)
```

Every request is gated fail-closed: `Authorization: Bearer`, exact
`API-Version: 2026-04-17`, and (on POST) a required `Idempotency-Key` with
replay-dedup (409 in-progress / 422 conflict / `Idempotent-Replayed: true` on
replay). Failures return the spec error envelope `{type, code, message, param}`.

On `complete`, the delegated SPT token is charged via a confirmed Stripe
PaymentIntent (`acp/payment.py`, isolated behind an interface so the preview API
version `2026-04-22.preview` is a one-file change), runs are credited, and a
**signed order receipt** is emitted at `/v1/audit/{order_id}` — so even an agent
purchase carries the product's verifiable-receipt trust signal.

### Out of scope (this iteration)

ChatGPT Instant Checkout listing: it is physical-goods-only and application-gated
(US-first, retail-anchored), so a solo dev tool can't list there yet. The ACP
seller endpoints are an open Apache-2.0 spec any ACP-compatible agent can call, so
we ship the faithful endpoints now and treat ChatGPT distribution as later.

## Stripe configuration (deploy secrets — never commit)

| Var | Purpose |
|-----|---------|
| `STRIPE_SECRET_KEY` | enables billing + ACP charge (`sk_live`/`sk_test`) |
| `STRIPE_WEBHOOK_SECRET` | webhook signature verification (`whsec_`) |
| `STRIPE_PRICE_PRO` / `STRIPE_PRICE_BUSINESS` | subscription Price ids |
| `STRIPE_PRICE_METERED` | metered usage Price id |
| `RECEIPT_SIGNING_KEY` | HMAC key for signed receipts (durable verification) |
| `MCP_ALLOWED_HOSTS` | comma-separated hosts for the `/mcp` endpoint (or `*`) |

Absent these, the catalog and pure endpoints still work; money/charge endpoints
return a clean `503 billing is not configured`.
