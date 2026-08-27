# ATLAS — the `universal-mail` pillar

Spine map of the mail organism: every asset resolved to one of seven primitives, with its
durability and live-state. This is the **one pillar** the mail estate distills into. It is absorbed
into the operator's private `domus` house at `communications/inbound/` (git-subtree mirror,
pull-only) and run by a local daemon's mail heartbeat. Mirrors the `edu-organism` ATLAS pattern.

> Distilled 2026-06-22 from a sweep of the whole mail estate (≈219 raw elements → ~57 canonical).
> Operator-specific data (mailbox addresses, credential locations, protected-sender lists) is kept
> in the private house repo and the operator's secret store — **never** in this public repo.

## The seven primitives (kernel = `core/` + `providers/`)

| Primitive | What it is | `edu-organism` analog | Implemented in |
|---|---|---|---|
| **Account** | a configured mailbox; provider + capability flags + receipt path | Member | `core/models.py`, `providers/base.py` |
| **Message** | a single envelope (sender/subject/tier/snippet/age) | Mandate | `core/models.py`, `providers/{mailapp,imap,gmail,outlook}.py` |
| **Classifier** | rules taxonomy + Eisenhower tiers + protected-sender gate | Standard | `core/rules.py` (2nd observer: `core/audit.py`) |
| **Action/Sweep** | the reversible move: flag-fire / archive / skip | Standing | `inbox_sweep.py`, `gmail_imap_sweep.py`, `providers/mailapp.py` |
| **Obligation** | derived next-step on a 3-rung PROTOCOL→PRECEDENT→EXPLORATION cascade | Progression | `obligations_build.py`, `core/protocols.py` |
| **Draft** | voice-matched outbound reply, **never sent** | Mandate (outbound) | `draft_writer.py`, `core/voice.py` |
| **Connector** | the write-door grant that permits a real mailbox mutation | Governance | `auth/onepassword.py`, `gmail_auth.py`, `providers/imap.py` |

The protected-sender gate is an **invariant** enforced independently by `core/audit.py` (re-derives
protection from the raw sender, not a passed flag) and `providers/base.py` — a two-observer design that
cannot be silently bypassed. The operator's never-archive allowlist is a gitignored local file
(`config/protected_senders.local.txt`) merged at import by `core/rules.py`; it is never committed.

## Provider matrix (Account × write-door)

| Provider | Archive | Notes |
|---|---|---|
| Apple Mail (`providers/mailapp.py`) | flag only on label-stores; real move on folder-stores | keyless AppleScript; can flag but cannot drop a label-store label |
| IMAP (`providers/imap.py`) | ✅ true archive | `X-GM-LABELS` drops `\Inbox` for label-stores; real `MOVE` for folder-stores |
| Gmail API (`providers/gmail.py`) | ✅ with `gmail.modify` | needs an OAuth token with modify scope |
| Outlook/Graph (`providers/outlook.py`) | ✅ | MSAL token cache required |

A label-store mailbox cannot be archived by Apple Mail (it only adds labels); the reliable archive
there is the raw-IMAP `\Inbox` drop in `providers/imap.py` (`gmail_imap_sweep.py`).

## Connector — the credential model (how the write-door opens)

Every mailbox mutation needs one modify-capable grant (the provider security-gates this). The grants
live in the **operator's secret store** (e.g. 1Password) — durable and universal; *app-passwords never
expire*. The recurring "make the password again" friction was never a missing credential — it was the
absence of a **headless-readable** wiring (a desktop-locked secret manager + a placeholder env var).
Permanent homes, in order of privacy:

1. **Local daemon** — resolve the app-password from the secret store via a service-account token
   (headless `op read`), keeping all mail content on-device. `providers/imap.py::_load_password` reads
   `IMAP_PASS` then `OP_ACCOUNT/OP_ITEM/OP_FIELD`.
2. **Private remote runner** — a scheduled job on a **private** repo with the app-password as a secret.
   (Do **not** run mail sweeps from this public repo: senders/subjects would leak into public logs.)

## How it runs (the heartbeat)

Executed by the operator's local daemon mail beat: sweep all Apple Mail accounts keyless (flag fires +
archive folder-stores), rebuild an obligations ledger from the sweep receipts via `obligations_build.py`
→ `core/protocols.py`, enrich reply drafts via `draft_writer.py` (never sends), render a local face. The
label-store archive leg (e.g. Gmail) is opt-in behind an env flag until the Connector is armed.
Receipts/ledger are gitignored, local, PII-bearing — never committed.

## Lineage (preserved, not deleted)

- A "mail-operations OS layer" (resolvers, historical-intelligence, ops cockpit) lives on branch
  `feat/operator-dashboard-mail-endzone` — preserved/pushed, awaiting its own PR decision.
- Deprecated, kept for reference (not in the live pipeline; several predate the protected-sender gate):
  `gmail_labeler*.py`, `imap_rules.py`, `auto_drain.py`, `archive_sorted.py`, `bulk_sweeper.py`,
  `run_automation.sh`, `icloud_triage.py`, and the stale `com.user.*.plist` LaunchAgent templates.
  Superseded by `inbox_sweep.py` + `gmail_imap_sweep.py` (which always enforce the gate).

## Surfaces (product / API)

`mcp_server/server.py` (MCP SDK v2 `MCPServer`, dry-run default, gate-enforced) · `api/` (FastAPI: triage / senders /
billing / audit; ACP checkout) · `cloudflare/worker.mjs` · `Dockerfile` / `render.yaml` · PyPI
trusted-publish (OIDC). Deploy secret: `CLOUDFLARE_API_TOKEN`.
