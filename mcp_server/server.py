"""MCPServer — the mail-triage engine as safety-gated agent tools.

Every tool delegates to :mod:`api.service`, the single chokepoint that enforces
the fail-closed protected-sender gate and the independent audit receipt. So an
agent driving these tools physically cannot get a "success" result if a protected
sender was archived — the guarantee is inherited, never re-implemented. This
inverts the 68+ existing Gmail MCP servers, which expose raw archive/delete with
no decision-layer restraint.

Two design choices that matter:
  * the destructive ``triage`` tool defaults to ``dry_run=True`` — the opposite of
    the ecosystem default — so a careless or prompt-injected agent previews by
    default and must *explicitly* ask to mutate;
  * a gate violation raises (``AuditInvariantError`` → MCP ``isError``) rather than
    returning success, and the message is generic so internal message ids never
    leak to the model.

Run:
    python -m mcp_server                         # stdio (Claude Desktop, etc.)
    uvicorn mcp_server.server:http_app           # hosted Streamable HTTP at /
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import os
from urllib.parse import urlsplit

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from api import metering, service, triage_runtime
from api.schemas import MAX_TRIAGE_LIMIT, SenderCheckResponse, TriageResponse
from api.store import get_store
from core.historical_intelligence import (
    HistoricalIntelligenceError,
    build_historical_intelligence,
)
from core.mail_history_export import (
    MailHistoryExportError,
    build_mail_history_export,
    write_mail_history_export,
)
from core.mail_action_plan import MailActionPlanError, build_action_plan
from core.mail_action_ledger import (
    MailActionLedgerError,
    build_action_ledger,
    build_action_plan_for_ledger,
    build_action_receipt,
)
from core.mail_resolver_plan import MailResolverPlanError, build_resolver_plan
from core.mail_resolver_receipt import (
    MailResolverReceiptError,
    build_resolver_ledger,
    build_resolver_receipt,
)
from core.github_resolver import (
    GitHubResolverError,
    build_github_resolver_receipts,
    build_github_resolver_snapshot,
)
from core.followup_resolver import (
    FollowupResolverError,
    build_followup_resolver_receipts,
    build_followup_resolver_snapshot,
)
from core.external_resolver import (
    ExternalResolverError,
    build_external_resolver_receipts,
    build_external_resolver_snapshot,
)
from core.provider_surface_plan import ProviderSurfacePlanError, build_provider_surface_plan
from core.mail_evidence_review import MailEvidenceReviewError, build_evidence_review
from core.mail_draft_package import MailDraftPackageError, build_draft_package
from core.mail_draft_approval import (
    MailDraftApprovalError,
    build_draft_approval_ledger,
    build_draft_approval_receipt,
)
from core.mail_delivery import (
    MailDeliveryError,
    build_delivery_ledger,
    build_delivery_receipt,
)
from core.input_validation import (
    InputValidationError,
    validate_api_token,
    validate_header_value,
    validate_mail_label,
    validate_provider_name,
    validate_search_query,
    validate_triage_limit,
)

logger = logging.getLogger(__name__)


_DEFAULT_LOOPBACK_HOSTS = ("localhost", "127.0.0.1")
_MCP_QUERY_MAX_CHARS = 2048
_MCP_PROVIDER_MAX_CHARS = 64
_MCP_REMOVE_LABEL_MAX_CHARS = 512


def _normalize_host(raw_host: str) -> Optional[str]:
    """Normalize one host entry for MCP allowed-host configuration.

    Accepts plain hosts (with optional :port) or scheme-qualified hosts like
    ``https://tenant.example.com`` and extracts the host token safely.
    """
    host_candidate = raw_host.strip()
    if not host_candidate:
        return None

    parsed = urlsplit(host_candidate if "://" in host_candidate else f"//{host_candidate}")
    if parsed.scheme:
        if parsed.scheme not in {"http", "https"}:
            return None
        if parsed.path or parsed.query or parsed.fragment:
            return None
        host_candidate = parsed.netloc
    else:
        # For //style parse, an invalid host like "a/b" sets a path fragment.
        if parsed.path and parsed.netloc:
            return None
        if parsed.query or parsed.fragment:
            return None
        host_candidate = parsed.netloc or parsed.path

    if not host_candidate:
        return None
    if " " in host_candidate or "?" in host_candidate or "#" in host_candidate:
        return None
    if "@" in host_candidate:
        return None

    return host_candidate.lower()


def _host_entries(raw: str) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for raw_host in raw.split(","):
        normalized = _normalize_host(raw_host)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        hosts.append(normalized)
    return hosts


def _clamp_text(value: Optional[str], *, max_chars: int) -> Optional[str]:
    if value is None:
        return None
    return value[:max_chars]


def _transport_security() -> TransportSecuritySettings:
    """DNS-rebinding protection for the hosted Streamable HTTP endpoint.

    Stays ON by default (loopback always allowed for local dev). Set
    MCP_ALLOWED_HOSTS to a comma-separated host list for production (e.g. the
    Render domain), or to "*" to disable protection when a fronting proxy already
    validates Host.
    """
    raw = os.environ.get("MCP_ALLOWED_HOSTS", "").strip()
    if raw == "*":
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    hosts = _host_entries(raw)
    if not hosts:
        logger.debug("MCP_ALLOWED_HOSTS is unset or empty; falling back to local defaults")
    for loopback_host in _DEFAULT_LOOPBACK_HOSTS:
        loopback_with_port = f"{loopback_host}:8000"
        if loopback_host not in hosts:
            hosts.append(loopback_host)
        if loopback_with_port not in hosts:
            hosts.append(loopback_with_port)
    origins = [f"http://{h}" for h in hosts] + [f"https://{h}" for h in hosts]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=origins,
    )

INSTRUCTIONS = (
    "Multi-provider email triage with provable restraint. Tools here cannot "
    "archive or move a sender the protected-sender gate classifies as protected "
    "(government, financial, legal, platform-security), and every triage returns "
    "a verifiable audit receipt. Use check_protected_sender to pre-check a sender, "
    "triage_preview to see what WOULD change (touches nothing), and triage to "
    "apply changes (dry_run=True by default; set dry_run=False and provide an "
    "account_api_key to mutate the mailbox). Use mail_intelligence to mine a "
    "local historical mail export into redacted opportunities, risks, evidence, "
    "and current /ops reconciliation without mutating the mailbox. Use "
    "mail_history_export to normalize local JSON/JSONL/mbox/eml/emlx sources "
    "into that private export file; it returns only a safe receipt. Use "
    "mail_action_plan to turn redacted intelligence into ranked, approval-aware "
    "next-action groups. Use mail_resolver_plan to map those groups to official "
    "surfaces and proof requirements. Use mail_provider_surface_plan to rank "
    "controlled provider/surface hints into a buildable resolver frontier without "
    "provider reads or automation. Use mail_resolver_ledger and "
    "mail_resolver_receipt to inspect or append redacted official-surface "
    "operator attestations without portal automation. Use mail_github_resolver "
    "for a bounded read-only GitHub CLI/API snapshot over GitHub resolver "
    "actions, and mail_github_resolver_receipts to record those provider-read "
    "or blocker candidates into the local redacted resolver ledger. Use "
    "mail_followup_resolver and mail_followup_resolver_receipts to inspect and "
    "record mail/LinkedIn follow-up proof from local draft approval and "
    "delivery receipts without reading LinkedIn, creating drafts, or sending. Use "
    "mail_external_resolver and mail_external_resolver_receipts to inspect or "
    "explicitly attest external provider/security/billing/subscription/legal "
    "blockers without logging into portals or mutating provider state. Use "
    "mail_action_ledger to inspect local redacted action "
    "status and receipts, and mail_action_receipt to append a redacted local "
    "proof receipt without mutating mail. Use mail_draft_package only with "
    "ack_private=True to build private draft candidates that still require "
    "approval before send. Use mail_draft_approvals and mail_draft_approval to "
    "record redacted local approval receipts without sending. Use "
    "mail_delivery_ledger and mail_delivery_receipt to track post-approval "
    "delivery intent and operator-attested external status without creating "
    "provider drafts or sending. Use "
    "mail_evidence_review only with ack_private=True to open a bounded private "
    "source message for a specific evidence id."
)

# Transport-specific settings belong on run()/streamable_http_app() in MCP SDK
# v2; the server object itself contains only transport-independent state.
mcp = MCPServer(
    "universal-mail",
    instructions=INSTRUCTIONS,
)


def _clamp_limit(limit: int) -> int:
    return validate_triage_limit(limit, max_limit=MAX_TRIAGE_LIMIT)


@mcp.tool(annotations={"read_only_hint": True})
def check_protected_sender(sender: str, subject: str = "") -> SenderCheckResponse:
    """Is this sender PROTECTED (never archived/moved) and how is it categorized?

    Pure — needs no mailbox credentials. Protected classes: government (.gov),
    financial, legal, and platform-security senders.
    """
    try:
        sender = validate_header_value(sender, field="sender", allow_empty=False)
        subject = validate_header_value(subject or "", field="subject")
    except InputValidationError as e:
        raise RuntimeError(f"invalid input: {e}") from e
    return SenderCheckResponse(**service.check_sender(sender, subject))


@mcp.tool(annotations={"read_only_hint": True})
def triage_preview(
    provider: str = "gmail",
    query: str = "has:nouserlabels",
    limit: int = 100,
) -> TriageResponse:
    """Dry-run a triage: return the disposition counts + audit receipt, touch
    NOTHING in the mailbox. Requires the server to hold mailbox credentials."""
    provider = _clamp_text(provider, max_chars=_MCP_PROVIDER_MAX_CHARS) or ""
    query = _clamp_text(query, max_chars=_MCP_QUERY_MAX_CHARS) or ""
    return _triage(provider, query, limit, dry_run=True, remove_label=None,
                   tier_routing=False, vip_only=False)


@mcp.tool(annotations={"destructive_hint": True, "idempotent_hint": False})
def triage(
    provider: str = "gmail",
    query: str = "has:nouserlabels",
    limit: int = 100,
    remove_label: Optional[str] = None,
    tier_routing: bool = False,
    vip_only: bool = False,
    dry_run: bool = True,
    account_api_key: Optional[str] = None,  # allow-secret: tool parameter
) -> TriageResponse:
    """Apply a triage (labels + archive per the rules). dry_run=True by DEFAULT —
    pass dry_run=False and account_api_key to actually mutate the mailbox.

    FAIL-CLOSED: if the independent audit proves a protected sender left the inbox,
    this raises (the run is rejected) rather than reporting success.
    """
    provider = _clamp_text(provider, max_chars=_MCP_PROVIDER_MAX_CHARS) or ""
    query = _clamp_text(query, max_chars=_MCP_QUERY_MAX_CHARS) or ""
    remove_label = _clamp_text(
        remove_label, max_chars=_MCP_REMOVE_LABEL_MAX_CHARS
    )
    return _triage(provider, query, limit, dry_run=dry_run, remove_label=remove_label,
                   tier_routing=tier_routing, vip_only=vip_only,
                   account_api_key=account_api_key)


@mcp.tool(annotations={"read_only_hint": True})
def mail_intelligence(
    history_path: str,
    ops_report_path: Optional[str] = None,
    stale_days: int = 14,
) -> Dict[str, Any]:
    """Read-only historical mail intelligence.

    Mines a local historical export into redacted missed opportunities, risks,
    timeline data, and evidence ids. If ``ops_report_path`` is supplied, the
    findings are reconciled against current operator lanes.
    """
    try:
        return build_historical_intelligence(
            Path(history_path).expanduser(),
            ops_report_path=Path(ops_report_path).expanduser() if ops_report_path else None,
            stale_days=stale_days,
        )
    except HistoricalIntelligenceError as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"destructive_hint": False, "idempotent_hint": True})
def mail_history_export(
    source_path: str,
    output_path: str,
    source_type: str = "auto",
    since: Optional[str] = None,
    until_exclusive: Optional[str] = None,
    limit: Optional[int] = None,
    body_char_limit: int = 4000,
    self_addresses: Optional[str] = None,
    mailbox_hint: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalize local historical mail sources into a private export file.

    Supported inputs include JSON, JSONL/NDJSON, mbox, EML, EMLX, and EMLX
    directories. The tool reads source mail and writes a local private export
    for ``mail_intelligence``; it returns only a redacted receipt and does not
    mutate the mailbox.
    """
    addresses = [
        item.strip()
        for item in (self_addresses or "").split(",")
        if item.strip()
    ]
    try:
        export = build_mail_history_export(
            Path(source_path).expanduser(),
            source_type=source_type,
            since=since,
            until_exclusive=until_exclusive,
            limit=limit,
            body_char_limit=body_char_limit,
            self_addresses=addresses,
            mailbox_hint=mailbox_hint,
        )
        return write_mail_history_export(export, Path(output_path).expanduser())
    except MailHistoryExportError as e:
        raise RuntimeError(e.detail) from e
    except OSError as e:
        raise RuntimeError(f"could not write historical export: {e}") from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_action_plan(
    intelligence_path: str,
    max_items: int = 40,
) -> Dict[str, Any]:
    """Build a redacted action plan from historical intelligence.

    The plan groups and ranks findings by lane, priority, approval type, and
    automation boundary. It does not expose raw mail and does not mutate the
    mailbox.
    """
    try:
        return build_action_plan(Path(intelligence_path).expanduser(), max_items=max_items)
    except MailActionPlanError as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_resolver_plan(
    intelligence_path: str,
    max_items: int = 100,
) -> Dict[str, Any]:
    """Build redacted official-surface resolver plans for action groups."""
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        return build_resolver_plan(plan, max_items=max_items)
    except (MailActionLedgerError, MailResolverPlanError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_provider_surface_plan(
    intelligence_path: str,
    max_items: int = 20,
) -> Dict[str, Any]:
    """Build a redacted provider-surface resolver frontier plan.

    This ranks controlled provider/surface hint slugs from the resolver plan,
    shows what official API/CLI/manual resolver should be built next, and
    exposes proof gaps. It does not read providers, open portals, mutate
    accounts, send, or mutate mail.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        resolver_plan = build_resolver_plan(plan, max_items=max(max_items, 10000))
        return build_provider_surface_plan(resolver_plan, max_items=max_items)
    except (MailActionLedgerError, MailResolverPlanError, ProviderSurfacePlanError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_resolver_ledger(
    intelligence_path: str,
    ledger_path: str,
    max_items: int = 100,
    max_receipts: int = 40,
) -> Dict[str, Any]:
    """Read redacted official-surface resolver proof state."""
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        resolver_plan = build_resolver_plan(plan, max_items=max(max_items, 10000))
        return build_resolver_ledger(
            resolver_plan,
            receipt_path=Path(ledger_path).expanduser(),
            max_items=max_items,
            max_receipts=max_receipts,
        )
    except (MailActionLedgerError, MailResolverPlanError, MailResolverReceiptError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_github_resolver(
    intelligence_path: str,
    gh_bin: str = "gh",
    query_limit: int = 50,
    max_items: int = 100,
    include_provider_queries: bool = True,
) -> Dict[str, Any]:
    """Read a redacted GitHub official-surface resolver snapshot.

    This can call the GitHub CLI for bounded read-only API checks. It does not
    mutate GitHub, mailboxes, portals, labels, drafts, or sends.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        resolver_plan = build_resolver_plan(plan, max_items=max(max_items, 10000))
        return build_github_resolver_snapshot(
            resolver_plan,
            gh_bin=gh_bin,
            query_limit=query_limit,
            max_items=max_items,
            include_provider_queries=include_provider_queries,
        )
    except (MailActionLedgerError, MailResolverPlanError, GitHubResolverError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"destructive_hint": False, "idempotent_hint": False})
def mail_github_resolver_receipts(
    intelligence_path: str,
    ledger_path: str,
    gh_bin: str = "gh",
    query_limit: int = 50,
    max_items: int = 100,
    max_receipts: int = 100,
    include_provider_queries: bool = True,
) -> Dict[str, Any]:
    """Record redacted resolver receipts from a GitHub resolver snapshot.

    This may read GitHub through the CLI/API, then writes only local UMA proof
    state. It does not mutate GitHub, mailboxes, portals, drafts, or sends.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        resolver_plan = build_resolver_plan(plan, max_items=max(max_items, 10000))
        snapshot = build_github_resolver_snapshot(
            resolver_plan,
            gh_bin=gh_bin,
            query_limit=query_limit,
            max_items=max_items,
            include_provider_queries=include_provider_queries,
        )
        return build_github_resolver_receipts(
            snapshot,
            resolver_plan,
            receipt_path=Path(ledger_path).expanduser(),
            max_receipts=max_receipts,
        )
    except (MailActionLedgerError, MailResolverPlanError, GitHubResolverError, MailResolverReceiptError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_followup_resolver(
    intelligence_path: str,
    draft_approval_receipt_path: str,
    delivery_receipt_path: str,
    max_items: int = 100,
) -> Dict[str, Any]:
    """Read a redacted mail/LinkedIn follow-up resolver snapshot.

    This reconciles local approval and delivery receipts for reply follow-up
    actions. It does not read LinkedIn, mutate mailboxes, create drafts, or send.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        resolver_plan = build_resolver_plan(plan, max_items=max(max_items, 10000))
        return build_followup_resolver_snapshot(
            resolver_plan,
            draft_approval_receipt_path=Path(draft_approval_receipt_path).expanduser(),
            delivery_receipt_path=Path(delivery_receipt_path).expanduser(),
            max_items=max_items,
        )
    except (MailActionLedgerError, MailResolverPlanError, FollowupResolverError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"destructive_hint": False, "idempotent_hint": False})
def mail_followup_resolver_receipts(
    intelligence_path: str,
    ledger_path: str,
    draft_approval_receipt_path: str,
    delivery_receipt_path: str,
    max_items: int = 100,
    max_receipts: int = 100,
) -> Dict[str, Any]:
    """Record resolver receipts from local mail/LinkedIn follow-up proof.

    This writes only local redacted resolver proof. It does not read LinkedIn,
    create provider drafts, send, or mutate a mailbox.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        resolver_plan = build_resolver_plan(plan, max_items=max(max_items, 10000))
        snapshot = build_followup_resolver_snapshot(
            resolver_plan,
            draft_approval_receipt_path=Path(draft_approval_receipt_path).expanduser(),
            delivery_receipt_path=Path(delivery_receipt_path).expanduser(),
            max_items=max_items,
        )
        return build_followup_resolver_receipts(
            snapshot,
            resolver_plan,
            receipt_path=Path(ledger_path).expanduser(),
            max_receipts=max_receipts,
        )
    except (MailActionLedgerError, MailResolverPlanError, FollowupResolverError, MailResolverReceiptError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_external_resolver(
    intelligence_path: str,
    ledger_path: str,
    max_items: int = 100,
) -> Dict[str, Any]:
    """Read a redacted external-surface resolver snapshot.

    This surfaces provider/security/billing/subscription/legal lanes and local
    resolver receipts. It does not log into portals or mutate provider state.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        resolver_plan = build_resolver_plan(plan, max_items=max(max_items, 10000))
        return build_external_resolver_snapshot(
            resolver_plan,
            receipt_path=Path(ledger_path).expanduser(),
            max_items=max_items,
            operator_attestation_requested=False,
        )
    except (MailActionLedgerError, MailResolverPlanError, ExternalResolverError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"destructive_hint": False, "idempotent_hint": False})
def mail_external_resolver_receipts(
    intelligence_path: str,
    ledger_path: str,
    max_items: int = 100,
    max_receipts: int = 100,
    attest_blockers: bool = False,
) -> Dict[str, Any]:
    """Record explicit external-surface blocker attestations.

    This writes only local redacted resolver receipts. It does not perform
    provider reads, portal automation, mailbox mutation, draft creation, or send.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        resolver_plan = build_resolver_plan(plan, max_items=max(max_items, 10000))
        snapshot = build_external_resolver_snapshot(
            resolver_plan,
            receipt_path=Path(ledger_path).expanduser(),
            max_items=max_items,
            operator_attestation_requested=bool(attest_blockers),
        )
        return build_external_resolver_receipts(
            snapshot,
            resolver_plan,
            receipt_path=Path(ledger_path).expanduser(),
            max_receipts=max_receipts,
        )
    except (MailActionLedgerError, MailResolverPlanError, ExternalResolverError, MailResolverReceiptError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"destructive_hint": False, "idempotent_hint": False})
def mail_resolver_receipt(
    intelligence_path: str,
    ledger_path: str,
    action_id: str,
    resolver_status: str,
    reason_code: str,
    proof_type: str,
    provider: str = "manual",
    external_reference: Optional[str] = None,
    max_items: int = 100,
) -> Dict[str, Any]:
    """Append a redacted official-surface resolver receipt.

    This writes only local proof state. It does not open portals, send, archive,
    mark read, label, or mutate mailbox messages.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max(max_items, 10000))
        resolver_plan = build_resolver_plan(plan, max_items=max(max_items, 10000))
        return build_resolver_receipt(
            resolver_plan,
            action_id=action_id,
            resolver_status=resolver_status,
            reason_code=reason_code,
            proof_type=proof_type,
            provider=provider,
            external_reference=external_reference,
            receipt_path=Path(ledger_path).expanduser(),
        )
    except (MailActionLedgerError, MailResolverPlanError, MailResolverReceiptError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_action_ledger(
    intelligence_path: str,
    ledger_path: str,
    max_items: int = 100,
    max_receipts: int = 40,
) -> Dict[str, Any]:
    """Read redacted action status and local proof receipts.

    This merges a redacted action plan with a local JSONL receipt ledger. It does
    not expose raw mail and does not mutate the mailbox.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max_items)
        return build_action_ledger(
            plan,
            receipt_path=Path(ledger_path).expanduser(),
            max_items=max_items,
            max_receipts=max_receipts,
        )
    except MailActionLedgerError as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"destructive_hint": False, "idempotent_hint": False})
def mail_action_receipt(
    intelligence_path: str,
    ledger_path: str,
    action_id: str,
    action_status: str,
    reason_code: str,
    evidence_ids: Optional[str] = None,
    max_items: int = 100,
) -> Dict[str, Any]:
    """Append a redacted local receipt for an action-plan item.

    This writes only local proof state. It does not send, archive, mark read, or
    label mailbox messages.
    """
    ids = [
        item.strip()
        for item in (evidence_ids or "").split(",")
        if item.strip()
    ]
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max_items)
        return build_action_receipt(
            plan,
            action_id=action_id,
            action_status=action_status,
            reason_code=reason_code,
            evidence_ids=ids,
            receipt_path=Path(ledger_path).expanduser(),
        )
    except MailActionLedgerError as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_draft_package(
    intelligence_path: str,
    history_path: str,
    action_id: str,
    ack_private: bool = False,
    user_name: str = "Anthony",
    max_drafts: int = 3,
    max_items: int = 100,
    body_char_limit: int = 3000,
) -> Dict[str, Any]:
    """Build private, approval-gated draft candidates for one action id.

    This may return raw private recipient and draft text. It requires
    ``ack_private=True`` and grants no send or mailbox-mutation authority.
    """
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max_items)
        return build_draft_package(
            plan,
            Path(history_path).expanduser(),
            action_id,
            ack_private=ack_private,
            user_name=user_name,
            max_drafts=max_drafts,
            body_char_limit=body_char_limit,
        )
    except (MailActionLedgerError, MailDraftPackageError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_draft_approvals(
    intelligence_path: str,
    history_path: str,
    approvals_path: str,
    action_id: str,
    ack_private: bool = False,
    user_name: str = "Anthony",
    max_drafts: int = 3,
    max_items: int = 100,
    max_receipts: int = 40,
    body_char_limit: int = 3000,
) -> Dict[str, Any]:
    """Read redacted local approval status for private draft candidates."""
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max_items)
        package = build_draft_package(
            plan,
            Path(history_path).expanduser(),
            action_id,
            ack_private=ack_private,
            user_name=user_name,
            max_drafts=max_drafts,
            body_char_limit=body_char_limit,
        )
        return build_draft_approval_ledger(
            package,
            receipt_path=Path(approvals_path).expanduser(),
            max_receipts=max_receipts,
        )
    except (MailActionLedgerError, MailDraftPackageError, MailDraftApprovalError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"destructive_hint": False, "idempotent_hint": False})
def mail_draft_approval(
    intelligence_path: str,
    history_path: str,
    approvals_path: str,
    action_id: str,
    draft_id: str,
    decision: str,
    reason_code: str,
    ack_private: bool = False,
    user_name: str = "Anthony",
    max_drafts: int = 3,
    max_items: int = 100,
    body_char_limit: int = 3000,
) -> Dict[str, Any]:
    """Append a redacted local approval receipt for a private draft candidate."""
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max_items)
        package = build_draft_package(
            plan,
            Path(history_path).expanduser(),
            action_id,
            ack_private=ack_private,
            user_name=user_name,
            max_drafts=max_drafts,
            body_char_limit=body_char_limit,
        )
        return build_draft_approval_receipt(
            package,
            draft_id=draft_id,
            decision=decision,
            reason_code=reason_code,
            ack_private=ack_private,
            receipt_path=Path(approvals_path).expanduser(),
        )
    except (MailActionLedgerError, MailDraftPackageError, MailDraftApprovalError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_delivery_ledger(
    intelligence_path: str,
    history_path: str,
    approvals_path: str,
    delivery_path: str,
    action_id: str,
    ack_private: bool = False,
    user_name: str = "Anthony",
    max_drafts: int = 3,
    max_items: int = 100,
    max_receipts: int = 40,
    body_char_limit: int = 3000,
) -> Dict[str, Any]:
    """Read redacted delivery intent/status for approved draft candidates."""
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max_items)
        package = build_draft_package(
            plan,
            Path(history_path).expanduser(),
            action_id,
            ack_private=ack_private,
            user_name=user_name,
            max_drafts=max_drafts,
            body_char_limit=body_char_limit,
        )
        return build_delivery_ledger(
            package,
            approval_receipt_path=Path(approvals_path).expanduser(),
            delivery_receipt_path=Path(delivery_path).expanduser(),
            max_items=max_items,
            max_receipts=max_receipts,
        )
    except (MailActionLedgerError, MailDraftPackageError, MailDraftApprovalError, MailDeliveryError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"destructive_hint": False, "idempotent_hint": False})
def mail_delivery_receipt(
    intelligence_path: str,
    history_path: str,
    approvals_path: str,
    delivery_path: str,
    action_id: str,
    draft_id: str,
    delivery_status: str,
    reason_code: str,
    ack_private: bool = False,
    provider: str = "manual",
    external_reference: Optional[str] = None,
    user_name: str = "Anthony",
    max_drafts: int = 3,
    max_items: int = 100,
    body_char_limit: int = 3000,
) -> Dict[str, Any]:
    """Append a redacted local delivery receipt for an approved draft candidate."""
    try:
        plan = build_action_plan_for_ledger(Path(intelligence_path).expanduser(), max_items=max_items)
        package = build_draft_package(
            plan,
            Path(history_path).expanduser(),
            action_id,
            ack_private=ack_private,
            user_name=user_name,
            max_drafts=max_drafts,
            body_char_limit=body_char_limit,
        )
        return build_delivery_receipt(
            package,
            draft_id=draft_id,
            delivery_status=delivery_status,
            reason_code=reason_code,
            provider=provider,
            external_reference=external_reference,
            ack_private=ack_private,
            approval_receipt_path=Path(approvals_path).expanduser(),
            receipt_path=Path(delivery_path).expanduser(),
        )
    except (MailActionLedgerError, MailDraftPackageError, MailDraftApprovalError, MailDeliveryError) as e:
        raise RuntimeError(e.detail) from e


@mcp.tool(annotations={"read_only_hint": True})
def mail_evidence_review(
    history_path: str,
    evidence_id: str,
    ack_private: bool = False,
    body_char_limit: int = 6000,
    context_limit: int = 6,
) -> Dict[str, Any]:
    """Open a gated private source message for a redacted evidence id.

    This returns raw private sender, address, subject, snippet, and bounded body.
    It requires ``ack_private=True`` and never mutates the mailbox.
    """
    try:
        return build_evidence_review(
            Path(history_path).expanduser(),
            evidence_id,
            ack_private=ack_private,
            body_char_limit=body_char_limit,
            context_limit=context_limit,
        )
    except MailEvidenceReviewError as e:
        raise RuntimeError(e.detail) from e


def _triage(provider, query, limit, *, dry_run, remove_label, tier_routing,
            vip_only, account_api_key=None) -> TriageResponse:
    try:
        provider = validate_provider_name(provider)
        query = validate_search_query(query)
        limit = _clamp_limit(limit)
        remove_label = validate_mail_label(remove_label)
        if account_api_key is not None:
            account_api_key = validate_api_token(
                account_api_key, field="account_api_key"
            )
    except InputValidationError as e:
        raise RuntimeError(f"invalid input: {e}") from e

    account = None
    if not dry_run:
        if not account_api_key:
            raise RuntimeError("live triage requires account_api_key")
        account = get_store().get_account_by_api_key(account_api_key)  # allow-secret: var ref
        if account is None:
            raise RuntimeError("invalid account_api_key")

    actor = {"type": "mcp_tool", "tool": "triage"}
    auth = {"scheme": "mcp_account_api_key", "authenticated": account is not None}
    extra = None
    if account is not None:
        extra = {"account_id": account.get("id"), "plan": account.get("plan")}

    try:
        result = triage_runtime.run_triage_with_receipt(
            provider=provider, query=query, limit=limit,
            dry_run=dry_run, remove_label=remove_label,
            tier_routing=tier_routing, vip_only=vip_only, account=account,
            surface="mcp",
            actor=actor,
            auth=auth,
            extra=extra,
        )
    except metering.EntitlementExhausted as e:
        raise RuntimeError(str(e)) from e
    except service.ProviderUnavailable as e:
        # Already generic (raw provider error logged in the service layer).
        raise RuntimeError(str(e)) from e
    except service.AuditInvariantError as e:
        logger.critical("SAFETY GATE VIOLATION via MCP: %s", e)
        raise RuntimeError(
            "SAFETY GATE VIOLATION: a protected sender was moved out of the inbox; "
            "the run was rejected."
        ) from e
    return TriageResponse(**result)


# Hosted Streamable HTTP ASGI app. stateless_http + json_response suit a
# horizontally-scaled deploy. Serving at this app's root keeps the parent mount
# at /mcp (instead of accidentally exposing /mcp/mcp).
http_app = mcp.streamable_http_app(
    streamable_http_path="/",
    json_response=True,
    stateless_http=True,
    transport_security=_transport_security(),
)


def main() -> None:
    parser = argparse.ArgumentParser(prog="universal-mail-mcp")
    parser.add_argument(
        "--transport", choices=["stdio", "streamable-http", "sse"], default="stdio"
    )
    args = parser.parse_args()
    if args.transport == "streamable-http":
        mcp.run(
            transport="streamable-http",
            streamable_http_path="/",
            json_response=True,
            stateless_http=True,
            transport_security=_transport_security(),
        )
    elif args.transport == "sse":
        mcp.run(transport="sse", transport_security=_transport_security())
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
