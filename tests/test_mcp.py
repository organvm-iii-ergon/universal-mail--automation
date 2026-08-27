"""Tests for the MCP server tool surface (mcp_server/).

Skipped where the optional ``mcp`` SDK is not installed so a core-only install
can still run the rest of the suite.
"""

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from fastapi.testclient import TestClient  # noqa: E402
from mcp.client import Client  # noqa: E402
from mcp.types import TextContent  # noqa: E402
from mcp.types.version import LATEST_HANDSHAKE_VERSION  # noqa: E402

from mcp_server.server import (  # noqa: E402
    check_protected_sender,
    mail_action_ledger,
    mail_action_plan,
    mail_action_receipt,
    mail_provider_surface_plan,
    mail_resolver_plan,
    mail_resolver_ledger,
    mail_resolver_receipt,
    mail_draft_approval,
    mail_draft_approvals,
    mail_draft_package,
    mail_delivery_ledger,
    mail_delivery_receipt,
    mail_evidence_review,
    mail_external_resolver,
    mail_external_resolver_receipts,
    mail_followup_resolver,
    mail_followup_resolver_receipts,
    mail_github_resolver,
    mail_github_resolver_receipts,
    mail_history_export,
    mail_intelligence,
    mcp,
    triage,
    triage_preview,
)
from api import metering, service  # noqa: E402
from api.store import get_store  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _tools():
    return asyncio.run(mcp.list_tools())


def _clean_triage_result():
    return {
        "dry_run": False,
        "provider": "fake",
        "receipt": "Triage receipt: 1 message(s) -- gate held.",
        "audit": {
            "total": 1,
            "protected_held": 0,
            "archived": 1,
            "moved": 0,
            "labeled": 0,
            "kept": 0,
            "violations": [],
        },
        "processed": {"processed_count": 1},
    }


def test_tools_registered():
    names = {t.name for t in _tools()}
    assert {
        "check_protected_sender",
        "triage_preview",
        "triage",
        "mail_action_ledger",
        "mail_action_plan",
        "mail_action_receipt",
        "mail_provider_surface_plan",
        "mail_resolver_plan",
        "mail_resolver_ledger",
        "mail_resolver_receipt",
        "mail_draft_approval",
        "mail_draft_approvals",
        "mail_draft_package",
        "mail_delivery_ledger",
        "mail_delivery_receipt",
        "mail_evidence_review",
        "mail_external_resolver",
        "mail_external_resolver_receipts",
        "mail_followup_resolver",
        "mail_followup_resolver_receipts",
        "mail_github_resolver",
        "mail_github_resolver_receipts",
        "mail_history_export",
        "mail_intelligence",
    } <= names


def test_tools_expose_output_schemas():
    # Pydantic return types give agents machine-checkable verdicts.
    for t in _tools():
        assert t.output_schema


def test_triage_is_marked_destructive_others_readonly():
    by_name = {t.name: t for t in _tools()}
    assert by_name["check_protected_sender"].annotations.read_only_hint is True
    assert by_name["triage_preview"].annotations.read_only_hint is True
    assert by_name["mail_intelligence"].annotations.read_only_hint is True
    assert by_name["mail_action_plan"].annotations.read_only_hint is True
    assert by_name["mail_provider_surface_plan"].annotations.read_only_hint is True
    assert by_name["mail_resolver_plan"].annotations.read_only_hint is True
    assert by_name["mail_resolver_ledger"].annotations.read_only_hint is True
    assert by_name["mail_github_resolver"].annotations.read_only_hint is True
    assert by_name["mail_action_ledger"].annotations.read_only_hint is True
    assert by_name["mail_draft_package"].annotations.read_only_hint is True
    assert by_name["mail_draft_approvals"].annotations.read_only_hint is True
    assert by_name["mail_delivery_ledger"].annotations.read_only_hint is True
    assert by_name["mail_evidence_review"].annotations.read_only_hint is True
    assert by_name["mail_history_export"].annotations.destructive_hint is False
    assert by_name["mail_resolver_receipt"].annotations.destructive_hint is False
    assert by_name["mail_action_receipt"].annotations.destructive_hint is False
    assert by_name["mail_draft_approval"].annotations.destructive_hint is False
    assert by_name["mail_delivery_receipt"].annotations.destructive_hint is False
    assert by_name["triage"].annotations.destructive_hint is True


def test_mcp_v2_in_process_client_lists_and_calls_safe_tool():
    async def exercise():
        async with Client(mcp) as client:
            listed = await client.list_tools()
            assert "check_protected_sender" in {tool.name for tool in listed.tools}

            result = await client.call_tool(
                "check_protected_sender",
                {"sender": "clerk@courts.ca.gov", "subject": "Case notice"},
            )

        assert result.is_error is False
        assert result.structured_content is not None
        assert result.structured_content["protected"] is True
        assert len(result.content) == 1
        assert isinstance(result.content[0], TextContent)

    asyncio.run(exercise())


def test_mcp_v2_streamable_http_is_mounted_once_at_mcp():
    from api.app import app

    headers = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "mcp-protocol-version": LATEST_HANDSHAKE_VERSION,
    }
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": LATEST_HANDSHAKE_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "0"},
        },
    }

    with TestClient(app, base_url="http://localhost:8000") as client:
        response = client.post("/mcp", headers=headers, json=initialize)
        nested_response = client.post("/mcp/mcp", headers=headers, json=initialize)

    assert response.status_code == 200
    assert response.json()["result"]["serverInfo"]["name"] == "universal-mail"
    assert nested_response.status_code == 404


def test_check_protected_sender_delegates():
    assert check_protected_sender("clerk@courts.ca.gov").protected is True
    assert check_protected_sender("news@deals-promo.example").protected is False


def test_check_protected_sender_rejects_header_controls():
    with pytest.raises(RuntimeError) as ei:
        check_protected_sender("alerts@example.com\r\nbcc: victim@example.com")
    assert "invalid input" in str(ei.value)


def test_triage_rejects_malformed_provider_before_service(monkeypatch):
    called = {"run": False}

    def run(**_kwargs):
        called["run"] = True
        return _clean_triage_result()

    monkeypatch.setattr(service, "run_triage", run)
    with pytest.raises(RuntimeError) as ei:
        triage_preview(provider="../gmail")
    assert "invalid input" in str(ei.value)
    assert called["run"] is False


def test_triage_audit_violation_is_generic(monkeypatch):
    def boom(**kwargs):
        raise service.AuditInvariantError("msg-7 protected sender leaked id")

    monkeypatch.setattr(service, "run_triage", boom)
    acct = get_store().create_account(plan="free")
    with pytest.raises(RuntimeError) as ei:
        triage(dry_run=False, account_api_key=acct["api_key"])
    assert "SAFETY GATE VIOLATION" in str(ei.value)
    assert "msg-7" not in str(ei.value)  # internal id never leaks to the agent


def test_live_triage_requires_account_key(monkeypatch):
    called = {"run": False}

    def run(**_kwargs):
        called["run"] = True
        return _clean_triage_result()

    monkeypatch.setattr(service, "run_triage", run)

    with pytest.raises(RuntimeError) as ei:
        triage(dry_run=False)

    assert "account_api_key" in str(ei.value)
    assert called["run"] is False


def test_live_triage_uses_mcp_account_entitlement(monkeypatch):
    monkeypatch.setattr(service, "run_triage", lambda **_kwargs: _clean_triage_result())
    store = get_store()
    acct = store.create_account(plan="free")

    result = triage(dry_run=False, provider="fake", account_api_key=acct["api_key"])

    assert result.run_id.startswith("run_")
    assert result.packet.schema == "uma.intake.packet.v1"
    assert store.get_usage_count(acct["id"], metering.current_period_key()) == 1


def test_live_triage_uses_credit_after_monthly_cap(monkeypatch):
    monkeypatch.setattr(service, "run_triage", lambda **_kwargs: _clean_triage_result())
    store = get_store()
    acct = store.create_account(plan="free", run_credits=1)
    period = metering.current_period_key()
    for _ in range(50):
        assert store.reserve_live_run(acct["id"], period, cap=50) is True

    triage(dry_run=False, provider="fake", account_api_key=acct["api_key"])

    assert store.get_account(acct["id"])["run_credits"] == 0
    assert store.get_usage_count(acct["id"], period) == 50


def test_triage_provider_unavailable_maps_to_error(monkeypatch):
    def boom(**kwargs):
        raise service.ProviderUnavailable("provider is not available")

    monkeypatch.setattr(service, "run_triage", boom)
    with pytest.raises(RuntimeError):
        triage_preview()


def test_mail_intelligence_mcp_tool_is_read_only_and_redacted():
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"

    result = mail_intelligence(str(history), stale_days=14)

    payload = str(result)
    assert result["schema"] == "uma.mail.intelligence.v1"
    assert result["mode"]["read_only"] is True
    assert result["mode"]["mailbox_mutations"] is False
    assert result["kpis"]["opportunities"] == 1
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_history_export_mcp_tool_returns_receipt_not_raw_mail(tmp_path):
    source = tmp_path / "history.json"
    output = tmp_path / "latest.json"
    source.write_text(
        (
            '{"messages":[{"sender":"Private Client <private-client@example.test>",'
            '"subject":"Private client work","body":"Could you review this opportunity?",'
            '"received_at":"2026-05-10T12:00:00Z"}]}'
        ),
        encoding="utf-8",
    )

    receipt = mail_history_export(str(source), str(output), source_type="json")

    payload = str(receipt)
    assert receipt["schema"] == "uma.mail.history_export.receipt.v1"
    assert receipt["output"]["message_count"] == 1
    assert output.exists()
    assert "Private Client" not in payload
    assert "private-client@example.test" not in payload
    assert "review this opportunity" not in payload


def test_mail_action_plan_mcp_tool_is_read_only_and_redacted(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")

    result = mail_action_plan(str(intelligence), max_items=4)

    payload = str(result)
    assert result["schema"] == "uma.mail.action_plan.v1"
    assert result["mode"]["read_only"] is True
    assert result["mode"]["mailbox_mutations"] is False
    assert result["kpis"]["send_allowed"] == 0
    assert len(result["items"]) <= 4
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_resolver_plan_mcp_tool_is_read_only_and_redacted(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")

    result = mail_resolver_plan(str(intelligence), max_items=3)

    payload = str(result)
    assert result["schema"] == "uma.mail.resolver_plan.v1"
    assert result["mode"]["read_only"] is True
    assert result["mode"]["mailbox_mutations"] is False
    assert result["mode"]["sends"] is False
    assert result["kpis"]["github_reconcile"] == 1
    assert result["kpis"]["send_allowed"] == 0
    assert len(result["items"]) <= 3
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_provider_surface_plan_mcp_tool_is_read_only_and_redacted(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")

    result = mail_provider_surface_plan(str(intelligence), max_items=5)

    payload = str(result)
    assert result["schema"] == "uma.provider.surface_plan.v1"
    assert result["mode"]["read_only"] is True
    assert result["mode"]["provider_backed_automation"] is False
    assert result["kpis"]["send_allowed"] == 0
    assert result["privacy"]["provider_hints_are_controlled_slugs"] is True
    assert len(result["items"]) <= 5
    assert any(item["provider"] == "github" for item in result["items"])
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_resolver_receipt_mcp_tools_record_redacted_attestations(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    ledger_path = tmp_path / "resolver-ledger.jsonl"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")
    plan = mail_resolver_plan(str(intelligence), max_items=10)
    action_id = next(item["action_id"] for item in plan["items"] if item["kind"] == "github_work")

    receipt = mail_resolver_receipt(
        str(intelligence),
        str(ledger_path),
        action_id,
        "verified_resolved",
        "github_reconciled",
        "github_issue_pr_billing_or_security_state",
        provider="github",
        external_reference="raw-provider-id-123",
    )
    ledger = mail_resolver_ledger(str(intelligence), str(ledger_path), max_items=3)

    payload = str(ledger)
    assert receipt["schema"] == "uma.mail.resolver_receipt.v1"
    assert receipt["safety"]["provider_backed_automation"] is False
    assert receipt["safety"]["send_allowed"] is False
    assert ledger["schema"] == "uma.mail.resolver_ledger.v1"
    assert ledger["kpis"]["verified_resolved"] == 1
    assert ledger["kpis"]["provider_backed_receipts"] == 0
    assert "raw-provider-id-123" not in payload
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_github_resolver_mcp_tool_is_read_only_and_redacted(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")

    result = mail_github_resolver(str(intelligence), include_provider_queries=False, max_items=5)
    payload = str(result)

    assert result["schema"] == "uma.github.resolver_snapshot.v1"
    assert result["mode"]["read_only"] is True
    assert result["mode"]["provider_backed_automation"] is False
    assert result["mode"]["mailbox_mutations"] is False
    assert result["status"] == "planned_only"
    assert result["kpis"]["planned_github_actions"] == 1
    assert result["kpis"]["send_allowed"] == 0
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_github_resolver_receipts_mcp_tool_records_no_proof_when_queries_skipped(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    ledger_path = tmp_path / "github-resolver-ledger.jsonl"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")

    result = mail_github_resolver_receipts(
        str(intelligence),
        str(ledger_path),
        include_provider_queries=False,
        max_items=5,
    )
    payload = str(result)

    assert result["schema"] == "uma.github.resolver_receipts.v1"
    assert result["status"] == "no_receipts_recorded"
    assert result["kpis"]["receipt_candidates"] == 0
    assert result["kpis"]["receipts_recorded"] == 0
    assert result["kpis"]["provider_backed_automation"] == 0
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_followup_resolver_mcp_tools_are_redacted_and_record_no_empty_proof(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    approvals = tmp_path / "approvals.jsonl"
    delivery = tmp_path / "delivery.jsonl"
    resolver_ledger = tmp_path / "resolver-ledger.jsonl"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")

    snapshot = mail_followup_resolver(str(intelligence), str(approvals), str(delivery), max_items=5)
    result = mail_followup_resolver_receipts(
        str(intelligence),
        str(resolver_ledger),
        str(approvals),
        str(delivery),
        max_items=5,
    )
    payload = str({"snapshot": snapshot, "result": result})

    assert snapshot["schema"] == "uma.followup.resolver_snapshot.v1"
    assert snapshot["mode"]["read_only"] is True
    assert snapshot["mode"]["provider_backed_automation"] is False
    assert snapshot["kpis"]["planned_followup_actions"] == 1
    assert snapshot["kpis"]["recordable_receipt_candidates"] == 0
    assert result["schema"] == "uma.followup.resolver_receipts.v1"
    assert result["status"] == "no_receipts_recorded"
    assert result["kpis"]["receipts_recorded"] == 0
    assert result["kpis"]["provider_backed_automation"] == 0
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_external_resolver_mcp_tools_require_explicit_attestation(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    resolver_ledger = tmp_path / "resolver-ledger.jsonl"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")

    snapshot = mail_external_resolver(str(intelligence), str(resolver_ledger), max_items=3)
    noop = mail_external_resolver_receipts(
        str(intelligence),
        str(resolver_ledger),
        max_items=3,
        max_receipts=3,
    )
    attested = mail_external_resolver_receipts(
        str(intelligence),
        str(resolver_ledger),
        max_items=2,
        max_receipts=2,
        attest_blockers=True,
    )
    payload = str({"snapshot": snapshot, "noop": noop, "attested": attested})

    assert snapshot["schema"] == "uma.external.resolver_snapshot.v1"
    assert snapshot["mode"]["read_only"] is True
    assert snapshot["mode"]["provider_backed_read"] is False
    assert snapshot["mode"]["provider_backed_automation"] is False
    assert snapshot["kpis"]["recordable_receipt_candidates"] == 0
    assert noop["schema"] == "uma.external.resolver_receipts.v1"
    assert noop["status"] == "no_receipts_recorded"
    assert noop["kpis"]["receipts_recorded"] == 0
    assert attested["schema"] == "uma.external.resolver_receipts.v1"
    assert attested["status"] == "recorded"
    assert attested["kpis"]["receipts_recorded"] == 2
    assert attested["kpis"]["provider_backed_automation"] == 0
    assert all(receipt["safety"]["provider_backed_read"] is False for receipt in attested["receipts"])
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_action_ledger_mcp_tools_record_redacted_receipts(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    ledger_path = tmp_path / "ledger.jsonl"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")
    plan = mail_action_plan(str(intelligence), max_items=4)
    action_id = plan["items"][0]["id"]

    receipt = mail_action_receipt(
        str(intelligence),
        str(ledger_path),
        action_id,
        "waiting",
        "awaiting_reply",
    )
    ledger = mail_action_ledger(str(intelligence), str(ledger_path), max_items=4)

    payload = str(ledger)
    assert receipt["schema"] == "uma.mail.action_receipt.v1"
    assert receipt["safety"]["send_allowed"] is False
    assert ledger["schema"] == "uma.mail.action_ledger.v1"
    assert ledger["mode"]["mailbox_mutations"] is False
    assert ledger["kpis"]["waiting"] == 1
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_draft_package_mcp_requires_ack_before_private_draft(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")
    plan = mail_action_plan(str(intelligence), max_items=4)
    action_id = next(item["id"] for item in plan["items"] if item["kind"] == "missed_lead")

    with pytest.raises(RuntimeError) as denied:
        mail_draft_package(str(intelligence), str(history), action_id)
    assert "ack_private=true" in str(denied.value)

    result = mail_draft_package(str(intelligence), str(history), action_id, ack_private=True, max_drafts=1)

    assert result["schema"] == "uma.mail.draft_package.v1"
    assert result["mode"]["draft_only"] is True
    assert result["safety"]["send_allowed"] is False
    assert result["drafts"][0]["to"]["name"] == "Private Recruiter"


def test_mail_draft_approval_mcp_records_redacted_receipt(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    approvals = tmp_path / "approvals.jsonl"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")
    plan = mail_action_plan(str(intelligence), max_items=4)
    action_id = next(item["id"] for item in plan["items"] if item["kind"] == "missed_lead")
    package = mail_draft_package(str(intelligence), str(history), action_id, ack_private=True, max_drafts=1)
    draft_id = package["drafts"][0]["draft_id"]

    with pytest.raises(RuntimeError) as denied:
        mail_draft_approval(
            str(intelligence),
            str(history),
            str(approvals),
            action_id,
            draft_id,
            "approved",
            "ready_to_send",
        )
    assert "ack_private=true" in str(denied.value)

    receipt = mail_draft_approval(
        str(intelligence),
        str(history),
        str(approvals),
        action_id,
        draft_id,
        "approved",
        "ready_to_send",
        ack_private=True,
    )
    ledger = mail_draft_approvals(str(intelligence), str(history), str(approvals), action_id, ack_private=True)

    payload = str(ledger)
    assert receipt["schema"] == "uma.mail.draft_approval_receipt.v1"
    assert receipt["safety"]["send_allowed"] is False
    assert ledger["schema"] == "uma.mail.draft_approval_ledger.v1"
    assert ledger["kpis"]["approved"] == 1
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload


def test_mail_delivery_mcp_records_redacted_receipt(tmp_path):
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = tmp_path / "latest-intelligence.json"
    approvals = tmp_path / "approvals.jsonl"
    delivery = tmp_path / "delivery.jsonl"
    intelligence.write_text(json.dumps(mail_intelligence(str(history))), encoding="utf-8")
    plan = mail_action_plan(str(intelligence), max_items=4)
    action_id = next(item["id"] for item in plan["items"] if item["kind"] == "missed_lead")
    package = mail_draft_package(str(intelligence), str(history), action_id, ack_private=True, max_drafts=1)
    draft_id = package["drafts"][0]["draft_id"]

    with pytest.raises(RuntimeError) as unapproved:
        mail_delivery_receipt(
            str(intelligence),
            str(history),
            str(approvals),
            str(delivery),
            action_id,
            draft_id,
            "provider_draft_requested",
            "approved_for_provider_draft",
            ack_private=True,
        )
    assert "approved draft approval receipt" in str(unapproved.value)

    mail_draft_approval(
        str(intelligence),
        str(history),
        str(approvals),
        action_id,
        draft_id,
        "approved",
        "ready_to_send",
        ack_private=True,
    )
    receipt = mail_delivery_receipt(
        str(intelligence),
        str(history),
        str(approvals),
        str(delivery),
        action_id,
        draft_id,
        "provider_draft_requested",
        "approved_for_provider_draft",
        ack_private=True,
        provider="gmail",
        external_reference="raw-provider-id-123",
    )
    ledger = mail_delivery_ledger(
        str(intelligence),
        str(history),
        str(approvals),
        str(delivery),
        action_id,
        ack_private=True,
    )

    payload = str(ledger)
    assert receipt["schema"] == "uma.mail.delivery_receipt.v1"
    assert receipt["safety"]["uma_sent_message"] is False
    assert ledger["schema"] == "uma.mail.delivery_ledger.v1"
    assert ledger["kpis"]["provider_draft_requested"] == 1
    assert "Private Recruiter" not in payload
    assert "private-recruiter@example.test" not in payload
    assert "raw-provider-id-123" not in payload


def test_mail_evidence_review_mcp_requires_ack_before_private_source():
    history = ROOT / "tests" / "fixtures" / "historical" / "latest.json"
    intelligence = mail_intelligence(str(history))
    evidence_id = intelligence["opportunities"][0]["evidence_ids"][0]

    with pytest.raises(RuntimeError) as denied:
        mail_evidence_review(str(history), evidence_id)
    assert "ack_private=true" in str(denied.value)

    result = mail_evidence_review(str(history), evidence_id, ack_private=True, body_char_limit=40)

    assert result["schema"] == "uma.mail.evidence_review.v1"
    assert result["mode"]["read_only"] is True
    assert result["mode"]["mailbox_mutations"] is False
    assert result["message"]["sender"] == "Private Recruiter"
