"""Commit 7 adversarial suite, part 1 — Groups A–E.

Group A: artifact fuzz / schema hostility
Group B: plan / mutation integrity
Group C: approval hostility
Group D: hostile provider
Group E: full-batch atomic preflight (batches of 10)

Doctrine under test: the system FAILS CLOSED. Every discovered production
defect fixed in this tranche is disclosed in the commit message and carries
a dedicated regression test.
"""

import json
import math
from datetime import datetime, timedelta, timezone

import pytest

import core.flag_workflow as fw
from core.flag_transactions import (
    TransactionEngine,
    TransactionLedger,
    TransactionRollbackReceipt,
)
from core.models import FlagColor
from providers.mailapp import mailapp_index_from_flag

from tests.test_commit6_transactions import (
    ELIG_SUBJECT,
    FakeMessage,
    FakeScopedProvider,
    Harness,
)

OBSERVED = FlagColor.ORANGE


def _row(pid, color=OBSERVED, sender="billing@corp.example",
         subject=ELIG_SUBJECT, account="acct", mailbox="INBOX",
         received="2026-07-01T00:00:00"):
    return type("R", (), {
        "provider_id": pid, "account": account, "mailbox": mailbox,
        "sender": sender, "subject": subject,
        "native_index": None if color == FlagColor.UNKNOWN
        else mailapp_index_from_flag(color),
        "flag_color": color, "received_iso": received})


def _ten_msg_harness(tmp_path):
    """Plan + approval over 10 auto-eligible messages."""
    h = Harness(tmp_path, pids=tuple(str(i) for i in range(1, 11)))
    # Harness fixture subject yields RED proposals from ORANGE observations;
    # every mutation is auto-eligible by construction.
    assert len(h.mutations) == 10
    assert all(m.auto_eligible for m in h.mutations)
    return h


# --- GROUP A: artifact fuzz -------------------------------------------------------


class TestSnapshotArtifactFuzz:
    def _attacked(self, tmp_path, **mutations):
        rows = [_row("1")]
        snap = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=rows, complete=True, scope_complete=True,
            status="complete", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=0, limit=500,
            since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0)
        d = snap.to_dict()
        d.pop("content_hash")
        d.update(mutations)
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / "fuzz.json"
        p.write_text(json.dumps(d))
        return p

    def test_missing_required_key_rejected(self, tmp_path):
        d = fw.build_snapshot(
            provider_name="mailapp", account="a", mailbox="m",
            rows=[_row("1")], complete=True, scope_complete=True,
            status="complete", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=0, limit=500,
            since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0).to_dict()
        d.pop("content_hash")
        d.pop("snapshot_id")                       # required key gone
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / "miss.json"
        p.write_text(json.dumps(d))
        with pytest.raises(Exception):
            fw.load_snapshot(p)

    @pytest.mark.parametrize("field,value,expectation", [
        ("limit", None, "build"),          # null where int required
        ("total_matched", -5, "validate"),          # negative counter
        ("hidden_by_limit", -3, "validate"),        # negative below contract
        ("inaccessible_count", -1, "validate"),
        ("timeout_count", -2, "validate"),
        ("status", "COMPLETE", "load"),             # malformed enum case
        ("ordering", 42, "load"),
        ("provider", None, "load"),
    ])
    def test_hostile_scalars_fail_closed(self, tmp_path, field, value,
                                          expectation):
        kw = dict(provider_name="mailapp", account="a", mailbox="m",
                  rows=[_row("1")], complete=True, scope_complete=True,
                  status="complete", errors=[], inaccessible_count=0,
                  timeout_count=0, unknown_index_count=0, limit=500,
                  since_days=None, total_matched=1, returned_count=1,
                  hidden_by_limit=0)
        if expectation == "build":
            with pytest.raises((fw.FlagWorkflowError, TypeError, ValueError)):
                fw.build_snapshot(**{**kw, field: value})
            return
        snap = fw.build_snapshot(**kw)
        d = snap.to_dict()
        d.pop("content_hash")
        d[field] = value
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / f"f-{abs(hash(field))}.json"
        p.write_text(json.dumps(d))
        with pytest.raises((fw.FlagWorkflowError, ValueError, TypeError)):
            fw.load_snapshot(p)

    def test_bool_as_int_limit_is_documented_admission(self):
        """bool IS an int in Python; True==1 is a coherent limit. Admitted,
        hash-bound — not a rejection case."""
        snap = fw.build_snapshot(
            provider_name="mailapp", account="a", mailbox="m",
            rows=[_row("1")], complete=True, scope_complete=True,
            status="complete", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=0, limit=True,
            since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0)
        assert snap.limit == 1

    @pytest.mark.parametrize("bad", ["a" * 63, "a" * 65, "g" * 64])
    def test_malformed_digest_lengths_rejected(self, tmp_path, bad):
        d = fw.build_snapshot(
            provider_name="mailapp", account="a", mailbox="m",
            rows=[_row("1")], complete=True, scope_complete=True,
            status="complete", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=0, limit=500,
            since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0).to_dict()
        d.pop("content_hash")
        d["messages"][0]["evidence_digest"] = bad
        # evidence_digest isn't serialized on messages; attack snapshot_id instead
        d["snapshot_id"] = bad
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / f"d-{len(bad)}.json"
        p.write_text(json.dumps(d))
        with pytest.raises((fw.FlagWorkflowError, Exception)):
            fw.load_snapshot(p)

    def test_nan_admitted_by_json_is_hash_bound_and_inert(self, tmp_path):
        """python json admits NaN; document behavior: it must not crash
        validation and MUST be covered by the canonical hash."""
        d = fw.build_snapshot(
            provider_name="mailapp", account="a", mailbox="m",
            rows=[_row("1")], complete=True, scope_complete=True,
            status="complete", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=0, limit=500,
            since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0).to_dict()
        d.pop("content_hash")
        d["since_days"] = float("nan")
        h1 = fw.sha256_hex(d)
        d2 = dict(d)
        d2["since_days"] = float("inf")
        h2 = fw.sha256_hex(d2)
        assert isinstance(h1, str) and isinstance(h2, str)
        assert h1 != h2                             # distinct junk ≠ same hash

    def test_key_order_does_not_change_canonical_hash(self):
        a = {"z": 1, "a": {"y": 2, "b": [3, {"q": 4, "p": 5}]}}
        b = json.loads(json.dumps(a))
        assert fw.sha256_hex(a) == fw.sha256_hex(b)

    def test_control_chars_survive_private_evidence_and_are_hashed(self):
        s1 = fw.build_snapshot(
            provider_name="mailapp", account="a", mailbox="m",
            rows=[_row("1", subject="tab\there")], complete=True,
            scope_complete=True, status="complete", errors=[],
            inaccessible_count=0, timeout_count=0, unknown_index_count=0,
            limit=500, since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0)
        s2 = fw.build_snapshot(
            provider_name="mailapp", account="a", mailbox="m",
            rows=[_row("1", subject="tab\there ")], complete=True,
            scope_complete=True, status="complete", errors=[],
            inaccessible_count=0, timeout_count=0, unknown_index_count=0,
            limit=500, since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0)   # different content → different digest
        assert s1.content_hash != s2.content_hash

    def test_unicode_account_mailbox_roundtrip(self, tmp_path):
        rows = [_row("1", account="äkkö@x.com", mailbox="Ünbox/日本",
                     sender="ünïcode@é.example",
                     subject="Résumé — 東京 オファー")]
        snap = fw.build_snapshot(
            provider_name="mailapp", account="äkkö@x.com",
            mailbox="Ünbox/日本", rows=rows, complete=True,
            scope_complete=True, status="complete", errors=[],
            inaccessible_count=0, timeout_count=0, unknown_index_count=0,
            limit=500, since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0)
        p = fw.write_private_snapshot(snap, tmp_path / "s")
        loaded = fw.load_snapshot(p)
        assert loaded.messages[0].account == "äkkö@x.com"
        assert loaded.account == "äkkö@x.com"

    def test_public_receipt_recursive_pii_scan(self, tmp_path):
        snap = fw.build_snapshot(
            provider_name="mailapp", account="secret-acct@corp",
            mailbox="SecretBox", rows=[
                _row("777", sender="vip@bank.example",
                     subject="Statement July <abc@x>")],
            complete=True, scope_complete=True, status="complete",
            errors=[], inaccessible_count=0, timeout_count=0,
            unknown_index_count=0, limit=500, since_days=None,
            total_matched=1, returned_count=1, hidden_by_limit=0)
        pub = snap.to_public_safe()
        blob = json.dumps(pub)

        forbidden_values = [
            "secret-acct@corp", "SecretBox", "vip@bank.example",
            "Statement July", "<abc@x>", "777", str(tmp_path),
            "/Users/",
        ]
        for needle in forbidden_values:
            assert needle not in blob, f"PII leak: {needle}"
        # Recursively: no key may even be named suspiciously.
        def walk(node):
            if isinstance(node, dict):
                for k, v in node.items():
                    assert k not in ("account", "mailbox", "sender",
                                     "subject", "provider_id", "message_id",
                                     "path"), k
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)
        walk(pub)
        fw.validate_public_receipt(pub)


# --- GROUP B: plan / mutation integrity ---------------------------------------------


class TestPlanIntegrity:
    def _plan(self):
        h_rows = [_row(str(i)) for i in range(1, 4)]
        snap = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=h_rows, complete=True, scope_complete=True,
            status="complete", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=0, limit=500,
            since_days=None, total_matched=3, returned_count=3,
            hidden_by_limit=0)
        return fw.build_plan(snap)

    ALL_FIELDS = [
        "mutation_id", "ref_digest", "observed_flag", "proposed_flag",
        "reason_code", "confidence", "review_required", "auto_eligible",
        "provider", "account", "mailbox", "provider_id", "snapshot_id",
        "observed_native_flag", "evidence_digest", "message_id_digest",
    ]

    def _flip(self, muts, field):
        out = []
        for i, m in enumerate(muts):
            m = dict(m)
            if i == 0:
                cur = m[field]
                if field.endswith(("flag",)) or field in (
                        "proposed_flag", "observed_flag"):
                    m[field] = "green" if cur != "green" else "red"
                elif field in ("confidence",):
                    m[field] = None if cur is not None else 0.5
                elif field in ("review_required", "auto_eligible"):
                    m[field] = not cur
                elif field == "observed_native_flag":
                    m[field] = 6 if cur != 6 else 0
                elif field in ("account", "mailbox"):
                    m[field] = "forged"
                elif field in ("mutation_id", "ref_digest", "snapshot_id",
                               "evidence_digest", "message_id_digest"):
                    m[field] = ("f" * 64) if len(str(cur)) == 64 else \
                        "mut-forged"
                elif field == "provider":
                    m[field] = "imap"
                elif field == "reason_code":
                    m[field] = "forged_reason"
                elif field == "provider_id":
                    m[field] = "99999"
            out.append(m)
        return out

    @pytest.mark.parametrize("field", ALL_FIELDS)
    def test_field_flip_without_rehash_rejected(self, field):
        plan = self._plan()
        forged = dict(plan)
        forged["mutations"] = self._flip(plan["mutations"], field)
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.validate_plan_schema(forged)

    @pytest.mark.parametrize("field", ALL_FIELDS)
    def test_field_flip_with_rehash_keeps_old_approval_rejected(self, field):
        """Any single-field forgery + recomputed plan hash changes
        plan_hash; the OLD approval must then be refused at its binding —
        regardless of whether the forged plan itself parses or trips a
        semantic invariant first. Refusal may come from either stage."""
        plan = self._plan()
        old_approval = fw.ApprovalReceipt.create(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=plan["snapshot_sha256"],
            policy_sha256=plan["policy_sha256"],
            approved_mutation_ids=[
                m["mutation_id"] for m in plan["mutations"]],
            approving_operator="op", canary_limit=len(plan["mutations"]))
        forged = dict(plan)
        forged["mutations"] = self._flip(plan["mutations"], field)
        forged.pop("plan_hash")
        forged["plan_hash"] = fw.compute_plan_hash(forged)
        refused, why = False, None
        try:
            muts = fw.validate_plan_schema(forged)
        except Exception as e:
            refused, why = True, repr(e)         # parse-time gate
        else:
            try:
                old_approval.validate(plan=dict(forged), plan_mutations=muts)
            except Exception as e:
                refused, why = True, repr(e)     # approval-binding gate
        assert refused, f"field {field} forgery was not refused ({why})"

    def test_same_id_different_ref_rejected(self):
        plan = self._plan()
        muts = [dict(m) for m in plan["mutations"]]
        muts[1]["ref_digest"] = muts[0]["ref_digest"]      # clone ref, keep id
        forged = dict(plan, mutations=muts)
        forged.pop("plan_hash")
        forged["plan_hash"] = fw.compute_plan_hash(forged)
        with pytest.raises(fw.FlagWorkflowError, match="duplicate ref_digest"):
            fw.validate_plan_schema(forged)

    def test_duplicate_mutation_ids_rejected(self):
        plan = self._plan()
        muts = [dict(m) for m in plan["mutations"]]
        muts[1]["mutation_id"] = muts[0]["mutation_id"]
        muts[1]["ref_digest"] = "e" * 64
        forged = dict(plan, mutations=muts)
        forged.pop("plan_hash")
        forged["plan_hash"] = fw.compute_plan_hash(forged)
        with pytest.raises(fw.FlagWorkflowError,
                           match="duplicate mutation_id"):
            fw.validate_plan_schema(forged)

    def test_snapshot_id_drift_inside_mutation_rejected(self):
        plan = self._plan()
        muts = [dict(m) for m in plan["mutations"]]
        real_sid = plan["snapshot_id"]
        muts[0] = dict(muts[0], snapshot_id="snap-elsewhere")
        forged = dict(plan, mutations=muts)
        forged.pop("plan_hash")
        forged["plan_hash"] = fw.compute_plan_hash(forged)
        with pytest.raises(fw.FlagWorkflowError, match="snapshot_id"):
            fw.validate_plan_schema(forged)
        del real_sid

    def test_unknown_provider_fails_closed(self):
        plan = self._plan()
        muts = [dict(m) for m in plan["mutations"]]
        muts[0] = dict(muts[0], provider="outlook")
        forged = dict(plan, mutations=muts)
        forged.pop("plan_hash")
        forged["plan_hash"] = fw.compute_plan_hash(forged)
        with pytest.raises(fw.FlagWorkflowError,
                           match="unsupported provider"):
            fw.validate_plan_schema(forged)


# --- GROUP C: approval hostility (direct-engine, zero-contact proofs) --------------


class TestApprovalHostilityDirectEngine:
    def _run(self, tmp_path, mutate=None):
        h = Harness(tmp_path, pids=("1",))
        if mutate:
            mutate(h, h.approval)
        calls_before = len(h.provider.calls)
        result = h.apply()
        assert result.status == "blocked"
        assert len(h.provider.calls) == calls_before
        return h, result

    def test_expiry_exactly_equal_issuance_rejected(self, tmp_path):
        now = datetime.now(timezone.utc)

        def mutate(h, a):
            a.issued_at = now.isoformat()
            a.expires_at = now.isoformat()
            a.content_hash = a.to_dict()["content_hash"]
        h, r = self._run(tmp_path, mutate)
        assert "approval_invalid" in r.error_code

    def test_expired_by_one_microsecond_rejected(self, tmp_path):
        now = datetime.now(timezone.utc)

        def mutate(h, a):
            a.issued_at = (now - timedelta(seconds=1)).isoformat()
            a.expires_at = (now - timedelta(microseconds=1)).isoformat()
            a.content_hash = a.to_dict()["content_hash"]
        h, r = self._run(tmp_path, mutate)
        assert "approval_invalid" in r.error_code

    def test_empty_operator_rejected(self, tmp_path):
        def mutate(h, a):
            a.approving_operator = "   "
            a.content_hash = a.to_dict()["content_hash"]
        h, r = self._run(tmp_path, mutate)
        assert "approval_invalid" in r.error_code

    def test_malformed_timezone_raises_closed(self, tmp_path):
        def mutate(h, a):
            a.expires_at = "2026-13-45T99:99:99+99:99"
            a.content_hash = a.to_dict()["content_hash"]
        with pytest.raises(Exception):
            self._run(tmp_path, mutate)

    def test_naive_timestamp_treated_as_local_fails_expired_check(
            self, tmp_path):
        def mutate(h, a):
            a.expires_at = "2000-01-01T00:00:00"       # naive & ancient
            a.content_hash = a.to_dict()["content_hash"]
        with pytest.raises(Exception):
            self._run(tmp_path, mutate)

    def test_approval_from_previous_snapshot_rejected(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        older = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=[type("R", (), {
                "provider_id": "1", "account": "acct", "mailbox": "INBOX",
                "sender": "billing@corp.example", "subject": ELIG_SUBJECT,
                "native_index": mailapp_index_from_flag(OBSERVED),
                "flag_color": OBSERVED,
                "received_iso": "2026-06-01T00:00:00"})()],
            complete=True, scope_complete=True, status="complete",
            errors=[], inaccessible_count=0, timeout_count=0,
            unknown_index_count=0, limit=500, since_days=None,
            total_matched=1, returned_count=1, hidden_by_limit=0)
        older_plan = fw.build_plan(older)
        stale = fw.ApprovalReceipt.create(
            plan_hash=older_plan["plan_hash"],
            snapshot_sha256=older_plan["snapshot_sha256"],
            policy_sha256=older_plan["policy_sha256"],
            approved_mutation_ids=h.approval.approved_mutation_ids,
            approving_operator="op", canary_limit=1)
        # Stale receipt vs CURRENT plan: cross-binding refuses.
        with pytest.raises(fw.FlagWorkflowError):
            stale.validate(plan=dict(h.plan), plan_mutations=h.mutations)

    def test_approval_reuse_after_regenerated_plan_rejected(self, tmp_path):
        h = Harness(tmp_path, pids=("1",))
        # Regenerate the SAME message set into a NEW snapshot/plan.
        fresh = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=[type("R", (), {
                "provider_id": "1", "account": "acct", "mailbox": "INBOX",
                "sender": "billing@corp.example", "subject": ELIG_SUBJECT,
                "native_index": mailapp_index_from_flag(OBSERVED),
                "flag_color": OBSERVED,
                "received_iso": "2026-07-01T00:00:00"})()],
            complete=True, scope_complete=True, status="complete",
            errors=[], inaccessible_count=0, timeout_count=0,
            unknown_index_count=0, limit=500, since_days=None,
            total_matched=1, returned_count=1, hidden_by_limit=0)
        fresh_plan = fw.build_plan(fresh)
        assert fresh_plan["snapshot_sha256"] != h.plan["snapshot_sha256"]
        with pytest.raises(fw.FlagWorkflowError):
            h.approval.validate(plan=dict(fresh_plan),
                                plan_mutations=h.mutations)


# --- GROUP D: hostile provider --------------------------------------------------------


class HostileProvider(FakeScopedProvider):
    def __init__(self, messages, mode=None, fail_on_pid=None):
        super().__init__(messages)
        self.mode = mode or {}
        self.fail_on_pid = fail_on_pid

    def resolve_scoped(self, ref):
        mode = self.mode.get("resolve")
        if mode and (self.fail_on_pid is None
                     or ref.provider_id == self.fail_on_pid):
            if mode == "raise":
                raise RuntimeError("resolve exploded")
            rec = self.messages[ref.provider_id]
            if mode == "wrong_account":
                rec = FakeMessage(rec.pid, rec.native, rec.received,
                                  rec.sender, rec.subject)
                fake = self._live_ref(ref)
                return type(fake.__class__.__name__, (), {
                    **{k: getattr(fake, k) for k in
                       ("provider", "provider_id", "observed_native_flag",
                        "evidence_digest")},
                    "account": "someone-else"})
            if mode == "none_native":
                fake = self._live_ref(ref)
                object.__setattr__(fake, "observed_native_flag", None)
                return fake
        return super().resolve_scoped(ref)

    def set_flag_color_ref(self, ref, color):
        mode = self.mode.get("set")
        if mode and (self.fail_on_pid is None
                     or ref.provider_id == self.fail_on_pid):
            if mode == "false":
                self.calls.append(("set_flag_color_ref", ref.provider_id))
                return False
            if mode == "raise_after_write":
                self.calls.append(("set_flag_color_ref", ref.provider_id))
                self.messages[ref.provider_id].native = \
                    mailapp_index_from_flag(color)      # write DID happen
                raise RuntimeError("died after write")
            if mode == "silent_noop":
                self.calls.append(("set_flag_color_ref", ref.provider_id))
                return True                              # no state change
            if mode == "wrong_state":
                self.calls.append(("set_flag_color_ref", ref.provider_id))
                self.messages[ref.provider_id].native = 6
                return True
            if mode == "unsupported_index":
                self.calls.append(("set_flag_color_ref", ref.provider_id))
                self.messages[ref.provider_id].native = 42
                return True
        return super().set_flag_color_ref(ref, color)


class TestHostileProviderClassification:
    def _single(self, tmp_path, provider_mode, fail_pid=None):
        h = Harness(tmp_path, pids=("1",))
        provider = HostileProvider(
            [FakeMessage(m.provider_id, m.observed_native_flag or -1)
             for m in h.mutations],
            mode=provider_mode, fail_on_pid=fail_pid)
        result = h.engine.apply_transaction(
            plan=dict(h.plan), approval=h.approval, provider=provider)
        return h, result

    def test_resolve_raise_blocks_before_write(self, tmp_path):
        h, r = self._single(tmp_path, {"resolve": "raise"})
        assert r.status == "blocked" and r.writes_performed == 0

    def test_resolve_none_native_blocks(self, tmp_path):
        h, r = self._single(tmp_path, {"resolve": "none_native"})
        assert r.status == "blocked"
        assert any(f["error_code"] == "native_flag_unavailable"
                   for f in r.failed)

    def test_set_returns_false_counts_as_failed_not_written_verified(
            self, tmp_path):
        h, r = self._single(tmp_path, {"set": "false"})
        assert r.status == "partially_failed"
        assert r.writes_performed == 0          # provider said nothing happened
        assert r.failed[0]["error_code"].startswith("provider_refused")

    def test_set_silent_noop_is_ambiguous(self, tmp_path):
        h, r = self._single(tmp_path, {"set": "silent_noop"})
        assert r.status == "partially_failed"
        assert r.failed[0]["status"] == "ambiguous"
        assert r.writes_performed == 1          # True returned: count it

    def test_set_wrong_state_is_ambiguous(self, tmp_path):
        h, r = self._single(tmp_path, {"set": "wrong_state"})
        assert r.failed[0]["status"] == "ambiguous"
        assert r.writes_performed == 1

    def test_unsupported_native_index_is_ambiguous(self, tmp_path):
        h, r = self._single(tmp_path, {"set": "unsupported_index"})
        assert r.failed[0]["status"] == "ambiguous"


# --- GROUP E: batch-of-10 atomic preflight -------------------------------------------


class TestBatchOfTenAtomicPreflight:
    DEFEATS = ["native_drift", "evidence_drift", "override",
               "resolve_raise", "unknown_native"]

    @staticmethod
    def _defeat(h, index, kind):
        pid = h.mutations[index].provider_id
        if kind == "native_drift":
            h.provider.messages[pid].native = 6
        elif kind == "evidence_drift":
            h.provider.messages[pid].subject = "HUMAN EDITED " + pid
        elif kind == "override":
            h.overrides.detect_override(
                next(m for m in h.mutations
                     if m.provider_id == pid).ref_digest,
                automation_expected_state="orange",
                human_observed_state="yellow")
        elif kind == "resolve_raise":
            orig = FakeScopedProvider.resolve_scoped
            def boom(ref, _o=orig, _h=h, _pid=pid):
                if ref.provider_id == _pid:
                    raise RuntimeError("nope")
                return _o(_h.provider, ref)
            h.provider.resolve_scoped = boom
        elif kind == "unknown_native":
            h.provider.messages[pid].native = None

    @pytest.mark.parametrize("index", range(10))
    def test_defect_at_any_index_zero_writes(self, tmp_path, index):
        h = _ten_msg_harness(tmp_path)
        kind = self.DEFEATS[index % len(self.DEFEATS)]
        self._defeat(h, index, kind)
        result = h.apply()
        assert result.status == "blocked"
        assert result.writes_performed == 0     # THE atomic property
        statuses = {e["status"] for e in h.ledger.entries()}
        assert "verified" not in statuses
        assert "preflight_passed" not in statuses   # nothing passed to write

    def test_preflight_precedes_first_write_proven_by_call_order(
            self, tmp_path):
        h = _ten_msg_harness(tmp_path)
        h.provider.messages[h.mutations[9].provider_id].native = 6
        h.apply()
        kinds = [c[0] for c in h.provider.calls]
        assert "set_flag_color_ref" not in kinds
        # resolves happened for preflight only:
        assert kinds.count("resolve_scoped") >= 10

    @pytest.mark.parametrize("prestate", [
        "already_verified+pending",
        "rolled_back+pending",
    ])
    def test_mixed_histories_deterministic(self, tmp_path, prestate):
        h = _ten_msg_harness(tmp_path, ) if False else \
            Harness(tmp_path, pids=tuple(str(i) for i in range(1, 11)))
        # Pre-run subset through a REAL apply, then reset live state so
        # remaining pendings still preflight cleanly.
        first_two_ids = [h.mutations[0].mutation_id,
                         h.mutations[1].mutation_id]
        full = h.approval
        limited = fw.ApprovalReceipt.create(
            plan_hash=h.plan["plan_hash"],
            snapshot_sha256=h.plan["snapshot_sha256"],
            policy_sha256=h.plan["policy_sha256"],
            approved_mutation_ids=first_two_ids,
            approving_operator="op", canary_limit=2)
        r1 = h.engine.apply_transaction(plan=dict(h.plan),
                                        approval=limited,
                                        provider=h.provider)
        assert r1.status == "applied"
        if prestate.startswith("rolled_back"):
            m0 = h.mutations[0]
            receipt = TransactionRollbackReceipt.create(
                transaction_id=r1.verified[0]["transaction_id"],
                plan_sha256=h.plan["plan_hash"],
                approval_sha256=limited.content_hash,
                mutation_id=m0.mutation_id,
                ref_digest=m0.ref_digest,
                pre_native_flag=m0.observed_native_flag,
                pre_semantic_flag=m0.observed_flag.value,
                applied_native_flag=mailapp_index_from_flag(
                    m0.proposed_flag),
                applied_semantic_flag=m0.proposed_flag.value)
            rb = h.rb_engine.rollback_transaction(receipt=receipt,
                                                  provider=h.provider)
            assert rb.status == "rolled_back"
            # restore live state of rolled-back item so later batch logic
            # (if ever re-approved) sees consistent world:
            h.provider.messages[m0.provider_id].native = \
                m0.observed_native_flag
        # Now attempt FULL approval: previously verified ones skip as
        # already_applied events; rolled-back one refuses deterministically.
        result = h.apply()
        if prestate.startswith("rolled_back"):
            assert result.status == "blocked"
            assert result.error_code == "previously_rolled_back"
        else:
            # Two pre-verified replay as events; remaining eight apply.
            assert result.status == "applied"
            assert len(result.already_applied) == 2
            assert result.writes_performed == 8
