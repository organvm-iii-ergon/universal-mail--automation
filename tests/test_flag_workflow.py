"""Tests for core.flag_workflow — hashing, schemas, snapshots, plans,
approvals, ledger, overrides, rollback receipts (Commit 3 extraction)."""

import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from core.models import FlagColor
from core import flag_workflow as fw
from core.flag_policy import (
    AUTO_ELIGIBLE_THRESHOLD,
    MIGRATION_POLICY_VERSION,
    POLICY_SHA256,
    propose,
    RC_LOW_CONFIDENCE_PURPLE,
)
from providers.mailapp import mailapp_index_from_flag


def _native(color=FlagColor.RED):
    """Consistent native index for a semantic color (None only for UNKNOWN)."""
    if color == FlagColor.UNKNOWN:
        return None
    return mailapp_index_from_flag(color)


def _msg(provider_id="1", sender="a@b.com", subject="Hi",
         color=FlagColor.RED, account="acct", mailbox="INBOX"):
    return fw.SnapshotMessage(
        provider="mailapp", account=account, mailbox=mailbox,
        provider_id=provider_id, sender=sender, subject=subject,
        native_index=_native(color), observed_flag=color, received_iso=None,
    )


def _row(provider_id="1", sender="a@b.com", subject="Hi",
         color=FlagColor.RED, account="acct", mailbox="INBOX",
         received_iso=None):
    """Transport-row stand-in with the attributes build_snapshot reads."""
    from types import SimpleNamespace
    return SimpleNamespace(
        provider_id=provider_id, account=account, mailbox=mailbox,
        sender=sender, subject=subject, native_index=_native(color),
        flag_color=color, received_iso=received_iso)


def _snapshot(messages, complete=True, status=None):
    complete = complete
    snap = fw.FlagSnapshot(
        schema=fw.SNAPSHOT_SCHEMA, snapshot_id="snap-" + fw.sha256_hex("test")[:32],
        generated_at=datetime.now(timezone.utc).isoformat(),
        provider="mailapp", account="acct", mailbox="INBOX",
        complete=complete,
        scope_complete=complete,
        status=status or ("complete" if complete else "partial"),
        zero_write_mode=True, errors=[],
        inaccessible_count=0, timeout_count=0, unknown_index_count=0,
        limit=500, since_days=None, ordering="received_desc",
        total_matched=len(messages), returned_count=len(messages),
        hidden_by_limit=0, next_cursor=None,
        messages=list(messages), content_hash="",
    )
    snap.content_hash = snap.to_dict()["content_hash"]
    return snap


class TestCanonicalHashing:
    def test_deterministic_and_order_insensitive(self):
        a = {"x": 1, "y": [2, 3]}
        b = {"y": [2, 3], "x": 1}
        assert fw.sha256_hex(a) == fw.sha256_hex(b)

    def test_full_64_hex(self):
        digest = fw.sha256_hex({"anything": True})
        assert len(digest) == 64
        assert set(digest) <= set("0123456789abcdef")

    def test_require_hex256_rejects_truncated(self):
        with pytest.raises(fw.FlagWorkflowError, match="full 64-char"):
            fw.require_hex256("abc123", "field")

    def test_require_hex256_rejects_uppercase_without_normalizing(self):
        with pytest.raises(fw.FlagWorkflowError, match="full 64-char"):
            fw.require_hex256("A" * 64, "field")

    def test_plan_hash_excludes_itself(self):
        plan = {"schema": "x", "plan_hash": "PLACEHOLDER", "n": 1}
        h = fw.compute_plan_hash(plan)
        assert h == fw.compute_plan_hash({**plan, "plan_hash": "OTHER"})
        assert len(h) == 64

    @pytest.mark.parametrize("payload", [
        {"value": float("nan")},
        {"value": float("inf")},
        {"value": object()},
        {"value": ("tuple",)},
        {1: "coerced-key"},
        {"value": FlagColor.RED},
    ])
    def test_non_json_or_coercive_values_fail_with_workflow_error(
            self, payload):
        with pytest.raises(fw.FlagWorkflowError):
            fw.sha256_hex(payload)

    def test_artifact_loader_rejects_duplicate_json_keys(self, tmp_path):
        artifact = tmp_path / "duplicate.json"
        artifact.write_text(
            '{"schema":"first","schema":"second"}', encoding="utf-8"
        )
        with pytest.raises(fw.FlagWorkflowError, match="invalid JSON"):
            fw.load_snapshot(artifact)


class TestSnapshotModel:
    def test_content_hash_changes_with_content(self):
        s1 = _snapshot([_msg(subject="A")])
        s2 = _snapshot([_msg(subject="B")])
        d1, d2 = s1.to_dict(), s2.to_dict()
        assert d1["content_hash"] != d2["content_hash"]
        assert len(d1["content_hash"]) == 64

    def test_public_safe_is_allowlist_never_private_derived(self):
        snap = _snapshot([
            _msg("11", "secret@corp.example", "Classified Subject X"),
        ])
        public = snap.to_public_safe()
        blob = json.dumps(public)
        # PII stripped
        assert "secret@corp.example" not in blob
        assert "Classified Subject X" not in blob
        assert '"provider_id"' not in blob
        # Raw scope NEVER present — only its digest
        assert "account" not in public and "mailbox" not in public
        assert "acct" not in blob and "INBOX" not in blob
        assert len(public["scope_digest"]) == 64
        # Free-form errors never leak; codes at most
        assert "errors" not in public and "error_codes" in public
        # Cryptographic link to private source
        assert public["source_snapshot_sha256"] == \
            snap.to_dict()["content_hash"]

    def test_public_hash_covers_projection_field(self):
        snap = _snapshot([_msg()])
        public = snap.to_public_safe()
        stored = public["content_hash"]
        body = {k: v for k, v in public.items() if k != "content_hash"}
        assert fw.sha256_hex(body) == stored
        # Tampering with ANY field — including 'projection' — breaks it.
        tampered = dict(public, projection="not_public")
        bad = {k: v for k, v in tampered.items() if k != "content_hash"}
        assert fw.sha256_hex(bad) != stored

    def test_public_receipt_validator_and_tamper(self, tmp_path):
        snap = _snapshot([_msg()])
        receipt = snap.to_public_safe()
        fw.validate_public_receipt(receipt)          # valid passes

        path = tmp_path / "public.json"
        path.write_text(json.dumps(receipt))
        loaded = json.loads(path.read_text())

        loaded_tampered = dict(loaded, content_hash="0" * 64)
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.validate_public_receipt(loaded_tampered)

        injected = dict(loaded, account="leak@corp.example",
                        content_hash=receipt["content_hash"])
        with pytest.raises(fw.FlagWorkflowError, match="forbidden keys"):
            fw.validate_public_receipt(injected)

        unsafe_code = dict(loaded, error_codes=["acct/SecretMailbox"])
        unsafe_code["content_hash"] = fw.sha256_hex({
            key: value
            for key, value in unsafe_code.items()
            if key != "content_hash"
        })
        with pytest.raises(fw.FlagWorkflowError, match="allowlist"):
            fw.validate_public_receipt(unsafe_code)

    @pytest.mark.parametrize("location,key,value", [
        ("top", "operator_note", "private"),
        ("counts", "raw_errors", ["private"]),
        ("message", "sender", "secret@example.test"),
    ])
    def test_public_receipt_rejects_hash_valid_unknown_nested_keys(
            self, location, key, value):
        public = _snapshot([_msg()]).to_public_safe()
        if location == "top":
            public[key] = value
        elif location == "counts":
            public["counts"][key] = value
        else:
            public["messages"][0][key] = value
        public["content_hash"] = fw.sha256_hex({
            name: field
            for name, field in public.items()
            if name != "content_hash"
        })
        with pytest.raises(fw.FlagWorkflowError, match="schema|forbidden"):
            fw.validate_public_receipt(public)

    @pytest.mark.parametrize("location,key", [
        ("top", "provider"),
        ("counts", "returned"),
        ("message", "flag"),
    ])
    def test_public_receipt_requires_every_schema_key(self, location, key):
        public = _snapshot([_msg()]).to_public_safe()
        if location == "top":
            public.pop(key)
        elif location == "counts":
            public["counts"].pop(key)
        else:
            public["messages"][0].pop(key)
        with pytest.raises(fw.FlagWorkflowError, match="missing"):
            fw.validate_public_receipt(public)

    @pytest.mark.parametrize("attack", [
        lambda public: public["counts"].__setitem__("returned", True),
        lambda public: public["messages"][0].__setitem__("flag", "Red"),
        lambda public: public.__setitem__("zero_write_mode", "true"),
    ])
    def test_public_receipt_rejects_hash_valid_coercive_values(
            self, attack):
        public = _snapshot([_msg()]).to_public_safe()
        attack(public)
        public["content_hash"] = fw.sha256_hex({
            name: field
            for name, field in public.items()
            if name != "content_hash"
        })
        with pytest.raises(fw.FlagWorkflowError):
            fw.validate_public_receipt(public)

    def test_snapshot_ids_unique_across_identical_audits(self):
        """P0 #1: same scope + same count + different runs → different ids,
        so write_private_snapshot can never overwrite an earlier artifact."""
        def rows_factory():
            return [_row(str(i)) for i in range(3)]
        t0 = "2026-08-25T10:00:00+00:00"
        t1 = "2026-08-25T10:05:00+00:00"
        kw = dict(provider_name="mailapp", account="a", mailbox="INBOX",
                  complete=True, scope_complete=True, status="complete",
                  errors=[], inaccessible_count=0, timeout_count=0,
                  unknown_index_count=0, limit=500, since_days=None,
                  total_matched=3, returned_count=3, hidden_by_limit=0)
        s_a = fw.build_snapshot(rows=rows_factory(), generated_at=t0, **kw)
        s_b = fw.build_snapshot(rows=rows_factory(), generated_at=t1, **kw)
        assert s_a.snapshot_id != s_b.snapshot_id

    def test_unique_ids_mean_no_file_overwrite(self, tmp_path):
        kw = dict(provider_name="mailapp", account="a", mailbox="INBOX",
                  complete=True, scope_complete=True, status="complete",
                  errors=[], inaccessible_count=0, timeout_count=0,
                  unknown_index_count=0, limit=500, since_days=None,
                  total_matched=1, returned_count=1, hidden_by_limit=0)
        msgs = [_row("9")]
        p1 = fw.write_private_snapshot(
            fw.build_snapshot(rows=msgs, generated_at="2026-08-25T10:00:00+00:00", **kw),
            tmp_path)
        p2 = fw.write_private_snapshot(
            fw.build_snapshot(rows=msgs, generated_at="2026-08-25T10:01:00+00:00", **kw),
            tmp_path)
        assert p1 != p2
        assert p1.exists() and p2.exists()

    def test_writer_hardens_preexisting_loose_dirs(self, tmp_path):
        """4b #3: pre-existing 0755 leaf AND managed uma/uma-flags ancestors
        are hardened to 0700 before the snapshot lands."""
        state_root = (
            tmp_path / "home" / ".local" / "share" / "uma" / "flags"
            / "snapshots"
        )
        # Pre-create the WHOLE chain loose, as another tool might have.
        state_root.mkdir(parents=True, exist_ok=True)
        os.chmod(state_root, 0o755)
        os.chmod(state_root.parent, 0o755)           # uma/flags
        os.chmod(state_root.parent.parent, 0o755)    # uma

        kw = dict(provider_name="mailapp", account="a", mailbox="INBOX",
                  complete=True, scope_complete=True, status="complete",
                  errors=[], inaccessible_count=0, timeout_count=0,
                  unknown_index_count=0, limit=500, since_days=None,
                  total_matched=1, returned_count=1, hidden_by_limit=0)
        written = fw.write_private_snapshot(
            fw.build_snapshot(rows=[_row("1")],
                              generated_at="2026-08-25T10:00:00+00:00", **kw),
            state_root)

        def mode(p):
            return oct(os.stat(p).st_mode)[-3:]

        assert mode(written.parent) == "700"
        assert mode(state_root.parent) == "700"       # uma/flags
        assert mode(state_root.parent.parent) == "700"  # uma
        assert mode(written) == "600"

    def test_writer_leaves_unrelated_flags_named_dir_alone(self, tmp_path):
        """A directory elsewhere merely NAMED 'flags' is never chmodded."""
        unrelated_parent = tmp_path / "documents" / "flags"
        out_dir = unrelated_parent / "out"
        out_dir.mkdir(parents=True)
        os.chmod(unrelated_parent, 0o755)

        kw = dict(provider_name="mailapp", account="a", mailbox="INBOX",
                  complete=True, scope_complete=True, status="complete",
                  errors=[], inaccessible_count=0, timeout_count=0,
                  unknown_index_count=0, limit=500, since_days=None,
                  total_matched=1, returned_count=1, hidden_by_limit=0)
        written = fw.write_private_snapshot(
            fw.build_snapshot(rows=[_row("1")],
                              generated_at="2026-08-25T10:00:00+00:00", **kw),
            out_dir)

        assert oct(os.stat(written).st_mode)[-3:] == "600"   # leaf hardened
        # The unrelated 'flags' parent keeps its original loose mode.
        assert oct(os.stat(unrelated_parent).st_mode)[-3:] == "755"

    def test_build_snapshot_rejects_complete_with_errors(self):
        with pytest.raises(fw.FlagWorkflowError,
                           match="inconsistent with scan dimensions"):
            fw.build_snapshot(
                provider_name="mailapp", account="a", mailbox="INBOX",
                rows=[], complete=True, scope_complete=True,
                status="complete", errors=["boom"],
                inaccessible_count=0, timeout_count=0,
                unknown_index_count=0, limit=500, since_days=None,
                total_matched=0, returned_count=0, hidden_by_limit=0,
            )

    def test_build_snapshot_rejects_complete_with_hidden_or_inaccessible(self):
        base = dict(provider_name="mailapp", account="a", mailbox="INBOX",
                    rows=[], complete=True, scope_complete=True,
                    status="complete", errors=[], timeout_count=0,
                    unknown_index_count=0, limit=100, since_days=None,
                    total_matched=5, returned_count=0)
        # Canonical status for inaccessible>0 is 'partial' — producer must
        # not be able to stamp complete=True over it.
        with pytest.raises(fw.FlagWorkflowError,
                           match="inconsistent with scan dimensions"):
            fw.build_snapshot(inaccessible_count=2, hidden_by_limit=0, **base)
        with pytest.raises(fw.FlagWorkflowError,
                           match="inconsistent with scan dimensions"):
            fw.build_snapshot(inaccessible_count=0, hidden_by_limit=3, **base)

    def test_load_snapshot_detects_tamper(self, tmp_path):
        snap = _snapshot([_msg()])
        path = tmp_path / "snap.json"
        path.write_text(json.dumps(snap.to_dict()))
        loaded = fw.load_snapshot(path)
        assert loaded.snapshot_id == snap.snapshot_id

        tampered = json.loads(path.read_text())
        tampered["total_matched"] = 999
        path.write_text(json.dumps(tampered))
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.load_snapshot(path)

    @pytest.mark.parametrize("payload", ["{broken", "[]", '"scalar"'])
    def test_load_snapshot_wraps_malformed_json_as_typed_error(
            self, tmp_path, payload):
        path = tmp_path / "malformed.json"
        path.write_text(payload, encoding="utf-8")
        with pytest.raises(fw.FlagWorkflowError):
            fw.load_snapshot(path)

    def test_complete_snapshot_requires_coherent_counts(self, tmp_path):
        snap = _snapshot([_msg()])
        raw = snap.to_dict()
        raw["total_matched"] = 2
        raw["content_hash"] = fw.sha256_hex({
            key: value
            for key, value in raw.items()
            if key != "content_hash"
        })
        path = tmp_path / "incoherent.json"
        path.write_text(json.dumps(raw), encoding="utf-8")
        with pytest.raises(fw.FlagWorkflowError, match="counts are incoherent"):
            fw.load_snapshot(path)

    @pytest.mark.parametrize("field,value", [
        ("limit", 0),
        ("limit", -1),
        ("since_days", 0),
        ("since_days", -1),
    ])
    def test_snapshot_rejects_nonpositive_scan_bounds(
            self, tmp_path, field, value):
        raw = _snapshot([_msg()]).to_dict()
        raw[field] = value
        raw["content_hash"] = fw.sha256_hex({
            key: item for key, item in raw.items() if key != "content_hash"
        })
        path = tmp_path / "bad-bound.json"
        path.write_text(json.dumps(raw), encoding="utf-8")

        with pytest.raises(fw.FlagWorkflowError, match=field):
            fw.load_snapshot(path)

    def test_public_error_codes_are_fixed_allowlist_without_scope(self):
        private_error = "secret@example/Private Mailbox: permission denied"
        snap = fw.build_snapshot(
            provider_name="mailapp",
            account="secret@example",
            mailbox="Private Mailbox",
            rows=[],
            complete=False,
            scope_complete=False,
            status="failed",
            errors=[private_error],
            inaccessible_count=0,
            timeout_count=0,
            unknown_index_count=0,
            limit=500,
            since_days=None,
            total_matched=0,
            returned_count=0,
            hidden_by_limit=0,
        )
        public = snap.to_public_safe()
        assert public["error_codes"] == ["provider_error"]
        assert "secret@example" not in json.dumps(public)
        assert "Private Mailbox" not in json.dumps(public)


class TestPlanBuildingAndValidation:
    def _complete_snapshot(self):
        return _snapshot([
            _msg("1", "recruiter@x.com", "great opportunity"),
            _msg("2", "unknown@y.com", "mystery"),
        ])

    def test_plan_binds_full_snapshot_hash_and_policy_digest(self):
        snap = self._complete_snapshot()
        plan = fw.build_plan(snap)
        assert plan["snapshot_sha256"] == snap.to_dict()["content_hash"]
        assert len(plan["plan_hash"]) == 64
        assert plan["policy_version"] == MIGRATION_POLICY_VERSION
        assert plan["policy_sha256"] == POLICY_SHA256
        assert plan["zero_write_declaration"] is True
        for m in plan["mutations"]:
            # Measured confidence — never None-by-laziness, never fake 0.7.
            assert isinstance(m["confidence"], float)
            assert 0.0 <= m["confidence"] <= 1.0
            if m["confidence"] < AUTO_ELIGIBLE_THRESHOLD:
                assert m["review_required"] is True
            # Durable private bindings ride along for Commit 6 preflight.
            for key in ("provider", "account", "mailbox", "provider_id",
                        "snapshot_id", "evidence_digest"):
                assert key in m
            assert m["snapshot_id"] == snap.snapshot_id
            assert "sender" not in m and "subject" not in m   # no raw PII

    def test_incomplete_snapshot_cannot_produce_plan(self):
        snap = self._complete_snapshot()
        broken = fw.FlagSnapshot(
            **{
                **snap.__dict__,
                "complete": False,
                "scope_complete": False,
                "status": "failed",
                "errors": ["scope incomplete"],
            },
        )
        broken.content_hash = ""
        broken.content_hash = broken.to_dict()["content_hash"]
        with pytest.raises(fw.FlagWorkflowError, match="refusing"):
            fw.build_plan(broken)

    def test_bounded_partial_status_blocks_plan(self):
        """hidden_by_limit>0 must be structurally plan-ineligible."""
        snap = self._complete_snapshot()
        bounded = fw.FlagSnapshot(
            **{**snap.__dict__, "complete": False,
               "scope_complete": True, "status": "bounded_partial",
               "total_matched": 146, "hidden_by_limit": 144,
               "next_cursor": '{"resume":"widen"}'},
        )
        bounded.content_hash = ""
        bounded.content_hash = bounded.to_dict()["content_hash"]
        with pytest.raises(fw.FlagWorkflowError, match="refusing"):
            fw.build_plan(bounded)

    def test_validate_accepts_built_plan(self):
        plan = fw.build_plan(self._complete_snapshot())
        mutations = fw.validate_plan_schema(plan)
        assert all(isinstance(m, fw.PlannedMutation) for m in mutations)

    def test_validate_rejects_wrong_schema(self):
        plan = fw.build_plan(self._complete_snapshot())
        plan["schema"] = "uma.flags.migration.plan.v1"
        with pytest.raises(fw.FlagWorkflowError, match="schema must be"):
            fw.validate_plan_schema(plan)

    def test_validate_fails_closed_on_unknown_color_string(self):
        plan = fw.build_plan(self._complete_snapshot())
        if not plan["mutations"]:
            pytest.skip("no mutations produced")
        plan["mutations"][0]["proposed_flag"] = "magenta"
        plan.pop("plan_hash")
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(ValueError, match="Unknown flag color"):
            fw.validate_plan_schema(plan)

    def test_validate_rejects_tampered_mutations(self):
        plan = fw.build_plan(self._complete_snapshot())
        if not plan["mutations"]:
            pytest.skip("no mutations produced")
        plan["mutations"][0]["proposed_flag"] = "blue"
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.validate_plan_schema(plan)

    def test_validate_rejects_truncated_snapshot_hash(self):
        plan = fw.build_plan(self._complete_snapshot())
        plan["snapshot_sha256"] = plan["snapshot_sha256"][:16]
        plan.pop("plan_hash")
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(fw.FlagWorkflowError, match="full 64-char"):
            fw.validate_plan_schema(plan)

    @pytest.mark.parametrize("field", ["review_required", "auto_eligible"])
    def test_validate_rejects_string_booleans(self, field):
        plan = fw.build_plan(self._complete_snapshot())
        plan["mutations"][0][field] = "false"
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(fw.FlagWorkflowError, match="must be a boolean"):
            fw.validate_plan_schema(plan)

    @pytest.mark.parametrize("field", ["reason", "confidence"])
    def test_validate_requires_reason_and_confidence_keys(self, field):
        plan = fw.build_plan(self._complete_snapshot())
        plan["mutations"][0].pop(field)
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(fw.FlagWorkflowError, match="missing required key"):
            fw.validate_plan_schema(plan)

    def test_validate_recomputes_ref_digest_from_scoped_identity(self):
        plan = fw.build_plan(self._complete_snapshot())
        plan["mutations"][0]["ref_digest"] = "b" * 64
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(fw.FlagWorkflowError, match="ref_digest does not match"):
            fw.validate_plan_schema(plan)

    def test_public_projection_revalidates_private_plan(self):
        plan = fw.build_plan(self._complete_snapshot())
        plan["snapshot_complete"] = False
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(fw.FlagWorkflowError, match="snapshot_complete"):
            fw.to_public_safe_plan(plan)

    @pytest.mark.parametrize("location,key,value", [
        ("top", "operator_note", "private"),
        ("mutation", "account", "secret@example.test"),
    ])
    def test_public_plan_rejects_hash_valid_unknown_keys(
            self, location, key, value):
        public = fw.to_public_safe_plan(
            fw.build_plan(self._complete_snapshot())
        )
        if location == "top":
            public[key] = value
        else:
            public["mutations"][0][key] = value
        public["plan_public_hash"] = fw.sha256_hex({
            name: field
            for name, field in public.items()
            if name != "plan_public_hash"
        })
        with pytest.raises(fw.FlagWorkflowError, match="schema|forbidden"):
            fw.validate_public_plan(public)

    @pytest.mark.parametrize("location,key", [
        ("top", "source_plan_sha256"),
        ("mutation", "reason_code"),
    ])
    def test_public_plan_requires_every_schema_key(self, location, key):
        public = fw.to_public_safe_plan(
            fw.build_plan(self._complete_snapshot())
        )
        if location == "top":
            public.pop(key)
        else:
            public["mutations"][0].pop(key)
        with pytest.raises(fw.FlagWorkflowError, match="missing"):
            fw.validate_public_plan(public)

    @pytest.mark.parametrize("field,value", [
        ("review_required", "false"),
        ("auto_eligible", 1),
        ("confidence", float("nan")),
        ("observed_flag", "Red"),
    ])
    def test_public_plan_rejects_hash_valid_coercive_mutation_values(
            self, field, value):
        public = fw.to_public_safe_plan(
            fw.build_plan(self._complete_snapshot())
        )
        public["mutations"][0][field] = value
        if isinstance(value, float) and not value == value:
            with pytest.raises(fw.FlagWorkflowError, match="non-finite"):
                fw.sha256_hex(public)
            return
        public["plan_public_hash"] = fw.sha256_hex({
            name: item
            for name, item in public.items()
            if name != "plan_public_hash"
        })
        with pytest.raises(fw.FlagWorkflowError):
            fw.validate_public_plan(public)

    def test_private_plan_writer_is_atomic_0600_and_revalidates(
            self, tmp_path):
        plan = fw.build_plan(self._complete_snapshot())
        private_dir = tmp_path / "loose-private-dir"
        private_dir.mkdir(mode=0o755)
        os.chmod(private_dir, 0o755)
        output = fw.write_private_plan(
            plan, private_dir / "private-plan.json"
        )
        assert output == private_dir / "private-plan.json"
        assert oct(os.stat(private_dir).st_mode)[-3:] == "700"
        assert oct(os.stat(output).st_mode)[-3:] == "600"
        assert json.loads(output.read_text(encoding="utf-8")) == plan
        assert not list(private_dir.glob(".tmp-flags-plan-*"))

        plan["mutations"][0]["ref_digest"] = "c" * 64
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(fw.FlagWorkflowError, match="ref_digest"):
            fw.write_private_plan(plan, private_dir / "forged-plan.json")


class TestApprovalValidation:
    """Commit 6 v2 contract: approval is a signed-off artifact with its own
    integrity hash, bound to the ACTUAL loaded plan. Fixtures use subjects
    the classifier rates structurally auto-eligible (0.95 confidence,
    deadline+consequence evidence) so approvals have something legal to
    approve."""

    ELIG = dict(sender="billing@corp.example",
                subject="Payment due tomorrow — account suspension otherwise")

    def _approval(self, plan, mutations, canary_limit=10, **kw):
        ids = [m.mutation_id for m in mutations][:canary_limit]
        return fw.ApprovalReceipt.create(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=plan["snapshot_sha256"],
            policy_sha256=plan["policy_sha256"],
            approved_mutation_ids=ids,
            approving_operator="operator",
            canary_limit=canary_limit,
            **kw,
        )

    @staticmethod
    def _rehash(approval):
        """Simulate an attacker rewriting fields AND their hash — lets the
        SPECIFIC rule under test fire instead of the generic tamper gate."""
        approval.content_hash = approval.to_dict()["content_hash"]

    def _eligible_snapshot(self, *pids):
        return _snapshot([
            _msg(pid, color=FlagColor.ORANGE, **self.ELIG) for pid in pids
        ])

    def test_valid_approval_passes_and_has_own_integrity_hash(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        assert muts and all(m.auto_eligible for m in muts)
        n = min(10, max(1, len(muts)))
        approval = self._approval(plan, muts, canary_limit=n)
        assert len(approval.content_hash) == 64      # own SHA-256
        assert approval.to_dict()["approval_id"].startswith("appr-")
        approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_tampered_content_hash_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts)
        approval.canary_limit = 9                    # mutate AFTER hashing
        with pytest.raises(fw.FlagWorkflowError,
                           match="content_hash mismatch"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_plan_hash_mismatch_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts)
        other = fw.build_plan(self._eligible_snapshot("7"))
        with pytest.raises(fw.FlagWorkflowError, match="wrong plan"):
            approval.validate(plan=dict(other), plan_mutations=muts)

    def test_snapshot_lineage_mismatch_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts)
        approval.snapshot_sha256 = "f" * 64
        self._rehash(approval)                       # isolate the rule
        with pytest.raises(fw.FlagWorkflowError, match="wrong snapshot"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_policy_hash_mismatch_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts)
        approval.policy_sha256 = "0" * 64
        self._rehash(approval)
        with pytest.raises(fw.FlagWorkflowError, match="policy"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_review_required_mutation_cannot_be_approved(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        if not muts:
            pytest.skip("no mutations")
        target = muts[0]
        approval = self._approval(plan, [target])
        object.__setattr__(target, "review_required", True)   # attacker edit
        with pytest.raises(fw.FlagWorkflowError,
                           match="review_required mutation"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_unknown_observation_cannot_be_approved(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        if not muts:
            pytest.skip("no mutations")
        target = muts[0]
        approval = self._approval(plan, [target])
        object.__setattr__(target, "observed_flag", FlagColor.UNKNOWN)
        object.__setattr__(target, "auto_eligible", True)
        with pytest.raises(fw.FlagWorkflowError, match="UNKNOWN"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    @pytest.mark.parametrize("bad_limit", [0, -1, 11, 100])
    def test_canary_bounds_hard_enforced(self, bad_limit):
        plan = fw.build_plan(self._eligible_snapshot("1", "2"))
        muts = fw.validate_plan_schema(plan)
        ids = [m.mutation_id for m in muts][:1]
        now = datetime.now(timezone.utc)
        approval = fw.ApprovalReceipt.create(
            plan_hash=plan["plan_hash"],
            snapshot_sha256=plan["snapshot_sha256"],
            policy_sha256=plan["policy_sha256"],
            approved_mutation_ids=ids,
            approving_operator="operator",
            canary_limit=10,
            issued_at=(now - timedelta(minutes=1)).isoformat(),
        )
        object.__setattr__(approval, "canary_limit", bad_limit)
        self._rehash(approval)                       # isolate the rule
        with pytest.raises(fw.FlagWorkflowError, match="canary_limit"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_zero_approved_ids_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts)
        approval.approved_mutation_ids = []
        self._rehash(approval)
        with pytest.raises(fw.FlagWorkflowError, match="NONEMPTY"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_duplicate_approved_ids_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1", "2"))
        muts = fw.validate_plan_schema(plan)
        if len(muts) < 1:
            pytest.skip("no mutations")
        mid = muts[0].mutation_id
        approval = self._approval(plan, [muts[0]], canary_limit=2)
        approval.approved_mutation_ids = [mid, mid]
        self._rehash(approval)
        with pytest.raises(fw.FlagWorkflowError, match="duplicates"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_approved_count_exceeding_canary_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1", "2", "3"))
        muts = fw.validate_plan_schema(plan)
        if len(muts) < 2:
            pytest.skip("need >=2 mutations")
        approval = self._approval(plan, muts, canary_limit=10)
        approval.approved_mutation_ids = [
            m.mutation_id for m in muts]             # more than limit below
        object.__setattr__(approval, "canary_limit", 1)
        self._rehash(approval)
        with pytest.raises(fw.FlagWorkflowError, match="exceed canary"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_expired_approval_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        now = datetime.now(timezone.utc)
        approval = self._approval(plan, muts, ttl_seconds=3600)
        # Keep issued<expires coherent; make the WINDOW fully past instead.
        approval.issued_at = (now - timedelta(hours=2)).isoformat()
        approval.expires_at = (now - timedelta(seconds=1)).isoformat()
        self._rehash(approval)
        with pytest.raises(fw.FlagWorkflowError, match="expired"):
            approval.validate(plan=dict(plan), plan_mutations=muts, now=now)

    def test_future_issued_at_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        now = datetime.now(timezone.utc)
        approval = self._approval(
            plan,
            muts,
            issued_at=(now + timedelta(minutes=1)).isoformat(),
        )
        with pytest.raises(fw.FlagWorkflowError, match="future"):
            approval.validate(
                plan=dict(plan), plan_mutations=muts, now=now
            )

    @pytest.mark.parametrize("bad_now", [
        "2026-01-01T00:00:00+00:00",
        0,
        datetime(2026, 1, 1),
    ])
    def test_validation_clock_requires_typed_aware_datetime(self, bad_now):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts)
        with pytest.raises(fw.FlagWorkflowError, match="validation clock"):
            approval.validate(
                plan=dict(plan), plan_mutations=muts, now=bad_now
            )

    def test_unknown_mutation_id_rejected(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        approval = self._approval(plan, muts)
        approval.approved_mutation_ids = ["mut-doesnotexist"]
        self._rehash(approval)
        with pytest.raises(fw.FlagWorkflowError, match="absent from plan"):
            approval.validate(plan=dict(plan), plan_mutations=muts)

    def test_expiry_is_derived_from_supplied_issued_at(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        issued = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        approval = self._approval(
            plan,
            muts,
            issued_at=issued.isoformat(),
            ttl_seconds=90,
        )
        assert datetime.fromisoformat(approval.expires_at) == (
            issued + timedelta(seconds=90)
        )

    @pytest.mark.parametrize(
        "issued_at", ["not-a-timestamp", "2026-01-01T12:00:00"]
    )
    def test_create_rejects_malformed_or_naive_issued_at(
            self, issued_at):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        with pytest.raises(fw.FlagWorkflowError):
            self._approval(plan, muts, issued_at=issued_at)

    def test_create_rejects_unrepresentable_expiry(self):
        plan = fw.build_plan(self._eligible_snapshot("1"))
        muts = fw.validate_plan_schema(plan)
        with pytest.raises(fw.FlagWorkflowError, match="cannot be represented"):
            self._approval(
                plan,
                muts,
                issued_at="9999-12-31T23:59:59+00:00",
                ttl_seconds=2,
            )


class TestAppliedPlanLedger:
    def test_record_then_has_true_idempotency_probe(self, tmp_path):
        ledger = fw.AppliedPlanLedger(tmp_path / "ledger.jsonl")
        ph = fw.sha256_hex("plan")
        assert ledger.has(ph, "mut-1") is False
        ledger.record(ph, "mut-1", verified=True)
        assert ledger.has(ph, "mut-1") is True
        assert ledger.all_entries()[0]["verified"] is True

    def test_entries_survive_reopen(self, tmp_path):
        ph = fw.sha256_hex("p")
        fw.AppliedPlanLedger(tmp_path / "l.jsonl").record(ph, "m", True)
        assert fw.AppliedPlanLedger(tmp_path / "l.jsonl").has(ph, "m")

    def test_malformed_authoritative_history_fails_closed(self, tmp_path):
        ledger = fw.AppliedPlanLedger(tmp_path / "ledger.jsonl")
        plan_hash = fw.sha256_hex("plan")
        ledger.record(plan_hash, "mut-1", True)
        with ledger.path.open("a", encoding="utf-8") as handle:
            handle.write("{malformed\n")
        with pytest.raises(fw.FlagWorkflowError, match="corrupt"):
            ledger.has(plan_hash, "mut-1")


class TestOverrideStore:
    def test_record_suppress_unlock_roundtrip(self, tmp_path):
        store = fw.OverrideStore(tmp_path / "overrides.json")
        ref = fw.sha256_hex("ref-1")
        assert store.is_overridden(ref) is False
        store.record_override(ref, "human changed RED -> GRAY after apply")
        assert store.is_overridden(ref) is True
        assert store.is_suppressed(ref) is True
        store.unlock(ref, actor="human-operator")
        assert store.is_suppressed(ref) is False
        # History (with unlock audit fields) persists after unlock.
        history = store.list_overrides()[ref]
        assert history["suppressed"] is False
        assert history["unlock_actor"] == "human-operator"
        assert history["unlocked_at"] is not None

    def test_constructor_expands_user_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HOME", str(tmp_path))
        store = fw.OverrideStore("~/state/overrides.json")
        assert store.path == tmp_path / "state" / "overrides.json"

    def test_automation_state_does_NOT_clear_override(self, tmp_path):
        """Commit 6 UNLOCK-ONLY contract: only explicit operator unlock
        clears suppression — automation verifying its own write can never
        silently resurrect authority over a human-touched message."""
        store = fw.OverrideStore(tmp_path / "o.json")
        ref = fw.sha256_hex("ref-2")
        store.record_override(ref, "diff")
        store.record_automation_state(ref, "orange", verified=True)
        assert store.is_suppressed(ref) is True      # STILL suppressed
        assert store.is_overridden(ref) is True
        store.unlock(ref, actor="operator")
        assert store.is_suppressed(ref) is False     # only unlock clears

    def test_corrupt_store_fails_closed(self, tmp_path):
        p = tmp_path / "o.json"
        p.write_text("{not json")
        store = fw.OverrideStore(p)
        with pytest.raises(fw.FlagWorkflowError, match="corrupt"):
            store.list_overrides()

    def test_duplicate_suppression_key_fails_closed(self, tmp_path):
        path = tmp_path / "o.json"
        path.write_text(
            '{"overrides":{},"suppressed":{},"suppressed":{},'
            '"last_automation":{}}',
            encoding="utf-8",
        )
        with pytest.raises(fw.FlagWorkflowError, match="corrupt"):
            fw.OverrideStore(path).list_overrides()

    def test_dangling_symlink_store_is_not_treated_as_fresh(self, tmp_path):
        path = tmp_path / "dangling.json"
        os.symlink(tmp_path / "missing-target.json", path)
        with pytest.raises(fw.FlagWorkflowError, match="unreadable"):
            fw.OverrideStore(path).list_overrides()

    def test_fifo_store_is_rejected_without_blocking(self, tmp_path):
        path = tmp_path / "override.fifo"
        os.mkfifo(path)
        with pytest.raises(fw.FlagWorkflowError, match="regular file"):
            fw.OverrideStore(path).list_overrides()

    def test_symlinked_store_parent_is_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        state_link = tmp_path / "state"
        os.symlink(outside, state_link)
        store = fw.OverrideStore(state_link / "overrides.json")

        with pytest.raises(fw.FlagWorkflowError, match="unavailable"):
            store.list_overrides()
        assert list(outside.iterdir()) == []

    @pytest.mark.parametrize(
        "payload",
        [
            [],
            {},
            {"overrides": {}, "suppressed": {}},
            {
                "overrides": {},
                "suppressed": {},
                "last_automation": {},
                "unexpected": {},
            },
            {
                "overrides": [],
                "suppressed": {},
                "last_automation": {},
            },
            {
                "overrides": {fw.sha256_hex("ref"): []},
                "suppressed": {},
                "last_automation": {},
            },
            {
                "overrides": {},
                "suppressed": {},
                "last_automation": [],
            },
        ],
    )
    def test_invalid_mapping_shapes_fail_closed(self, tmp_path, payload):
        path = tmp_path / "o.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(fw.FlagWorkflowError, match="corrupt"):
            fw.OverrideStore(path).list_overrides()

    @staticmethod
    def _active_override(ref):
        return {
            "ref_digest": ref,
            "detected_at": "2026-08-27T12:00:00+00:00",
            "automation_expected_state": "red",
            "human_observed_state": "gray",
            "suppressed": True,
            "unlocked_at": None,
            "unlock_actor": None,
        }

    @pytest.mark.parametrize(
        "case",
        [
            "active_missing_suppression",
            "orphan_suppression",
            "active_with_unlock_fields",
            "unlocked_missing_audit",
            "unlocked_naive_timestamp",
            "unlocked_empty_actor",
            "unlocked_still_suppressed",
        ],
    )
    def test_inconsistent_override_lifecycle_fails_closed(
            self, tmp_path, case):
        ref = fw.sha256_hex("ref")
        record = self._active_override(ref)
        payload = {
            "overrides": {ref: record},
            "suppressed": {ref: True},
            "last_automation": {},
        }
        if case == "active_missing_suppression":
            payload["suppressed"] = {}
        elif case == "orphan_suppression":
            payload["overrides"] = {}
        elif case == "active_with_unlock_fields":
            record["unlocked_at"] = "2026-08-27T12:01:00+00:00"
            record["unlock_actor"] = "operator"
        else:
            record["suppressed"] = False
            payload["suppressed"] = {}
            if case == "unlocked_naive_timestamp":
                record["unlocked_at"] = "2026-08-27T12:01:00"
                record["unlock_actor"] = "operator"
            elif case == "unlocked_empty_actor":
                record["unlocked_at"] = "2026-08-27T12:01:00+00:00"
                record["unlock_actor"] = ""
            elif case == "unlocked_still_suppressed":
                record["unlocked_at"] = "2026-08-27T12:01:00+00:00"
                record["unlock_actor"] = "operator"
                payload["suppressed"] = {ref: True}

        path = tmp_path / "o.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(fw.FlagWorkflowError):
            fw.OverrideStore(path).list_overrides()

    def test_store_wide_lock_preserves_concurrent_distinct_updates(
            self, tmp_path):
        path = tmp_path / "o.json"
        references = [fw.sha256_hex(f"ref-{index}") for index in range(32)]

        def record(reference):
            fw.OverrideStore(path).detect_override(reference, "red", "gray")

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(record, references))

        store = fw.OverrideStore(path)
        assert set(store.list_overrides()) == set(references)
        assert all(store.is_suppressed(reference) for reference in references)
        assert oct(os.stat(path).st_mode)[-3:] == "600"
        assert not list(tmp_path.glob(".tmp-o.json-*"))


class TestRollbackReceipt:
    @staticmethod
    def _receipt():
        return fw.RollbackReceipt.create(
            fw.sha256_hex("plan"),
            [fw.RollbackEntry(
                ref_digest=fw.sha256_hex("r"),
                pre_apply_native_index=0,
                pre_apply_flag=FlagColor.RED,
                automation_applied_flag=FlagColor.ORANGE,
            )],
        )

    @staticmethod
    def _rehash(raw):
        raw["content_hash"] = fw.sha256_hex({
            key: value for key, value in raw.items()
            if key != "content_hash"
        })

    def test_create_validate_roundtrip(self):
        receipt = self._receipt()
        receipt.validate()
        restored = fw.RollbackReceipt.from_dict(receipt.to_dict())
        assert restored.plan_hash == receipt.plan_hash

    def test_tamper_rejected(self):
        entries = [fw.RollbackEntry(
            ref_digest=fw.sha256_hex("r"),
            pre_apply_native_index=-1,
            pre_apply_flag=FlagColor.NO_FLAG,
            automation_applied_flag=FlagColor.BLUE,
        )]
        receipt = fw.RollbackReceipt.create(fw.sha256_hex("p"), entries)
        raw = receipt.to_dict()
        raw["entries"][0]["pre_apply_native_index"] = 6
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.RollbackReceipt.from_dict(raw)

    @pytest.mark.parametrize("bad_index", [True, "0", 0.0])
    def test_recomputed_receipt_rejects_untyped_native_index(
            self, bad_index):
        raw = self._receipt().to_dict()
        raw["entries"][0]["pre_apply_native_index"] = bad_index
        self._rehash(raw)
        with pytest.raises(fw.FlagWorkflowError,
                           match="pre_apply_native_index"):
            fw.RollbackReceipt.from_dict(raw)

    def test_recomputed_receipt_rejects_native_flag_mismatch(self):
        raw = self._receipt().to_dict()
        raw["entries"][0]["pre_apply_native_index"] = 6
        self._rehash(raw)
        with pytest.raises(fw.FlagWorkflowError, match="disagree"):
            fw.RollbackReceipt.from_dict(raw)

    @pytest.mark.parametrize("unknown_index", [None, 99])
    def test_recomputed_receipt_rejects_unknown_pre_apply_state(
            self, unknown_index):
        raw = self._receipt().to_dict()
        raw["entries"][0]["pre_apply_native_index"] = unknown_index
        raw["entries"][0]["pre_apply_flag"] = "unknown"
        self._rehash(raw)
        with pytest.raises(fw.FlagWorkflowError, match="not rollbackable"):
            fw.RollbackReceipt.from_dict(raw)

    @pytest.mark.parametrize("field,value", [
        ("created_at", "not-a-timestamp"),
        ("receipt_id", "rb-short"),
    ])
    def test_recomputed_receipt_rejects_malformed_metadata(
            self, field, value):
        raw = self._receipt().to_dict()
        raw[field] = value
        self._rehash(raw)
        with pytest.raises(fw.FlagWorkflowError):
            fw.RollbackReceipt.from_dict(raw)

    def test_recomputed_receipt_rejects_noncanonical_flag_alias(self):
        raw = self._receipt().to_dict()
        raw["entries"][0]["automation_applied_flag"] = "grey"
        self._rehash(raw)
        with pytest.raises(fw.FlagWorkflowError, match="non-canonical"):
            fw.RollbackReceipt.from_dict(raw)

    def test_recomputed_receipt_rejects_unknown_nested_key(self):
        raw = self._receipt().to_dict()
        raw["entries"][0]["provider_id"] = "private"
        self._rehash(raw)
        with pytest.raises(fw.FlagWorkflowError, match="schema"):
            fw.RollbackReceipt.from_dict(raw)

    def test_recomputed_receipt_rejects_duplicate_references(self):
        raw = self._receipt().to_dict()
        raw["entries"].append(dict(raw["entries"][0]))
        raw["entries"][1]["automation_applied_flag"] = "blue"
        self._rehash(raw)
        with pytest.raises(fw.FlagWorkflowError, match="duplicated"):
            fw.RollbackReceipt.from_dict(raw)


class TestLegacyPolicyContract:
    """Commit 5: the legacy heuristic is REPLACED; this suite now pins the
    evidence-classifier contract (deterministic, review-gated, no fake
    confidence, legacy color never drives semantics)."""

    def test_all_proposals_carry_measured_confidence(self):
        for sender, subject, observed in [
            ("recruiter@x.com", "job opportunity", FlagColor.RED),
            ("a@b.com", "", FlagColor.RED),
            ("c@d.com", "meeting scheduled", FlagColor.RED),
            ("e@f.com", "", FlagColor.PURPLE),
        ]:
            p = propose(sender, subject, observed)
            if not p.is_identity:
                # Confidence is always a real measured number now.
                assert isinstance(p.confidence, float)
                assert 0.0 <= p.confidence <= 1.0
                if p.confidence < 0.80:      # below AUTO threshold
                    assert p.review_required is True

    def test_reason_codes_are_deterministic_and_case_insensitive(self):
        p1 = propose("recruiter@x.com", "Please choose an interview slot",
                     FlagColor.RED)
        p2 = propose("RECRUITER@X.COM", "PLEASE CHOOSE AN INTERVIEW SLOT",
                     FlagColor.NO_FLAG)
        assert p1.reason_code == p2.reason_code
        assert p1.proposed_flag == p2.proposed_flag == FlagColor.ORANGE
        p3 = propose("nothing@matches.here", "no signals at all", FlagColor.RED)
        assert p3.reason_code == RC_LOW_CONFIDENCE_PURPLE


class TestEstateEnumeration:
    """Multi-surface enumeration: discovery fallback, dedupe, partial."""

    class _Surface:
        def __init__(self, account, mailbox, path_components=None):
            self.account, self.mailbox = account, mailbox
            self.path_components = path_components

    class _Provider:
        name = "mailapp"

        def __init__(self, surfaces, results=None):
            self._surfaces = surfaces
            self._results = results or {}
            self.discover_called = False

        def discover_surfaces(self):
            self.discover_called = True
            return self._surfaces

        def enumerate_flagged(self, mailbox, limit=500, since_days=None,
                              timeout_seconds=600, account=None,
                              mailbox_path=None):
            del mailbox_path
            for s in self._surfaces:
                if s.mailbox == mailbox and s.account == account and \
                        (s.account, s.mailbox) in self._results:
                    return self._results[(s.account, s.mailbox)]
            raise RuntimeError(f"unexpected surface {account}/{mailbox}")

    @staticmethod
    def _result(rows, hidden=0, errors=None, inaccessible=0,
                scope_complete=True, timeouts=0):
        from providers.mailapp import EnumerationResult
        return EnumerationResult.build(
            rows=rows, scope_complete=scope_complete,
            errors=list(errors or []), inaccessible_count=inaccessible,
            timeout_count=timeouts, unknown_index_count=0,
            hidden_by_limit=hidden,
            scanned_boundary={"total_flagged_seen": (
                                  len(rows) + hidden + inaccessible),
                              "hidden_by_limit": hidden,
                              "account": rows[0].account if rows else "?",
                              "mailbox": rows[0].mailbox if rows else "?"},
        )

    @staticmethod
    def _trow(pid, account, mailbox, color=FlagColor.RED):
        from types import SimpleNamespace
        return SimpleNamespace(
            provider_id=pid, account=account, mailbox=mailbox,
            sender="s@x.com", subject="S", native_index=_native(color),
            flag_color=color, received_iso=None)

    def test_discovers_surfaces_when_none_given(self):
        surfaces = [self._Surface("a@x", "INBOX")]
        prov = self._Provider(surfaces, {("a@x", "INBOX"): self._result([])})
        out = fw.enumerate_estate(prov)
        assert prov.discover_called is True
        # One real, cleanly-scanned, genuinely-empty surface IS complete.
        assert out["estate_complete"] is True

    def test_legacy_surface_omits_optional_mailbox_path_keyword(self):
        surface = self._Surface("a@x", "INBOX")
        result = self._result([])

        class LegacyProvider(self._Provider):
            def enumerate_flagged(self, mailbox, limit=500, since_days=None,
                                  timeout_seconds=600, account=None):
                return result

        out = fw.enumerate_estate(LegacyProvider([surface]))
        assert out["estate_complete"] is True

    def test_zero_discovered_surfaces_is_not_complete(self):
        """Discovery returning nothing must NOT masquerade as a clean estate."""
        prov = self._Provider([], {})
        out = fw.enumerate_estate(prov)
        assert out["estate_complete"] is False
        # 4b #1: zero surfaces means NOTHING was scanned — that is a FAILED
        # scan with an explicit reason, never "bounded_partial".
        assert out["status"] == "failed"
        assert any(
            "discovery returned zero surfaces" in e for e in out["errors"]
        )
        snap = fw.build_estate_snapshot(out, provider_name="mailapp")
        assert snap.status == "failed"
        with pytest.raises(fw.FlagWorkflowError, match="refusing"):
            fw.build_plan(snap)

    def test_discovery_failure_yields_typed_aggregate_never_crashes(self):
        """4b #1: a raising discover_surfaces() must produce a typed FAILED
        aggregate, not propagate out of enumerate_estate."""
        class ExplodingDiscovery(self._Provider):
            def discover_surfaces(self):
                raise RuntimeError("osascript exited 1: not authorised")

        out = fw.enumerate_estate(ExplodingDiscovery([], {}))
        assert out["estate_complete"] is False
        assert out["status"] == "failed"
        assert out["surfaces"] == []
        assert any(
            e.startswith("discovery_failed:") for e in out["errors"]
        )
        snap = fw.build_estate_snapshot(out, provider_name="mailapp")
        assert snap.complete is False and snap.status == "failed"
        with pytest.raises(fw.FlagWorkflowError, match="refusing"):
            fw.build_plan(snap)

    def test_discovery_error_without_timeout_words_still_failed(self):
        """Classification is structural/textual-agnostic: a discovery error
        containing no 'timed out' text still lands as failed."""
        class WeirdDiscovery(self._Provider):
            def discover_surfaces(self):
                raise RuntimeError("bridge hiccup -42")

        out = fw.enumerate_estate(WeirdDiscovery([], {}))
        assert out["status"] == "failed"

    def test_cross_surface_duplicates_removed_by_ref_digest(self):
        s1 = self._Surface("a@x", "INBOX")
        s2 = self._Surface("b@y", "INBOX")
        results = {
            ("a@x", "INBOX"): self._result([self._trow("7", "a@x", "INBOX")]),
            ("b@y", "INBOX"): self._result([self._trow("7", "b@y", "INBOX")]),
        }
        # Same provider_id on DIFFERENT accounts is NOT a duplicate.
        out = fw.enumerate_estate(self._Provider([s1, s2], results))
        assert len(out["rows"]) == 2
        assert out["deduplicated_removed"] == 0

        same_acct = [self._Surface("a@x", "INBOX"), self._Surface("a@x", "Archive")]
        results2 = {
            ("a@x", "INBOX"): self._result([self._trow("7", "a@x", "INBOX")]),
            ("a@x", "Archive"): self._result([self._trow("7", "a@x", "INBOX")]),
        }
        out2 = fw.enumerate_estate(self._Provider(same_acct, results2))
        assert len(out2["rows"]) == 1
        assert out2["deduplicated_removed"] == 1

    def test_failed_surface_breaks_estate_completeness(self):
        s_ok = self._Surface("a@x", "INBOX")
        s_bad = self._Surface("b@y", "INBOX")

        class ExplodesForB(self._Provider):
            def __init__(self):
                super().__init__(
                    [s_ok, s_bad],
                    {("a@x", "INBOX"): TestEstateEnumeration._result([])})

            def enumerate_flagged(self, mailbox="INBOX", limit=500,
                                  since_days=None, timeout_seconds=600,
                                  account=None, mailbox_path=None):
                del mailbox_path
                if account == "b@y":
                    raise RuntimeError("AppleScript timed out")
                return self._results[("a@x", "INBOX")]

        out = fw.enumerate_estate(ExplodesForB(), per_surface_limit=10)
        assert out["estate_complete"] is False
        assert out["status"] in ("failed", "timed_out")
        assert any("b@y" in e for e in out["errors"])

    def test_hidden_rows_anywhere_break_completeness(self):
        s1 = self._Surface("a@x", "INBOX")
        s2 = self._Surface("a@x", "Archive")
        results = {
            ("a@x", "INBOX"): self._result([]),
            ("a@x", "Archive"): self._result(
                [self._trow("9", "a@x", "Archive")], hidden=4),
        }
        out = fw.enumerate_estate(self._Provider([s1, s2], results))
        assert out["estate_complete"] is False
        assert out["hidden_by_limit_total"] == 4
        snap = fw.build_estate_snapshot(out, provider_name="mailapp")
        assert snap.status == "bounded_partial"
        with pytest.raises(fw.FlagWorkflowError, match="refusing"):
            fw.build_plan(snap)

    def test_clean_multi_surface_estate_is_plan_eligible(self):
        s1 = self._Surface("a@x", "INBOX")
        s2 = self._Surface("a@x", "Archive")
        results = {
            ("a@x", "INBOX"): self._result([self._trow("1", "a@x", "INBOX")]),
            ("a@x", "Archive"): self._result([self._trow("2", "a@x", "Archive")]),
        }
        out = fw.enumerate_estate(
            self._Provider([s1, s2], results),
            per_surface_limit=25,
            since_days=30,
        )
        assert out["estate_complete"] is True
        snap = fw.build_estate_snapshot(out, provider_name="mailapp")
        assert snap.limit == 25
        assert snap.since_days == 30
        plan = fw.build_plan(snap)      # must not raise
        assert plan["schema"] == fw.PLAN_SCHEMA

    def test_inaccessible_only_estate_is_canonical_partial(self):
        surface = self._Surface("a@x", "INBOX")
        result = self._result([], inaccessible=1, scope_complete=True)
        out = fw.enumerate_estate(
            self._Provider([surface], {("a@x", "INBOX"): result})
        )
        assert out["scope_complete"] is True
        assert out["estate_complete"] is False
        assert out["status"] == "partial"
        snapshot = fw.build_estate_snapshot(out, provider_name="mailapp")
        assert snapshot.scope_complete is True
        assert snapshot.status == "partial"

    def test_hidden_rows_preserve_aggregate_scope_complete(self):
        surface = self._Surface("a@x", "INBOX")
        result = self._result([], hidden=2, scope_complete=True)
        out = fw.enumerate_estate(
            self._Provider([surface], {("a@x", "INBOX"): result})
        )
        assert out["scope_complete"] is True
        assert out["status"] == "bounded_partial"
        snapshot = fw.build_estate_snapshot(out, provider_name="mailapp")
        assert snapshot.scope_complete is True

    def test_nested_surface_passes_exact_path_components(self):
        surface = self._Surface(
            "a@x", "Projects/PRs", ("Projects", "PRs")
        )
        result = self._result([])

        class CapturingProvider(self._Provider):
            def __init__(self):
                super().__init__(
                    [surface], {("a@x", "Projects/PRs"): result}
                )
                self.mailbox_paths = []

            def enumerate_flagged(self, *args, mailbox_path=None, **kwargs):
                self.mailbox_paths.append(mailbox_path)
                return super().enumerate_flagged(
                    *args, mailbox_path=mailbox_path, **kwargs
                )

        provider = CapturingProvider()
        fw.enumerate_estate(provider)
        assert provider.mailbox_paths == [("Projects", "PRs")]

    def test_unknown_count_recomputed_after_estate_deduplication(self):
        inbox = self._Surface("a@x", "INBOX")
        archive = self._Surface("a@x", "Archive")
        duplicate = self._trow(
            "7", "a@x", "INBOX", color=FlagColor.UNKNOWN
        )
        results = {
            ("a@x", "INBOX"): self._result([duplicate]),
            ("a@x", "Archive"): self._result([duplicate]),
        }
        out = fw.enumerate_estate(
            self._Provider([inbox, archive], results)
        )
        assert len(out["rows"]) == 1
        assert out["deduplicated_removed"] == 1
        assert out["unknown_index_count"] == 1
