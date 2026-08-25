"""Commit 5 acceptance: artifact-only planning, snapshot SEMANTIC
validation (hash-valid ≠ semantically valid), durable plan bindings,
public-safe plan projection, and immutable policy digest binding."""

import json
from types import SimpleNamespace

import pytest

import cli
from core import flag_workflow as fw
from core.models import FlagColor
from providers.mailapp import mailapp_index_from_flag


def _native(color):
    return None if color == FlagColor.UNKNOWN else mailapp_index_from_flag(color)


def _row(pid, sender="a@b.com", subject="Hi", color=FlagColor.RED,
         account="acct", mailbox="INBOX", received_iso=None):
    return SimpleNamespace(
        provider_id=pid, account=account, mailbox=mailbox,
        sender=sender, subject=subject, native_index=_native(color),
        flag_color=color, received_iso=received_iso)


def _complete_snapshot():
    return fw.build_snapshot(
        provider_name="mailapp", account="acct", mailbox="INBOX",
        rows=[
            _row("1", "recruiter@x.com", "Please choose an interview slot",
                 FlagColor.RED),
            _row("2", "shop@x.com", "Your order has shipped",
                 FlagColor.ORANGE),
        ],
        complete=True, scope_complete=True, status="complete",
        errors=[], inaccessible_count=0, timeout_count=0,
        unknown_index_count=0, limit=500, since_days=None,
        total_matched=2, returned_count=2, hidden_by_limit=0,
    )


def _write_snapshot_file(snapshot, tmp_path):
    return fw.write_private_snapshot(snapshot, tmp_path / "snaps")


# --- Artifact-only planning ----------------------------------------------------


class TestPlanIsArtifactOnly:
    def test_plan_succeeds_with_every_live_PATH_poisoned(self,
                                                          monkeypatch,
                                                          tmp_path,
                                                          capsys):
        """THE hard test: every provider/enumeration symbol raises; the
        artifact-only planner must not touch any of them."""
        def _poison(*a, **k):
            raise AssertionError("live provider path was touched")

        monkeypatch.setattr(cli, "get_provider", _poison)
        from providers import mailapp
        monkeypatch.setattr(mailapp.MailAppProvider, "enumerate_flagged",
                            _poison)
        monkeypatch.setattr(mailapp.MailAppProvider, "__init__",
                            lambda self, *a, **k: _poison())
        monkeypatch.setattr(fw, "enumerate_estate", _poison)

        snap_file = _write_snapshot_file(_complete_snapshot(), tmp_path)
        out = tmp_path / "plan.json"
        args = type("Args", (), {})()
        args.snapshot = str(snap_file)
        args.output = str(out)
        rc = cli.cmd_flags_plan(args)
        assert rc == 0
        assert out.exists()
        plan = json.loads(out.read_text())
        assert plan["schema"] == fw.PLAN_SCHEMA
        assert plan["zero_write_declaration"] is True
        assert "provider was" not in capsys.readouterr().out

    def test_missing_snapshot_arg_fails_parsing(self, monkeypatch):
        """No backwards-compatible live fallback: bare `flags plan` cannot
        even be parsed (argparse required=True → SystemExit 2)."""
        import sys as _sys
        monkeypatch.setattr(
            _sys, "argv",
            ["prog", "flags", "plan", "--output", "/tmp/x.json"])
        with pytest.raises(SystemExit) as exc:
            cli.main()
        assert exc.value.code != 0

    def test_handler_refuses_without_snapshot_attribute(self, capsys):
        args = type("Args", (), {})()
        args.output = "/tmp/x.json"
        rc = cli.cmd_flags_plan(args)
        assert rc == 2
        assert "--snapshot is required" in capsys.readouterr().err

    def test_missing_snapshot_file_exit_1(self, capsys, tmp_path):
        args = type("Args", (), {})()
        args.snapshot = str(tmp_path / "nope.json")
        args.output = str(tmp_path / "plan.json")
        rc = cli.cmd_flags_plan(args)
        assert rc == 1

    def test_tampered_snapshot_exit_20(self, capsys, tmp_path):
        snap_file = _write_snapshot_file(_complete_snapshot(), tmp_path)
        raw = json.loads(snap_file.read_text())
        raw["total_scanned"] = 999          # breaks content hash
        snap_file.write_text(json.dumps(raw))
        args = type("Args", (), {})()
        args.snapshot = str(snap_file)
        args.output = str(tmp_path / "plan.json")
        rc = cli.cmd_flags_plan(args)
        assert rc == 20


# --- Snapshot SEMANTIC validation -----------------------------------------------


class TestSnapshotSemanticValidation:
    """An attacker (or buggy producer) can recompute a VALID content hash
    over IMPOSSIBLE content — load_snapshot must reject it regardless."""

    def _attacked(self, tmp_path, **mutations):
        d = _complete_snapshot().to_dict()
        d.pop("content_hash")
        d.update(mutations)
        d["content_hash"] = fw.sha256_hex(d)      # attacker recomputes!
        p = tmp_path / "evil.json"
        p.write_text(json.dumps(d))
        return p

    def _expect_reject(self, tmp_path, match, **mutations):
        p = self._attacked(tmp_path, **mutations)
        with pytest.raises(fw.FlagWorkflowError, match=match):
            fw.load_snapshot(p)

    def test_complete_with_errors_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "errors are recorded",
                            errors=["boom"], status="complete")

    def test_complete_with_hidden_rows_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "hidden by limit",
                            hidden_by_limit=7, status="bounded_partial")

    def test_complete_with_inaccessible_rows_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "inaccessible rows",
                            inaccessible_count=3)

    def test_complete_with_timeouts_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "after timeout", timeout_count=1)

    def test_complete_status_mismatch_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "requires status 'complete'",
                            status="partial")

    def test_returned_count_mismatch_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "returned_count", returned_count=5)

    def test_total_matched_below_returned_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "total_matched", total_matched=1)

    def test_unknown_count_inconsistent_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "unknown_index_count",
                            unknown_index_count=2)

    def test_native_semantic_combo_invalid_rejected(self, tmp_path):
        d = _complete_snapshot().to_dict()
        d.pop("content_hash")
        d["messages"][0]["native_index"] = None       # RED w/o native index
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / "combo.json"
        p.write_text(json.dumps(d))
        with pytest.raises(fw.FlagWorkflowError,
                           match="inconsistent with observed_flag"):
            fw.load_snapshot(p)

    def test_duplicate_qualified_refs_rejected(self, tmp_path):
        d = _complete_snapshot().to_dict()
        d.pop("content_hash")
        dup = dict(d["messages"][0])
        d["messages"].append(dup)                     # same qualified ref twice
        d["returned_count"] = len(d["messages"])
        d["total_matched"] = len(d["messages"])
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / "dup.json"
        p.write_text(json.dumps(d))
        with pytest.raises(fw.FlagWorkflowError, match="duplicate qualified"):
            fw.load_snapshot(p)

    def test_zero_write_mode_false_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "zero_write_mode",
                            zero_write_mode=False)

    def test_valid_snapshot_still_loads(self, tmp_path):
        p = _write_snapshot_file(_complete_snapshot(), tmp_path)
        snap = fw.load_snapshot(p)
        assert snap.complete is True and len(snap.messages) == 2


# --- Durable plan bindings + policy digest ---------------------------------------


class TestPlanBindingsAndPolicyDigest:
    def test_mutations_carry_durable_private_bindings(self):
        snap = _complete_snapshot()
        plan = fw.build_plan(snap)
        m = plan["mutations"][0]
        assert m["provider"] == "mailapp"
        assert m["account"] == "acct"
        assert m["mailbox"] == "INBOX"
        assert m["provider_id"] in ("1", "2")
        assert m["snapshot_id"] == snap.snapshot_id
        assert m["observed_native_flag"] in set(
            mailapp_index_from_flag(c) for c in
            (FlagColor.RED, FlagColor.ORANGE))
        assert m["evidence_digest"] and len(m["evidence_digest"]) == 64

    def test_plan_hash_covers_private_bindings(self, tmp_path):
        """Tampering ANY private binding breaks plan_hash integrity."""
        plan = fw.build_plan(_complete_snapshot())
        plan["mutations"][0]["account"] = "evil"
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.validate_plan_schema(plan)

    def test_mutation_id_binds_evidence_and_snapshot(self):
        kw = dict(provider_name="mailapp", account="acct", mailbox="INBOX",
                  complete=True, scope_complete=True, status="complete",
                  errors=[], inaccessible_count=0, timeout_count=0,
                  unknown_index_count=0, limit=500, since_days=None,
                  total_matched=1, returned_count=1, hidden_by_limit=0)
        s1 = fw.build_snapshot(
            rows=[_row("9", received_iso="2026-01-01T00:00:00")],
            generated_at="2026-08-25T10:00:00+00:00", **kw)
        s2 = fw.build_snapshot(
            rows=[_row("9", received_iso="2026-02-02T00:00:00")],
            generated_at="2026-08-25T10:05:00+00:00", **kw)
        p1, p2 = fw.build_plan(s1), fw.build_plan(s2)
        assert p1["mutations"] and p2["mutations"]
        assert p1["mutations"][0]["mutation_id"] != \
            p2["mutations"][0]["mutation_id"]

    def test_policy_digest_participates_in_validation(self):
        plan = fw.build_plan(_complete_snapshot())
        # Attacker swaps digest AND recomputes plan_hash — still rejected:
        # version string alone would NOT catch this; the digest does.
        plan["policy_sha256"] = "f" * 64
        plan.pop("plan_hash")
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(fw.FlagWorkflowError, match="policy_sha256"):
            fw.validate_plan_schema(plan)

    def test_policy_digest_is_deterministic_and_matches_rules(self):
        from core.flag_policy import compute_policy_sha256
        assert compute_policy_sha256() == compute_policy_sha256()
        assert fw.POLICY_SHA256 == compute_policy_sha256()


# --- Public-safe plan projection ---------------------------------------------------


class TestPublicPlanProjection:
    def test_projection_contains_no_private_identity(self):
        plan = fw.build_plan(_complete_snapshot())
        pub = fw.to_public_safe_plan(plan)
        blob = json.dumps(pub)
        for secret in ('"acct"', '"INBOX"', '"provider_id"',
                       '"evidence_digest"', '"observed_native_flag"',
                       '"message_id_digest"', 'recruiter@', 'shop@'):
            assert secret not in blob, f"leaked {secret}"
        fw.validate_public_plan(pub)

    def test_projection_validator_rejects_injection_and_tamper(self):
        plan = fw.build_plan(_complete_snapshot())
        pub = fw.to_public_safe_plan(plan)
        injected = dict(pub, account="leak")
        with pytest.raises(fw.FlagWorkflowError, match="forbidden keys"):
            fw.validate_public_plan(injected)
        tampered = dict(pub)
        tampered["total_scanned"] = 999999
        with pytest.raises(fw.FlagWorkflowError, match="tampered"):
            fw.validate_public_plan(tampered)


# --- UNKNOWN observations never mutation-eligible ------------------------------


class TestUnknownNeverEligible:
    def test_unknown_observation_forces_review_even_when_confident(self):
        rows = [
            _row("7", "a@b.com", "Please send the signed contract tomorrow",
                 FlagColor.UNKNOWN),
        ]
        snap = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=rows, complete=False, scope_complete=False,
            status="bounded_partial", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=1, limit=500,
            since_days=None, total_matched=1, returned_count=1,
            hidden_by_limit=0,
        )
        with pytest.raises(fw.FlagWorkflowError):
            fw.build_plan(snap)     # incomplete anyway — plans need complete

        # Even a COMPLETE snapshot containing an UNKNOWN observation:
        rows2 = [
            _row("8", "a@b.com", "Please send the signed contract tomorrow",
                 FlagColor.RED),
            _row("9", "c@d.com", "Please pay today", FlagColor.UNKNOWN),
        ]
        snap2 = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=rows2, complete=True, scope_complete=True,
            status="complete", errors=[], inaccessible_count=0,
            timeout_count=0, unknown_index_count=1, limit=500,
            since_days=None, total_matched=2, returned_count=2,
            hidden_by_limit=0,
        )
        plan = fw.build_plan(snap2)
        by_pid = {m["provider_id"]: m for m in plan["mutations"]}
        assert by_pid["9"]["review_required"] is True   # forced, always
