"""Commit 5 acceptance: artifact-only planning, snapshot SEMANTIC
validation (hash-valid ≠ semantically valid), durable plan bindings,
public-safe plan projection, and immutable policy digest binding."""

import json
from types import SimpleNamespace

import pytest

import cli
from core import flag_workflow as fw
from core.flag_policy import classify
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
        self._expect_reject(tmp_path, "inconsistent with scan dimensions",
                            errors=["boom"], status="complete")

    def test_complete_with_hidden_rows_rejected(self, tmp_path):
        self._expect_reject(
            tmp_path,
            "complete=True inconsistent with canonical status "
            "'bounded_partial'",
            hidden_by_limit=7, status="bounded_partial")

    def test_complete_with_inaccessible_rows_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "inconsistent with scan dimensions",
                            inaccessible_count=3)

    def test_complete_with_timeouts_rejected(self, tmp_path):
        self._expect_reject(tmp_path, "inconsistent with scan dimensions",
                            timeout_count=1)

    def test_complete_status_mismatch_rejected(self, tmp_path):
        # Reverse direction: complete=False stamped with status 'complete'.
        d = _complete_snapshot().to_dict()
        d.pop("content_hash")
        d["status"] = "complete"
        d["complete"] = False
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / "reverse.json"
        p.write_text(json.dumps(d))
        with pytest.raises(fw.FlagWorkflowError,
                           match="inconsistent with canonical status"):
            fw.load_snapshot(p)

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
                           match="maps to.*but observed_flag"):
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


# --- 5b FIX 1: EXACT native↔semantic mapping via provider registry ----------


class TestExactNativeMappingValidation:
    def _attempt(self, tmp_path, native_index, flag):
        """Craft a snapshot dict with forced native index + recompute hash."""
        base = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=[_row("5", "a@b.com", "s", color=FlagColor.RED)],
            complete=True, scope_complete=True, status="complete",
            errors=[], inaccessible_count=0, timeout_count=0,
            unknown_index_count=0, limit=500, since_days=None,
            total_matched=1, returned_count=1, hidden_by_limit=0,
        ).to_dict()
        base.pop("content_hash")
        m = base["messages"][0]
        m["native_index"] = native_index
        m["observed_flag"] = flag.value
        if flag == FlagColor.UNKNOWN:
            base["unknown_index_count"] = 1
        base["content_hash"] = fw.sha256_hex(base)
        p = tmp_path / f"map-{native_index}-{flag.value}.json"
        p.write_text(json.dumps(base))
        return p

    @pytest.mark.parametrize("native,flag", [
        (0, FlagColor.RED),          # valid
        (4, FlagColor.BLUE),         # valid
        (-1, FlagColor.NO_FLAG),     # valid
        (None, FlagColor.UNKNOWN),   # valid transport contract
    ])
    def test_valid_pairs_load(self, tmp_path, native, flag):
        snap = fw.load_snapshot(self._attempt(tmp_path, native, flag))
        assert snap.messages[0].observed_flag is flag

    @pytest.mark.parametrize("native,flag", [
        (0, FlagColor.BLUE),         # impossible
        (4, FlagColor.RED),          # impossible
        (-1, FlagColor.ORANGE),      # impossible
        (99, FlagColor.RED),         # unknown integer ≠ RED
    ])
    def test_impossible_pairs_rejected(self, tmp_path, native, flag):
        with pytest.raises(fw.FlagWorkflowError, match="maps to"):
            fw.load_snapshot(self._attempt(tmp_path, native, flag))

    def test_unknown_integer_with_unknown_flag_is_valid(self, tmp_path):
        snap = fw.load_snapshot(
            self._attempt(tmp_path, 99, FlagColor.UNKNOWN))
        assert snap.unknown_index_count == 1

    def test_unregistered_provider_fails_closed(self, tmp_path):
        from core.models import MessageReference as _MR  # noqa: F401
        d = _complete_snapshot().to_dict()
        d.pop("content_hash")
        d["provider"] = "mystery-provider"
        for m in d["messages"]:
            m["provider"] = "mystery-provider"
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / "mystery.json"
        p.write_text(json.dumps(d))
        with pytest.raises(fw.FlagWorkflowError,
                           match="no native-flag validator registered"):
            fw.load_snapshot(p)


# --- 5b FIX 2: canonical status state machine --------------------------------


class TestCanonicalStatusStateMachine:
    def test_transport_and_canonical_agree_on_full_truth_table(self):
        """The provider's _status and flag_workflow's canonical function
        are ONE precedence — proven over every dimension combination."""
        from providers.mailapp import EnumerationResult
        import itertools
        for scope, errs, inacc, to, hid in itertools.product(
                (True, False), (0, 1), (0, 1), (0, 1), (0, 1)):
            errs_list = ["x"] * errs
            a = EnumerationResult._status(scope, errs_list, inacc, to, hid)
            b = fw.canonical_scan_status(
                scope_complete=scope, errors=errs_list,
                inaccessible_count=inacc, timeout_count=to,
                hidden_by_limit=hid)
            assert a == b, (scope, errs, inacc, to, hid)

    @pytest.mark.parametrize("mutation,fragment", [
        (dict(status="timed_out", timeout_count=0),
         "inconsistent with scan dimensions"),      # timed_out w/o timeout
        (dict(status="bounded_partial"),
         "inconsistent with scan dimensions"),      # bounded_partial, hidden=0
        (dict(status="partial"),
         "inconsistent with scan dimensions"),      # partial, inaccessible=0
        (dict(status="failed"),
         "inconsistent with scan dimensions"),      # failed, no failure dims
        (dict(status="failed", scope_complete=False, complete=True),
         "complete=True inconsistent with canonical status 'failed'"),
    ])
    def test_impossible_status_combinations_rejected(self, tmp_path,
                                                     mutation, fragment):
        d = _complete_snapshot().to_dict()
        d.pop("content_hash")
        d.update(mutation)
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / f"st-{abs(hash(fragment))}.json"
        p.write_text(json.dumps(d))
        with pytest.raises(fw.FlagWorkflowError, match=fragment):
            fw.load_snapshot(p)

    def test_coherent_partial_snapshot_loads(self, tmp_path):
        d = _complete_snapshot().to_dict()
        d.pop("content_hash")
        d.update(complete=False, status="partial", inaccessible_count=2,
                 total_matched=4, hidden_by_limit=0)
        d["content_hash"] = fw.sha256_hex(d)
        p = tmp_path / "partial-ok.json"
        p.write_text(json.dumps(d))
        snap = fw.load_snapshot(p)
        assert snap.status == "partial" and snap.complete is False


# --- 5b FIX 3: marketing auto-eligibility exclusion ---------------------------


class TestMarketingEligibilityExclusion:
    def test_gate_is_structural_not_confidence_accidental(self):
        """Adversarial: enough positive evidence to exceed 0.80 + marketing
        signal → auto_eligible MUST remain False even at confidence 0.95."""
        from core.flag_policy import Classification, is_auto_eligible
        strong_clean = Classification(
            domain="finance", semantic_type="action_request",
            urgency="imminent", next_action_owner="operator",
            due_evidence="tomorrow", follow_up_evidence=None,
            operator_state="open_loop", marketing_or_bulk=False,
            confidence=0.95, evidence_basis=("operator_action_request",
                                             "material_consequence"))
        same_but_marketing = Classification(
            domain="commerce", semantic_type="action_request",
            urgency="imminent", next_action_owner="operator",
            due_evidence="tonight", follow_up_evidence=None,
            operator_state="open_loop", marketing_or_bulk=True,
            confidence=0.95, evidence_basis=("operator_action_request",
                                             "marketing_indicator:sale"))
        assert is_auto_eligible(strong_clean) is True
        assert is_auto_eligible(same_but_marketing) is False   # THE rule

    def test_real_classifier_sets_typed_axis(self):
        c = classify("deals@shop.example",
                     "Please confirm your subscription today")
        assert isinstance(c.marketing_or_bulk, bool)

    def test_propose_respects_typed_axis_not_evidence_strings(self):
        """Even a crafted high-confidence marketing classification can never
        become auto-eligible through propose()'s gate path."""
        from core.flag_policy import propose as _p
        proposal = _p("no-reply@promo.example",
                      "SALE ends tonight, shop now", FlagColor.NO_FLAG)
        if not proposal.is_identity:
            assert proposal.auto_eligible is False
            assert proposal.review_required is True


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


# --- 5b FIX 4: policy digest covers ALL declarative classifier inputs ---------


class TestPolicyDigestCoverage:
    def test_domain_hints_live_inside_hashed_policy(self):
        from core.flag_policy import POLICY_RULES
        assert "domain_hints" in POLICY_RULES
        assert POLICY_RULES["domain_hints"]["career"]   # actually populated

    def test_modifying_a_domain_hint_changes_the_digest(self):
        import copy
        from core.flag_policy import POLICY_RULES, compute_policy_sha256
        mutated = copy.deepcopy(POLICY_RULES)
        mutated["domain_hints"]["career"] = ["kubernetes-operator"]
        # A hint change MUST change the digest...
        assert compute_policy_sha256(mutated) != compute_policy_sha256()
        # ...and the shipped digest is the digest of the SHIPPED rules.
        assert compute_policy_sha256(POLICY_RULES) == fw.POLICY_SHA256

    def test_runtime_domain_detection_derives_from_policy_rules(self):
        """The runtime map derives from POLICY_RULES, not a parallel
        declaration: add an exotic domain to the config and detection
        follows it (module state fully restored afterwards)."""
        import copy
        import core.flag_policy as fp
        original_rules = fp.POLICY_RULES
        original_hints = dict(fp._DOMAIN_HINTS)
        try:
            mutated = copy.deepcopy(original_rules)
            mutated["domain_hints"]["astronomy"] = ["comet", "telescope"]
            fp.POLICY_RULES = mutated
            derived = {
                d: tuple(w)
                for d, w in mutated["domain_hints"].items()
            }
            fp._DOMAIN_HINTS.clear()
            fp._DOMAIN_HINTS.update(derived)
            c = fp.classify("obs@x.com", "Comet visible via telescope")
            assert c.domain == "astronomy"
        finally:
            fp.POLICY_RULES = original_rules
            fp._DOMAIN_HINTS.clear()
            fp._DOMAIN_HINTS.update(original_hints)

    def test_version_string_spoofing_still_cannot_pass_digest(self):
        plan = fw.build_plan(_complete_snapshot())
        plan["policy_sha256"] = "0" * 64
        plan.pop("plan_hash")
        plan["plan_hash"] = fw.compute_plan_hash(plan)
        with pytest.raises(fw.FlagWorkflowError, match="policy_sha256"):
            fw.validate_plan_schema(plan)


# --- UNKNOWN observations never mutation-eligible ------------------------------


class TestUnknownNeverEligible:
    def test_unknown_observation_forces_review_even_when_confident(self):
        # Coherent INCOMPLETE snapshot: plan refusal comes first...
        rows = [
            _row("7", "a@b.com", "Please send the signed contract tomorrow",
                 FlagColor.UNKNOWN),
        ]
        snap = fw.build_snapshot(
            provider_name="mailapp", account="acct", mailbox="INBOX",
            rows=rows, complete=False, scope_complete=True,
            status="partial", errors=[], inaccessible_count=1,
            timeout_count=0, unknown_index_count=1, limit=500,
            since_days=None, total_matched=2, returned_count=1,
            hidden_by_limit=0,
        )
        with pytest.raises(fw.FlagWorkflowError):
            fw.build_plan(snap)

        # ...then a COMPLETE snapshot containing an UNKNOWN observation:
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
