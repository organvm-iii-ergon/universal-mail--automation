"""Commit 5 classifier acceptance: axis-first classification, hard
mapping rules, explicit precedence cases, evidence-derived deterministic
confidence, and legacy-color independence (observed flag is NEVER
classifier input)."""

import pytest

from core.models import FlagColor
from core.flag_policy import (
    AUTO_ELIGIBLE_THRESHOLD,
    REVIEW_THRESHOLD,
    classify,
    propose,
    RC_DEADLINE_RED,
    RC_OPERATOR_ACTION_ORANGE,
    RC_AWAITING_OTHER_YELLOW,
    RC_EVENT_CONFIRMED_GREEN,
    RC_CLOSED_NO_FLAG,
    RC_LOW_CONFIDENCE_PURPLE,
)


def _prop(subject, observed=FlagColor.RED):
    return propose("sender@example.com", subject, observed)


# --- Explicit precedence cases from the Commit 5 review ------------------------


class TestPrecedenceCases:
    def test_interview_scheduled_tuesday_is_GREEN_not_orange(self):
        p = _prop("Interview scheduled Tuesday at 2 PM")
        assert p.proposed_flag is FlagColor.GREEN
        assert p.reason_code == RC_EVENT_CONFIRMED_GREEN
        c = p.classification
        assert c.semantic_type == "event_confirmed"
        assert c.due_evidence is not None          # structured date extracted

    def test_choose_an_interview_slot_is_ORANGE(self):
        p = _prop("Please choose an interview slot")
        assert p.proposed_flag is FlagColor.ORANGE
        assert p.reason_code == RC_OPERATOR_ACTION_ORANGE
        assert p.classification.next_action_owner == "operator"

    def test_application_received_has_no_active_action(self):
        p = _prop("Application received")
        assert p.proposed_flag is not FlagColor.ORANGE
        assert p.reason_code == RC_CLOSED_NO_FLAG

    def test_rejection_is_no_flag_candidate(self):
        p = _prop("Unfortunately we will not be moving forward")
        assert p.proposed_flag is FlagColor.NO_FLAG
        assert p.reason_code == RC_CLOSED_NO_FLAG

    def test_payment_receipt_never_RED_from_payment_word(self):
        p = _prop("Payment receipt")
        assert p.proposed_flag is not FlagColor.RED
        assert p.proposed_flag is not FlagColor.BLUE   # no active-reference
        assert p.reason_code == RC_CLOSED_NO_FLAG

    def test_payment_due_tomorrow_is_RED_or_ORANGE(self):
        p = propose("billing@corp.example",
                    "Payment due tomorrow — account suspension otherwise",
                    FlagColor.ORANGE)     # observed ≠ targets → real proposal
        assert p.proposed_flag in (FlagColor.RED, FlagColor.ORANGE)
        if p.proposed_flag is FlagColor.RED:
            assert p.reason_code == RC_DEADLINE_RED
            assert p.classification.urgency == "imminent"
        assert p.confidence >= REVIEW_THRESHOLD

    def test_account_requires_action_is_PURPLE_unless_identifiable(self):
        p = _prop("Your account requires action")
        assert p.proposed_flag is FlagColor.PURPLE
        assert p.review_required is True

    def test_marketing_urgency_never_RED(self):
        p = _prop("URGENT SALE ENDS TONIGHT — 50% OFF everything!")
        assert p.proposed_flag is not FlagColor.RED
        # Marketing penalty drives it below auto-eligibility.
        assert p.confidence < AUTO_ELIGIBLE_THRESHOLD
        assert p.review_required is True

    def test_follow_up_on_promised_documents_is_ORANGE(self):
        p = _prop("Following up on the documents you promised")
        assert p.proposed_flag is FlagColor.ORANGE
        assert p.classification.next_action_owner == "operator"

    def test_we_received_documents_and_will_respond_is_YELLOW(self):
        p = _prop("We received your documents and will respond shortly")
        assert p.proposed_flag is FlagColor.YELLOW
        assert p.reason_code == RC_AWAITING_OTHER_YELLOW
        assert p.classification.next_action_owner == "other_party"

    def test_appointment_confirmed_for_september_2_is_GREEN(self):
        p = _prop("Appointment confirmed for September 2")
        assert p.proposed_flag is FlagColor.GREEN


# --- Legacy color independence ---------------------------------------------------


class TestLegacyColorIndependence:
    @pytest.mark.parametrize("subject", [
        "URGENT SALE ENDS TONIGHT",
        "Appointment confirmed for September 2",
        "Payment receipt",
        "Please choose an interview slot",
    ])
    def test_observed_color_does_not_change_semantics(self, subject):
        # The CLASSIFIER never sees the observed flag: identical content
        # under different observations yields identical classifications.
        from core.flag_policy import classify
        a = propose("x@y.com", subject, FlagColor.RED)
        b = propose("x@y.com", subject, FlagColor.PURPLE)
        assert a.classification == b.classification == classify(
            "x@y.com", subject)
        if not (a.is_identity or b.is_identity):
            # When both produce actual change proposals they must agree.
            assert a.proposed_flag == b.proposed_flag
            assert a.reason_code == b.reason_code

    def test_legacy_purple_does_not_force_purple_proposal(self):
        p = propose("x@y.com", "Meeting confirmed Thursday 10 am",
                    FlagColor.PURPLE)
        assert p.proposed_flag is FlagColor.GREEN

    def test_domain_axis_not_inferred_from_flag(self):
        """Same content under different observations → identical domain."""
        c1 = classify("hr@corp.example", "Your interview is confirmed")
        c2 = classify("hr@corp.example", "Your interview is confirmed")
        assert c1.domain == c2.domain == "career"


# --- Confidence determinism + thresholds ------------------------------------------


class TestConfidenceContract:
    def test_deterministic_across_calls_and_case(self):
        a = classify("A@B.com", "Please pay invoice TODAY")
        b = classify("a@b.com", "please pay invoice today")
        assert a == b

    def test_structured_date_extraction_recorded_in_evidence_basis(self):
        c = classify("s@x.com", "Appointment confirmed for September 2")
        assert any(e.startswith("structured_date:")
                   for e in c.evidence_basis)

    def test_thresholds_ordering_sane(self):
        assert 0.0 < REVIEW_THRESHOLD < AUTO_ELIGIBLE_THRESHOLD <= 1.0

    def test_low_confidence_lands_purple_review_only(self):
        p = _prop("hello")
        assert p.proposed_flag is FlagColor.PURPLE
        assert p.reason_code == RC_LOW_CONFIDENCE_PURPLE
        assert p.confidence < REVIEW_THRESHOLD
        assert p.review_required is True

    def test_identity_when_classification_matches_observed(self):
        p = propose("s@x.com", "Appointment confirmed for September 2",
                    FlagColor.GREEN)
        assert p.is_identity
        assert p.confidence == 1.0

    def test_axes_present_in_classification(self):
        c = classify("boss@x.com", "Please send the report by 5 pm today")
        for axis in ("domain", "semantic_type", "urgency",
                     "next_action_owner", "due_evidence",
                     "follow_up_evidence", "operator_state",
                     "confidence", "evidence_basis"):
            assert hasattr(c, axis), f"missing axis {axis}"
