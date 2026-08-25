"""Evidence-based seven-state migration classifier.

STATUS (Commit 5): replaces the legacy keyword heuristic wholesale. The
classifier evaluates INDEPENDENT AXES FIRST (domain, semantic_type,
urgency, next-action ownership, due/follow-up evidence, operator state)
and only THEN maps the classification to a flag. The observed legacy color
is NEVER classifier input — it is retained solely as migration context
(identity comparison happens after classification).

CONFIDENCE is additive/penalized and fully deterministic:

    base + strong deterministic signals (capped) + independent-axis
    confirmations + structured date extraction - ambiguous actor -
    conflicting signals - marketing/bulk indicators - missing context

Thresholds separate AUTO_ELIGIBLE (potentially mutation-eligible AFTER
Commit 6 approval+preflight; writes remain impossible in Commit 5),
REVIEW (displayed for human review), and below-REVIEW (PURPLE / human
judgment).

POLICY IMMUTABILITY: POLICY_RULES is the canonical machine-readable
statement of every threshold, weight, pattern id, and marker list used
below. POLICY_SHA256 = sha256(canonical_json(POLICY_RULES)) binds plans
to the exact rules that generated them; flag_workflow stamps it into the
plan hash so Commit 6 can reject approval if policy code/config changed
since planning. A bare human string like "v2" alone would NOT be
tamper-evident; the digest is.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, cast

from core.models import FlagColor

MIGRATION_POLICY_VERSION = "1.evidence-classifier.1"

AUTO_ELIGIBLE_THRESHOLD = 0.80
REVIEW_THRESHOLD = 0.55

# Deterministic reason codes — stable identifiers for receipts/plans.
RC_DEADLINE_RED = "deadline_evidence_red"
RC_OPERATOR_ACTION_ORANGE = "operator_action_owed_orange"
RC_AWAITING_OTHER_YELLOW = "awaiting_other_party_yellow"
RC_EVENT_CONFIRMED_GREEN = "event_confirmed_green"
RC_ACTIVE_REFERENCE_BLUE = "active_reference_blue"
RC_AMBIGUOUS_PURPLE = "ambiguous_purple"
RC_UNIDENTIFIABLE_ACTION_PURPLE = "unidentifiable_action_purple"
RC_LOW_CONFIDENCE_PURPLE = "low_confidence_purple"
RC_DEFERRED_GRAY = "deliberate_deferral_gray"
RC_CLOSED_NO_FLAG = "closed_no_open_loop_no_flag"
RC_NO_CHANGE = "no_change"

# --- Canonical rule configuration (digest-bound) ------------------------------

POLICY_RULES = {
    "version": MIGRATION_POLICY_VERSION,
    "thresholds": {
        "auto_eligible": AUTO_ELIGIBLE_THRESHOLD,
        "review": REVIEW_THRESHOLD,
    },
    "confidence": {
        "base": 0.30,
        "strong_signal": 0.20,
        "strong_signal_cap_count": 2,
        "independent_axis_bonus": 0.10,
        "independent_axis_cap": 0.20,
        "structured_date_extraction": 0.15,
        "penalty_ambiguous_actor": 0.25,
        "penalty_conflicting_signals": 0.20,
        "penalty_marketing_bulk": 0.30,
        "penalty_missing_context": 0.10,
    },
    # Urgency words ALONE are insufficient for RED (hard rule).
    "insufficient_alone_for_red": [
        "urgent", "important", "final notice", "action required",
        "payment", "billing",
    ],
    "marketing_indicators": [
        "sale", "% off", "discount", "limited time", "offer ends",
        "promo", "deals", "unsubscribe", "shop now",
    ],
    "material_consequence_markers": [
        "overdue", "past due", "final notice", "suspension",
        "late fee", "cancel your", "account will be closed",
        "legal action",
    ],
    "confirmed_event_patterns": [
        r"\b(confirmed|scheduled|booked)\b[^.?!]*\b"
        r"(appointment|meeting|interview|call|consultation|visit)\b",
        r"\b(appointment|meeting|interview|call|consultation|visit)\b"
        r"[^.?!]*\b(confirmed|scheduled|booked)\b",
        r"\bsee you (on|at)\b",
        r"\byour (appointment|interview|consultation) is\b",
    ],
    "operator_action_patterns": [
        r"\bplease (choose|send|provide|submit|reply|confirm|complete|"
        r"sign|upload|review|pay|register|respond)\b",
        r"\bwe need you to\b",
        r"\bcould you\b",
        r"\bcan you\b",
        r"\byou promised\b",
        r"\byou agreed to\b",
        r"\bkindly (send|provide|submit|confirm)\b",
        r"\blet us know\b",
        r"\brsvp\b",
        # Payment/schedule obligations owed BY the operator.
        r"\b(payment|invoice|amount|balance) is (now )?due\b",
        r"\bis due (today|tomorrow|by|on)\b",
        r"\bdue (today|tomorrow|tonight)\b",
        r"\bpayment due\b",
        r"\bdue date is\b",
    ],
    "other_party_action_patterns": [
        r"\bwe will respond\b",
        r"\bwe'?ll (get back|respond|follow up)\b",
        r"\bwe will follow up\b",
        r"\bis (now )?(being|under) (review|processed)\b",
        r"\bawaiting (internal|team|manager) review\b",
        r"\bwe (have )?received\b[^.?!]*\bwill\b",
        r"\bour team will\b",
    ],
    "closed_markers": [
        r"\bunfortunately\b",
        r"\bnot (be )?moving forward\b",
        r"\bregret to inform\b",
        r"\bposition has been filled\b",
        r"\bapplication has been (rejected|withdrawn|closed)\b",
        r"\bhas been cancelled\b",
        r"\breceipt\b",
        r"\bpayment received\b",
        r"\bwe have received your\b",
        # Bare confirmations of receipt: no open loop, nothing owed.
        r"\b(application|payment|documents?|request|form|submission) "
        r"(has been )?received\b",
        r"\border confirmed\b",
        r"\byour order has shipped\b",
        r"\bthank you for your (payment|order|application)\b",
    ],
    # BLUE requires ACTIVE-reference value; receipts alone never suffice.
    "active_reference_markers": [
        r"\btracking number\b",
        r"\bwarranty\b",
        r"\bfor your records\b",
        r"\bkeep (this|until)\b",
        r"\byou will need this\b",
        r"\breference number\b",
        r"\bbooking reference\b",
    ],
    "deferral_markers": [
        r"\bno rush\b",
        r"\bwhenever you (get a chance|can)\b",
        r"\bcircle back\b",
        r"\brevisit (this|in)\b",
        r"\bsomeday\b",
    ],
    "ambiguous_actor_markers": [
        r"\brequires action\b",
        r"\baction (is|required|may be) required\b",
        r"\bneeds attention\b",
        r"\bplease take action\b",
    ],
    # Structured date/deadline extraction patterns.
    "date_patterns": [
        r"\b(today|tonight|tomorrow)\b",
        r"\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b",
        r"\b(january|february|march|april|may|june|july|august|september"
        r"|october|november|december)\s+\d{1,2}\b",
        r"\b\d{4}-\d{2}-\d{2}\b",
        r"\bin \d+ (days?|weeks?)\b",
        r"\b(at|by|before) \d{1,2}(:\d{2})?\s?(am|pm)\b",
        r"\b\d{1,2}/\d{1,2}(/\d{2,4})?\b",
    ],
    "near_term_date_words": ["today", "tonight", "tomorrow"],
}

_POLICY_RULES_TEXT = json.dumps(
    POLICY_RULES, sort_keys=True, separators=(",", ":"),
).encode("utf-8")
POLICY_SHA256 = hashlib.sha256(_POLICY_RULES_TEXT).hexdigest()


def compute_policy_sha256() -> str:
    """Deterministic digest of the active rule configuration."""
    return hashlib.sha256(json.dumps(
        POLICY_RULES, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


# --- Compiled detectors --------------------------------------------------------

_CONFIRMED_EVENT = [re.compile(p, re.I) for p in POLICY_RULES["confirmed_event_patterns"]]
_OPERATOR_ACTION = [re.compile(p, re.I) for p in POLICY_RULES["operator_action_patterns"]]
_OTHER_PARTY_ACTION = [re.compile(p, re.I) for p in POLICY_RULES["other_party_action_patterns"]]
_CLOSED = [re.compile(p, re.I) for p in POLICY_RULES["closed_markers"]]
_ACTIVE_REFERENCE = [re.compile(p, re.I) for p in POLICY_RULES["active_reference_markers"]]
_DEFERRAL = [re.compile(p, re.I) for p in POLICY_RULES["deferral_markers"]]
_AMBIGUOUS_ACTOR = [re.compile(p, re.I) for p in POLICY_RULES["ambiguous_actor_markers"]]
_DATE = [re.compile(p, re.I) for p in POLICY_RULES["date_patterns"]]

_MARKETING_WORDS = tuple(w.lower() for w in POLICY_RULES["marketing_indicators"])
_CONSEQUENCE_MARKERS = [re.compile(re.escape(w), re.I) for w in POLICY_RULES["material_consequence_markers"]]
_NEAR_TERM_WORDS = tuple(POLICY_RULES["near_term_date_words"])

_DOMAIN_HINTS = {
    "career": ("job", "position", "interview", "recruiter", "hiring",
               "application", "candidate", "resume", "offer"),
    "finance": ("invoice", "payment", "bank", "statement", "tax",
                "billing", "account", "loan"),
    "commerce": ("order", "shipped", "delivery", "cart", "purchase",
                 "refund", "tracking"),
    "scheduling": ("appointment", "calendar", "meeting", "invite",
                   "reschedule", "slot"),
}


@dataclass(frozen=True)
class Classification:
    """Axis-first result: semantics decided BEFORE any flag mapping.

    ``evidence_basis`` lists deterministic detector ids that fired — the
    audit trail for the confidence number.
    """
    domain: str                       # career|finance|commerce|scheduling|general
    semantic_type: str                # event_confirmed|action_request|...
    urgency: str                      # imminent|near_term|none
    next_action_owner: str            # operator|other_party|none
    due_evidence: Optional[str]       # matched date phrase, if any
    follow_up_evidence: Optional[str]
    operator_state: str               # open_loop|closed|reference_only|deferred
    confidence: float
    evidence_basis: Tuple[str, ...]


@dataclass(frozen=True)
class Proposal:
    """One migration proposal for a message.

    ``proposed_flag == observed`` means identity (no mutation proposed).
    ``auto_eligible`` marks >= AUTO_ELIGIBLE_THRESHOLD classifications;
    actual mutation remains IMPOSSIBLE in Commit 5 regardless.
    """
    observed_flag: FlagColor
    proposed_flag: FlagColor
    reason_code: str
    reason: str
    confidence: Optional[float] = None
    review_required: bool = False
    auto_eligible: bool = False
    classification: Optional[Classification] = None

    @property
    def is_identity(self) -> bool:
        return self.proposed_flag == self.observed_flag


def _first_match(text: str, patterns) -> Optional[str]:
    for p in patterns:
        m = p.search(text)
        if m:
            return m.group(0)
    return None


def _any_match(text: str, patterns) -> bool:
    return any(p.search(text) for p in patterns)


def _detect_domain(text: str) -> str:
    best, hits = "general", 0
    for domain, words in _DOMAIN_HINTS.items():
        n = sum(1 for w in words if w in text)
        if n > hits:
            best, hits = domain, n
    return best


def classify(sender: str, subject: str) -> Classification:
    """Deterministic axis-first classification of one message.

    The observed legacy flag is intentionally ABSENT from the signature
    and from every rule: semantics are derived from content evidence only.
    """
    text = f"{sender or ''} {subject or ''}".lower()
    weights = POLICY_RULES["confidence"]

    evidence: list = []

    confirmed_event = _first_match(text, _CONFIRMED_EVENT)
    if confirmed_event:
        evidence.append("confirmed_event")
    operator_action = _first_match(text, _OPERATOR_ACTION)
    if operator_action:
        evidence.append("operator_action_request")
    other_party_action = _first_match(text, _OTHER_PARTY_ACTION)
    if other_party_action:
        evidence.append("other_party_next_action")
    closed = _first_match(text, _CLOSED)
    if closed:
        evidence.append("closed_marker")
    active_reference = _first_match(text, _ACTIVE_REFERENCE)
    if active_reference:
        evidence.append("active_reference")
    deferral = _first_match(text, _DEFERRAL)
    if deferral:
        evidence.append("explicit_deferral")
    ambiguous_actor = _any_match(text, _AMBIGUOUS_ACTOR)

    marketing_hits = sorted({w for w in _MARKETING_WORDS if w in text})
    if marketing_hits:
        evidence.append("marketing_indicator:" + marketing_hits[0])
    consequence = next(
        (w for w in POLICY_RULES["material_consequence_markers"]
         if re.search(re.escape(w), text, re.I)), None)
    if consequence:
        evidence.append("material_consequence")

    date_phrase = _first_match(text, _DATE)
    near_term = next((w for w in _NEAR_TERM_WORDS if re.search(
        rf"\b{w}\b", text, re.I)), None)
    if date_phrase:
        evidence.append(f"structured_date:{date_phrase}")

    # --- Axis resolution (precedence encoded HERE, deterministically) ------
    conflicting = (
        (closed is not None and operator_action is not None)
        or (confirmed_event is not None and closed is not None)
    )

    if confirmed_event and not conflicting:
        semantic_type = "event_confirmed"
        owner = "none"
        state = "open_loop"          # future commitment still needs attending
        urgency = "near_term" if date_phrase else "none"
    elif operator_action and not conflicting:
        semantic_type = "action_request"
        owner = "operator"
        state = "open_loop"
        if consequence and near_term:
            urgency = "imminent"
        elif consequence or near_term:
            urgency = "near_term"
        else:
            urgency = "none"
    elif other_party_action and not conflicting:
        semantic_type = "awaiting_other_party"
        owner = "other_party"
        state = "open_loop"
        urgency = "none"
    elif deferral and not operator_action and not confirmed_event:
        semantic_type = "deferred_item"
        owner = "none"
        state = "deferred"
        urgency = "none"
    elif closed and not operator_action and not confirmed_event \
            and not other_party_action:
        semantic_type = "closed_or_receipt"
        owner = "none"
        state = "reference_only" if active_reference else "closed"
        urgency = "none"
    elif ambiguous_actor:
        semantic_type = "unidentifiable_action"
        owner = "unknown"
        state = "open_loop"
        urgency = "none"
    elif conflicting:
        semantic_type = "conflicting_signals"
        owner = "unknown"
        state = "open_loop"
        urgency = "none"
    else:
        semantic_type = "unclassifiable"
        owner = "unknown"
        state = "open_loop"
        urgency = "none"

    domain = _detect_domain(text)

    # --- Confidence (additive/penalized, deterministic) ---------------------
    weights = cast(Dict[str, Any], POLICY_RULES["confidence"])
    conf = weights["base"]
    strong = sum(1 for s in (
        confirmed_event, operator_action, other_party_action,
        active_reference, deferral, consequence,
    ) if s)
    conf += weights["strong_signal"] * min(strong, weights["strong_signal_cap_count"])
    axes_confirmed = len({bool(confirmed_event), bool(operator_action),
                          bool(other_party_action)} - {False})
    conf += min(axes_confirmed * weights["independent_axis_bonus"],
                weights["independent_axis_cap"])
    if date_phrase and semantic_type in (
            "event_confirmed", "action_request"):
        conf += weights["structured_date_extraction"]
    if ambiguous_actor:
        conf -= weights["penalty_ambiguous_actor"]
    if conflicting:
        conf -= weights["penalty_conflicting_signals"]
    if marketing_hits and semantic_type != "action_request":
        conf -= weights["penalty_marketing_bulk"]
    if semantic_type in ("unclassifiable", "unidentifiable_action") \
            and not date_phrase:
        conf -= weights["penalty_missing_context"]
    confidence = round(max(0.0, min(1.0, conf)), 3)

    return Classification(
        domain=domain,
        semantic_type=semantic_type,
        urgency=urgency,
        next_action_owner=owner,
        # The extracted date phrase is the due/follow-up evidence for both
        # operator-owed actions AND confirmed future events.
        due_evidence=(
            date_phrase
            if (owner == "operator" or semantic_type == "event_confirmed")
            else None
        ),
        follow_up_evidence=(
            other_party_action if owner == "other_party" else None),
        operator_state=state,
        confidence=confidence,
        evidence_basis=tuple(evidence),
    )


def map_to_flag(c: Classification) -> Tuple[FlagColor, str, str]:
    """Map an independent classification to its semantic flag.

    Hard mapping rules (see module docstring): words like 'urgent',
    'important', 'payment' ALONE are insufficient for RED; receipts do
    not create BLUE without active-reference value; NO_FLAG is reserved
    for confidently-closed mail, never mere age.
    """
    if c.semantic_type == "event_confirmed":
        return (
            FlagColor.GREEN, RC_EVENT_CONFIRMED_GREEN,
            f"Confirmed scheduled event ({c.due_evidence or 'dated'}); "
            f"confidence {c.confidence:.2f}.",
        )
    if c.semantic_type == "action_request":
        if c.urgency == "imminent":
            return (
                FlagColor.RED, RC_DEADLINE_RED,
                f"Operator-owed action with material consequence and "
                f"near-term deadline ({c.due_evidence}); confidence "
                f"{c.confidence:.2f}.",
            )
        return (
            FlagColor.ORANGE, RC_OPERATOR_ACTION_ORANGE,
            f"Operator owes an action ({c.next_action_owner} "
            f"evidence); confidence {c.confidence:.2f}.",
        )
    if c.semantic_type == "awaiting_other_party":
        return (
            FlagColor.YELLOW, RC_AWAITING_OTHER_YELLOW,
            "Open loop where the next action belongs to the other party; "
            f"confidence {c.confidence:.2f}.",
        )
    if c.semantic_type == "deferred_item":
        return (
            FlagColor.GRAY, RC_DEFERRED_GRAY,
            "Explicit deliberate-deferral evidence present; conservative "
            f"proposal at confidence {c.confidence:.2f}.",
        )
    if c.semantic_type == "closed_or_receipt":
        if c.operator_state == "reference_only":
            return (
                FlagColor.BLUE, RC_ACTIVE_REFERENCE_BLUE,
                "Active-reference value established "
                f"({c.follow_up_evidence or 'records marker'}); confidence "
                f"{c.confidence:.2f}.",
            )
        return (
            FlagColor.NO_FLAG, RC_CLOSED_NO_FLAG,
            "Confidently closed/receipt correspondence with no open loop; "
            f"confidence {c.confidence:.2f}.",
        )
    if c.semantic_type == "unidentifiable_action":
        return (
            FlagColor.PURPLE, RC_UNIDENTIFIABLE_ACTION_PURPLE,
            "Action asserted but NOT identifiable; purple pending human "
            f"judgment (confidence {c.confidence:.2f}).",
        )
    return (
        FlagColor.PURPLE, RC_LOW_CONFIDENCE_PURPLE,
        f"Ambiguous or weak evidence ({c.semantic_type}); below review "
        f"threshold — human judgment required.",
    )


def propose(sender: str, subject: str, observed: FlagColor) -> Proposal:
    """Classify on CONTENT ONLY; compare against the observed flag last.

    ``observed`` never feeds the classifier — it exists purely so identity
    (no change needed) can be detected after semantic evaluation.
    """
    c = classify(sender, subject)
    flag, reason_code, reason = map_to_flag(c)
    auto = (
        c.confidence >= AUTO_ELIGIBLE_THRESHOLD
        and "marketing_indicator" not in c.evidence_basis
        and c.semantic_type not in ("unclassifiable", "unidentifiable_action")
    )
    if flag == observed:
        return Proposal(
            observed, observed, RC_NO_CHANGE,
            "Independent classification matches the observed state.",
            confidence=1.0, review_required=False,
            auto_eligible=False, classification=c,
        )
    review_required = not auto or observed == FlagColor.UNKNOWN
    return Proposal(
        observed, flag, reason_code, reason,
        confidence=c.confidence, review_required=review_required,
        auto_eligible=auto and not review_required,
        classification=c,
    )


def is_auto_eligible(proposal: Proposal) -> bool:
    """Threshold gate used by plan construction (writes stay disabled)."""
    return proposal.auto_eligible
