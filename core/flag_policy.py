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
import math
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, cast

from core.models import FlagColor

MIGRATION_POLICY_VERSION = "1.evidence-classifier.4"

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
    # Structural safety invariants.  These are digest-bound so a plan cannot
    # silently cross a future policy change that makes a human-review state
    # mutation-eligible.
    "review_only_semantic_types": [
        "unclassifiable",
        "unidentifiable_action",
        "conflicting_signals",
    ],
    "review_only_flags": [FlagColor.PURPLE.value],
    # Canonical classifier-axis and semantic-decision contract.  Plan
    # validators consume this same digest-bound table; a self-rehashed plan
    # cannot reinterpret a conflicting classification as an automatic RED.
    "classification_domains": [
        "career", "finance", "commerce", "scheduling", "general",
    ],
    "semantic_contract": {
        "event_confirmed": {
            "next_action_owners": ["none"],
            "operator_states": ["open_loop"],
            "urgencies": ["none", "near_term"],
            "default": {
                "flag": FlagColor.GREEN.value,
                "reason_code": RC_EVENT_CONFIRMED_GREEN,
            },
        },
        "action_request": {
            "next_action_owners": ["operator"],
            "operator_states": ["open_loop"],
            "urgencies": ["none", "near_term", "imminent"],
            "default": {
                "flag": FlagColor.ORANGE.value,
                "reason_code": RC_OPERATOR_ACTION_ORANGE,
            },
            "by_urgency": {
                "imminent": {
                    "flag": FlagColor.RED.value,
                    "reason_code": RC_DEADLINE_RED,
                },
            },
        },
        "awaiting_other_party": {
            "next_action_owners": ["other_party"],
            "operator_states": ["open_loop"],
            "urgencies": ["none"],
            "default": {
                "flag": FlagColor.YELLOW.value,
                "reason_code": RC_AWAITING_OTHER_YELLOW,
            },
        },
        "deferred_item": {
            "next_action_owners": ["none"],
            "operator_states": ["deferred"],
            "urgencies": ["none"],
            "default": {
                "flag": FlagColor.GRAY.value,
                "reason_code": RC_DEFERRED_GRAY,
            },
        },
        "closed_or_receipt": {
            "next_action_owners": ["none"],
            "operator_states": ["closed", "reference_only"],
            "urgencies": ["none"],
            "default": {
                "flag": FlagColor.NO_FLAG.value,
                "reason_code": RC_CLOSED_NO_FLAG,
            },
            "by_operator_state": {
                "reference_only": {
                    "flag": FlagColor.BLUE.value,
                    "reason_code": RC_ACTIVE_REFERENCE_BLUE,
                },
            },
        },
        "conflicting_signals": {
            "next_action_owners": ["unknown"],
            "operator_states": ["open_loop"],
            "urgencies": ["none"],
            "default": {
                "flag": FlagColor.PURPLE.value,
                "reason_code": RC_AMBIGUOUS_PURPLE,
            },
        },
        "active_reference": {
            "next_action_owners": ["none"],
            "operator_states": ["reference_only"],
            "urgencies": ["none"],
            "default": {
                "flag": FlagColor.BLUE.value,
                "reason_code": RC_ACTIVE_REFERENCE_BLUE,
            },
        },
        "unidentifiable_action": {
            "next_action_owners": ["unknown"],
            "operator_states": ["open_loop"],
            "urgencies": ["none"],
            "default": {
                "flag": FlagColor.PURPLE.value,
                "reason_code": RC_UNIDENTIFIABLE_ACTION_PURPLE,
            },
        },
        "unclassifiable": {
            "next_action_owners": ["unknown"],
            "operator_states": ["open_loop"],
            "urgencies": ["none"],
            "default": {
                "flag": FlagColor.PURPLE.value,
                "reason_code": RC_LOW_CONFIDENCE_PURPLE,
            },
        },
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
    # Domain classification hints — DECLARATIVE classifier input, therefore
    # INSIDE the hashed policy object (a hint change must change the digest).
    "domain_hints": {
        "career": ["job", "position", "interview", "recruiter", "hiring",
                   "application", "candidate", "resume", "offer"],
        "finance": ["invoice", "payment", "bank", "statement", "tax",
                    "billing", "account", "loan"],
        "commerce": ["order", "shipped", "delivery", "cart", "purchase",
                     "refund", "tracking"],
        "scheduling": ["appointment", "calendar", "meeting", "invite",
                       "reschedule", "slot"],
    },
}

_POLICY_RULES_TEXT = json.dumps(
    POLICY_RULES, sort_keys=True, separators=(",", ":"),
).encode("utf-8")
POLICY_SHA256 = hashlib.sha256(_POLICY_RULES_TEXT).hexdigest()


def compute_policy_sha256(rules: Optional[Dict[str, Any]] = None) -> str:
    """Deterministic digest of the active rule configuration.

    ``rules`` override exists so tests can prove that ANY declarative
    mutation (e.g. a domain hint) changes the digest.
    """
    payload = POLICY_RULES if rules is None else rules
    return hashlib.sha256(json.dumps(
        payload, sort_keys=True, separators=(",", ":"),
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

# Derived FROM the hashed policy object — never declared outside it.
_DOMAIN_HINTS: Dict[str, Tuple[str, ...]] = {
    domain: tuple(words)
    for domain, words in cast(Dict[str, Any],
                              POLICY_RULES["domain_hints"]).items()
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
    marketing_or_bulk: bool           # typed axis — NEVER parsed from strings
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

    # An explicit request to the operator takes precedence over evidence that
    # an event is already scheduled.  "Please confirm your appointment is
    # scheduled Tuesday" remains an owed action, not a completed commitment.
    if operator_action and not conflicting:
        semantic_type = "action_request"
        owner = "operator"
        state = "open_loop"
        if consequence and near_term:
            urgency = "imminent"
        elif consequence or near_term:
            urgency = "near_term"
        else:
            urgency = "none"
    elif confirmed_event and not conflicting:
        semantic_type = "event_confirmed"
        owner = "none"
        state = "open_loop"          # future commitment still needs attending
        urgency = "near_term" if date_phrase else "none"
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
    elif conflicting:
        semantic_type = "conflicting_signals"
        owner = "unknown"
        state = "open_loop"
        urgency = "none"
    elif active_reference:
        semantic_type = "active_reference"
        owner = "none"
        state = "reference_only"
        urgency = "none"
    elif ambiguous_actor:
        semantic_type = "unidentifiable_action"
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
    axes_confirmed = sum(
        1 for signal in (
            confirmed_event, operator_action, other_party_action,
        )
        if signal
    )
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
        marketing_or_bulk=bool(marketing_hits),
        confidence=confidence,
        evidence_basis=tuple(evidence),
    )


def validate_classification_contract(c: Classification) -> None:
    """Validate the digest-bound axis relationships used for mutation safety."""
    if c.domain not in POLICY_RULES["classification_domains"]:
        raise ValueError(f"non-canonical classification domain {c.domain!r}")
    contracts = cast(
        Dict[str, Dict[str, Any]], POLICY_RULES["semantic_contract"],
    )
    contract = contracts.get(c.semantic_type)
    if contract is None:
        raise ValueError(
            f"non-canonical classification semantic_type {c.semantic_type!r}"
        )
    if c.next_action_owner not in contract["next_action_owners"]:
        raise ValueError(
            f"{c.semantic_type} cannot have next_action_owner "
            f"{c.next_action_owner!r}"
        )
    if c.operator_state not in contract["operator_states"]:
        raise ValueError(
            f"{c.semantic_type} cannot have operator_state "
            f"{c.operator_state!r}"
        )
    if c.urgency not in contract["urgencies"]:
        raise ValueError(
            f"{c.semantic_type} cannot have urgency {c.urgency!r}"
        )
    if isinstance(c.confidence, bool) or not isinstance(
            c.confidence, (int, float)) or not math.isfinite(c.confidence) \
            or not 0.0 <= c.confidence <= 1.0:
        raise ValueError("classification confidence must be finite in [0,1]")
    if type(c.marketing_or_bulk) is not bool:
        raise ValueError("classification marketing_or_bulk must be boolean")
    if c.semantic_type not in ("event_confirmed", "action_request") \
            and c.due_evidence is not None:
        raise ValueError(
            f"{c.semantic_type} cannot carry due_evidence"
        )
    if c.semantic_type == "event_confirmed" and (
            (c.urgency == "near_term") != (c.due_evidence is not None)):
        raise ValueError(
            "event_confirmed near_term and due_evidence must agree"
        )
    if c.semantic_type == "action_request" \
            and c.urgency == "imminent" and c.due_evidence is None:
        raise ValueError("imminent action_request requires due_evidence")
    if (c.semantic_type == "awaiting_other_party") != \
            (c.follow_up_evidence is not None):
        raise ValueError(
            "follow_up_evidence is exclusive to awaiting_other_party"
        )


def canonical_semantic_decision(
        c: Classification) -> Tuple[FlagColor, str]:
    """Return the one digest-bound flag/reason-code pair for ``c``."""
    validate_classification_contract(c)
    contracts = cast(
        Dict[str, Dict[str, Any]], POLICY_RULES["semantic_contract"],
    )
    contract = contracts[c.semantic_type]
    decision = contract.get("by_urgency", {}).get(c.urgency)
    if decision is None:
        decision = contract.get("by_operator_state", {}).get(
            c.operator_state
        )
    if decision is None:
        decision = contract["default"]
    return (
        FlagColor.from_string(decision["flag"]),
        cast(str, decision["reason_code"]),
    )


def map_to_flag(c: Classification) -> Tuple[FlagColor, str, str]:
    """Map an independently validated classification to its semantic flag."""
    flag, reason_code = canonical_semantic_decision(c)
    if reason_code == RC_EVENT_CONFIRMED_GREEN:
        reason = (
            f"Confirmed scheduled event ({c.due_evidence or 'dated'}); "
            f"confidence {c.confidence:.2f}."
        )
    elif reason_code == RC_DEADLINE_RED:
        reason = (
            "Operator-owed action with material consequence and near-term "
            f"deadline ({c.due_evidence}); confidence {c.confidence:.2f}."
        )
    elif reason_code == RC_OPERATOR_ACTION_ORANGE:
        reason = (
            f"Operator owes an action ({c.next_action_owner} evidence); "
            f"confidence {c.confidence:.2f}."
        )
    elif reason_code == RC_AWAITING_OTHER_YELLOW:
        reason = (
            "Open loop where the next action belongs to the other party; "
            f"confidence {c.confidence:.2f}."
        )
    elif reason_code == RC_DEFERRED_GRAY:
        reason = (
            "Explicit deliberate-deferral evidence present; conservative "
            f"proposal at confidence {c.confidence:.2f}."
        )
    elif reason_code == RC_ACTIVE_REFERENCE_BLUE:
        reason = (
            "Active-reference value established "
            f"({c.follow_up_evidence or 'records marker'}); confidence "
            f"{c.confidence:.2f}."
        )
    elif reason_code == RC_CLOSED_NO_FLAG:
        reason = (
            "Confidently closed/receipt correspondence with no open loop; "
            f"confidence {c.confidence:.2f}."
        )
    elif reason_code == RC_UNIDENTIFIABLE_ACTION_PURPLE:
        reason = (
            "Action asserted but NOT identifiable; purple pending human "
            f"judgment (confidence {c.confidence:.2f})."
        )
    elif reason_code == RC_AMBIGUOUS_PURPLE:
        reason = (
            "Conflicting evidence requires human judgment; "
            f"confidence {c.confidence:.2f}."
        )
    else:
        reason = (
            f"Ambiguous or weak evidence ({c.semantic_type}); below review "
            "threshold — human judgment required."
        )
    return flag, reason_code, reason


def is_auto_eligible(c: Classification) -> bool:
    """STRUCTURAL eligibility gate — typed axes only, never string parsing.

    Marketing/bulk signals hard-exclude auto-eligibility regardless of
    confidence, so a future weight change can never silently push bulk
    mail past the threshold. Commit 6 must build preflight on THIS gate,
    not on confidence numbers alone.
    """
    review_only_types = cast(
        Tuple[str, ...], tuple(POLICY_RULES["review_only_semantic_types"]),
    )
    return (
        c.confidence >= AUTO_ELIGIBLE_THRESHOLD
        and not c.marketing_or_bulk
        and c.semantic_type not in review_only_types
    )


def proposal_from_classification(
        c: Classification, observed: FlagColor) -> Proposal:
    """Derive the one canonical proposal for validated classifier axes."""
    flag, reason_code, reason = map_to_flag(c)
    if flag == observed:
        return Proposal(
            observed, observed, RC_NO_CHANGE,
            "Independent classification matches the observed state.",
            confidence=1.0, review_required=False,
            auto_eligible=False, classification=c,
        )
    # PURPLE is the human-judgment queue by contract.  No confidence score
    # can turn a contradictory evidence set into an automatic mutation.
    review_only_flags = tuple(POLICY_RULES["review_only_flags"])
    auto = is_auto_eligible(c) and flag.value not in review_only_flags
    review_required = (
        flag.value in review_only_flags
        or not auto
        or observed == FlagColor.UNKNOWN
    )
    return Proposal(
        observed, flag, reason_code, reason,
        confidence=c.confidence, review_required=review_required,
        auto_eligible=auto and not review_required,
        classification=c,
    )


def propose(sender: str, subject: str, observed: FlagColor) -> Proposal:
    """Classify on CONTENT ONLY; compare against the observed flag last.

    ``observed`` never feeds the classifier — it exists purely so identity
    (no change needed) can be detected after semantic evaluation.
    """
    return proposal_from_classification(
        classify(sender, subject), observed,
    )
