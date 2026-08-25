"""Flag migration policy — proposals for reclassifying legacy flags.

STATUS: legacy heuristic carrier. The keyword block below is the ORIGINAL
migration heuristic preserved verbatim from cli.py so the workflow layer has
a working proposal source. The replacement classifier (domain/semantic-type/
urgency axes, evidence-based confidence) is Commit 5's deliverable and will
replace :func:`propose` internals WITHOUT changing this module's contract.

HONESTY RULES ALREADY ENFORCED HERE (per PR #192 review):
- Every non-identity proposal is emitted with ``confidence=None`` and
  ``review_required=True``. The previous fixed ``0.7`` is prohibited and
  does not exist anywhere in this codebase.
- Keyword matches alone can NEVER produce an apply-eligible mutation; plans
  built from these proposals are review-only by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.models import FlagColor

MIGRATION_POLICY_VERSION = "0.legacy-heuristic.1"

# Deterministic reason codes — stable identifiers for receipts/plans.
RC_KEEP_RED_INSUFFICIENT_EVIDENCE = "keep_red_insufficient_evidence"
RC_CAREER_SIGNAL_ORANGE = "career_signal_orange"
RC_AWAITING_YELLOW = "awaiting_yellow"
RC_SCHEDULED_GREEN = "scheduled_green"
RC_RECEIPT_BLUE = "receipt_blue"
RC_AMBIGUOUS_PURPLE = "ambiguous_purple"
RC_PURPLE_REVIEW = "purple_review"
RC_NO_CHANGE = "no_change"


@dataclass(frozen=True)
class Proposal:
    """One migration proposal for a message.

    ``proposed_flag == observed`` means identity (no mutation proposed).
    Non-identity proposals carry ``review_required=True`` and
    ``confidence=None`` until a real classifier supplies measured confidence.
    """
    observed_flag: FlagColor
    proposed_flag: FlagColor
    reason_code: str
    reason: str
    confidence: Optional[float] = None
    review_required: bool = False

    @property
    def is_identity(self) -> bool:
        return self.proposed_flag == self.observed_flag


_RED_URGENCY_KEYWORDS = (
    "security", "fraud", "unauthorized", "billing", "payment",
    "overdue", "default", "urgent", "action required",
)
_CAREER_KEYWORDS = (
    "recruiter", "hiring", "job", "interview", "opportunity", "position",
)
_AWAITING_KEYWORDS = ("awaiting", "pending", "follow up", "reply", "response")
_SCHEDULED_KEYWORDS = (
    "meeting", "calendar", "scheduled", "appointment", "call",
)
_RECEIPT_KEYWORDS = (
    "receipt", "confirmation", "order", "shipped", "tracking",
)


def propose(sender: str, subject: str, observed: FlagColor) -> Proposal:
    """Propose a semantic target for one observed flag (legacy heuristic).

    Identity for everything except legacy RED (analyzed against keywords,
    defaulting to PURPLE when nothing matches) and PURPLE (stays under
    review). All non-identity outputs are review-only with no claimed
    confidence.
    """
    combined = f"{sender or ''} {subject or ''}".lower()

    if observed == FlagColor.RED:
        if any(k in combined for k in _RED_URGENCY_KEYWORDS):
            return Proposal(
                observed, FlagColor.RED,
                RC_KEEP_RED_INSUFFICIENT_EVIDENCE,
                "Legacy Red kept: urgency keywords alone are insufficient "
                "evidence to recolor; requires human confirmation.",
                confidence=None, review_required=True,
            )
        if any(k in combined for k in _CAREER_KEYWORDS):
            return Proposal(
                observed, FlagColor.ORANGE, RC_CAREER_SIGNAL_ORANGE,
                "Legacy Red -> Orange: career-signal keywords present.",
                confidence=None, review_required=True,
            )
        if any(k in combined for k in _AWAITING_KEYWORDS):
            return Proposal(
                observed, FlagColor.YELLOW, RC_AWAITING_YELLOW,
                "Legacy Red -> Yellow: awaiting/follow-up language present.",
                confidence=None, review_required=True,
            )
        if any(k in combined for k in _SCHEDULED_KEYWORDS):
            return Proposal(
                observed, FlagColor.GREEN, RC_SCHEDULED_GREEN,
                "Legacy Red -> Green: scheduling language present "
                "(NOT verified as a confirmed commitment).",
                confidence=None, review_required=True,
            )
        if any(k in combined for k in _RECEIPT_KEYWORDS):
            return Proposal(
                observed, FlagColor.BLUE, RC_RECEIPT_BLUE,
                "Legacy Red -> Blue: receipt/confirmation language present "
                "(active-reference evidence NOT established).",
                confidence=None, review_required=True,
            )
        return Proposal(
            observed, FlagColor.PURPLE, RC_AMBIGUOUS_PURPLE,
            "Legacy Red -> Purple: no recognizable signal; human judgment "
            "required.",
            confidence=None, review_required=True,
        )

    if observed == FlagColor.PURPLE:
        return Proposal(
            observed, FlagColor.PURPLE, RC_PURPLE_REVIEW,
            "Legacy Purple stays Purple pending actual evaluation.",
            confidence=None, review_required=True,
        )

    return Proposal(
        observed, observed, RC_NO_CHANGE,
        "No change proposed by legacy policy.", confidence=1.0,
        review_required=False,
    )
