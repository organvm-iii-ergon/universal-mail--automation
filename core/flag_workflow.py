"""Flag workflow — canonical hashing, schemas, snapshots, plans, receipts.

This module OWNS the authoritative state machinery for the seven-state flag
workflow. The CLI is a thin argument/display layer and must never:

- construct AppleScript,
- inspect private provider methods,
- calculate authoritative hashes,
- interpret mutation state,
- or manipulate receipt internals.

Everything here operates on FULL SHA-256 digests (64 hex chars). Truncated
hashes are a defect; :func:`require_hex256` rejects them at every boundary.

Snapshot/plan/approval/ledger/override/rollback models are typed dataclasses
with ``validate()`` contracts that fail closed on unknown values.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import FlagColor
from core.flag_policy import MIGRATION_POLICY_VERSION, Proposal, propose

# --- Schema names ----------------------------------------------------------

SNAPSHOT_SCHEMA = "uma.flags.snapshot.v1"
PLAN_SCHEMA = "uma.flags.migration.plan.v2"
APPROVAL_SCHEMA = "uma.flags.approval.v1"
APPLY_RECEIPT_SCHEMA = "uma.flags.apply_receipt.v1"
ROLLBACK_RECEIPT_SCHEMA = "uma.flags.rollback_receipt.v1"

# Canary hard limits (enforced everywhere an approval is validated).
CANARY_MIN = 1
CANARY_MAX = 10

_HEX_CHARS = set("0123456789abcdef")


class FlagWorkflowError(ValueError):
    """Raised when a workflow artifact fails schema/integrity validation."""


# --- Canonical hashing ------------------------------------------------------


def canonical_json_bytes(payload: Any) -> bytes:
    """Deterministic JSON encoding used for EVERY authoritative hash."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_hex(payload: Any) -> str:
    """Full 64-char SHA-256 over the canonical JSON of *payload*."""
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def require_hex256(value: Any, name: str) -> str:
    """Reject anything that is not a full 64-char lowercase hex digest."""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or not set(value.lower()) <= _HEX_CHARS
    ):
        raise FlagWorkflowError(
            f"{name} must be a full 64-char SHA-256 hex digest, got {value!r}"
        )
    return value.lower()


def compute_plan_hash(plan: Dict[str, Any]) -> str:
    """Hash the plan content EXCLUDING its own plan_hash field."""
    body = {k: v for k, v in plan.items() if k != "plan_hash"}
    return sha256_hex(body)


# --- Snapshot model ---------------------------------------------------------


@dataclass(frozen=True)
class SnapshotMessage:
    """Scoped message reference + observed state captured in a snapshot.

    Private evidence fields (sender/subject) live here ONLY in the private
    snapshot file; the public-safe projection drops them entirely.
    """
    provider: str
    account: str
    mailbox: str
    provider_id: str
    sender: str
    subject: str
    native_index: Optional[int]
    observed_flag: FlagColor
    received_iso: Optional[str] = None

    @property
    def ref_digest(self) -> str:
        """Stable digest of the qualified reference (PII-free)."""
        return sha256_hex({
            "provider": self.provider,
            "account": self.account,
            "mailbox": self.mailbox,
            "provider_id": self.provider_id,
        })


@dataclass
class FlagSnapshot:
    """Immutable observation of one flagged-estate scan.

    ``complete=False`` snapshots are structurally ineligible to produce
    apply-capable plans (:func:`build_plan` refuses them).
    """
    schema: str
    snapshot_id: str
    generated_at: str
    provider: str
    account: str
    mailbox: str
    complete: bool
    status: str                       # complete|partial|failed|timed_out
    zero_write_mode: bool
    errors: List[str]
    inaccessible_count: int
    timeout_count: int
    unknown_index_count: int
    total_flagged_seen: int
    hidden_by_limit: int
    messages: List[SnapshotMessage]
    content_hash: str                 # sha256 over everything except itself

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "schema": self.schema,
            "snapshot_id": self.snapshot_id,
            "generated_at": self.generated_at,
            "provider": self.provider,
            "account": self.account,
            "mailbox": self.mailbox,
            "complete": self.complete,
            "status": self.status,
            "zero_write_mode": self.zero_write_mode,
            "errors": list(self.errors),
            "inaccessible_count": self.inaccessible_count,
            "timeout_count": self.timeout_count,
            "unknown_index_count": self.unknown_index_count,
            "total_flagged_seen": self.total_flagged_seen,
            "hidden_by_limit": self.hidden_by_limit,
            "messages": [
                {
                    "provider": m.provider,
                    "account": m.account,
                    "mailbox": m.mailbox,
                    "provider_id": m.provider_id,
                    "sender": m.sender,
                    "subject": m.subject,
                    "native_index": m.native_index,
                    "observed_flag": m.observed_flag.value,
                    "received_iso": m.received_iso,
                }
                for m in self.messages
            ],
        }
        d["content_hash"] = sha256_hex(d)
        return d

    def to_public_safe(self) -> Dict[str, Any]:
        """Aggregate projection: NO senders, subjects, or raw provider ids.

        Only counts, statuses, and per-message reference digests survive —
        safe to write into shared receipts.
        """
        base = self.to_dict()
        base["messages"] = [
            {"ref_digest": m.ref_digest, "observed_flag": m.observed_flag.value}
            for m in self.messages
        ]
        # Recompute hash over the redacted content so the public artifact is
        # independently verifiable.
        base.pop("content_hash")
        base["content_hash"] = sha256_hex(base)
        base["projection"] = "public_safe"
        return base


def build_snapshot(
    *,
    provider_name: str,
    account: str,
    mailbox: str,
    rows: List[Any],
    complete: bool,
    errors: List[str],
    inaccessible_count: int,
    timeout_count: int,
    unknown_index_count: int,
    total_flagged_seen: int,
    hidden_by_limit: int,
    generated_at: Optional[str] = None,
) -> FlagSnapshot:
    """Build a FlagSnapshot from a provider EnumerationResult's fields.

    ``rows`` elements need: provider_id, account, mailbox, sender, subject,
    native_index, flag_color (FlagColor), received_iso — i.e. providers'
    transport rows as-is.
    """
    if errors and complete:
        raise FlagWorkflowError(
            "cannot mark snapshot complete while errors are recorded"
        )
    if timeout_count and complete:
        raise FlagWorkflowError("cannot mark snapshot complete after timeout")
    status = (
        "complete" if complete
        else ("timed_out" if timeout_count else ("failed" if errors else "partial"))
    )
    messages = [
        SnapshotMessage(
            provider=getattr(r, "provider", None) or provider_name,
            account=r.account,
            mailbox=r.mailbox,
            provider_id=r.provider_id,
            sender=r.sender,
            subject=r.subject,
            native_index=r.native_index,
            observed_flag=r.flag_color,
            received_iso=r.received_iso,
        )
        for r in rows
    ]
    snap = FlagSnapshot(
        schema=SNAPSHOT_SCHEMA,
        snapshot_id="snap-" + sha256_hex({
            "provider": provider_name, "account": account,
            "mailbox": mailbox, "generated_at": generated_at,
            "n_messages": len(messages),
        })[:32],
        generated_at=generated_at
        or datetime.now(timezone.utc).isoformat(),
        provider=provider_name,
        account=account,
        mailbox=mailbox,
        complete=complete,
        status=status,
        zero_write_mode=True,
        errors=list(errors),
        inaccessible_count=inaccessible_count,
        timeout_count=timeout_count,
        unknown_index_count=unknown_index_count,
        total_flagged_seen=total_flagged_seen,
        hidden_by_limit=hidden_by_limit,
        messages=messages,
        content_hash="",
    )
    snap.content_hash = snap.to_dict()["content_hash"]
    return snap


def write_private_snapshot(snapshot: FlagSnapshot, directory: Path) -> Path:
    """Atomically write the PRIVATE snapshot (mode 0600) under *directory*.

    The directory is created user-private (0700). Atomicity via temp file +
    os.replace in the same directory.
    """
    directory = Path(directory).expanduser()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(snapshot.to_dict(), indent=2, default=str)
    fd, tmp_name = tempfile.mkstemp(
        dir=directory, prefix=".tmp-snap-", suffix=".json"
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_path, 0o600)
        final = directory / f"{snapshot.snapshot_id}.json"
        os.replace(tmp_path, final)
        os.chmod(final, 0o600)
        return final
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def load_snapshot(path: Path) -> FlagSnapshot:
    """Load + verify a snapshot file's content_hash."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if raw.get("schema") != SNAPSHOT_SCHEMA:
        raise FlagWorkflowError(f"not a {SNAPSHOT_SCHEMA} snapshot")
    stored = require_hex256(raw.get("content_hash"), "snapshot content_hash")
    body = {k: v for k, v in raw.items() if k != "content_hash"}
    if sha256_hex(body) != stored:
        raise FlagWorkflowError("snapshot content_hash mismatch (tampered)")
    messages = [
        SnapshotMessage(
            provider=m["provider"], account=m["account"],
            mailbox=m["mailbox"], provider_id=m["provider_id"],
            sender=m.get("sender", ""), subject=m.get("subject", ""),
            native_index=m.get("native_index"),
            observed_flag=FlagColor.from_string(m["observed_flag"]),
            received_iso=m.get("received_iso"),
        )
        for m in raw.get("messages", [])
    ]
    return FlagSnapshot(
        schema=raw["schema"], snapshot_id=raw["snapshot_id"],
        generated_at=raw["generated_at"], provider=raw["provider"],
        account=raw["account"], mailbox=raw["mailbox"],
        complete=bool(raw["complete"]), status=raw["status"],
        zero_write_mode=bool(raw.get("zero_write_mode", True)),
        errors=list(raw.get("errors", [])),
        inaccessible_count=int(raw.get("inaccessible_count", 0)),
        timeout_count=int(raw.get("timeout_count", 0)),
        unknown_index_count=int(raw.get("unknown_index_count", 0)),
        total_flagged_seen=int(raw.get("total_flagged_seen", 0)),
        hidden_by_limit=int(raw.get("hidden_by_limit", 0)),
        messages=messages, content_hash=stored,
    )


# --- Plan -------------------------------------------------------------------


@dataclass(frozen=True)
class PlannedMutation:
    """One proposed flag change, review-gated by construction."""
    mutation_id: str
    ref_digest: str
    observed_flag: FlagColor
    proposed_flag: FlagColor
    reason_code: str
    reason: str
    confidence: Optional[float]
    review_required: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "ref_digest": self.ref_digest,
            "observed_flag": self.observed_flag.value,
            "proposed_flag": self.proposed_flag.value,
            "reason_code": self.reason_code,
            "reason": self.reason,
            "confidence": self.confidence,
            "review_required": self.review_required,
        }


def _mutation_from_dict(d: Dict[str, Any], idx: int) -> PlannedMutation:
    prefix = f"mutations[{idx}]"
    for key in (
        "mutation_id", "ref_digest", "observed_flag",
        "proposed_flag", "reason_code", "review_required",
    ):
        if key not in d:
            raise FlagWorkflowError(f"{prefix}: missing required key {key!r}")
    confidence = d.get("confidence")
    if confidence is not None and not (
        isinstance(confidence, (int, float)) and 0.0 <= float(confidence) <= 1.0
    ):
        raise FlagWorkflowError(f"{prefix}: confidence must be null or in [0,1]")
    return PlannedMutation(
        mutation_id=str(d["mutation_id"]),
        ref_digest=require_hex256(d["ref_digest"], f"{prefix}.ref_digest"),
        observed_flag=FlagColor.from_string(str(d["observed_flag"])),
        proposed_flag=FlagColor.from_string(str(d["proposed_flag"])),
        reason_code=str(d["reason_code"]),
        reason=str(d.get("reason", "")),
        confidence=None if confidence is None else float(confidence),
        review_required=bool(d["review_required"]),
    )


def build_plan(snapshot: FlagSnapshot) -> Dict[str, Any]:
    """Build a plan bound to ONE snapshot. Refuses incomplete snapshots.

    The plan carries NO raw PII: mutations reference messages by ref_digest.
    Every proposal from the legacy policy is review-only; none is
    apply-eligible until a future classifier supplies real confidence AND an
    approval receipt exists (apply path, later commit).
    """
    if not snapshot.complete:
        raise FlagWorkflowError(
            f"refusing to build apply-capable plan from "
            f"{snapshot.status} snapshot {snapshot.snapshot_id}"
        )
    proposals: List[Proposal] = []
    for m in snapshot.messages:
        proposals.append(propose(m.sender, m.subject, m.observed_flag))
    mutations: List[PlannedMutation] = []
    for m, p in zip(snapshot.messages, proposals):
        if p.is_identity and p.reason_code == "no_change":
            continue
        mutations.append(PlannedMutation(
            mutation_id="mut-" + sha256_hex({
                "ref": m.ref_digest,
                "observed": p.observed_flag.value,
                "proposed": p.proposed_flag.value,
                "reason_code": p.reason_code,
            })[:24],
            ref_digest=m.ref_digest,
            observed_flag=p.observed_flag,
            proposed_flag=p.proposed_flag,
            reason_code=p.reason_code,
            reason=p.reason,
            confidence=p.confidence,
            review_required=True,   # legacy policy: ALWAYS review-gated
        ))
    plan: Dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "policy_version": MIGRATION_POLICY_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "snapshot_id": snapshot.snapshot_id,
        # Derive from to_dict(), never the possibly-stale dataclass field.
        "snapshot_sha256": snapshot.to_dict()["content_hash"],
        "snapshot_complete": snapshot.complete,
        "zero_write_declaration": True,
        "total_scanned": snapshot.total_flagged_seen,
        "mutations": [m.to_dict() for m in mutations],
        "unchanged_count": len(snapshot.messages) - len(mutations),
    }
    plan["plan_hash"] = compute_plan_hash(plan)
    return plan


def validate_plan_schema(plan: Dict[str, Any]) -> List[PlannedMutation]:
    """Strict validation; returns parsed mutations or raises.

    Catches: wrong schema, missing/truncated hashes, unknown color strings,
    bad confidence values, non-mutation junk, tampered plan_hash.
    """
    if not isinstance(plan, dict):
        raise FlagWorkflowError("plan must be a JSON object")
    if plan.get("schema") != PLAN_SCHEMA:
        raise FlagWorkflowError(
            f"plan schema must be {PLAN_SCHEMA}, got {plan.get('schema')!r}"
        )
    require_hex256(plan.get("snapshot_sha256"), "snapshot_sha256")
    require_hex256(plan.get("plan_hash"), "plan_hash")
    stored_hash = plan["plan_hash"]
    if compute_plan_hash(plan) != stored_hash:
        raise FlagWorkflowError("plan_hash mismatch — plan was tampered with")
    if plan.get("policy_version") != MIGRATION_POLICY_VERSION:
        raise FlagWorkflowError(
            f"policy_version must be {MIGRATION_POLICY_VERSION}, "
            f"got {plan.get('policy_version')!r}"
        )
    mutations_raw = plan.get("mutations")
    if not isinstance(mutations_raw, list):
        raise FlagWorkflowError("mutations must be a list")
    return [
        _mutation_from_dict(d, i) for i, d in enumerate(mutations_raw)
    ]


# --- Approval receipt --------------------------------------------------------


@dataclass
class ApprovalReceipt:
    """Separate explicit operator approval bound to snapshot+plan+canary."""
    schema: str
    snapshot_sha256: str
    plan_hash: str
    approved_mutation_ids: List[str]
    issued_at: str
    expires_at: str
    approving_operator: str
    canary_limit: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "snapshot_sha256": self.snapshot_sha256,
            "plan_hash": self.plan_hash,
            "approved_mutation_ids": list(self.approved_mutation_ids),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "approving_operator": self.approving_operator,
            "canary_limit": self.canary_limit,
        }

    def validate(self, *, plan_mutations: List[PlannedMutation],
                 now: Optional[datetime] = None) -> None:
        """Fail-closed approval checks against an already-validated plan."""
        if self.schema != APPROVAL_SCHEMA:
            raise FlagWorkflowError(
                f"approval schema must be {APPROVAL_SCHEMA}, got {self.schema!r}"
            )
        require_hex256(self.snapshot_sha256, "approval.snapshot_sha256")
        require_hex256(self.plan_hash, "approval.plan_hash")
        if not self.approving_operator.strip():
            raise FlagWorkflowError("approving_operator must be named")
        issued = datetime.fromisoformat(self.issued_at)
        expires = datetime.fromisoformat(self.expires_at)
        if expires <= issued:
            raise FlagWorkflowError("approval expires_at must be after issued_at")
        now = now or datetime.now(timezone.utc)
        if expires <= now:
            raise FlagWorkflowError("approval has expired")
        if not (CANARY_MIN <= self.canary_limit <= CANARY_MAX):
            raise FlagWorkflowError(
                f"canary_limit must be within [{CANARY_MIN},{CANARY_MAX}], "
                f"got {self.canary_limit}"
            )
        known_ids = {m.mutation_id for m in plan_mutations}
        unknown = set(self.approved_mutation_ids) - known_ids
        if unknown:
            raise FlagWorkflowError(
                f"approval references mutation ids absent from plan: "
                f"{sorted(unknown)}"
            )


# --- Transaction ledger (append-only idempotency guard) ----------------------


class AppliedPlanLedger:
    """Append-only JSONL ledger of consumed transactions.

    One record per applied mutation: {plan_hash, mutation_id, applied_at,
    verified}. ``has()`` makes reapplication a provable no-op.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    def _ensure_dir(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def record(self, plan_hash: str, mutation_id: str,
               verified: bool, applied_at: Optional[str] = None) -> None:
        require_hex256(plan_hash, "plan_hash")
        entry = {
            "plan_hash": plan_hash,
            "mutation_id": mutation_id,
            "applied_at": applied_at
            or datetime.now(timezone.utc).isoformat(),
            "verified": bool(verified),
        }
        self._ensure_dir()
        line = canonical_json_bytes(entry).decode("utf-8") + "\n"
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def has(self, plan_hash: str, mutation_id: str) -> bool:
        if not self.path.exists():
            return False
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if (entry.get("plan_hash") == plan_hash
                    and entry.get("mutation_id") == mutation_id):
                return True
        return False

    def all_entries(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        out = []
        for raw in self.path.read_text(encoding="utf-8").splitlines():
            if raw.strip():
                try:
                    out.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
        return out


# --- Human-override store -----------------------------------------------------


class OverrideStore:
    """Durable last-automation state + detected human overrides.

    An override EXISTS only when automation recorded a verified post-state
    for a message and the live state later differs without an explaining
    transaction. Until detection wiring lands (later commit), this store
    provides the durable substrate: record / list / suppress / unlock.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    def _load(self) -> Dict[str, Any]:
        if not self.path.exists():
            return {"overrides": {}, "suppressed": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            raise FlagWorkflowError(
                f"override store corrupt (invalid JSON): {self.path}"
            )
        data.setdefault("overrides", {})
        data.setdefault("suppressed", {})
        return data

    def _save(self, data: Dict[str, Any]) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        payload = json.dumps(data, indent=2, sort_keys=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    @staticmethod
    def _key(ref_digest: str) -> str:
        return require_hex256(ref_digest, "ref_digest")

    def record_automation_state(self, ref_digest: str, flag_value: str,
                                verified: bool) -> None:
        data = self._load()
        data["overrides"].pop(self._key(ref_digest), None)   # cleared by verify
        data.setdefault("last_automation", {})[self._key(ref_digest)] = {
            "flag": flag_value, "verified": bool(verified),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save(data)

    def record_override(self, ref_digest: str, detail: str) -> None:
        data = self._load()
        data["overrides"][self._key(ref_digest)] = {
            "detail": detail,
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }
        data["suppressed"][self._key(ref_digest)] = True
        self._save(data)

    def is_overridden(self, ref_digest: str) -> bool:
        return self._key(ref_digest) in self._load()["overrides"]

    def is_suppressed(self, ref_digest: str) -> bool:
        return self._key(ref_digest) in self._load()["suppressed"]

    def unlock(self, ref_digest: str) -> None:
        data = self._load()
        k = self._key(ref_digest)
        data["suppressed"].pop(k, None)
        data["overrides"].pop(k, None)
        self._save(data)

    def list_overrides(self) -> Dict[str, Any]:
        return dict(self._load()["overrides"])


# --- Rollback receipt model ----------------------------------------------------


@dataclass
class RollbackEntry:
    ref_digest: str
    pre_apply_native_index: Optional[int]
    pre_apply_flag: FlagColor
    automation_applied_flag: FlagColor

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ref_digest": self.ref_digest,
            "pre_apply_native_index": self.pre_apply_native_index,
            "pre_apply_flag": self.pre_apply_flag.value,
            "automation_applied_flag": self.automation_applied_flag.value,
        }


@dataclass
class RollbackReceipt:
    """Immutable rollback intent bound to the apply that produced it."""
    schema: str
    receipt_id: str
    plan_hash: str
    created_at: str
    entries: List[RollbackEntry] = field(default_factory=list)
    content_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "plan_hash": self.plan_hash,
            "created_at": self.created_at,
            "entries": [e.to_dict() for e in self.entries],
        }
        d["content_hash"] = sha256_hex(d)
        return d

    def validate(self) -> None:
        if self.schema != ROLLBACK_RECEIPT_SCHEMA:
            raise FlagWorkflowError(
                f"rollback schema must be {ROLLBACK_RECEIPT_SCHEMA}, "
                f"got {self.schema!r}"
            )
        require_hex256(self.plan_hash, "rollback.plan_hash")
        stored = require_hex256(self.content_hash, "rollback.content_hash")
        body = self.to_dict()
        body.pop("content_hash")
        if sha256_hex(body) != stored:
            raise FlagWorkflowError(
                "rollback receipt content_hash mismatch (tampered)"
            )

    @classmethod
    def create(cls, plan_hash: str, entries: List[RollbackEntry]) -> "RollbackReceipt":
        receipt = cls(
            schema=ROLLBACK_RECEIPT_SCHEMA,
            receipt_id="rb-" + sha256_hex({
                "plan_hash": plan_hash,
                "entries": [e.to_dict() for e in entries],
                "created_hint": datetime.now(timezone.utc).isoformat(),
            })[:32],
            plan_hash=plan_hash,
            created_at=datetime.now(timezone.utc).isoformat(),
            entries=list(entries),
        )
        receipt.content_hash = receipt.to_dict()["content_hash"]
        return receipt

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "RollbackReceipt":
        entries = [
            RollbackEntry(
                ref_digest=require_hex256(e.get("ref_digest"), "entry.ref_digest"),
                pre_apply_native_index=e.get("pre_apply_native_index"),
                pre_apply_flag=FlagColor.from_string(e["pre_apply_flag"]),
                automation_applied_flag=FlagColor.from_string(
                    e["automation_applied_flag"]),
            )
            for e in raw.get("entries", [])
        ]
        receipt = cls(
            schema=raw.get("schema", ""),
            receipt_id=raw.get("receipt_id", ""),
            plan_hash=raw.get("plan_hash", ""),
            created_at=raw.get("created_at", ""),
            entries=entries,
            content_hash=raw.get("content_hash", ""),
        )
        receipt.validate()
        return receipt
