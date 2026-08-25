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
from typing import Any, Callable, Dict, List, Optional

from core.models import FlagColor, MessageReference
from core.flag_policy import (
    AUTO_ELIGIBLE_THRESHOLD,
    MIGRATION_POLICY_VERSION,
    POLICY_SHA256,
    Proposal,
    propose,
)

# --- Schema names ----------------------------------------------------------

SNAPSHOT_SCHEMA = "uma.flags.snapshot.v1"
PUBLIC_RECEIPT_SCHEMA = "uma.flags.public_receipt.v1"
PLAN_SCHEMA = "uma.flags.migration.plan.v3"       # v3: durable ref bindings + policy_sha256
PUBLIC_PLAN_SCHEMA = "uma.flags.migration.plan.public.v1"
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


# --- Provider-aware native-flag validation registry ---------------------------
#
# The generic snapshot model must not hard-code Mail.app's native mapping,
# but Commit 6 preflight treats observed_native_flag as evidence, so the
# mapping MUST be validated exactly. Providers REGISTER their
# native-index→FlagColor transport function at import time; validation is
# fail-closed (an unregistered provider cannot have its snapshots planned).

NativeFlagValidator = Callable[[Optional[int]], FlagColor]
_NATIVE_FLAG_VALIDATORS: Dict[str, NativeFlagValidator] = {}

# Declarative bootstrap map: provider name -> PURE codec module path.
# Codec modules are I/O-free by contract (no provider construction, no
# connections, no AppleScript/osascript, no enumeration) and are imported
# lazily ONLY when a snapshot for that provider must be validated — so
# artifact-only planning works in a completely fresh process.
_PROVIDER_CODEC_MODULES: Dict[str, str] = {
    "mailapp": "providers.flag_codecs",
}


def register_native_flag_validator(provider_name: str,
                                   validator: NativeFlagValidator) -> None:
    """Register a provider's native-index transport validator.

    NON-OVERWRITING: registering a DIFFERENT validator for an already
    registered provider raises — a mutable global that later code could
    silently replace would weaken the artifact-validation boundary.
    Registering the IDENTICAL function is an accepted no-op (idempotent).
    """
    existing = _NATIVE_FLAG_VALIDATORS.get(provider_name)
    if existing is not None:
        if existing is validator:
            return                      # idempotent re-registration: harmless
        raise FlagWorkflowError(
            f"a different native-flag validator is already registered "
            f"for provider {provider_name!r} — conflicting registration "
            f"refused")
    _NATIVE_FLAG_VALIDATORS[provider_name] = validator


def _native_validator_for(provider_name: str) -> NativeFlagValidator:
    validator = _NATIVE_FLAG_VALIDATORS.get(provider_name)
    if validator is None:
        # Bootstrap the PURE codec (I/O-free) if one is declared. This
        # never constructs a runtime provider nor touches Mail.app. The
        # explicit register() call handles already-cached modules (importlib
        # does not re-run module bodies on cache hits).
        import importlib
        codec_path = _PROVIDER_CODEC_MODULES.get(provider_name)
        if codec_path is not None:
            codec = importlib.import_module(codec_path)
            register_hook = getattr(codec, "register", None)
            if callable(register_hook):
                register_hook()
            validator = _NATIVE_FLAG_VALIDATORS.get(provider_name)
    if validator is None:
        raise FlagWorkflowError(
            f"no native-flag validator registered for provider "
            f"{provider_name!r} — import its provider module or refuse "
            "planning; fail-closed"
        )
    return validator


def canonical_scan_status(*, scope_complete: bool, errors: List[str],
                          inaccessible_count: int, timeout_count: int,
                          hidden_by_limit: int) -> str:
    """THE deterministic scan-status derivation.

    Single source of truth shared by the provider transport
    (EnumerationResult._status), estate aggregation, and snapshot
    validation — precedence: timeouts > failed(errors/scope) >
    partial(inaccessible) > bounded_partial(hidden) > complete.
    """
    if timeout_count:
        return "timed_out"
    if errors or not scope_complete:
        return "failed"
    if inaccessible_count:
        return "partial"
    if hidden_by_limit:
        return "bounded_partial"
    return "complete"


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

    Completeness is TWO-valued (never one ambiguous boolean):

    - ``scope_complete``: the bounded window was walked with zero omissions
      from the provider.
    - ``complete`` (estate-honest): scope_complete AND nothing hidden by the
      limit AND zero inaccessible rows. ONLY ``complete`` snapshots may
      produce plans (:func:`build_plan` enforces this).
    """
    schema: str
    snapshot_id: str
    generated_at: str
    provider: str
    account: str
    mailbox: str
    complete: bool                     # estate-honest; plan-eligibility gate
    scope_complete: bool               # window walked without omission
    status: str                        # complete|bounded_partial|partial|failed|timed_out
    zero_write_mode: bool
    errors: List[str]
    inaccessible_count: int
    timeout_count: int
    unknown_index_count: int
    limit: int
    since_days: Optional[int]
    ordering: str                      # e.g. "received_desc"
    total_matched: int                 # predicate-bounded count reported
    returned_count: int                # rows actually captured
    hidden_by_limit: int
    next_cursor: Optional[str]
    messages: List[SnapshotMessage]
    content_hash: str                 # sha256 over everything except itself

    def validate(self) -> None:
        """Semantic validation — hash integrity is NOT enough.

        An attacker (or buggy producer) can recompute a valid content_hash
        over semantically impossible content. Every invariant that makes a
        snapshot MEANINGFUL is re-checked here; build_snapshot() and
        load_snapshot() both call this.
        """
        if self.zero_write_mode is False:
            raise FlagWorkflowError(
                "snapshot zero_write_mode must be True — snapshots from a "
                "mutating producer are untrustworthy")

        # --- Canonical status state machine (bidirectional) ----------------
        # status and completeness form ONE coherent state, validated against
        # the same deterministic precedence the transport itself uses.
        expected_status = canonical_scan_status(
            scope_complete=self.scope_complete,
            errors=self.errors,
            inaccessible_count=self.inaccessible_count,
            timeout_count=self.timeout_count,
            hidden_by_limit=self.hidden_by_limit,
        )
        if self.status != expected_status:
            raise FlagWorkflowError(
                f"status {self.status!r} inconsistent with scan dimensions "
                f"(canonical: {expected_status!r}, timeouts="
                f"{self.timeout_count}, errors={len(self.errors)}, "
                f"inaccessible={self.inaccessible_count}, hidden="
                f"{self.hidden_by_limit}, scope_complete="
                f"{self.scope_complete})"
            )
        # complete=True IFF canonical 'complete' — BOTH directions enforced.
        if self.complete != (expected_status == "complete"):
            raise FlagWorkflowError(
                f"complete={self.complete} inconsistent with canonical "
                f"status {expected_status!r}"
            )
        if self.status == "timed_out" and not (
                self.timeout_count > 0 and self.complete is False):
            raise FlagWorkflowError(
                "timed_out requires timeout_count > 0 and complete=False")
        if self.status == "bounded_partial" and not (
                self.hidden_by_limit > 0 and self.complete is False):
            raise FlagWorkflowError(
                "bounded_partial requires hidden_by_limit > 0 and "
                "complete=False")
        if self.status == "partial" and not (
                self.inaccessible_count > 0 and self.complete is False):
            raise FlagWorkflowError(
                "partial requires inaccessible_count > 0 and complete=False")
        if self.status == "failed" and self.complete is not False:
            raise FlagWorkflowError("failed requires complete=False")

        if self.returned_count != len(self.messages):
            raise FlagWorkflowError(
                f"returned_count {self.returned_count} != actual message "
                f"count {len(self.messages)}")
        if self.total_matched < self.returned_count:
            raise FlagWorkflowError(
                f"total_matched {self.total_matched} < returned_count "
                f"{self.returned_count}")
        unknown_actual = sum(
            1 for m in self.messages if m.observed_flag == FlagColor.UNKNOWN)
        if unknown_actual != self.unknown_index_count:
            raise FlagWorkflowError(
                f"unknown_index_count {self.unknown_index_count} != actual "
                f"UNKNOWN messages {unknown_actual}")
        seen_refs = set()
        validator = _native_validator_for(self.provider)
        for m in self.messages:
            # EXACT native↔semantic consistency via the provider registry:
            # native=0+BLUE and native=4+RED are as impossible as None+RED.
            try:
                expected_flag = validator(m.native_index)
            except Exception as e:
                raise FlagWorkflowError(
                    f"message {m.provider_id}: native index "
                    f"{m.native_index!r} rejected by {self.provider} "
                    f"transport validator: {e}") from e
            if expected_flag != m.observed_flag:
                raise FlagWorkflowError(
                    f"message {m.provider_id}: native_index="
                    f"{m.native_index!r} maps to "
                    f"{expected_flag.value!r} but observed_flag is "
                    f"{m.observed_flag.value!r}")
            ref = m.ref_digest
            if ref in seen_refs:
                raise FlagWorkflowError(
                    f"duplicate qualified reference in deduplicated "
                    f"snapshot: {ref[:16]}…")
            seen_refs.add(ref)

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "schema": self.schema,
            "snapshot_id": self.snapshot_id,
            "generated_at": self.generated_at,
            "provider": self.provider,
            "account": self.account,
            "mailbox": self.mailbox,
            "complete": self.complete,
            "scope_complete": self.scope_complete,
            "status": self.status,
            "zero_write_mode": self.zero_write_mode,
            "errors": list(self.errors),
            "inaccessible_count": self.inaccessible_count,
            "timeout_count": self.timeout_count,
            "unknown_index_count": self.unknown_index_count,
            "limit": self.limit,
            "since_days": self.since_days,
            "ordering": self.ordering,
            "total_matched": self.total_matched,
            "returned_count": self.returned_count,
            "hidden_by_limit": self.hidden_by_limit,
            "next_cursor": self.next_cursor,
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
                    "evidence_digest": (
                        MessageReference.compute_evidence_digest(
                            m.received_iso, m.sender, m.subject)
                        if (m.received_iso or m.sender or m.subject) else None
                    ),
                }
                for m in self.messages
            ],
        }
        d["content_hash"] = sha256_hex(d)
        return d

    def to_public_safe(self) -> Dict[str, Any]:
        """EXPLICIT ALLOWLIST projection — never derived from the private dict.

        Contains NO raw account, mailbox, sender, subject, native id, local
        path, or free-form error text. Cryptographically linked to its source
        private snapshot via source_snapshot_sha256, which participates in
        the public content_hash along with every other field (hash computed
        LAST, after all authoritative fields — including 'projection').
        """
        private_hash = self.to_dict()["content_hash"]
        public: Dict[str, Any] = {
            "schema": PUBLIC_RECEIPT_SCHEMA,
            "projection": "public_safe",
            "source_snapshot_sha256": private_hash,
            "snapshot_id": self.snapshot_id,
            "provider": self.provider,
            "scope_digest": sha256_hex({
                "account": self.account, "mailbox": self.mailbox,
            }),
            "generated_at": self.generated_at,
            "status": self.status,
            "complete": self.complete,
            "zero_write_mode": self.zero_write_mode,
            "counts": {
                "total_matched": self.total_matched,
                "returned": self.returned_count,
                "hidden_by_limit": self.hidden_by_limit,
                "unknown_index": self.unknown_index_count,
                "inaccessible": self.inaccessible_count,
                "timeouts": self.timeout_count,
                "errors": len(self.errors),
            },
            # Error CODES only — never free-form text (may embed locals).
            "error_codes": sorted({
                e.split(":")[0].split(" ")[0][:40] for e in self.errors if e
            }),
            "messages": [
                {"ref": m.ref_digest, "flag": m.observed_flag.value}
                for m in self.messages
            ],
        }
        public["content_hash"] = sha256_hex(public)   # LAST, over everything
        return public


def validate_public_receipt(raw: Any) -> None:
    """Fail-closed integrity check for a public-safe receipt."""
    if not isinstance(raw, dict):
        raise FlagWorkflowError("public receipt must be a JSON object")
    if raw.get("schema") != PUBLIC_RECEIPT_SCHEMA:
        raise FlagWorkflowError(
            f"public receipt schema must be {PUBLIC_RECEIPT_SCHEMA}, "
            f"got {raw.get('schema')!r}"
        )
    if raw.get("projection") != "public_safe":
        raise FlagWorkflowError("projection must be 'public_safe'")
    # Structural privacy gate FIRST: a receipt carrying forbidden fields is
    # invalid no matter what its hash says.
    forbidden = {"account", "mailbox", "sender", "subject", "messages_raw"}
    present = forbidden & set(raw.keys())
    if present:
        raise FlagWorkflowError(
            f"public receipt contains forbidden keys: {sorted(present)}"
        )
    stored = require_hex256(raw.get("content_hash"), "public content_hash")
    require_hex256(raw.get("source_snapshot_sha256"),
                   "source_snapshot_sha256")
    body = {k: v for k, v in raw.items() if k != "content_hash"}
    if sha256_hex(body) != stored:
        raise FlagWorkflowError(
            "public receipt content_hash mismatch (tampered)"
        )


def build_snapshot(
    *,
    provider_name: str,
    account: str,
    mailbox: str,
    rows: List[Any],
    complete: bool,
    scope_complete: bool,
    status: str,
    errors: List[str],
    inaccessible_count: int,
    timeout_count: int,
    unknown_index_count: int,
    limit: int,
    since_days: Optional[int],
    ordering: str = "received_desc",
    total_matched: int,
    returned_count: int,
    hidden_by_limit: int,
    next_cursor: Optional[str] = None,
    generated_at: Optional[str] = None,
) -> FlagSnapshot:
    """Build a FlagSnapshot from a provider EnumerationResult's fields.

    Identity (P0 #1): the timestamp is MATERIALIZED FIRST and participates
    in snapshot_id together with exact scope and a canonical digest of all
    row evidence — two audits of the same scope with identical counts can
    never collide, so write_private_snapshot can never overwrite one.
    """
    generated_at = generated_at or datetime.now(timezone.utc).isoformat()

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
    evidence_digest = sha256_hex([{
        "id": m.provider_id, "flag": m.observed_flag.value,
        "received": m.received_iso, "sender": m.sender,
        "subject": m.subject,
    } for m in messages])
    snap = FlagSnapshot(
        schema=SNAPSHOT_SCHEMA,
        # Unique per audit run: real timestamp + scope + full evidence digest.
        snapshot_id="snap-" + sha256_hex({
            "generated_at": generated_at,
            "provider": provider_name, "account": account,
            "mailbox": mailbox,
            "evidence": evidence_digest,
        })[:32],
        generated_at=generated_at,
        provider=provider_name,
        account=account,
        mailbox=mailbox,
        complete=complete,
        scope_complete=scope_complete,
        status=status,
        zero_write_mode=True,
        errors=list(errors),
        inaccessible_count=inaccessible_count,
        timeout_count=timeout_count,
        unknown_index_count=unknown_index_count,
        limit=int(limit),
        since_days=since_days,
        ordering=ordering,
        total_matched=total_matched,
        returned_count=returned_count,
        hidden_by_limit=hidden_by_limit,
        next_cursor=next_cursor,
        messages=messages,
        content_hash="",
    )
    snap.content_hash = snap.to_dict()["content_hash"]
    # Semantic validation (same contract load_snapshot enforces) — snapshots
    # are the plan-eligibility boundary, so the producer side re-checks too.
    snap.validate()
    return snap


def _chmod_0700_best_effort(path: Path) -> None:
    """Best-effort 0700; never blocks the snapshot write."""
    try:
        if path.is_dir():
            os.chmod(path, 0o700)
    except OSError:
        pass


def _harden_private_dir(path: Path) -> None:
    """Harden the leaf dir to 0700 plus MANAGED ancestors.

    Managed ancestors are precisely the ``uma`` namespace this application
    owns: a directory named ``uma``, and ``flags`` / ``snapshots`` components
    DIRECTLY INSIDE that uma chain. A directory elsewhere that merely happens
    to be named "flags" is never touched.
    """
    resolved = path.resolve()
    parts = resolved.parts
    for i, name in enumerate(parts):
        if name != "uma":
            continue
        cand = Path(*parts[: i + 1])
        _chmod_0700_best_effort(cand)
        if i + 1 < len(parts) and parts[i + 1] == "flags":
            cand2 = Path(*parts[: i + 2])
            _chmod_0700_best_effort(cand2)
            if i + 2 < len(parts) and parts[i + 2] == "snapshots":
                _chmod_0700_best_effort(Path(*parts[: i + 3]))
    _chmod_0700_best_effort(resolved)


def write_private_snapshot(snapshot: FlagSnapshot, directory: Path) -> Path:
    """Atomically write the PRIVATE snapshot (mode 0600) under *directory*.

    The directory tree is created user-private AND hardened: even when an
    ancestor (e.g. ~/.local/share/uma/flags) already exists with looser
    permissions left by another tool, the leaf and every managed ``uma``
    component are re-chmodded to 0700 before writing. Atomicity via temp
    file + os.replace in the same directory.
    """
    directory = Path(directory).expanduser()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    _harden_private_dir(directory)
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
    snapshot = FlagSnapshot(
        schema=raw["schema"], snapshot_id=raw["snapshot_id"],
        generated_at=raw["generated_at"], provider=raw["provider"],
        account=raw["account"], mailbox=raw["mailbox"],
        complete=bool(raw["complete"]),
        scope_complete=bool(raw.get("scope_complete", raw["complete"])),
        status=raw["status"],
        zero_write_mode=bool(raw.get("zero_write_mode", True)),
        errors=list(raw.get("errors", [])),
        inaccessible_count=int(raw.get("inaccessible_count", 0)),
        timeout_count=int(raw.get("timeout_count", 0)),
        unknown_index_count=int(raw.get("unknown_index_count", 0)),
        limit=int(raw.get("limit", 0)),
        since_days=raw.get("since_days"),
        ordering=str(raw.get("ordering", "received_desc")),
        total_matched=int(raw.get("total_matched",
                                  raw.get("total_flagged_seen", 0))),
        returned_count=int(raw.get("returned_count", len(messages))),
        hidden_by_limit=int(raw.get("hidden_by_limit", 0)),
        next_cursor=raw.get("next_cursor"),
        messages=messages, content_hash=stored,
    )
    # Hash verified above; now verify SEMANTICS — a valid hash over
    # impossible content (e.g. complete=True with errors) must fail closed.
    snapshot.validate()
    return snapshot

# --- Estate-wide enumeration (multi-surface) ---------------------------------


def enumerate_estate(
    provider: Any,
    *,
    surfaces: Optional[List[Any]] = None,
    per_surface_limit: int = 500,
    since_days: Optional[int] = None,
    timeout_seconds: int = 600,
) -> Dict[str, Any]:
    """Enumerate flagged messages across MULTIPLE account/mailbox surfaces.

    ``surfaces=None`` triggers read-only discovery on the provider. Every
    surface is scanned with its own limit+timeout; per-surface failures are
    recorded and DO break estate completeness. Rows are deduplicated by
    qualified-reference digest across surfaces.

    Returns a typed aggregate — never raises for surface-level OR discovery
    failure.
    """
    if surfaces is None:
        try:
            surfaces = provider.discover_surfaces()
        except Exception as e:   # ProviderScriptError and any transport layer
            return {
                "rows": [],
                "deduplicated_removed": 0,
                "estate_complete": False,
                "status": "failed",
                "errors": [f"discovery_failed: {e}"],
                "inaccessible_count": 0,
                "timeout_count": 0,
                "unknown_index_count": 0,
                "hidden_by_limit_total": 0,
                "total_matched_all_surfaces": 0,
                "surfaces": [],
            }
    surface_reports: List[Dict[str, Any]] = []
    all_rows: List[Any] = []           # transport rows from provider
    seen_refs: set = set()
    deduped_rows: List[Any] = []
    errors: List[str] = []
    inaccessible_total = 0
    timeout_total = 0
    unknown_total = 0
    hidden_total = 0
    total_matched_all = 0

    if not surfaces:
        # Discovery succeeded but found NOTHING: nothing was scanned, so this
        # is a FAILED estate scan with an explicit reason — never the
        # misleading "bounded_partial" (which implies partial work happened).
        return {
            "rows": [],
            "deduplicated_removed": 0,
            "estate_complete": False,
            "status": "failed",
            "errors": ["discovery returned zero surfaces"],
            "inaccessible_count": 0,
            "timeout_count": 0,
            "unknown_index_count": 0,
            "hidden_by_limit_total": 0,
            "total_matched_all_surfaces": 0,
            "surfaces": [],
        }

    for surface in surfaces:
        try:
            result = provider.enumerate_flagged(
                mailbox=surface.mailbox,
                limit=per_surface_limit,
                since_days=since_days,
                timeout_seconds=timeout_seconds,
                account=surface.account,
            )
        except RuntimeError as e:
            # A raised surface error is a failed surface, not a silent skip.
            surface_reports.append({
                "account": surface.account, "mailbox": surface.mailbox,
                "status": "failed", "error": str(e),
            })
            errors.append(f"{surface.account}/{surface.mailbox}: {e}")
            continue
        surface_reports.append({
            "account": surface.account, "mailbox": surface.mailbox,
            "status": result.status,
            "total_matched": result.scanned_boundary.get(
                "total_flagged_seen", len(result.rows)),
            "returned": len(result.rows),
        })
        all_rows.extend(result.rows)
        errors.extend(f"{surface.account}/{surface.mailbox}: {e}"
                      for e in result.errors)
        inaccessible_total += result.inaccessible_count
        timeout_total += result.timeout_count
        unknown_total += result.unknown_index_count
        hidden_total += max(0, result.scanned_boundary.get(
            "hidden_by_limit", 0))
        total_matched_all += result.scanned_boundary.get(
            "total_flagged_seen", 0)
        if not result.scope_complete:
            errors.append(
                f"{surface.account}/{surface.mailbox}: scope incomplete")
        for row in result.rows:
            key = MessageReference(
                provider=getattr(provider, "name",
                                 getattr(row, "provider", "mailapp")),
                account=row.account, mailbox=row.mailbox,
                provider_id=row.provider_id,
            ).ref_digest
            if key in seen_refs:
                continue                      # cross-surface duplicate
            seen_refs.add(key)
            deduped_rows.append(row)

    estate_complete = (
        not errors and inaccessible_total == 0 and timeout_total == 0
        and hidden_total == 0 and bool(surfaces)
    )
    status = (
        "complete" if estate_complete
        else ("timed_out" if timeout_total else
              ("failed" if errors else "bounded_partial"))
    )
    return {
        "rows": deduped_rows,
        "deduplicated_removed": len(all_rows) - len(deduped_rows),
        "estate_complete": estate_complete,
        "status": status,
        "errors": errors,
        "inaccessible_count": inaccessible_total,
        "timeout_count": timeout_total,
        "unknown_index_count": unknown_total,
        "hidden_by_limit_total": hidden_total,
        "total_matched_all_surfaces": total_matched_all,
        "surfaces": surface_reports,
    }


def build_estate_snapshot(estate: Dict[str, Any], *, provider_name: str,
                          generated_at: Optional[str] = None) -> FlagSnapshot:
    """Snapshot over an estate aggregate. Scope fields describe the WHOLE
    discovered estate; completeness follows the same strict contract."""
    return build_snapshot(
        provider_name=provider_name,
        account="<estate>",
        mailbox=f"{len(estate['surfaces'])} surfaces",
        rows=estate["rows"],
        complete=estate["estate_complete"],
        scope_complete=not any(
            s.get("status") == "failed" for s in estate["surfaces"]),
        status=estate["status"],
        errors=estate["errors"],
        inaccessible_count=estate["inaccessible_count"],
        timeout_count=estate["timeout_count"],
        unknown_index_count=estate["unknown_index_count"],
        limit=-1,                    # multi-surface; per-surface limits recorded
        since_days=None,
        total_matched=estate["total_matched_all_surfaces"],
        returned_count=len(estate["rows"]),
        hidden_by_limit=estate["hidden_by_limit_total"],
        next_cursor=None,
        generated_at=generated_at,
    )


# --- Plan -------------------------------------------------------------------


@dataclass(frozen=True)
class PlannedMutation:
    """One proposed flag change, review-gated by construction.

    Commit 5: carries the DURABLE PRIVATE BINDINGS Commit 6's preflight
    will need to reconstruct the exact qualified target — provider,
    account, mailbox, provider_id, snapshot_id, observed native flag,
    evidence digest (and the RFC Message-ID digest when the provider has
    captured one). These NEVER enter the public-safe projection.
    """
    mutation_id: str
    ref_digest: str
    observed_flag: FlagColor
    proposed_flag: FlagColor
    reason_code: str
    reason: str
    confidence: Optional[float]
    review_required: bool
    provider: str = ""
    account: str = ""
    mailbox: str = ""
    provider_id: str = ""
    snapshot_id: str = ""
    observed_native_flag: Optional[int] = None
    evidence_digest: Optional[str] = None
    message_id_digest: Optional[str] = None

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
            "provider": self.provider,
            "account": self.account,
            "mailbox": self.mailbox,
            "provider_id": self.provider_id,
            "snapshot_id": self.snapshot_id,
            "observed_native_flag": self.observed_native_flag,
            "evidence_digest": self.evidence_digest,
            "message_id_digest": self.message_id_digest,
        }


def _mutation_from_dict(d: Dict[str, Any], idx: int) -> PlannedMutation:
    prefix = f"mutations[{idx}]"
    for key in (
        "mutation_id", "ref_digest", "observed_flag",
        "proposed_flag", "reason_code", "review_required",
        # v3 durable bindings — required, not optional.
        "provider", "account", "mailbox", "provider_id", "snapshot_id",
        "observed_native_flag", "evidence_digest", "message_id_digest",
    ):
        if key not in d:
            raise FlagWorkflowError(f"{prefix}: missing required key {key!r}")
    confidence = d.get("confidence")
    if confidence is not None and not (
        isinstance(confidence, (int, float)) and 0.0 <= float(confidence) <= 1.0
    ):
        raise FlagWorkflowError(f"{prefix}: confidence must be null or in [0,1]")
    native = d["observed_native_flag"]
    return PlannedMutation(
        mutation_id=str(d["mutation_id"]),
        ref_digest=require_hex256(d["ref_digest"], f"{prefix}.ref_digest"),
        observed_flag=FlagColor.from_string(str(d["observed_flag"])),
        proposed_flag=FlagColor.from_string(str(d["proposed_flag"])),
        reason_code=str(d["reason_code"]),
        reason=str(d.get("reason", "")),
        confidence=None if confidence is None else float(confidence),
        review_required=bool(d["review_required"]),
        provider=str(d["provider"]),
        account=str(d["account"]),
        mailbox=str(d["mailbox"]),
        provider_id=str(d["provider_id"]),
        snapshot_id=str(d["snapshot_id"]),
        observed_native_flag=None if native is None else int(native),
        evidence_digest=(
            None if d["evidence_digest"] is None
            else str(require_hex256(
                d["evidence_digest"], f"{prefix}.evidence_digest"))
        ),
        message_id_digest=(
            None if d["message_id_digest"] is None
            else str(require_hex256(
                d["message_id_digest"], f"{prefix}.message_id_digest"))
        ),
    )


def build_plan(snapshot: FlagSnapshot) -> Dict[str, Any]:
    """Build a plan bound to ONE snapshot. Refuses incomplete snapshots.

    Every mutation carries its DURABLE PRIVATE BINDING (provider/account/
    mailbox/provider_id/snapshot_id/observed native flag/evidence digest)
    so Commit 6 can preflight the exact qualified target without ever
    searching for identity. The plan hash covers those bindings.

    ``policy_sha256`` (digest of POLICY_RULES) participates in plan_hash:
    if policy code/configuration changes after planning, the stored hash
    no longer matches and validation fails — approval cannot cross a
    policy change silently.
    """
    if not snapshot.complete or snapshot.status != "complete":
        raise FlagWorkflowError(
            f"refusing to build apply-capable plan from "
            f"{snapshot.status} snapshot {snapshot.snapshot_id} "
            f"(complete={snapshot.complete}, scope_complete="
            f"{snapshot.scope_complete}, hidden="
            f"{snapshot.hidden_by_limit}, inaccessible="
            f"{snapshot.inaccessible_count})"
        )
    proposals: List[Proposal] = []
    for m in snapshot.messages:
        proposals.append(propose(m.sender, m.subject, m.observed_flag))
    mutations: List[PlannedMutation] = []
    for m, p in zip(snapshot.messages, proposals):
        if p.is_identity and p.reason_code == "no_change":
            continue
        # UNKNOWN observations are NEVER mutation-eligible.
        review_required = True if m.observed_flag == FlagColor.UNKNOWN \
            else p.review_required
        evidence_digest = (
            MessageReference.compute_evidence_digest(
                m.received_iso, m.sender, m.subject)
            if (m.received_iso or m.sender or m.subject) else None
        )
        mutations.append(PlannedMutation(
            # Mutation id binds the FULL durable context, not just colors:
            # changing any binding (or the source snapshot) changes ids.
            mutation_id="mut-" + sha256_hex({
                "ref": m.ref_digest,
                "observed": p.observed_flag.value,
                "proposed": p.proposed_flag.value,
                "reason_code": p.reason_code,
                "snapshot_id": snapshot.snapshot_id,
                "account": m.account,
                "mailbox": m.mailbox,
                "provider_id": m.provider_id,
                "evidence": evidence_digest,
            })[:24],
            ref_digest=m.ref_digest,
            observed_flag=p.observed_flag,
            proposed_flag=p.proposed_flag,
            reason_code=p.reason_code,
            reason=p.reason,
            confidence=p.confidence,
            review_required=review_required,
            provider=m.provider,
            account=m.account,
            mailbox=m.mailbox,
            provider_id=m.provider_id,
            snapshot_id=snapshot.snapshot_id,
            observed_native_flag=m.native_index,
            evidence_digest=evidence_digest,
            message_id_digest=None,   # populated once provider captures it
        ))
    plan: Dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "policy_version": MIGRATION_POLICY_VERSION,
        # Digest of the exact rule configuration used — tamper-evident
        # companion to the human-readable version string.
        "policy_sha256": POLICY_SHA256,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "snapshot_id": snapshot.snapshot_id,
        # Derive from to_dict(), never the possibly-stale dataclass field.
        "snapshot_sha256": snapshot.to_dict()["content_hash"],
        "snapshot_complete": snapshot.complete,
        "zero_write_declaration": True,
        "total_scanned": snapshot.total_matched,
        "mutations": [m.to_dict() for m in mutations],
        "unchanged_count": len(snapshot.messages) - len(mutations),
        # Plan-level visibility into the threshold split. Writes stay
        # impossible regardless of this count until Commit 6 gates exist.
        "auto_eligible_count": sum(
            1 for m in mutations
            if m.confidence is not None
            and m.confidence >= AUTO_ELIGIBLE_THRESHOLD
            and not m.review_required
        ),
    }
    plan["plan_hash"] = compute_plan_hash(plan)
    return plan


# --- Public-safe plan projection ---------------------------------------------


def to_public_safe_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    """EXPLICIT ALLOWLIST projection of a private plan.

    Retains ONLY digests: raw account/mailbox/provider_id/snapshot-scoped
    bindings (native flag, evidence digest, message-id digest), sender,
    subject never appear. Cryptographically linked to the source plan via
    source_plan_sha256; plan_public_hash computed LAST over all fields.
    """
    require_hex256(plan.get("plan_hash"), "plan_hash")
    public: Dict[str, Any] = {
        "schema": PUBLIC_PLAN_SCHEMA,
        "projection": "public_safe",
        "source_plan_sha256": plan["plan_hash"],
        "policy_version": plan["policy_version"],
        "policy_sha256": plan["policy_sha256"],
        "generated_at": plan["generated_at"],
        "snapshot_id": plan["snapshot_id"],
        "snapshot_sha256": plan["snapshot_sha256"],
        "zero_write_declaration": plan["zero_write_declaration"],
        "total_scanned": plan["total_scanned"],
        "unchanged_count": plan["unchanged_count"],
        "mutations": [
            {
                "mutation_id": m["mutation_id"],
                "ref_digest": m["ref_digest"],
                "observed_flag": m["observed_flag"],
                "proposed_flag": m["proposed_flag"],
                "reason_code": m["reason_code"],
                "confidence": m["confidence"],
                "review_required": m["review_required"],
            }
            for m in plan["mutations"]
        ],
    }
    public["plan_public_hash"] = sha256_hex(public)   # LAST
    return public


def validate_public_plan(raw: Any) -> None:
    """Fail-closed check: forbidden keys absent, then hash integrity."""
    if not isinstance(raw, dict):
        raise FlagWorkflowError("public plan must be a JSON object")
    if raw.get("schema") != PUBLIC_PLAN_SCHEMA:
        raise FlagWorkflowError(
            f"public plan schema must be {PUBLIC_PLAN_SCHEMA}")
    forbidden = {
        "account", "mailbox", "provider_id", "native_index",
        "observed_native_flag", "evidence_digest", "message_id_digest",
        "sender", "subject", "errors",
    }
    present = forbidden.intersection(raw.keys())
    if present:
        raise FlagWorkflowError(f"forbidden keys present: {sorted(present)}")
    for m in raw.get("mutations", []):
        leak = forbidden.intersection(m.keys())
        if leak:
            raise FlagWorkflowError(
                f"forbidden keys in mutation projection: {sorted(leak)}")
    stored = require_hex256(
        raw.get("plan_public_hash"), "plan_public_hash")
    body = {k: v for k, v in raw.items() if k != "plan_public_hash"}
    if sha256_hex(body) != stored:
        raise FlagWorkflowError("public plan hash mismatch (tampered)")


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
    # The digest is the tamper-evident half of policy identity: a plan
    # stamped with the right version string but generated under DIFFERENT
    # rules cannot pass.
    if plan.get("policy_sha256") != POLICY_SHA256:
        raise FlagWorkflowError(
            "policy_sha256 mismatch — plan was generated under different "
            "rule configuration (or digest tampered)"
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
