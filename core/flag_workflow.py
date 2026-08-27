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

import fcntl
import hashlib
import json
import math
import os
import secrets
import stat
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional

from core.models import FlagColor, MessageReference
from core.flag_policy import (
    Classification,
    MIGRATION_POLICY_VERSION,
    POLICY_SHA256,
    Proposal,
    propose,
    proposal_from_classification,
)

# --- Schema names ----------------------------------------------------------

SNAPSHOT_SCHEMA = "uma.flags.snapshot.v1"
PUBLIC_RECEIPT_SCHEMA = "uma.flags.public_receipt.v1"
PLAN_SCHEMA = "uma.flags.migration.plan.v5"
PUBLIC_PLAN_SCHEMA = "uma.flags.migration.plan.public.v2"
APPROVAL_SCHEMA = "uma.flags.approval.v4"
CLASSIFICATION_PROOF_SCHEMA = "uma.flags.classification_proof.v1"
MUTATION_ID_SCHEMA = "uma.flags.mutation_id.v2"
APPLY_RECEIPT_SCHEMA = "uma.flags.apply_receipt.v1"
ROLLBACK_RECEIPT_SCHEMA = "uma.flags.rollback_receipt.v1"

# Canary hard limits (enforced everywhere an approval is validated).
CANARY_MIN = 1
CANARY_MAX = 10

# Approval authority is deliberately separate from classifier state.  A
# human-nominated first activation canary may exercise a review-required
# mutation, but never rewrites the plan's confidence or eligibility fields.
SELECTION_SOURCE_AUTOMATIC = "automatic"
SELECTION_SOURCE_HUMAN_CANARY = "human_canary"
PURPOSE_MIGRATION = "migration"
PURPOSE_ACTIVATION_CANARY = "activation_canary"
HUMAN_CANARY_MAX = 3

_HEX_CHARS = set("0123456789abcdef")

_PUBLIC_ERROR_CODES = frozenset({
    "discovery_failed",
    "provider_error",
    "scan_timed_out",
    "scope_incomplete",
})

_OVERRIDE_LOCKS_GUARD = threading.Lock()
_OVERRIDE_LOCKS: Dict[str, threading.RLock] = {}


class FlagWorkflowError(ValueError):
    """Raised when a workflow artifact fails schema/integrity validation."""


def _require_bool(value: Any, name: str) -> bool:
    """Return an actual JSON boolean; never accept truthy substitutes."""
    if type(value) is not bool:
        raise FlagWorkflowError(
            f"{name} must be a boolean, got {type(value).__name__}"
        )
    return value


def _require_int(value: Any, name: str, *, minimum: Optional[int] = None) -> int:
    """Return an actual integer while rejecting bool and scalar coercion."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise FlagWorkflowError(
            f"{name} must be an int, got {type(value).__name__}"
        )
    if minimum is not None and value < minimum:
        raise FlagWorkflowError(f"{name} must be >= {minimum}, got {value}")
    return value


def _require_optional_int(value: Any, name: str) -> Optional[int]:
    if value is None:
        return None
    return _require_int(value, name)


def _require_string(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise FlagWorkflowError(
            f"{name} must be a string, got {type(value).__name__}"
        )
    if not allow_empty and not value.strip():
        raise FlagWorkflowError(f"{name} must be a non-empty string")
    return value


def _require_optional_string(value: Any, name: str) -> Optional[str]:
    if value is None:
        return None
    return _require_string(value, name, allow_empty=True)


def _parse_aware_timestamp(value: Any, name: str) -> datetime:
    """Parse an ISO timestamp and require an explicit UTC offset."""
    text = _require_string(value, name)
    try:
        parsed = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text
        )
        offset = parsed.utcoffset()
    except (OverflowError, TypeError, ValueError) as exc:
        raise FlagWorkflowError(f"{name} malformed: {value!r}") from exc
    if parsed.tzinfo is None or offset is None:
        raise FlagWorkflowError(f"{name} must be timezone-aware")
    return parsed


def _normalize_aware_datetime(value: Any, name: str) -> datetime:
    """Type-check an aware runtime clock and normalize it to UTC."""
    if not isinstance(value, datetime):
        raise FlagWorkflowError(
            f"{name} must be a datetime, got {type(value).__name__}"
        )
    try:
        offset = value.utcoffset()
        if value.tzinfo is None or offset is None:
            raise FlagWorkflowError(f"{name} must be timezone-aware")
        return value.astimezone(timezone.utc)
    except FlagWorkflowError:
        raise
    except (OverflowError, TypeError, ValueError) as exc:
        raise FlagWorkflowError(f"{name} is invalid") from exc


def _reject_nonfinite_json(value: str) -> Any:
    raise ValueError(f"non-finite JSON number {value}")


def _reject_duplicate_json_keys(
    pairs: List[tuple[str, Any]],
) -> Dict[str, Any]:
    """Build a JSON object while rejecting last-value-wins ambiguity."""
    parsed: Dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError(f"duplicate JSON object key {key!r}")
        parsed[key] = value
    return parsed


def _json_object_from_path(path: Path, artifact_name: str) -> Dict[str, Any]:
    """Read one strict UTF-8 JSON object and convert failures to our type."""
    try:
        raw_text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise FlagWorkflowError(
            f"{artifact_name} unreadable: {Path(path)}"
        ) from exc
    try:
        raw = json.loads(
            raw_text,
            parse_constant=_reject_nonfinite_json,
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise FlagWorkflowError(
            f"{artifact_name} contains invalid JSON: {Path(path)}"
        ) from exc
    if not isinstance(raw, dict):
        raise FlagWorkflowError(f"{artifact_name} must be a JSON object")
    return raw


# --- Canonical hashing ------------------------------------------------------


def _validate_strict_json_value(value: Any, path: str = "$") -> None:
    """Require values that can exist in decoded JSON without coercion.

    ``json.dumps`` otherwise accepts Python-only conveniences such as tuples,
    integer mapping keys, ``str`` subclasses, and a ``default`` converter.
    Authoritative hashes must bind one unambiguous JSON value, so those values
    fail before serialization instead of being silently transformed.
    """
    if value is None or type(value) in (bool, int, str):
        return
    if type(value) is float:
        if not math.isfinite(value):
            raise FlagWorkflowError(
                f"{path} contains a non-finite JSON number"
            )
        return
    if type(value) is list:
        for index, item in enumerate(value):
            _validate_strict_json_value(item, f"{path}[{index}]")
        return
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise FlagWorkflowError(
                    f"{path} contains a non-string JSON object key"
                )
            _validate_strict_json_value(item, f"{path}.{key}")
        return
    raise FlagWorkflowError(
        f"{path} contains non-JSON value {type(value).__name__}"
    )


def canonical_json_bytes(payload: Any) -> bytes:
    """Deterministic JSON encoding used for EVERY authoritative hash."""
    try:
        _validate_strict_json_value(payload)
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except FlagWorkflowError:
        raise
    except (OverflowError, RecursionError, TypeError, UnicodeEncodeError,
            ValueError) as exc:
        raise FlagWorkflowError(
            "payload cannot be encoded as strict canonical JSON"
        ) from exc


def sha256_hex(payload: Any) -> str:
    """Full 64-char SHA-256 over the canonical JSON of *payload*."""
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def require_hex256(value: Any, name: str) -> str:
    """Reject anything that is not a full 64-char lowercase hex digest."""
    if (
        not isinstance(value, str)
        or len(value) != 64
        or not set(value) <= _HEX_CHARS
    ):
        raise FlagWorkflowError(
            f"{name} must be a full 64-char SHA-256 hex digest, got {value!r}"
        )
    return value


def _require_exact_keys(raw: Dict[str, Any], expected: set[str],
                        name: str) -> None:
    """Reject missing, unknown, and non-string object keys."""
    if not all(type(key) is str for key in raw):
        raise FlagWorkflowError(f"{name} keys must be strings")
    actual = set(raw)
    missing = expected - actual
    unexpected = actual - expected
    if missing or unexpected:
        details = []
        if missing:
            details.append(f"missing={sorted(missing)}")
        if unexpected:
            details.append(f"unexpected={sorted(unexpected)}")
        raise FlagWorkflowError(
            f"{name} keys must match the schema exactly " + ", ".join(details)
        )


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
    _require_bool(scope_complete, "scope_complete")
    if not isinstance(errors, list) or not all(
        isinstance(error, str) for error in errors
    ):
        raise FlagWorkflowError("errors must be a list of strings")
    _require_int(inaccessible_count, "inaccessible_count", minimum=0)
    _require_int(timeout_count, "timeout_count", minimum=0)
    _require_int(hidden_by_limit, "hidden_by_limit", minimum=0)
    if timeout_count:
        return "timed_out"
    if errors or not scope_complete:
        return "failed"
    if inaccessible_count:
        return "partial"
    if hidden_by_limit:
        return "bounded_partial"
    return "complete"


def _public_error_code(error: str) -> str:
    """Map private failure detail onto a fixed, scope-free code allowlist."""
    lowered = error.casefold()
    if lowered.startswith("discovery_failed:"):
        code = "discovery_failed"
    elif "timed out" in lowered or "timeout" in lowered:
        code = "scan_timed_out"
    elif lowered.endswith(": scope incomplete"):
        code = "scope_incomplete"
    else:
        code = "provider_error"
    if code not in _PUBLIC_ERROR_CODES:  # pragma: no cover - closed mapping
        raise FlagWorkflowError("internal public error-code mapping failure")
    return code


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
        if self.schema != SNAPSHOT_SCHEMA:
            raise FlagWorkflowError(
                f"snapshot schema must be {SNAPSHOT_SCHEMA}, "
                f"got {self.schema!r}"
            )
        _require_bool(self.complete, "complete")
        _require_bool(self.scope_complete, "scope_complete")
        _require_bool(self.zero_write_mode, "zero_write_mode")
        if self.zero_write_mode is not True:
            raise FlagWorkflowError(
                "snapshot zero_write_mode must be True — snapshots from a "
                "mutating producer are untrustworthy")
        if not isinstance(self.errors, list) or not all(
            isinstance(error, str) for error in self.errors
        ):
            raise FlagWorkflowError("errors must be a list of strings")
        # Scalar type sanity: bools are not integers at an artifact boundary.
        _require_int(self.limit, "limit", minimum=1)
        for name in ("total_matched", "returned_count",
                     "inaccessible_count", "timeout_count",
                     "unknown_index_count", "hidden_by_limit"):
            _require_int(getattr(self, name), name)
        for name in ("total_matched", "returned_count", "inaccessible_count",
                     "timeout_count", "unknown_index_count",
                     "hidden_by_limit"):
            _require_int(getattr(self, name), name, minimum=0)
        if self.since_days is not None:
            _require_int(self.since_days, "since_days", minimum=1)
        _require_optional_string(self.next_cursor, "next_cursor")
        _require_string(self.ordering, "ordering")
        _require_string(self.provider, "provider")
        _require_string(self.account, "account")
        _require_string(self.mailbox, "mailbox")
        _require_string(self.status, "status")
        # snapshot_id provenance shape: 'snap-' + 32 hex (producer contract).
        if not (isinstance(self.snapshot_id, str)
                and self.snapshot_id.startswith("snap-")
                and len(self.snapshot_id) == 37
                and set(self.snapshot_id[5:].lower()) <= _HEX_CHARS):
            raise FlagWorkflowError(
                f"snapshot_id malformed: {self.snapshot_id!r} "
                "(expected 'snap-' + 32 hex)")
        # generated_at must be a parseable, timezone-aware ISO timestamp.
        _parse_aware_timestamp(self.generated_at, "generated_at")

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
        accounted_minimum = (
            self.returned_count
            + self.hidden_by_limit
            + self.inaccessible_count
        )
        if self.total_matched < accounted_minimum:
            raise FlagWorkflowError(
                f"total_matched {self.total_matched} is smaller than "
                f"returned + hidden + inaccessible ({accounted_minimum})"
            )
        if (
            self.scope_complete
            and not self.errors
            and self.timeout_count == 0
            and self.total_matched != accounted_minimum
        ):
            raise FlagWorkflowError(
                f"scope-complete snapshot counts are incoherent: "
                f"total_matched={self.total_matched}, returned="
                f"{self.returned_count}, hidden={self.hidden_by_limit}, "
                f"inaccessible={self.inaccessible_count}"
            )
        if not isinstance(self.messages, list):
            raise FlagWorkflowError("messages must be a list")
        if not all(isinstance(message, SnapshotMessage)
                   for message in self.messages):
            raise FlagWorkflowError(
                "messages must contain SnapshotMessage objects"
            )
        unknown_actual = sum(
            1 for m in self.messages if m.observed_flag == FlagColor.UNKNOWN)
        if unknown_actual != self.unknown_index_count:
            raise FlagWorkflowError(
                f"unknown_index_count {self.unknown_index_count} != actual "
                f"UNKNOWN messages {unknown_actual}")
        seen_refs = set()
        validator = _native_validator_for(self.provider)
        for m in self.messages:
            for name in ("provider", "account", "mailbox", "provider_id"):
                _require_string(getattr(m, name), f"message.{name}")
            _require_string(m.sender, "message.sender", allow_empty=True)
            _require_string(m.subject, "message.subject", allow_empty=True)
            _require_optional_int(m.native_index, "message.native_index")
            _require_optional_string(m.received_iso, "message.received_iso")
            if not isinstance(m.observed_flag, FlagColor):
                raise FlagWorkflowError(
                    "message.observed_flag must be a FlagColor"
                )
            if m.provider != self.provider:
                raise FlagWorkflowError(
                    f"message {m.provider_id}: provider {m.provider!r} "
                    f"disagrees with snapshot provider {self.provider!r}"
                )
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
        self.validate()
        private_hash = self.to_dict()["content_hash"]
        if self.content_hash != private_hash:
            raise FlagWorkflowError(
                "snapshot content_hash mismatch (stale or tampered object)"
            )
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
                _public_error_code(error) for error in self.errors
            }),
            "messages": [
                {"ref": m.ref_digest, "flag": m.observed_flag.value}
                for m in self.messages
            ],
        }
        public["content_hash"] = sha256_hex(public)   # LAST, over everything
        return public


def validate_public_receipt(raw: Any) -> None:
    """Fail-closed exact-schema check for a public-safe receipt."""
    if not isinstance(raw, dict):
        raise FlagWorkflowError("public receipt must be a JSON object")
    expected_keys = {
        "schema", "projection", "source_snapshot_sha256", "snapshot_id",
        "provider", "scope_digest", "generated_at", "status", "complete",
        "zero_write_mode", "counts", "error_codes", "messages",
        "content_hash",
    }
    if not all(type(key) is str for key in raw):
        raise FlagWorkflowError("public receipt keys must be strings")
    unexpected = set(raw) - expected_keys
    if unexpected:
        raise FlagWorkflowError(
            f"public receipt contains forbidden keys: {sorted(unexpected)}"
        )
    _require_exact_keys(raw, expected_keys, "public receipt")
    if raw.get("schema") != PUBLIC_RECEIPT_SCHEMA:
        raise FlagWorkflowError(
            f"public receipt schema must be {PUBLIC_RECEIPT_SCHEMA}, "
            f"got {raw.get('schema')!r}"
        )
    if raw.get("projection") != "public_safe":
        raise FlagWorkflowError("projection must be 'public_safe'")
    require_hex256(
        raw["source_snapshot_sha256"], "source_snapshot_sha256"
    )
    snapshot_id = _require_string(raw["snapshot_id"], "snapshot_id")
    if not (
        snapshot_id.startswith("snap-")
        and len(snapshot_id) == 37
        and set(snapshot_id[5:]) <= _HEX_CHARS
    ):
        raise FlagWorkflowError(
            "snapshot_id must be 'snap-' followed by 32 lowercase hex "
            "characters"
        )
    _require_string(raw["provider"], "provider")
    require_hex256(raw["scope_digest"], "scope_digest")
    _parse_aware_timestamp(raw["generated_at"], "generated_at")
    status = _require_string(raw["status"], "status")
    if status not in {
        "complete", "bounded_partial", "partial", "failed", "timed_out",
    }:
        raise FlagWorkflowError(f"invalid public receipt status {status!r}")
    complete = _require_bool(raw["complete"], "complete")
    if complete != (status == "complete"):
        raise FlagWorkflowError(
            "public receipt complete flag disagrees with status"
        )
    if _require_bool(raw["zero_write_mode"], "zero_write_mode") is not True:
        raise FlagWorkflowError("public receipt zero_write_mode must be True")

    counts = raw["counts"]
    if not isinstance(counts, dict):
        raise FlagWorkflowError("public receipt counts must be an object")
    count_keys = {
        "total_matched", "returned", "hidden_by_limit", "unknown_index",
        "inaccessible", "timeouts", "errors",
    }
    _require_exact_keys(counts, count_keys, "public receipt counts")
    parsed_counts = {
        key: _require_int(value, f"counts.{key}", minimum=0)
        for key, value in counts.items()
    }

    error_codes = raw.get("error_codes")
    if (
        not isinstance(error_codes, list)
        or not all(type(code) is str for code in error_codes)
        or not set(error_codes) <= _PUBLIC_ERROR_CODES
    ):
        raise FlagWorkflowError(
            "public receipt error_codes must use the fixed public allowlist"
        )
    if error_codes != sorted(set(error_codes)):
        raise FlagWorkflowError(
            "public receipt error_codes must be sorted and unique"
        )
    if len(error_codes) > parsed_counts["errors"]:
        raise FlagWorkflowError(
            "public receipt error_codes exceed the reported error count"
        )
    if bool(error_codes) != bool(parsed_counts["errors"]):
        raise FlagWorkflowError(
            "public receipt error_codes disagree with the reported error "
            "count"
        )

    messages = raw["messages"]
    if not isinstance(messages, list):
        raise FlagWorkflowError("public receipt messages must be a list")
    allowed_flags = {color.value for color in FlagColor}
    seen_refs = set()
    unknown_count = 0
    for index, message in enumerate(messages):
        prefix = f"public receipt messages[{index}]"
        if not isinstance(message, dict):
            raise FlagWorkflowError(f"{prefix} must be an object")
        _require_exact_keys(message, {"ref", "flag"}, prefix)
        ref_digest = require_hex256(message["ref"], f"{prefix}.ref")
        if ref_digest in seen_refs:
            raise FlagWorkflowError(
                f"{prefix}.ref duplicates an earlier message"
            )
        seen_refs.add(ref_digest)
        flag = _require_string(message["flag"], f"{prefix}.flag")
        if flag not in allowed_flags:
            raise FlagWorkflowError(f"{prefix}.flag is not canonical")
        unknown_count += int(flag == FlagColor.UNKNOWN.value)

    if parsed_counts["returned"] != len(messages):
        raise FlagWorkflowError(
            "public receipt returned count does not match messages"
        )
    if parsed_counts["unknown_index"] != unknown_count:
        raise FlagWorkflowError(
            "public receipt unknown_index count does not match messages"
        )
    accounted_minimum = (
        parsed_counts["returned"]
        + parsed_counts["hidden_by_limit"]
        + parsed_counts["inaccessible"]
    )
    if parsed_counts["total_matched"] < accounted_minimum:
        raise FlagWorkflowError("public receipt counts are incoherent")
    if complete and any(
        parsed_counts[key]
        for key in ("hidden_by_limit", "inaccessible", "timeouts", "errors")
    ):
        raise FlagWorkflowError(
            "complete public receipt cannot report omitted or failed rows"
        )
    if complete and parsed_counts["total_matched"] != len(messages):
        raise FlagWorkflowError(
            "complete public receipt total does not match returned messages"
        )
    if status == "bounded_partial" and not parsed_counts["hidden_by_limit"]:
        raise FlagWorkflowError(
            "bounded_partial public receipt requires hidden rows"
        )
    if status == "timed_out" and not parsed_counts["timeouts"]:
        raise FlagWorkflowError(
            "timed_out public receipt requires a timeout"
        )
    if status == "partial" and not parsed_counts["inaccessible"]:
        raise FlagWorkflowError(
            "partial public receipt requires inaccessible rows"
        )

    stored = require_hex256(raw["content_hash"], "public content_hash")
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
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).isoformat()

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
        limit=limit,
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
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
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


def _open_private_parent(path: Path, *, create: bool, label: str) -> int:
    """Hold a private artifact parent via dirfd without following symlinks."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    parent = absolute.parent
    anchor = parent.parent
    child_name = parent.name
    if not child_name:
        raise FlagWorkflowError(
            f"{label} cannot live directly under filesystem root"
        )
    if create:
        try:
            anchor.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise FlagWorkflowError(
                f"{label} state root unavailable ({anchor}): {exc}"
            ) from exc
    anchor_fd: Optional[int] = None
    parent_fd: Optional[int] = None
    try:
        anchor_fd = os.open(
            anchor,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
        try:
            parent_fd = os.open(
                child_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=anchor_fd,
            )
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(child_name, mode=0o700, dir_fd=anchor_fd)
            except FileExistsError:
                pass
            parent_fd = os.open(
                child_name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=anchor_fd,
            )
        os.fchmod(parent_fd, 0o700)
        return parent_fd
    except FileNotFoundError:
        if parent_fd is not None:
            os.close(parent_fd)
        raise
    except OSError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        raise FlagWorkflowError(
            f"{label} parent unusable ({parent}): {exc}"
        ) from exc
    finally:
        if anchor_fd is not None:
            os.close(anchor_fd)


def write_private_snapshot(snapshot: FlagSnapshot, directory: Path) -> Path:
    """Atomically write the PRIVATE snapshot (mode 0600) under *directory*.

    The directory tree is created user-private AND hardened: even when an
    ancestor (e.g. ~/.local/share/uma/flags) already exists with looser
    permissions left by another tool, the leaf and every managed ``uma``
    component are re-chmodded to 0700 before writing. Atomicity via temp
    file + os.replace in the same directory.
    """
    snapshot.validate()
    payload = snapshot.to_dict()
    if snapshot.content_hash != payload["content_hash"]:
        raise FlagWorkflowError(
            "snapshot content_hash mismatch (stale or tampered object)"
        )
    directory = Path(directory).expanduser()
    final = directory / f"{snapshot.snapshot_id}.json"
    return _atomic_write_private_json(final, payload, prefix=".tmp-snap-")


def _atomic_write_private_json(
    path: Path,
    payload: Dict[str, Any],
    *,
    prefix: str,
) -> Path:
    """Atomically replace *path* via a unique same-directory 0600 file."""
    final = Path(path).expanduser()
    parent_fd: Optional[int] = None
    fd: Optional[int] = None
    tmp_name: Optional[str] = None
    try:
        encoded = (
            json.dumps(
                payload,
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
                allow_nan=False,
            )
            + "\n"
        ).encode("utf-8")
        parent_fd = _open_private_parent(
            final, create=True, label="private artifact"
        )
        _harden_private_dir(final.parent)
        for _ in range(100):
            candidate = f"{prefix}{secrets.token_hex(16)}.tmp"
            try:
                fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                    os.O_NOFOLLOW | os.O_NONBLOCK,
                    0o600,
                    dir_fd=parent_fd,
                )
                tmp_name = candidate
                break
            except FileExistsError:
                continue
        if fd is None or tmp_name is None:
            raise OSError("could not allocate a unique private temp file")
    except (OSError, TypeError, UnicodeEncodeError, ValueError) as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        raise FlagWorkflowError(
            f"private artifact preparation failed ({final}): {exc}"
        ) from exc
    try:
        os.fchmod(fd, 0o600)
        written = 0
        while written < len(encoded):
            count = os.write(fd, encoded[written:])
            if count <= 0:
                raise OSError("private artifact write made no progress")
            written += count
        os.fsync(fd)
        os.close(fd)
        fd = None
        os.replace(
            tmp_name,
            final.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        tmp_name = None
        final_fd = os.open(
            final.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_fd,
        )
        try:
            if not stat.S_ISREG(os.fstat(final_fd).st_mode):
                raise OSError("private artifact is not a regular file")
            os.fchmod(final_fd, 0o600)
        finally:
            os.close(final_fd)
        os.fsync(parent_fd)
        return final
    except OSError as exc:
        raise FlagWorkflowError(
            f"private artifact write failed ({final}): {exc}"
        ) from exc
    finally:
        if fd is not None:
            os.close(fd)
        if tmp_name is not None and parent_fd is not None:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass
        if parent_fd is not None:
            os.close(parent_fd)


def write_private_plan(plan: Dict[str, Any], path: Path) -> Path:
    """Validate and atomically write a private migration plan as mode 0600."""
    validate_plan_schema(plan)
    return _atomic_write_private_json(
        Path(path), plan, prefix=".tmp-flags-plan-"
    )


def load_plan(path: Path) -> Dict[str, Any]:
    """Load and strictly validate one private migration plan artifact."""
    plan = _json_object_from_path(Path(path), "plan")
    validate_plan_schema(plan)
    return plan


def validate_plan_snapshot_lineage(
        plan: Dict[str, Any], snapshot: FlagSnapshot) -> List[PlannedMutation]:
    """Prove that *plan* is the complete plan derived from *snapshot*.

    A plan hash proves only the integrity of the plan object itself.  It does
    not prove that a caller retained every mutation from the source snapshot:
    an omitted mutation plus adjusted counts can be re-hashed into another
    internally coherent object.  The activation boundary therefore rebuilds
    the plan from the validated private snapshot, preserves the plan's
    original generation timestamp, and requires byte-semantic equality.
    """
    parsed = validate_plan_schema(plan)
    snapshot.validate()
    snapshot_hash = snapshot.to_dict()["content_hash"]
    if snapshot.content_hash != snapshot_hash:
        raise FlagWorkflowError(
            "snapshot content_hash mismatch (stale or tampered object)"
        )
    if plan.get("snapshot_id") != snapshot.snapshot_id:
        raise FlagWorkflowError(
            "plan.snapshot_id does not match the supplied snapshot"
        )
    if plan.get("snapshot_sha256") != snapshot_hash:
        raise FlagWorkflowError(
            "plan.snapshot_sha256 does not match the supplied snapshot"
        )

    rebuilt = build_plan(snapshot)
    rebuilt["generated_at"] = plan["generated_at"]
    rebuilt["plan_hash"] = compute_plan_hash(rebuilt)
    if rebuilt != plan:
        raise FlagWorkflowError(
            "plan is not the complete canonical derivation of the supplied "
            "snapshot"
        )
    return parsed


def load_snapshot(path: Path) -> FlagSnapshot:
    """Load + verify a snapshot file's content_hash."""
    raw = _json_object_from_path(Path(path), "snapshot")
    required = {
        "schema", "snapshot_id", "generated_at", "provider", "account",
        "mailbox", "complete", "scope_complete", "status",
        "zero_write_mode", "errors", "inaccessible_count",
        "timeout_count", "unknown_index_count", "limit", "since_days",
        "ordering", "total_matched", "returned_count", "hidden_by_limit",
        "next_cursor", "messages", "content_hash",
    }
    missing = required.difference(raw)
    if missing:
        raise FlagWorkflowError(
            f"snapshot missing required keys: {sorted(missing)}"
        )
    if raw.get("schema") != SNAPSHOT_SCHEMA:
        raise FlagWorkflowError(f"not a {SNAPSHOT_SCHEMA} snapshot")
    stored = require_hex256(raw.get("content_hash"), "snapshot content_hash")
    body = {k: v for k, v in raw.items() if k != "content_hash"}
    if sha256_hex(body) != stored:
        raise FlagWorkflowError("snapshot content_hash mismatch (tampered)")
    messages_raw = raw["messages"]
    if not isinstance(messages_raw, list):
        raise FlagWorkflowError("snapshot.messages must be a list")
    messages: List[SnapshotMessage] = []
    message_required = {
        "provider", "account", "mailbox", "provider_id", "sender",
        "subject", "native_index", "observed_flag", "received_iso",
        "evidence_digest",
    }
    for index, message_raw in enumerate(messages_raw):
        prefix = f"snapshot.messages[{index}]"
        if not isinstance(message_raw, dict):
            raise FlagWorkflowError(f"{prefix} must be a JSON object")
        missing_message = message_required.difference(message_raw)
        if missing_message:
            raise FlagWorkflowError(
                f"{prefix} missing required keys: {sorted(missing_message)}"
            )
        provider = _require_string(message_raw["provider"], f"{prefix}.provider")
        account = _require_string(message_raw["account"], f"{prefix}.account")
        mailbox = _require_string(message_raw["mailbox"], f"{prefix}.mailbox")
        provider_id = _require_string(
            message_raw["provider_id"], f"{prefix}.provider_id"
        )
        sender = _require_string(
            message_raw["sender"], f"{prefix}.sender", allow_empty=True
        )
        subject = _require_string(
            message_raw["subject"], f"{prefix}.subject", allow_empty=True
        )
        native_index = _require_optional_int(
            message_raw["native_index"], f"{prefix}.native_index"
        )
        received_iso = _require_optional_string(
            message_raw["received_iso"], f"{prefix}.received_iso"
        )
        observed_raw = _require_string(
            message_raw["observed_flag"], f"{prefix}.observed_flag"
        )
        try:
            observed_flag = FlagColor.from_string(observed_raw)
        except ValueError as exc:
            raise FlagWorkflowError(f"{prefix}: {exc}") from exc
        expected_evidence = (
            MessageReference.compute_evidence_digest(
                received_iso, sender, subject
            )
            if (received_iso or sender or subject)
            else None
        )
        evidence_raw = message_raw["evidence_digest"]
        evidence_digest = (
            None
            if evidence_raw is None
            else require_hex256(evidence_raw, f"{prefix}.evidence_digest")
        )
        if evidence_digest != expected_evidence:
            raise FlagWorkflowError(
                f"{prefix}.evidence_digest does not match message evidence"
            )
        messages.append(SnapshotMessage(
            provider=provider,
            account=account,
            mailbox=mailbox,
            provider_id=provider_id,
            sender=sender,
            subject=subject,
            native_index=native_index,
            observed_flag=observed_flag,
            received_iso=received_iso,
        ))

    errors = raw["errors"]
    if not isinstance(errors, list) or not all(
        isinstance(error, str) for error in errors
    ):
        raise FlagWorkflowError("snapshot.errors must be a list of strings")
    snapshot = FlagSnapshot(
        schema=_require_string(raw["schema"], "snapshot.schema"),
        snapshot_id=_require_string(raw["snapshot_id"], "snapshot.snapshot_id"),
        generated_at=_require_string(raw["generated_at"], "snapshot.generated_at"),
        provider=_require_string(raw["provider"], "snapshot.provider"),
        account=_require_string(raw["account"], "snapshot.account"),
        mailbox=_require_string(raw["mailbox"], "snapshot.mailbox"),
        complete=_require_bool(raw["complete"], "snapshot.complete"),
        scope_complete=_require_bool(
            raw["scope_complete"], "snapshot.scope_complete"
        ),
        status=_require_string(raw["status"], "snapshot.status"),
        zero_write_mode=_require_bool(
            raw["zero_write_mode"], "snapshot.zero_write_mode"
        ),
        errors=errors,
        inaccessible_count=_require_int(
            raw["inaccessible_count"], "snapshot.inaccessible_count"
        ),
        timeout_count=_require_int(
            raw["timeout_count"], "snapshot.timeout_count"
        ),
        unknown_index_count=_require_int(
            raw["unknown_index_count"], "snapshot.unknown_index_count"
        ),
        limit=_require_int(raw["limit"], "snapshot.limit"),
        since_days=_require_optional_int(raw["since_days"], "snapshot.since_days"),
        ordering=_require_string(raw["ordering"], "snapshot.ordering"),
        total_matched=_require_int(
            raw["total_matched"], "snapshot.total_matched"
        ),
        returned_count=_require_int(
            raw["returned_count"], "snapshot.returned_count"
        ),
        hidden_by_limit=_require_int(
            raw["hidden_by_limit"], "snapshot.hidden_by_limit"
        ),
        next_cursor=_require_optional_string(
            raw["next_cursor"], "snapshot.next_cursor"
        ),
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
    _require_int(per_surface_limit, "per_surface_limit", minimum=1)
    if since_days is not None:
        _require_int(since_days, "since_days", minimum=1)
    _require_int(timeout_seconds, "timeout_seconds", minimum=1)
    if surfaces is None:
        try:
            surfaces = provider.discover_surfaces()
        except Exception as e:   # ProviderScriptError and any transport layer
            return {
                "rows": [],
                "deduplicated_removed": 0,
                "estate_complete": False,
                "scope_complete": False,
                "status": "failed",
                "errors": [f"discovery_failed: {e}"],
                "inaccessible_count": 0,
                "timeout_count": 0,
                "unknown_index_count": 0,
                "hidden_by_limit_total": 0,
                "total_matched_all_surfaces": 0,
                "surfaces": [],
                "per_surface_limit": per_surface_limit,
                "since_days": since_days,
            }
    surface_reports: List[Dict[str, Any]] = []
    all_rows: List[Any] = []           # transport rows from provider
    seen_refs: set = set()
    deduped_rows: List[Any] = []
    errors: List[str] = []
    inaccessible_total = 0
    timeout_total = 0
    hidden_total = 0
    total_matched_all = 0
    estate_scope_complete = True

    if not surfaces:
        # Discovery succeeded but found NOTHING: nothing was scanned, so this
        # is a FAILED estate scan with an explicit reason — never the
        # misleading "bounded_partial" (which implies partial work happened).
        return {
            "rows": [],
            "deduplicated_removed": 0,
            "estate_complete": False,
            "scope_complete": False,
            "status": "failed",
            "errors": ["discovery returned zero surfaces"],
            "inaccessible_count": 0,
            "timeout_count": 0,
            "unknown_index_count": 0,
            "hidden_by_limit_total": 0,
            "total_matched_all_surfaces": 0,
            "surfaces": [],
            "per_surface_limit": per_surface_limit,
            "since_days": since_days,
        }

    for surface in surfaces:
        try:
            enumerate_kwargs = {
                "mailbox": surface.mailbox,
                "limit": per_surface_limit,
                "since_days": since_days,
                "timeout_seconds": timeout_seconds,
                "account": surface.account,
            }
            path_components = getattr(surface, "path_components", None)
            if path_components:
                enumerate_kwargs["mailbox_path"] = path_components
            result = provider.enumerate_flagged(**enumerate_kwargs)
        except Exception as e:
            # A raised surface error is a failed surface, not a silent skip.
            estate_scope_complete = False
            surface_reports.append({
                "account": surface.account, "mailbox": surface.mailbox,
                "status": "failed", "scope_complete": False,
                "error": str(e),
            })
            errors.append(f"{surface.account}/{surface.mailbox}: {e}")
            continue
        surface_reports.append({
            "account": surface.account, "mailbox": surface.mailbox,
            "status": result.status,
            "scope_complete": result.scope_complete,
            "total_matched": result.scanned_boundary.get(
                "total_flagged_seen", len(result.rows)),
            "returned": len(result.rows),
        })
        all_rows.extend(result.rows)
        errors.extend(f"{surface.account}/{surface.mailbox}: {e}"
                      for e in result.errors)
        inaccessible_total += result.inaccessible_count
        timeout_total += result.timeout_count
        hidden_total += max(0, result.scanned_boundary.get(
            "hidden_by_limit", 0))
        total_matched_all += result.scanned_boundary.get(
            "total_flagged_seen", 0)
        if not result.scope_complete:
            estate_scope_complete = False
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

    unknown_total = sum(
        1 for row in deduped_rows
        if row.flag_color == FlagColor.UNKNOWN
    )
    status = canonical_scan_status(
        scope_complete=estate_scope_complete,
        errors=errors,
        inaccessible_count=inaccessible_total,
        timeout_count=timeout_total,
        hidden_by_limit=hidden_total,
    )
    estate_complete = status == "complete"
    return {
        "rows": deduped_rows,
        "deduplicated_removed": len(all_rows) - len(deduped_rows),
        "estate_complete": estate_complete,
        "scope_complete": estate_scope_complete,
        "status": status,
        "errors": errors,
        "inaccessible_count": inaccessible_total,
        "timeout_count": timeout_total,
        "unknown_index_count": unknown_total,
        "hidden_by_limit_total": hidden_total,
        "total_matched_all_surfaces": total_matched_all,
        "surfaces": surface_reports,
        "per_surface_limit": per_surface_limit,
        "since_days": since_days,
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
        scope_complete=estate["scope_complete"],
        status=estate["status"],
        errors=estate["errors"],
        inaccessible_count=estate["inaccessible_count"],
        timeout_count=estate["timeout_count"],
        unknown_index_count=estate["unknown_index_count"],
        limit=_require_int(
            estate.get("per_surface_limit"),
            "estate.per_surface_limit",
            minimum=1,
        ),
        since_days=(
            None
            if estate.get("since_days") is None
            else _require_int(
                estate.get("since_days"), "estate.since_days", minimum=1
            )
        ),
        total_matched=(
            estate["total_matched_all_surfaces"]
            - estate["deduplicated_removed"]
        ),
        returned_count=len(estate["rows"]),
        hidden_by_limit=estate["hidden_by_limit_total"],
        next_cursor=None,
        generated_at=generated_at,
    )


# --- Plan -------------------------------------------------------------------


@dataclass(frozen=True)
class ClassificationProof:
    """PII-free, policy/snapshot/evidence-bound classifier provenance."""

    schema: str
    policy_sha256: str
    snapshot_sha256: str
    ref_digest: str
    input_binding_sha256: str
    domain: str
    semantic_type: str
    urgency: str
    next_action_owner: str
    operator_state: str
    marketing_or_bulk: bool
    confidence: float
    due_evidence_present: bool
    follow_up_evidence_present: bool
    evidence_basis_sha256: str
    proof_sha256: str

    def body_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "policy_sha256": self.policy_sha256,
            "snapshot_sha256": self.snapshot_sha256,
            "ref_digest": self.ref_digest,
            "input_binding_sha256": self.input_binding_sha256,
            "domain": self.domain,
            "semantic_type": self.semantic_type,
            "urgency": self.urgency,
            "next_action_owner": self.next_action_owner,
            "operator_state": self.operator_state,
            "marketing_or_bulk": self.marketing_or_bulk,
            "confidence": self.confidence,
            "due_evidence_present": self.due_evidence_present,
            "follow_up_evidence_present": self.follow_up_evidence_present,
            "evidence_basis_sha256": self.evidence_basis_sha256,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {**self.body_dict(), "proof_sha256": self.proof_sha256}

    def to_classification(self) -> Classification:
        return Classification(
            domain=self.domain,
            semantic_type=self.semantic_type,
            urgency=self.urgency,
            next_action_owner=self.next_action_owner,
            due_evidence=(
                "present" if self.due_evidence_present else None
            ),
            follow_up_evidence=(
                "present" if self.follow_up_evidence_present else None
            ),
            operator_state=self.operator_state,
            marketing_or_bulk=self.marketing_or_bulk,
            confidence=self.confidence,
            evidence_basis=(),
        )

    @classmethod
    def create(cls, classification: Classification, *,
               policy_sha256: str, snapshot_sha256: str,
               ref_digest: str,
               evidence_digest: Optional[str]) -> "ClassificationProof":
        proof = cls(
            schema=CLASSIFICATION_PROOF_SCHEMA,
            policy_sha256=policy_sha256,
            snapshot_sha256=snapshot_sha256,
            ref_digest=ref_digest,
            input_binding_sha256=sha256_hex({
                "schema": "uma.flags.classifier_input_binding.v1",
                "evidence_digest": evidence_digest,
            }),
            domain=classification.domain,
            semantic_type=classification.semantic_type,
            urgency=classification.urgency,
            next_action_owner=classification.next_action_owner,
            operator_state=classification.operator_state,
            marketing_or_bulk=classification.marketing_or_bulk,
            confidence=classification.confidence,
            due_evidence_present=classification.due_evidence is not None,
            follow_up_evidence_present=(
                classification.follow_up_evidence is not None
            ),
            evidence_basis_sha256=sha256_hex(
                list(classification.evidence_basis)
            ),
            proof_sha256="",
        )
        return cls(**{
            **proof.__dict__,
            "proof_sha256": sha256_hex(proof.body_dict()),
        })


_CLASSIFICATION_PROOF_KEYS = {
    "schema", "policy_sha256", "snapshot_sha256", "ref_digest",
    "input_binding_sha256", "domain", "semantic_type", "urgency",
    "next_action_owner", "operator_state", "marketing_or_bulk",
    "confidence", "due_evidence_present", "follow_up_evidence_present",
    "evidence_basis_sha256", "proof_sha256",
}


def _classification_proof_from_dict(
        raw: Any, prefix: str, *, policy_sha256: str,
        snapshot_sha256: str, ref_digest: str,
        evidence_digest: Optional[str], verify_input_binding: bool,
) -> ClassificationProof:
    if not isinstance(raw, dict):
        raise FlagWorkflowError(f"{prefix} must be a JSON object")
    _require_exact_keys(raw, _CLASSIFICATION_PROOF_KEYS, prefix)
    confidence = raw["confidence"]
    if isinstance(confidence, bool) or not isinstance(
            confidence, (int, float)) or not math.isfinite(confidence) \
            or not 0.0 <= confidence <= 1.0:
        raise FlagWorkflowError(
            f"{prefix}.confidence must be finite in [0,1]"
        )
    proof = ClassificationProof(
        schema=_require_string(raw["schema"], f"{prefix}.schema"),
        policy_sha256=require_hex256(
            raw["policy_sha256"], f"{prefix}.policy_sha256"
        ),
        snapshot_sha256=require_hex256(
            raw["snapshot_sha256"], f"{prefix}.snapshot_sha256"
        ),
        ref_digest=require_hex256(
            raw["ref_digest"], f"{prefix}.ref_digest"
        ),
        input_binding_sha256=require_hex256(
            raw["input_binding_sha256"],
            f"{prefix}.input_binding_sha256",
        ),
        domain=_require_string(raw["domain"], f"{prefix}.domain"),
        semantic_type=_require_string(
            raw["semantic_type"], f"{prefix}.semantic_type"
        ),
        urgency=_require_string(raw["urgency"], f"{prefix}.urgency"),
        next_action_owner=_require_string(
            raw["next_action_owner"], f"{prefix}.next_action_owner"
        ),
        operator_state=_require_string(
            raw["operator_state"], f"{prefix}.operator_state"
        ),
        marketing_or_bulk=_require_bool(
            raw["marketing_or_bulk"], f"{prefix}.marketing_or_bulk"
        ),
        confidence=float(confidence),
        due_evidence_present=_require_bool(
            raw["due_evidence_present"],
            f"{prefix}.due_evidence_present",
        ),
        follow_up_evidence_present=_require_bool(
            raw["follow_up_evidence_present"],
            f"{prefix}.follow_up_evidence_present",
        ),
        evidence_basis_sha256=require_hex256(
            raw["evidence_basis_sha256"],
            f"{prefix}.evidence_basis_sha256",
        ),
        proof_sha256=require_hex256(
            raw["proof_sha256"], f"{prefix}.proof_sha256"
        ),
    )
    if proof.schema != CLASSIFICATION_PROOF_SCHEMA:
        raise FlagWorkflowError(
            f"{prefix}.schema must be {CLASSIFICATION_PROOF_SCHEMA}"
        )
    if proof.policy_sha256 != policy_sha256:
        raise FlagWorkflowError(f"{prefix} policy binding mismatch")
    if proof.snapshot_sha256 != snapshot_sha256:
        raise FlagWorkflowError(f"{prefix} snapshot binding mismatch")
    if proof.ref_digest != ref_digest:
        raise FlagWorkflowError(
            f"{prefix} ref_digest does not match proof binding"
        )
    if sha256_hex(proof.body_dict()) != proof.proof_sha256:
        raise FlagWorkflowError(f"{prefix} digest mismatch")
    if verify_input_binding:
        expected_input = sha256_hex({
            "schema": "uma.flags.classifier_input_binding.v1",
            "evidence_digest": evidence_digest,
        })
        if proof.input_binding_sha256 != expected_input:
            raise FlagWorkflowError(f"{prefix} input binding mismatch")
    try:
        proposal_from_classification(
            proof.to_classification(), FlagColor.UNKNOWN,
        )
    except ValueError as exc:
        raise FlagWorkflowError(
            f"{prefix} violates the canonical classifier contract: {exc}"
        ) from exc
    return proof


def compute_execution_binding_sha256(*, provider: str, account: str,
                                     mailbox: str, provider_id: str,
                                     snapshot_id: str,
                                     observed_native_flag: Optional[int],
                                     evidence_digest: Optional[str],
                                     message_id_digest: Optional[str]) -> str:
    """Commit private execution scope into a public-safe digest."""
    return sha256_hex({
        "schema": "uma.flags.execution_binding.v1",
        "provider": provider,
        "account": account,
        "mailbox": mailbox,
        "provider_id": provider_id,
        "snapshot_id": snapshot_id,
        "observed_native_flag": observed_native_flag,
        "evidence_digest": evidence_digest,
        "message_id_digest": message_id_digest,
    })


def compute_mutation_id(mutation: Dict[str, Any], *,
                        policy_sha256: str,
                        snapshot_sha256: str) -> str:
    """Compute the canonical id from every committed mutation field."""
    fields = {
        "schema": MUTATION_ID_SCHEMA,
        "policy_sha256": policy_sha256,
        "snapshot_sha256": snapshot_sha256,
        "ref_digest": mutation["ref_digest"],
        "observed_flag": mutation["observed_flag"],
        "proposed_flag": mutation["proposed_flag"],
        "reason_code": mutation["reason_code"],
        "reason_sha256": mutation["reason_sha256"],
        "confidence": mutation["confidence"],
        "review_required": mutation["review_required"],
        "auto_eligible": mutation["auto_eligible"],
        "execution_binding_sha256": mutation["execution_binding_sha256"],
        "classification_proof": mutation["classification_proof"],
    }
    return "mut-" + sha256_hex(fields)[:24]


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
    reason_sha256: str
    execution_binding_sha256: str
    classification_proof: ClassificationProof
    auto_eligible: bool = False
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
            "reason_sha256": self.reason_sha256,
            "confidence": self.confidence,
            "review_required": self.review_required,
            "auto_eligible": self.auto_eligible,
            "execution_binding_sha256": self.execution_binding_sha256,
            "classification_proof": self.classification_proof.to_dict(),
            "provider": self.provider,
            "account": self.account,
            "mailbox": self.mailbox,
            "provider_id": self.provider_id,
            "snapshot_id": self.snapshot_id,
            "observed_native_flag": self.observed_native_flag,
            "evidence_digest": self.evidence_digest,
            "message_id_digest": self.message_id_digest,
        }


def validate_planned_mutation_contract(
        mutation: PlannedMutation, *, policy_sha256: str,
        snapshot_sha256: str) -> None:
    """Re-derive semantic decision, private binding, and canonical id."""
    _classification_proof_from_dict(
        mutation.classification_proof.to_dict(),
        f"mutation {mutation.mutation_id}.classification_proof",
        policy_sha256=policy_sha256,
        snapshot_sha256=snapshot_sha256,
        ref_digest=mutation.ref_digest,
        evidence_digest=mutation.evidence_digest,
        verify_input_binding=True,
    )
    expected_reason_sha = sha256_hex({
        "schema": "uma.flags.mutation_reason.v1",
        "reason": mutation.reason,
    })
    if mutation.reason_sha256 != expected_reason_sha:
        raise FlagWorkflowError(
            f"mutation {mutation.mutation_id}: reason digest mismatch"
        )
    expected_execution = compute_execution_binding_sha256(
        provider=mutation.provider,
        account=mutation.account,
        mailbox=mutation.mailbox,
        provider_id=mutation.provider_id,
        snapshot_id=mutation.snapshot_id,
        observed_native_flag=mutation.observed_native_flag,
        evidence_digest=mutation.evidence_digest,
        message_id_digest=mutation.message_id_digest,
    )
    if mutation.execution_binding_sha256 != expected_execution:
        raise FlagWorkflowError(
            f"mutation {mutation.mutation_id}: execution binding mismatch"
        )
    expected_id = compute_mutation_id(
        mutation.to_dict(),
        policy_sha256=policy_sha256,
        snapshot_sha256=snapshot_sha256,
    )
    if mutation.mutation_id != expected_id:
        raise FlagWorkflowError(
            f"mutation_id mismatch: expected {expected_id}, got "
            f"{mutation.mutation_id}"
        )
    try:
        expected = proposal_from_classification(
            mutation.classification_proof.to_classification(),
            mutation.observed_flag,
        )
    except ValueError as exc:
        raise FlagWorkflowError(
            f"mutation {mutation.mutation_id}: invalid classifier proof: "
            f"{exc}"
        ) from exc
    if expected.is_identity:
        raise FlagWorkflowError(
            f"mutation {mutation.mutation_id}: identity/no-change decisions "
            "cannot appear in a mutation plan"
        )
    canonical = {
        "proposed_flag": (mutation.proposed_flag, expected.proposed_flag),
        "reason_code": (mutation.reason_code, expected.reason_code),
        "confidence": (mutation.confidence, expected.confidence),
        "review_required": (
            mutation.review_required, expected.review_required
        ),
        "auto_eligible": (mutation.auto_eligible, expected.auto_eligible),
    }
    for field_name, (observed, required) in canonical.items():
        if observed != required:
            raise FlagWorkflowError(
                f"mutation {mutation.mutation_id}: {field_name} must be "
                f"{required!r} for semantic_type "
                f"{mutation.classification_proof.semantic_type!r}, got "
                f"{observed!r}"
            )


def _mutation_from_dict(d: Dict[str, Any], idx: int, *,
                        policy_sha256: str,
                        snapshot_sha256: str) -> PlannedMutation:
    prefix = f"mutations[{idx}]"
    if not isinstance(d, dict):
        raise FlagWorkflowError(f"{prefix} must be a JSON object")
    mutation_keys = {
        "mutation_id", "ref_digest", "observed_flag",
        "proposed_flag", "reason_code", "reason", "reason_sha256",
        "confidence", "review_required", "auto_eligible",
        "execution_binding_sha256", "classification_proof",
        "provider", "account", "mailbox", "provider_id", "snapshot_id",
        "observed_native_flag", "evidence_digest", "message_id_digest",
    }
    missing = mutation_keys.difference(d)
    if missing:
        first = sorted(missing)[0]
        raise FlagWorkflowError(
            f"{prefix}: missing required key {first!r}"
        )
    _require_exact_keys(d, mutation_keys, prefix)
    confidence = d["confidence"]
    if confidence is not None and not (
        not isinstance(confidence, bool)
        and isinstance(confidence, (int, float))
        and math.isfinite(confidence)
        and 0.0 <= confidence <= 1.0
    ):
        raise FlagWorkflowError(f"{prefix}: confidence must be null or in [0,1]")
    native = _require_optional_int(
        d["observed_native_flag"], f"{prefix}.observed_native_flag"
    )
    review_required = _require_bool(
        d["review_required"], f"{prefix}.review_required"
    )
    auto_eligible = _require_bool(
        d["auto_eligible"], f"{prefix}.auto_eligible"
    )
    # Structural eligibility invariants — hash-valid but impossible plans
    # must fail closed at parse time, exactly like snapshots do.
    if review_required and auto_eligible:
        raise FlagWorkflowError(
            f"{prefix}: auto_eligible=True is incompatible with "
            "review_required=True")
    proposed_raw = _require_string(
        d["proposed_flag"], f"{prefix}.proposed_flag"
    )
    observed_raw = _require_string(
        d["observed_flag"], f"{prefix}.observed_flag"
    )
    try:
        proposed = FlagColor.from_string(proposed_raw)
        observed = FlagColor.from_string(observed_raw)
    except ValueError as exc:
        raise FlagWorkflowError(f"{prefix}: {exc}") from exc
    if proposed == FlagColor.UNKNOWN:
        raise FlagWorkflowError(
            f"{prefix}: UNKNOWN is not a writable proposed flag")
    if proposed == FlagColor.PURPLE and (
            auto_eligible or not review_required):
        raise FlagWorkflowError(
            f"{prefix}: PURPLE is the human-review queue and must have "
            "review_required=True and auto_eligible=False"
        )
    if observed == FlagColor.UNKNOWN and auto_eligible:
        raise FlagWorkflowError(
            f"{prefix}: UNKNOWN observations can never be auto_eligible")
    ref_digest = require_hex256(d["ref_digest"], f"{prefix}.ref_digest")
    reason = _require_string(
        d["reason"], f"{prefix}.reason", allow_empty=True
    )
    evidence_digest = (
        None if d["evidence_digest"] is None
        else require_hex256(
            d["evidence_digest"], f"{prefix}.evidence_digest"
        )
    )
    message_id_digest = (
        None if d["message_id_digest"] is None
        else require_hex256(
            d["message_id_digest"], f"{prefix}.message_id_digest"
        )
    )
    classification_proof = _classification_proof_from_dict(
        d["classification_proof"], f"{prefix}.classification_proof",
        policy_sha256=policy_sha256,
        snapshot_sha256=snapshot_sha256,
        ref_digest=ref_digest,
        evidence_digest=evidence_digest,
        verify_input_binding=True,
    )
    mutation = PlannedMutation(
        mutation_id=_require_string(
            d["mutation_id"], f"{prefix}.mutation_id"
        ),
        ref_digest=ref_digest,
        observed_flag=observed,
        proposed_flag=proposed,
        reason_code=_require_string(d["reason_code"], f"{prefix}.reason_code"),
        reason=reason,
        reason_sha256=require_hex256(
            d["reason_sha256"], f"{prefix}.reason_sha256"
        ),
        confidence=None if confidence is None else float(confidence),
        review_required=review_required,
        execution_binding_sha256=require_hex256(
            d["execution_binding_sha256"],
            f"{prefix}.execution_binding_sha256",
        ),
        classification_proof=classification_proof,
        auto_eligible=auto_eligible,
        provider=_require_string(d["provider"], f"{prefix}.provider"),
        account=_require_string(d["account"], f"{prefix}.account"),
        mailbox=_require_string(d["mailbox"], f"{prefix}.mailbox"),
        provider_id=_require_string(d["provider_id"], f"{prefix}.provider_id"),
        snapshot_id=_require_string(d["snapshot_id"], f"{prefix}.snapshot_id"),
        observed_native_flag=native,
        evidence_digest=evidence_digest,
        message_id_digest=message_id_digest,
    )
    validate_planned_mutation_contract(
        mutation,
        policy_sha256=policy_sha256,
        snapshot_sha256=snapshot_sha256,
    )
    return mutation


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
    snapshot.validate()
    current_snapshot_hash = snapshot.to_dict()["content_hash"]
    if snapshot.content_hash != current_snapshot_hash:
        raise FlagWorkflowError(
            "snapshot content_hash mismatch (stale or tampered object)"
        )
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
        if p.classification is None:  # pragma: no cover - propose guarantees it
            raise FlagWorkflowError("proposal lacks classifier provenance")
        evidence_digest = (
            MessageReference.compute_evidence_digest(
                m.received_iso, m.sender, m.subject)
            if (m.received_iso or m.sender or m.subject) else None
        )
        classification_proof = ClassificationProof.create(
            p.classification,
            policy_sha256=POLICY_SHA256,
            snapshot_sha256=current_snapshot_hash,
            ref_digest=m.ref_digest,
            evidence_digest=evidence_digest,
        )
        reason_sha256 = sha256_hex({
            "schema": "uma.flags.mutation_reason.v1",
            "reason": p.reason,
        })
        execution_binding_sha256 = compute_execution_binding_sha256(
            provider=m.provider,
            account=m.account,
            mailbox=m.mailbox,
            provider_id=m.provider_id,
            snapshot_id=snapshot.snapshot_id,
            observed_native_flag=m.native_index,
            evidence_digest=evidence_digest,
            message_id_digest=None,
        )
        identity_fields = {
            "ref_digest": m.ref_digest,
            "observed_flag": p.observed_flag.value,
            "proposed_flag": p.proposed_flag.value,
            "reason_code": p.reason_code,
            "reason_sha256": reason_sha256,
            "confidence": p.confidence,
            "review_required": p.review_required,
            "auto_eligible": p.auto_eligible,
            "execution_binding_sha256": execution_binding_sha256,
            "classification_proof": classification_proof.to_dict(),
        }
        mutation = PlannedMutation(
            mutation_id=compute_mutation_id(
                identity_fields,
                policy_sha256=POLICY_SHA256,
                snapshot_sha256=current_snapshot_hash,
            ),
            ref_digest=m.ref_digest,
            observed_flag=p.observed_flag,
            proposed_flag=p.proposed_flag,
            reason_code=p.reason_code,
            reason=p.reason,
            reason_sha256=reason_sha256,
            confidence=p.confidence,
            review_required=p.review_required,
            execution_binding_sha256=execution_binding_sha256,
            classification_proof=classification_proof,
            auto_eligible=p.auto_eligible,
            provider=m.provider,
            account=m.account,
            mailbox=m.mailbox,
            provider_id=m.provider_id,
            snapshot_id=snapshot.snapshot_id,
            observed_native_flag=m.native_index,
            evidence_digest=evidence_digest,
            message_id_digest=None,
        )
        validate_planned_mutation_contract(
            mutation,
            policy_sha256=POLICY_SHA256,
            snapshot_sha256=current_snapshot_hash,
        )
        mutations.append(mutation)
    plan: Dict[str, Any] = {
        "schema": PLAN_SCHEMA,
        "policy_version": MIGRATION_POLICY_VERSION,
        # Digest of the exact rule configuration used — tamper-evident
        # companion to the human-readable version string.
        "policy_sha256": POLICY_SHA256,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "snapshot_id": snapshot.snapshot_id,
        # Derive from to_dict(), never the possibly-stale dataclass field.
        "snapshot_sha256": current_snapshot_hash,
        "snapshot_complete": snapshot.complete,
        "zero_write_declaration": True,
        "total_scanned": snapshot.total_matched,
        "mutations": [m.to_dict() for m in mutations],
        "unchanged_count": len(snapshot.messages) - len(mutations),
        # Plan-level visibility into the threshold split. Writes stay
        # impossible regardless of this count until Commit 6 gates exist.
        "auto_eligible_count": sum(
            1 for mutation in mutations if mutation.auto_eligible
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
    parsed = validate_plan_schema(plan)
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
                "mutation_id": mutation.mutation_id,
                "ref_digest": mutation.ref_digest,
                "observed_flag": mutation.observed_flag.value,
                "proposed_flag": mutation.proposed_flag.value,
                "reason_code": mutation.reason_code,
                "reason_sha256": mutation.reason_sha256,
                "confidence": mutation.confidence,
                "review_required": mutation.review_required,
                "auto_eligible": mutation.auto_eligible,
                "execution_binding_sha256": (
                    mutation.execution_binding_sha256
                ),
                "classification_proof": (
                    mutation.classification_proof.to_dict()
                ),
            }
            for mutation in parsed
        ],
    }
    public["plan_public_hash"] = sha256_hex(public)   # LAST
    return public


def validate_public_plan(raw: Any) -> None:
    """Fail-closed exact recursive schema and integrity check."""
    if not isinstance(raw, dict):
        raise FlagWorkflowError("public plan must be a JSON object")
    expected_keys = {
        "schema", "projection", "source_plan_sha256", "policy_version",
        "policy_sha256", "generated_at", "snapshot_id", "snapshot_sha256",
        "zero_write_declaration", "total_scanned", "unchanged_count",
        "mutations", "plan_public_hash",
    }
    if not all(type(key) is str for key in raw):
        raise FlagWorkflowError("public plan keys must be strings")
    unexpected = set(raw) - expected_keys
    if unexpected:
        raise FlagWorkflowError(
            f"forbidden keys present: {sorted(unexpected)}"
        )
    _require_exact_keys(raw, expected_keys, "public plan")
    if raw["schema"] != PUBLIC_PLAN_SCHEMA:
        raise FlagWorkflowError(
            f"public plan schema must be {PUBLIC_PLAN_SCHEMA}")
    if raw["projection"] != "public_safe":
        raise FlagWorkflowError("public plan projection must be 'public_safe'")

    # Privacy structure precedes hash verification: an unhashed injection is
    # still reported as an invalid projection, without inspecting its value.
    mutation_keys = {
        "mutation_id", "ref_digest", "observed_flag", "proposed_flag",
        "reason_code", "reason_sha256", "confidence", "review_required",
        "auto_eligible", "execution_binding_sha256",
        "classification_proof",
    }
    mutations = raw["mutations"]
    if not isinstance(mutations, list):
        raise FlagWorkflowError("public plan mutations must be a list")
    for index, mutation in enumerate(mutations):
        prefix = f"public plan mutations[{index}]"
        if not isinstance(mutation, dict):
            raise FlagWorkflowError(f"{prefix} must be an object")
        _require_exact_keys(mutation, mutation_keys, prefix)

    # With the privacy allowlist established, reject ordinary field tampering
    # before interpreting semantic relationships. A maliciously re-hashed
    # artifact continues into the strict type and invariant checks below.
    stored = require_hex256(
        raw["plan_public_hash"], "plan_public_hash")
    body = {k: v for k, v in raw.items() if k != "plan_public_hash"}
    if sha256_hex(body) != stored:
        raise FlagWorkflowError("public plan hash mismatch (tampered)")

    require_hex256(raw["source_plan_sha256"], "source_plan_sha256")
    if raw["policy_version"] != MIGRATION_POLICY_VERSION:
        raise FlagWorkflowError(
            f"public plan policy_version must be {MIGRATION_POLICY_VERSION}"
        )
    policy_sha256 = require_hex256(
        raw["policy_sha256"], "policy_sha256"
    )
    if policy_sha256 != POLICY_SHA256:
        raise FlagWorkflowError("public plan policy_sha256 is not current")
    _parse_aware_timestamp(raw["generated_at"], "public plan generated_at")
    snapshot_id = _require_string(raw["snapshot_id"], "snapshot_id")
    if not (
        snapshot_id.startswith("snap-")
        and len(snapshot_id) == 37
        and set(snapshot_id[5:]) <= _HEX_CHARS
    ):
        raise FlagWorkflowError(
            "public plan snapshot_id must be 'snap-' followed by 32 "
            "lowercase hex characters"
        )
    snapshot_sha256 = require_hex256(
        raw["snapshot_sha256"], "snapshot_sha256"
    )
    if _require_bool(
        raw["zero_write_declaration"], "zero_write_declaration"
    ) is not True:
        raise FlagWorkflowError(
            "public plan zero_write_declaration must be True"
        )
    total_scanned = _require_int(
        raw["total_scanned"], "total_scanned", minimum=0
    )
    unchanged_count = _require_int(
        raw["unchanged_count"], "unchanged_count", minimum=0
    )
    allowed_flags = {color.value for color in FlagColor}
    seen_ids = set()
    seen_refs = set()
    for index, mutation in enumerate(mutations):
        prefix = f"public plan mutations[{index}]"
        mutation_id = _require_string(
            mutation["mutation_id"], f"{prefix}.mutation_id"
        )
        if not (
            mutation_id.startswith("mut-")
            and len(mutation_id) == 28
            and set(mutation_id[4:]) <= _HEX_CHARS
        ):
            raise FlagWorkflowError(
                f"{prefix}.mutation_id must be 'mut-' followed by 24 "
                "lowercase hex characters"
            )
        if mutation_id in seen_ids:
            raise FlagWorkflowError(f"{prefix}.mutation_id is duplicated")
        seen_ids.add(mutation_id)
        ref_digest = require_hex256(
            mutation["ref_digest"], f"{prefix}.ref_digest"
        )
        if ref_digest in seen_refs:
            raise FlagWorkflowError(f"{prefix}.ref_digest is duplicated")
        seen_refs.add(ref_digest)
        observed = _require_string(
            mutation["observed_flag"], f"{prefix}.observed_flag"
        )
        proposed = _require_string(
            mutation["proposed_flag"], f"{prefix}.proposed_flag"
        )
        if observed not in allowed_flags or proposed not in allowed_flags:
            raise FlagWorkflowError(f"{prefix} contains a non-canonical flag")
        if proposed == FlagColor.UNKNOWN.value:
            raise FlagWorkflowError(f"{prefix} proposes UNKNOWN")
        reason_code = _require_string(
            mutation["reason_code"], f"{prefix}.reason_code"
        )
        require_hex256(
            mutation["reason_sha256"], f"{prefix}.reason_sha256"
        )
        require_hex256(
            mutation["execution_binding_sha256"],
            f"{prefix}.execution_binding_sha256",
        )
        confidence = mutation["confidence"]
        if confidence is not None and not (
            not isinstance(confidence, bool)
            and isinstance(confidence, (int, float))
            and math.isfinite(confidence)
            and 0.0 <= confidence <= 1.0
        ):
            raise FlagWorkflowError(
                f"{prefix}.confidence must be null or in [0,1]"
            )
        review_required = _require_bool(
            mutation["review_required"], f"{prefix}.review_required"
        )
        auto_eligible = _require_bool(
            mutation["auto_eligible"], f"{prefix}.auto_eligible"
        )
        if review_required and auto_eligible:
            raise FlagWorkflowError(
                f"{prefix} cannot require review and be auto-eligible"
            )
        if proposed == FlagColor.PURPLE.value and (
                auto_eligible or not review_required):
            raise FlagWorkflowError(
                f"{prefix}: PURPLE must remain review-only"
            )
        if observed == FlagColor.UNKNOWN.value and auto_eligible:
            raise FlagWorkflowError(
                f"{prefix} cannot auto-apply an UNKNOWN observation"
            )
        proof = _classification_proof_from_dict(
            mutation["classification_proof"],
            f"{prefix}.classification_proof",
            policy_sha256=policy_sha256,
            snapshot_sha256=snapshot_sha256,
            ref_digest=ref_digest,
            evidence_digest=None,
            verify_input_binding=False,
        )
        expected_id = compute_mutation_id(
            mutation,
            policy_sha256=policy_sha256,
            snapshot_sha256=snapshot_sha256,
        )
        if mutation_id != expected_id:
            raise FlagWorkflowError(
                f"{prefix}.mutation_id mismatch: expected {expected_id}, "
                f"got {mutation_id}"
            )
        observed_color = FlagColor.from_string(observed)
        expected = proposal_from_classification(
            proof.to_classification(), observed_color,
        )
        if expected.is_identity:
            raise FlagWorkflowError(
                f"{prefix} contains an identity/no-change decision"
            )
        canonical = {
            "proposed_flag": (proposed, expected.proposed_flag.value),
            "reason_code": (reason_code, expected.reason_code),
            "confidence": (confidence, expected.confidence),
            "review_required": (
                review_required, expected.review_required
            ),
            "auto_eligible": (auto_eligible, expected.auto_eligible),
        }
        for field_name, (actual, required) in canonical.items():
            if actual != required:
                raise FlagWorkflowError(
                    f"{prefix}.{field_name} must be {required!r} for "
                    f"semantic_type {proof.semantic_type!r}, got "
                    f"{actual!r}"
                )
    if len(mutations) + unchanged_count != total_scanned:
        raise FlagWorkflowError(
            "public plan counts are incoherent: mutations + unchanged_count "
            "must equal total_scanned"
        )


def validate_plan_schema(plan: Dict[str, Any]) -> List[PlannedMutation]:
    """Strict validation; returns parsed mutations or raises.

    Catches: wrong schema, missing/truncated hashes, unknown color strings,
    bad confidence values, non-mutation junk, tampered plan_hash.
    """
    if not isinstance(plan, dict):
        raise FlagWorkflowError("plan must be a JSON object")
    required = {
        "schema", "policy_version", "policy_sha256", "generated_at",
        "snapshot_id", "snapshot_sha256", "snapshot_complete",
        "zero_write_declaration", "total_scanned", "mutations",
        "unchanged_count", "auto_eligible_count", "plan_hash",
    }
    _require_exact_keys(plan, required, "plan")
    if plan.get("schema") != PLAN_SCHEMA:
        raise FlagWorkflowError(
            f"plan schema must be {PLAN_SCHEMA}, got {plan.get('schema')!r}"
        )
    snapshot_sha256 = require_hex256(
        plan.get("snapshot_sha256"), "snapshot_sha256"
    )
    require_hex256(plan.get("plan_hash"), "plan_hash")
    stored_hash = plan["plan_hash"]
    if compute_plan_hash(plan) != stored_hash:
        raise FlagWorkflowError("plan_hash mismatch — plan was tampered with")
    if _require_bool(
        plan["snapshot_complete"], "snapshot_complete"
    ) is not True:
        raise FlagWorkflowError("snapshot_complete must be True")
    if _require_bool(
        plan["zero_write_declaration"], "zero_write_declaration"
    ) is not True:
        raise FlagWorkflowError("zero_write_declaration must be True")
    _parse_aware_timestamp(plan["generated_at"], "plan.generated_at")
    snapshot_id = _require_string(plan["snapshot_id"], "plan.snapshot_id")
    if not (
        snapshot_id.startswith("snap-")
        and len(snapshot_id) == 37
        and set(snapshot_id[5:].lower()) <= _HEX_CHARS
    ):
        raise FlagWorkflowError(
            "plan.snapshot_id must be 'snap-' followed by 32 hex characters"
        )
    total_scanned = _require_int(
        plan["total_scanned"], "total_scanned", minimum=0
    )
    unchanged_count = _require_int(
        plan["unchanged_count"], "unchanged_count", minimum=0
    )
    auto_eligible_count = _require_int(
        plan["auto_eligible_count"], "auto_eligible_count", minimum=0
    )
    if plan.get("policy_version") != MIGRATION_POLICY_VERSION:
        raise FlagWorkflowError(
            f"policy_version must be {MIGRATION_POLICY_VERSION}, "
            f"got {plan.get('policy_version')!r}"
        )
    # The digest is the tamper-evident half of policy identity: a plan
    # stamped with the right version string but generated under DIFFERENT
    # rules cannot pass.
    policy_sha256 = require_hex256(
        plan.get("policy_sha256"), "policy_sha256"
    )
    if policy_sha256 != POLICY_SHA256:
        raise FlagWorkflowError(
            "policy_sha256 mismatch — plan was generated under different "
            "rule configuration (or digest tampered)"
        )
    mutations_raw = plan.get("mutations")
    if not isinstance(mutations_raw, list):
        raise FlagWorkflowError("mutations must be a list")
    parsed = [
        _mutation_from_dict(
            d, i,
            policy_sha256=policy_sha256,
            snapshot_sha256=snapshot_sha256,
        )
        for i, d in enumerate(mutations_raw)
    ]
    if len(parsed) + unchanged_count != total_scanned:
        raise FlagWorkflowError(
            "plan counts are incoherent: mutations + unchanged_count must "
            "equal total_scanned"
        )
    if sum(1 for mutation in parsed if mutation.auto_eligible) != \
            auto_eligible_count:
        raise FlagWorkflowError(
            "auto_eligible_count does not match parsed mutations"
        )
    # Cross-mutation integrity (Commit 7 hardening): snapshots are
    # deduplicated by construction, so duplicates or scope drift inside a
    # plan indicate forgery.
    seen_ids = set()
    seen_refs = set()
    for m in parsed:
        if m.mutation_id in seen_ids:
            raise FlagWorkflowError(
                f"duplicate mutation_id in plan: {m.mutation_id}")
        seen_ids.add(m.mutation_id)
        if m.ref_digest in seen_refs:
            raise FlagWorkflowError(
                f"duplicate ref_digest in plan: {m.ref_digest[:16]}…")
        seen_refs.add(m.ref_digest)
        if m.snapshot_id != plan.get("snapshot_id"):
            raise FlagWorkflowError(
                f"mutation {m.mutation_id}: snapshot_id "
                f"{m.snapshot_id!r} disagrees with plan artifact "
                f"{plan.get('snapshot_id')!r}")
        if m.provider not in ("mailapp",):
            # Unknown providers have no registered writer/codec — fail
            # closed before any transaction machinery runs.
            raise FlagWorkflowError(
                f"mutation {m.mutation_id}: unsupported provider "
                f"{m.provider!r}")
        reference = MessageReference(
            provider=m.provider,
            account=m.account,
            mailbox=m.mailbox,
            provider_id=m.provider_id,
        )
        try:
            reference.validate_scoped()
        except ValueError as exc:
            raise FlagWorkflowError(
                f"mutation {m.mutation_id}: invalid scoped reference: {exc}"
            ) from exc
        if m.ref_digest != reference.ref_digest:
            raise FlagWorkflowError(
                f"mutation {m.mutation_id}: ref_digest does not match "
                "provider/account/mailbox/provider_id"
            )
        try:
            expected_observed = _native_validator_for(m.provider)(
                m.observed_native_flag
            )
        except Exception as exc:
            raise FlagWorkflowError(
                f"mutation {m.mutation_id}: observed_native_flag rejected"
            ) from exc
        if expected_observed != m.observed_flag:
            raise FlagWorkflowError(
                f"mutation {m.mutation_id}: observed native and semantic "
                "flags disagree"
            )
        if m.auto_eligible and m.evidence_digest is None:
            raise FlagWorkflowError(
                f"mutation {m.mutation_id}: auto-eligible mutation lacks "
                "an evidence digest"
            )
    return parsed


# --- Approval receipt (authority-bound signed-off artifact) --------------------


@dataclass(frozen=True)
class HumanCanaryTarget:
    """One exact human-nominated reversible activation target.

    This is an approval-side execution overlay, not a replacement for the
    classifier-derived :class:`PlannedMutation`.  It records only stable
    digests and a temporary known flag, never raw message identity.
    """

    mutation_id: str
    ref_digest: str
    temporary_flag: FlagColor

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mutation_id": self.mutation_id,
            "ref_digest": self.ref_digest,
            "temporary_flag": self.temporary_flag.value,
        }

    @classmethod
    def from_dict(cls, raw: Any, prefix: str) -> "HumanCanaryTarget":
        if not isinstance(raw, dict):
            raise FlagWorkflowError(f"{prefix} must be a JSON object")
        _require_exact_keys(
            raw,
            {"mutation_id", "ref_digest", "temporary_flag"},
            prefix,
        )
        mutation_id = _require_string(
            raw["mutation_id"], f"{prefix}.mutation_id"
        )
        if not (
            mutation_id.startswith("mut-")
            and len(mutation_id) == 28
            and set(mutation_id[4:]) <= _HEX_CHARS
        ):
            raise FlagWorkflowError(
                f"{prefix}.mutation_id must be mut-<24 lowercase hex>"
            )
        try:
            temporary = FlagColor.from_string(_require_string(
                raw["temporary_flag"], f"{prefix}.temporary_flag"
            ))
        except ValueError as exc:
            raise FlagWorkflowError(
                f"{prefix}.temporary_flag is not a canonical FlagColor"
            ) from exc
        if temporary is FlagColor.UNKNOWN:
            raise FlagWorkflowError(
                f"{prefix}.temporary_flag cannot be unknown"
            )
        return cls(
            mutation_id=mutation_id,
            ref_digest=require_hex256(
                raw["ref_digest"], f"{prefix}.ref_digest"
            ),
            temporary_flag=temporary,
        )


def human_canary_risk_blocker(mutation: PlannedMutation) -> Optional[str]:
    """Return a deterministic safety block for a human canary target.

    The classifier remains authoritative for what it has actually detected.
    This does not infer risk from absent evidence; it refuses only typed
    high-risk domains and active/deadline-like classifier axes.  Human review
    of the private shortlist remains necessary for risk classes the current
    classifier does not deterministically expose.
    """
    proof = mutation.classification_proof
    if proof.domain in {"career", "finance", "scheduling"}:
        return f"blocked_domain:{proof.domain}"
    if proof.semantic_type in {
        "action_request",
        "awaiting_other_party",
        "event_confirmed",
        "conflicting_signals",
        "unidentifiable_action",
    }:
        return f"blocked_semantic_type:{proof.semantic_type}"
    if proof.urgency != "none":
        return "blocked_urgency"
    if proof.next_action_owner != "none":
        return "blocked_next_action_owner"
    if proof.operator_state == "open_loop":
        return "blocked_open_loop"
    if proof.due_evidence_present:
        return "blocked_due_evidence"
    if proof.follow_up_evidence_present:
        return "blocked_follow_up_evidence"
    return None


@dataclass
class ApprovalReceipt:
    """Explicit operator approval — a REAL signed-off artifact.

    Authority contract:
    - carries its own full SHA-256 content_hash (tamper-evident artifact);
    - binds plan_sha256 AND snapshot_sha256 AND policy_sha256;
    - validation compares against the ACTUAL loaded plan dict and parsed
      mutations, not merely field shapes;
    - ordinary migration approvals require every target to remain
      auto_eligible=True and review_required=False;
    - a human_canary / activation_canary approval may select only an exact
      1..3-message review-required set, retaining the immutable classifier
      record while binding a distinct temporary test flag per target;
    - 1 <= canary_limit <= CANARY_MAX and len(approved) <= canary_limit;
    - no force flag, no bypass path exists anywhere.
    """
    schema: str
    approval_id: str
    snapshot_sha256: str
    plan_hash: str
    policy_sha256: str
    approved_mutation_ids: List[str]
    issued_at: str
    expires_at: str
    approving_operator: str
    canary_limit: int
    selection_source: str = SELECTION_SOURCE_AUTOMATIC
    purpose: str = PURPOSE_MIGRATION
    manual_canary: bool = False
    human_canary_targets: List[HumanCanaryTarget] = field(
        default_factory=list
    )
    content_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "schema": self.schema,
            "approval_id": self.approval_id,
            "snapshot_sha256": self.snapshot_sha256,
            "plan_hash": self.plan_hash,
            "policy_sha256": self.policy_sha256,
            "approved_mutation_ids": list(self.approved_mutation_ids),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "approving_operator": self.approving_operator,
            "canary_limit": self.canary_limit,
            "selection_source": self.selection_source,
            "purpose": self.purpose,
            "manual_canary": self.manual_canary,
            "human_canary_targets": [
                target.to_dict() for target in self.human_canary_targets
            ],
        }
        d["content_hash"] = sha256_hex(d)
        return d

    @classmethod
    def create(cls, *, plan_hash: str, snapshot_sha256: str,
               policy_sha256: str, approved_mutation_ids: List[str],
               approving_operator: str, canary_limit: int,
               issued_at: Optional[str] = None,
               ttl_seconds: int = 3600,
               selection_source: str = SELECTION_SOURCE_AUTOMATIC,
               purpose: str = PURPOSE_MIGRATION,
               manual_canary: bool = False,
               human_canary_targets: Optional[
                   List[HumanCanaryTarget]
               ] = None) -> "ApprovalReceipt":
        """Single construction path computing approval_id + content_hash."""
        require_hex256(plan_hash, "approval.plan_hash")
        require_hex256(snapshot_sha256, "approval.snapshot_sha256")
        require_hex256(policy_sha256, "approval.policy_sha256")
        _require_int(canary_limit, "approval.canary_limit")
        _require_int(ttl_seconds, "approval.ttl_seconds", minimum=1)
        _require_string(approving_operator, "approval.approving_operator")
        _require_string(selection_source, "approval.selection_source")
        _require_string(purpose, "approval.purpose")
        _require_bool(manual_canary, "approval.manual_canary")
        if not isinstance(approved_mutation_ids, list) or not all(
            isinstance(mutation_id, str) and mutation_id
            for mutation_id in approved_mutation_ids
        ):
            raise FlagWorkflowError(
                "approval.approved_mutation_ids must be a list of "
                "non-empty strings"
            )
        if human_canary_targets is None:
            targets: List[HumanCanaryTarget] = []
        elif not isinstance(human_canary_targets, list) or not all(
                isinstance(target, HumanCanaryTarget)
                for target in human_canary_targets
        ):
            raise FlagWorkflowError(
                "approval.human_canary_targets must be HumanCanaryTarget "
                "values"
            )
        else:
            targets = list(human_canary_targets)
        now = datetime.now(timezone.utc)
        issued_text = issued_at if issued_at is not None else now.isoformat()
        issued = _parse_aware_timestamp(issued_text, "approval.issued_at")
        try:
            expires_text = (
                issued + timedelta(seconds=ttl_seconds)
            ).isoformat()
        except (OverflowError, TypeError, ValueError) as exc:
            raise FlagWorkflowError(
                "approval expiry cannot be represented"
            ) from exc
        receipt = cls(
            schema=APPROVAL_SCHEMA,
            approval_id="appr-" + sha256_hex({
                "plan_hash": plan_hash,
                "approved": sorted(approved_mutation_ids),
                "issued_hint": issued_text,
                "selection_source": selection_source,
                "purpose": purpose,
                "manual_canary": manual_canary,
                "human_canary_targets": [
                    target.to_dict() for target in targets
                ],
            })[:32],
            snapshot_sha256=snapshot_sha256,
            plan_hash=plan_hash,
            policy_sha256=policy_sha256,
            approved_mutation_ids=list(approved_mutation_ids),
            issued_at=issued_text,
            expires_at=expires_text,
            approving_operator=approving_operator,
            canary_limit=canary_limit,
            selection_source=selection_source,
            purpose=purpose,
            manual_canary=manual_canary,
            human_canary_targets=targets,
        )
        receipt.content_hash = receipt.to_dict()["content_hash"]
        return receipt

    @classmethod
    def create_human_canary(
            cls, *, plan_hash: str, snapshot_sha256: str,
            policy_sha256: str,
            nominated_targets: List[HumanCanaryTarget],
            approving_operator: str, canary_limit: int,
            issued_at: Optional[str] = None,
            ttl_seconds: int = 3600) -> "ApprovalReceipt":
        """Create a bounded approval for exact human-selected test targets."""
        if not isinstance(nominated_targets, list) or not nominated_targets:
            raise FlagWorkflowError(
                "human canary nominations must be a non-empty list"
            )
        return cls.create(
            plan_hash=plan_hash,
            snapshot_sha256=snapshot_sha256,
            policy_sha256=policy_sha256,
            approved_mutation_ids=[
                target.mutation_id for target in nominated_targets
            ],
            approving_operator=approving_operator,
            canary_limit=canary_limit,
            issued_at=issued_at,
            ttl_seconds=ttl_seconds,
            selection_source=SELECTION_SOURCE_HUMAN_CANARY,
            purpose=PURPOSE_ACTIVATION_CANARY,
            manual_canary=True,
            human_canary_targets=nominated_targets,
        )

    @property
    def is_human_canary(self) -> bool:
        return (
            self.selection_source == SELECTION_SOURCE_HUMAN_CANARY
            and self.purpose == PURPOSE_ACTIVATION_CANARY
            and self.manual_canary is True
        )

    def execution_flag_for(self, mutation: PlannedMutation) -> FlagColor:
        """Return the hash-bound writable state for an approved target."""
        if not self.is_human_canary:
            return mutation.proposed_flag
        for target in self.human_canary_targets:
            if target.mutation_id == mutation.mutation_id:
                return target.temporary_flag
        raise FlagWorkflowError(
            f"{mutation.mutation_id}: absent from human canary nominations"
        )

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "ApprovalReceipt":
        """Parse a strict approval artifact without scalar coercion."""
        if not isinstance(raw, dict):
            raise FlagWorkflowError("approval must be a JSON object")
        _require_exact_keys(raw, {
            "schema", "approval_id", "snapshot_sha256", "plan_hash",
            "policy_sha256", "approved_mutation_ids", "issued_at",
            "expires_at", "approving_operator", "canary_limit",
            "selection_source", "purpose", "manual_canary",
            "human_canary_targets", "content_hash",
        }, "approval")
        ids = raw["approved_mutation_ids"]
        if not isinstance(ids, list) or not all(
            isinstance(mutation_id, str) and mutation_id
            for mutation_id in ids
        ):
            raise FlagWorkflowError(
                "approval.approved_mutation_ids must be a list of "
                "non-empty strings"
            )
        targets_raw = raw["human_canary_targets"]
        if not isinstance(targets_raw, list):
            raise FlagWorkflowError(
                "approval.human_canary_targets must be a list"
            )
        receipt = cls(
            schema=_require_string(raw["schema"], "approval.schema"),
            approval_id=_require_string(
                raw["approval_id"], "approval.approval_id"
            ),
            snapshot_sha256=require_hex256(
                raw["snapshot_sha256"], "approval.snapshot_sha256"
            ),
            plan_hash=require_hex256(
                raw["plan_hash"], "approval.plan_hash"
            ),
            policy_sha256=require_hex256(
                raw["policy_sha256"], "approval.policy_sha256"
            ),
            approved_mutation_ids=list(ids),
            issued_at=_require_string(
                raw["issued_at"], "approval.issued_at"
            ),
            expires_at=_require_string(
                raw["expires_at"], "approval.expires_at"
            ),
            approving_operator=_require_string(
                raw["approving_operator"],
                "approval.approving_operator",
            ),
            canary_limit=_require_int(
                raw["canary_limit"], "approval.canary_limit"
            ),
            selection_source=_require_string(
                raw["selection_source"], "approval.selection_source"
            ),
            purpose=_require_string(raw["purpose"], "approval.purpose"),
            manual_canary=_require_bool(
                raw["manual_canary"], "approval.manual_canary"
            ),
            human_canary_targets=[
                HumanCanaryTarget.from_dict(
                    target,
                    f"approval.human_canary_targets[{index}]",
                )
                for index, target in enumerate(targets_raw)
            ],
            content_hash=require_hex256(
                raw["content_hash"], "approval.content_hash"
            ),
        )
        if receipt.to_dict()["content_hash"] != receipt.content_hash:
            raise FlagWorkflowError(
                "approval content_hash mismatch (tampered)"
            )
        return receipt

    def validate(self, *, plan: Dict[str, Any],
                 plan_mutations: List[PlannedMutation],
                 now: Optional[datetime] = None,
                 require_current_window: bool = True) -> None:
        """Fail-closed checks against the ACTUAL loaded plan."""
        _require_bool(
            require_current_window, "approval.require_current_window"
        )
        if self.schema != APPROVAL_SCHEMA:
            raise FlagWorkflowError(
                f"approval schema must be {APPROVAL_SCHEMA}, "
                f"got {self.schema!r}"
            )
        approval_id = _require_string(
            self.approval_id, "approval.approval_id"
        )
        if not (
            approval_id.startswith("appr-")
            and len(approval_id) == 37
            and set(approval_id[5:]) <= _HEX_CHARS
        ):
            raise FlagWorkflowError(
                "approval.approval_id must be 'appr-' followed by 32 "
                "lowercase hex characters"
            )
        # Own-integrity FIRST: a tampered approval is rejected before any
        # cross-binding comparison can be gamed.
        stored = require_hex256(self.content_hash, "approval.content_hash")
        body = self.to_dict()
        body.pop("content_hash")
        if sha256_hex(body) != stored:
            raise FlagWorkflowError(
                "approval content_hash mismatch (tampered)")
        _require_string(
            self.approving_operator, "approval.approving_operator"
        )
        issued = _parse_aware_timestamp(self.issued_at, "approval.issued_at")
        expires = _parse_aware_timestamp(
            self.expires_at, "approval.expires_at"
        )
        if expires <= issued:
            raise FlagWorkflowError("approval expires_at must be after issued_at")
        if require_current_window:
            validation_now = _normalize_aware_datetime(
                datetime.now(timezone.utc) if now is None else now,
                "approval validation clock",
            )
            try:
                if issued > validation_now:
                    raise FlagWorkflowError(
                        "approval issued_at is in the future"
                    )
                expired = expires <= validation_now
            except FlagWorkflowError:
                raise
            except (OverflowError, TypeError, ValueError) as exc:
                raise FlagWorkflowError(
                    "approval timestamps cannot be compared to validation "
                    "clock"
                ) from exc
            if expired:
                raise FlagWorkflowError("approval has expired")

        # Cross-bindings against the ACTUAL plan artifact:
        if self.plan_hash != plan.get("plan_hash"):
            raise FlagWorkflowError(
                "approval.plan_hash != plan.plan_hash — wrong plan")
        if self.snapshot_sha256 != plan.get("snapshot_sha256"):
            raise FlagWorkflowError(
                "approval.snapshot_sha256 != plan.snapshot_sha256 — "
                "wrong snapshot lineage")
        if self.policy_sha256 != plan.get("policy_sha256"):
            raise FlagWorkflowError(
                "approval.policy_sha256 != plan.policy_sha256 — policy "
                "changed between planning and approval")

        canary_limit = _require_int(
            self.canary_limit, "approval.canary_limit"
        )
        if not (CANARY_MIN <= canary_limit <= CANARY_MAX):
            raise FlagWorkflowError(
                f"canary_limit must be within [{CANARY_MIN},{CANARY_MAX}], "
                f"got {self.canary_limit}"
            )
        automatic_authority = (
            self.selection_source == SELECTION_SOURCE_AUTOMATIC
            and self.purpose == PURPOSE_MIGRATION
            and self.manual_canary is False
        )
        human_canary_authority = self.is_human_canary
        if not (automatic_authority or human_canary_authority):
            raise FlagWorkflowError(
                "approval authority must be automatic/migration or "
                "human_canary/activation_canary"
            )
        if not isinstance(self.human_canary_targets, list) or not all(
                isinstance(target, HumanCanaryTarget)
                for target in self.human_canary_targets
        ):
            raise FlagWorkflowError(
                "approval.human_canary_targets must be typed targets"
            )
        ids = self.approved_mutation_ids
        if not isinstance(ids, list) or not all(
            isinstance(mutation_id, str) and mutation_id for mutation_id in ids
        ):
            raise FlagWorkflowError(
                "approved_mutation_ids must be a list of non-empty strings"
            )
        if not ids:
            raise FlagWorkflowError(
                "approved_mutation_ids must be NONEMPTY — silent full-batch "
                "approvals are forbidden")
        if len(ids) != len(set(ids)):
            raise FlagWorkflowError(
                "approved_mutation_ids contains duplicates")
        if len(ids) > canary_limit:
            raise FlagWorkflowError(
                f"{len(ids)} approved mutations exceed canary_limit "
                f"{canary_limit}")
        by_id = {m.mutation_id: m for m in plan_mutations}
        unknown = [i for i in ids if i not in by_id]
        if unknown:
            raise FlagWorkflowError(
                f"approval references mutation ids absent from plan: "
                f"{sorted(unknown)}"
        )
        policy_sha256 = require_hex256(
            plan.get("policy_sha256"), "plan.policy_sha256"
        )
        snapshot_sha256 = require_hex256(
            plan.get("snapshot_sha256"), "plan.snapshot_sha256"
        )
        if automatic_authority:
            if self.human_canary_targets:
                raise FlagWorkflowError(
                    "automatic approval cannot carry human canary targets"
                )
            for mid in ids:
                m = by_id[mid]
                if m.auto_eligible is not True:
                    raise FlagWorkflowError(
                        f"{mid}: auto_eligible is not True — confidence "
                        "alone can NEVER grant mutation eligibility"
                    )
                if m.review_required is not False:
                    raise FlagWorkflowError(
                        f"{mid}: review_required mutation cannot be "
                        "approved by automatic authority"
                    )
                if m.observed_flag == FlagColor.UNKNOWN:
                    raise FlagWorkflowError(
                        f"{mid}: UNKNOWN observations can never be "
                        "approved"
                    )
                if m.proposed_flag == FlagColor.UNKNOWN:
                    raise FlagWorkflowError(
                        f"{mid}: proposed UNKNOWN is not writable"
                    )
                validate_planned_mutation_contract(
                    m,
                    policy_sha256=policy_sha256,
                    snapshot_sha256=snapshot_sha256,
                )
            return

        # HUMAN-NOMINATED ACTIVATION CANARY: deliberately distinct from
        # automatic migration.  The classifier fields above remain bound to
        # the immutable plan and must continue to say review_required=True,
        # auto_eligible=False.
        if not (CANARY_MIN <= canary_limit <= HUMAN_CANARY_MAX):
            raise FlagWorkflowError(
                "human canary_limit must be within [1,3]"
            )
        targets = self.human_canary_targets
        if len(targets) != len(ids):
            raise FlagWorkflowError(
                "human canary nominations must exactly match approved ids"
            )
        target_ids = [target.mutation_id for target in targets]
        if target_ids != ids:
            raise FlagWorkflowError(
                "human canary approved ids must exactly match nomination "
                "order"
            )
        if len(target_ids) != len(set(target_ids)):
            raise FlagWorkflowError(
                "human canary nominations contain duplicate mutation ids"
            )
        if len(targets) > HUMAN_CANARY_MAX:
            raise FlagWorkflowError(
                "human canary may nominate at most 3 targets"
            )
        for target in targets:
            # Reparse the typed object through the public-free wire format so
            # direct in-memory construction cannot evade target validation.
            checked = HumanCanaryTarget.from_dict(
                target.to_dict(), "approval.human_canary_target"
            )
            m = by_id[checked.mutation_id]
            if checked.ref_digest != m.ref_digest:
                raise FlagWorkflowError(
                    f"{m.mutation_id}: human nomination ref digest does "
                    "not match the immutable plan"
                )
            if m.auto_eligible is not False or m.review_required is not True:
                raise FlagWorkflowError(
                    f"{m.mutation_id}: human canary requires the original "
                    "review_required=True and auto_eligible=False state"
                )
            if m.observed_flag == FlagColor.UNKNOWN:
                raise FlagWorkflowError(
                    f"{m.mutation_id}: UNKNOWN observations can never be "
                    "human-canary targets"
                )
            if checked.temporary_flag == m.observed_flag:
                raise FlagWorkflowError(
                    f"{m.mutation_id}: human canary temporary flag must "
                    "differ from the exact observed flag"
                )
            blocker = human_canary_risk_blocker(m)
            if blocker is not None:
                raise FlagWorkflowError(
                    f"{m.mutation_id}: human canary target refused: "
                    f"{blocker}"
                )
            validate_planned_mutation_contract(
                m,
                policy_sha256=policy_sha256,
                snapshot_sha256=snapshot_sha256,
            )


def load_approval(path: Path) -> ApprovalReceipt:
    """Load a strict private approval artifact."""
    return ApprovalReceipt.from_dict(
        _json_object_from_path(Path(path), "approval")
    )


def write_private_approval(
        approval: ApprovalReceipt, path: Path,
        *, plan: Dict[str, Any]) -> Path:
    """Validate and atomically persist an approval as mode 0600."""
    mutations = validate_plan_schema(plan)
    approval.validate(plan=dict(plan), plan_mutations=mutations)
    return _atomic_write_private_json(
        Path(path), approval.to_dict(), prefix=".tmp-flags-approval-"
    )


# --- Transaction ledger (append-only idempotency guard) ----------------------


class AppliedPlanLedger:
    """Append-only JSONL ledger of consumed transactions.

    One record per applied mutation: {plan_hash, mutation_id, applied_at,
    verified}. ``has()`` makes reapplication a provable no-op.
    """

    def __init__(self, path: Path):
        self.path = Path(path).expanduser()

    def _ensure_dir(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def record(self, plan_hash: str, mutation_id: str,
               verified: bool, applied_at: Optional[str] = None) -> None:
        require_hex256(plan_hash, "plan_hash")
        _require_string(mutation_id, "mutation_id")
        _require_bool(verified, "verified")
        applied_text = (
            applied_at
            if applied_at is not None
            else datetime.now(timezone.utc).isoformat()
        )
        _parse_aware_timestamp(applied_text, "applied_at")
        entry = {
            "plan_hash": plan_hash,
            "mutation_id": mutation_id,
            "applied_at": applied_text,
            "verified": verified,
        }
        self._ensure_dir()
        line = canonical_json_bytes(entry).decode("utf-8") + "\n"
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())

    def has(self, plan_hash: str, mutation_id: str) -> bool:
        require_hex256(plan_hash, "plan_hash")
        _require_string(mutation_id, "mutation_id")
        for entry in self._read_entries():
            if (entry.get("plan_hash") == plan_hash
                    and entry.get("mutation_id") == mutation_id):
                return True
        return False

    def all_entries(self) -> List[Dict[str, Any]]:
        return self._read_entries()

    def _read_entries(self) -> List[Dict[str, Any]]:
        """Parse every authoritative row; one malformed row blocks all use."""
        if not self.path.exists():
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise FlagWorkflowError(
                f"applied-plan ledger unreadable: {self.path}"
            ) from exc
        out: List[Dict[str, Any]] = []
        for line_number, raw in enumerate(lines, start=1):
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise FlagWorkflowError(
                    f"applied-plan ledger corrupt at line {line_number}"
                ) from exc
            if not isinstance(entry, dict):
                raise FlagWorkflowError(
                    f"applied-plan ledger line {line_number} must be an object"
                )
            required = {"plan_hash", "mutation_id", "applied_at", "verified"}
            missing = required.difference(entry)
            if missing:
                raise FlagWorkflowError(
                    f"applied-plan ledger line {line_number} missing "
                    f"{sorted(missing)}"
                )
            require_hex256(
                entry["plan_hash"],
                f"applied-plan ledger line {line_number}.plan_hash",
            )
            _require_string(
                entry["mutation_id"],
                f"applied-plan ledger line {line_number}.mutation_id",
            )
            _parse_aware_timestamp(
                entry["applied_at"],
                f"applied-plan ledger line {line_number}.applied_at",
            )
            _require_bool(
                entry["verified"],
                f"applied-plan ledger line {line_number}.verified",
            )
            out.append(entry)
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
        # Resolve ``~`` at the trust boundary once.  Every later lock/read/
        # replace operation must address this same concrete store path.
        self.path = Path(path).expanduser()

    @contextmanager
    def _locked(self) -> Iterator[None]:
        """Serialize every read and full read-modify-write by store path."""
        key = os.path.abspath(os.fspath(self.path))
        with _OVERRIDE_LOCKS_GUARD:
            thread_lock = _OVERRIDE_LOCKS.setdefault(key, threading.RLock())
        with thread_lock:
            parent_fd: Optional[int] = None
            lock_fd: Optional[int] = None
            try:
                parent_fd = _open_private_parent(
                    self.path, create=True, label="override store"
                )
                lock_name = f".{self.path.name}.lock"
                lock_fd = os.open(
                    lock_name,
                    os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                    0o600,
                    dir_fd=parent_fd,
                )
                if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                    raise OSError("override lock is not a regular file")
                os.fchmod(lock_fd, 0o600)
                fcntl.flock(lock_fd, fcntl.LOCK_EX)
            except (FlagWorkflowError, OSError) as exc:
                if lock_fd is not None:
                    os.close(lock_fd)
                if parent_fd is not None:
                    os.close(parent_fd)
                raise FlagWorkflowError(
                    f"override store lock unavailable ({self.path}): {exc}"
                ) from exc
            if parent_fd is not None:
                os.close(parent_fd)
            try:
                yield
            finally:
                if lock_fd is not None:
                    try:
                        fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    finally:
                        os.close(lock_fd)

    @staticmethod
    def _validate_mapping(data: Any, path: Path) -> Dict[str, Any]:
        """Validate top-level and nested store mappings without coercion."""
        if not isinstance(data, dict):
            raise FlagWorkflowError(
                f"override store corrupt (top level is not an object): {path}"
            )
        required_sections = {"overrides", "suppressed", "last_automation"}
        if set(data) != required_sections:
            missing = sorted(required_sections.difference(data))
            unexpected = sorted(set(data).difference(required_sections))
            raise FlagWorkflowError(
                "override store corrupt (top-level sections must be exactly "
                f"{sorted(required_sections)}; missing={missing}, "
                f"unexpected={unexpected}): {path}"
            )
        for section in required_sections:
            if not isinstance(data[section], dict):
                raise FlagWorkflowError(
                    f"override store corrupt ({section} is not a mapping): "
                    f"{path}"
                )

        for ref_digest, record in data["overrides"].items():
            key = require_hex256(ref_digest, "override key")
            if not isinstance(record, dict):
                raise FlagWorkflowError(
                    f"override store corrupt (override {key} is not a mapping)"
                )
            record_ref = require_hex256(
                record.get("ref_digest"), f"override {key}.ref_digest"
            )
            if record_ref != key:
                raise FlagWorkflowError(
                    f"override store corrupt (override {key} ref mismatch)"
                )
            _parse_aware_timestamp(
                record.get("detected_at"), f"override {key}.detected_at"
            )
            _require_string(
                record.get("automation_expected_state"),
                f"override {key}.automation_expected_state",
                allow_empty=True,
            )
            _require_string(
                record.get("human_observed_state"),
                f"override {key}.human_observed_state",
                allow_empty=True,
            )
            is_active = _require_bool(
                record.get("suppressed"), f"override {key}.suppressed"
            )
            unlocked_at = record.get("unlocked_at")
            unlock_actor = record.get("unlock_actor")
            if is_active:
                if unlocked_at is not None or unlock_actor is not None:
                    raise FlagWorkflowError(
                        "override store corrupt "
                        f"(active override {key} has unlock audit fields)"
                    )
                if data["suppressed"].get(key) is not True:
                    raise FlagWorkflowError(
                        "override store corrupt "
                        f"(active override {key} is not suppressed)"
                    )
            else:
                if unlocked_at is None:
                    raise FlagWorkflowError(
                        "override store corrupt "
                        f"(unlocked override {key} has no unlocked_at)"
                    )
                _parse_aware_timestamp(
                    unlocked_at, f"override {key}.unlocked_at"
                )
                _require_string(
                    unlock_actor,
                    f"override {key}.unlock_actor",
                )
                if key in data["suppressed"]:
                    raise FlagWorkflowError(
                        "override store corrupt "
                        f"(unlocked override {key} remains suppressed)"
                    )

        for ref_digest, suppressed in data["suppressed"].items():
            key = require_hex256(ref_digest, "suppressed key")
            if _require_bool(suppressed, f"suppressed {key}") is not True:
                raise FlagWorkflowError(
                    f"override store corrupt (suppressed {key} is not true)"
                )
            record = data["overrides"].get(key)
            if not isinstance(record, dict) or record.get("suppressed") is not True:
                raise FlagWorkflowError(
                    "override store corrupt "
                    f"(suppressed {key} has no matching active override)"
                )

        for ref_digest, record in data["last_automation"].items():
            key = require_hex256(ref_digest, "last_automation key")
            if not isinstance(record, dict):
                raise FlagWorkflowError(
                    "override store corrupt "
                    f"(last_automation {key} is not a mapping)"
                )
            _require_string(
                record.get("flag"), f"last_automation {key}.flag"
            )
            _require_bool(
                record.get("verified"), f"last_automation {key}.verified"
            )
            _parse_aware_timestamp(
                record.get("recorded_at"),
                f"last_automation {key}.recorded_at",
            )
        return data

    def _load_unlocked(self) -> Dict[str, Any]:
        empty: Dict[str, Any] = {
            "overrides": {},
            "suppressed": {},
            "last_automation": {},
        }
        parent_fd: Optional[int] = None
        fd: Optional[int] = None
        try:
            # O_NONBLOCK ensures a hostile FIFO/device cannot hang a state
            # read before fstat rejects it; O_NOFOLLOW rejects symlinks,
            # including dangling ones that Path.exists() misclassifies.
            parent_fd = _open_private_parent(
                self.path, create=False, label="override store"
            )
            fd = os.open(
                self.path.name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            if parent_fd is not None:
                os.close(parent_fd)
            return empty
        except (FlagWorkflowError, OSError) as exc:
            if parent_fd is not None:
                os.close(parent_fd)
            raise FlagWorkflowError(
                f"override store unreadable ({self.path}): {exc}"
            ) from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise FlagWorkflowError(
                    "override store unusable (not a regular file): "
                    f"{self.path}"
                )
            if metadata.st_size > 10 * 1024 * 1024:
                raise FlagWorkflowError(
                    f"override store corrupt (too large): {self.path}"
                )
            with os.fdopen(fd, "rb") as handle:
                fd = None
                raw_bytes = handle.read(10 * 1024 * 1024 + 1)
        except OSError as exc:
            raise FlagWorkflowError(
                f"override store unreadable ({self.path}): {exc}"
            ) from exc
        finally:
            if fd is not None:
                os.close(fd)
            if parent_fd is not None:
                os.close(parent_fd)
        if len(raw_bytes) > 10 * 1024 * 1024:
            raise FlagWorkflowError(
                f"override store corrupt (too large): {self.path}"
            )
        try:
            raw = raw_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FlagWorkflowError(
                f"override store corrupt (invalid encoding): {self.path}"
            ) from exc
        try:
            data = json.loads(
                raw,
                parse_constant=_reject_nonfinite_json,
                object_pairs_hook=_reject_duplicate_json_keys,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise FlagWorkflowError(
                f"override store corrupt (invalid JSON): {self.path}"
            ) from exc
        return self._validate_mapping(data, self.path)

    def _save_unlocked(self, data: Dict[str, Any]) -> None:
        validated = self._validate_mapping(data, self.path)
        _atomic_write_private_json(
            self.path, validated, prefix=f".tmp-{self.path.name}-"
        )

    @staticmethod
    def _key(ref_digest: str) -> str:
        return require_hex256(ref_digest, "ref_digest")

    def record_automation_state(self, ref_digest: str, flag_value: str,
                                verified: bool) -> None:
        """Record last verified automation state.

        UNLOCK-ONLY CONTRACT (Commit 6): this method NEVER clears a
        detected human override. Overrides are cleared exclusively by
        :meth:`unlock` — an explicit operator action. Automation verifying
        its own write cannot silently resurrect its authority over a
        message a human has touched.
        """
        _require_string(flag_value, "flag_value")
        _require_bool(verified, "verified")
        with self._locked():
            data = self._load_unlocked()
            k = self._key(ref_digest)
            data["last_automation"][k] = {
                "flag": flag_value,
                "verified": verified,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
            # NOTE: no pop of overrides/suppressed here — unlock-only.
            self._save_unlocked(data)

    def detect_override(self, ref_digest: str,
                        automation_expected_state: str,
                        human_observed_state: str) -> None:
        """Persist a detected human override and SUPPRESS the ref.

        Lifecycle: current != last verified automation state AND no
        approved transaction explains the change => override recorded,
        automation suppressed until an explicit operator unlock.
        """
        _require_string(
            automation_expected_state,
            "automation_expected_state",
            allow_empty=True,
        )
        _require_string(
            human_observed_state, "human_observed_state", allow_empty=True
        )
        with self._locked():
            data = self._load_unlocked()
            k = self._key(ref_digest)
            data["overrides"][k] = {
                "ref_digest": k,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "automation_expected_state": automation_expected_state,
                "human_observed_state": human_observed_state,
                "suppressed": True,
                "unlocked_at": None,
                "unlock_actor": None,
            }
            data["suppressed"][k] = True
            self._save_unlocked(data)

    def record_override(self, ref_digest: str, detail: str) -> None:
        """Legacy detail-shaped detection (kept for existing callers)."""
        _require_string(detail, "detail", allow_empty=True)
        self.detect_override(ref_digest, "unknown", f"detail:{detail}")

    def is_overridden(self, ref_digest: str) -> bool:
        key = self._key(ref_digest)
        with self._locked():
            return key in self._load_unlocked()["overrides"]

    def is_suppressed(self, ref_digest: str) -> bool:
        key = self._key(ref_digest)
        with self._locked():
            return key in self._load_unlocked()["suppressed"]

    def unlock(self, ref_digest: str, actor: str = "") -> None:
        """EXPLICIT operator action — the ONLY path that clears suppression.

        Records who unlocked and when (audit trail persists in overrides
        history), then clears the active suppression.
        """
        _require_string(actor, "actor", allow_empty=True)
        with self._locked():
            data = self._load_unlocked()
            k = self._key(ref_digest)
            if k in data["overrides"]:
                data["overrides"][k]["suppressed"] = False
                data["overrides"][k]["unlocked_at"] = (
                    datetime.now(timezone.utc).isoformat()
                )
                data["overrides"][k]["unlock_actor"] = (
                    actor or "unnamed-operator"
                )
            data["suppressed"].pop(k, None)
            self._save_unlocked(data)

    def list_overrides(self) -> Dict[str, Any]:
        with self._locked():
            return dict(self._load_unlocked()["overrides"])


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
        receipt_id = _require_string(self.receipt_id, "rollback.receipt_id")
        if not (
            receipt_id.startswith("rb-")
            and len(receipt_id) == 35
            and set(receipt_id[3:]) <= _HEX_CHARS
        ):
            raise FlagWorkflowError(
                "rollback.receipt_id must be 'rb-' followed by 32 "
                "lowercase hex characters"
            )
        require_hex256(self.plan_hash, "rollback.plan_hash")
        _parse_aware_timestamp(self.created_at, "rollback.created_at")
        if not isinstance(self.entries, list):
            raise FlagWorkflowError("rollback.entries must be a list")
        if not all(isinstance(entry, RollbackEntry) for entry in self.entries):
            raise FlagWorkflowError(
                "rollback.entries must contain RollbackEntry objects"
            )
        stored = require_hex256(self.content_hash, "rollback.content_hash")
        body = self.to_dict()
        body.pop("content_hash")
        if sha256_hex(body) != stored:
            raise FlagWorkflowError(
                "rollback receipt content_hash mismatch (tampered)"
            )

        seen_refs = set()
        validator = _native_validator_for("mailapp")
        for index, entry in enumerate(self.entries):
            prefix = f"rollback.entries[{index}]"
            ref_digest = require_hex256(
                entry.ref_digest, f"{prefix}.ref_digest"
            )
            if ref_digest in seen_refs:
                raise FlagWorkflowError(f"{prefix}.ref_digest is duplicated")
            seen_refs.add(ref_digest)
            native_index = _require_optional_int(
                entry.pre_apply_native_index,
                f"{prefix}.pre_apply_native_index",
            )
            if not isinstance(entry.pre_apply_flag, FlagColor):
                raise FlagWorkflowError(
                    f"{prefix}.pre_apply_flag must be a FlagColor"
                )
            if not isinstance(entry.automation_applied_flag, FlagColor):
                raise FlagWorkflowError(
                    f"{prefix}.automation_applied_flag must be a FlagColor"
                )
            expected_pre_flag = validator(native_index)
            if expected_pre_flag == FlagColor.UNKNOWN:
                raise FlagWorkflowError(
                    f"{prefix}.pre_apply_native_index is not rollbackable"
                )
            if expected_pre_flag != entry.pre_apply_flag:
                raise FlagWorkflowError(
                    f"{prefix} native index and pre-apply flag disagree"
                )
            if entry.automation_applied_flag == FlagColor.UNKNOWN:
                raise FlagWorkflowError(
                    f"{prefix}.automation_applied_flag cannot be UNKNOWN"
                )
            if entry.pre_apply_flag == entry.automation_applied_flag:
                raise FlagWorkflowError(
                    f"{prefix} does not describe a state change"
                )

    @classmethod
    def create(cls, plan_hash: str,
               entries: List[RollbackEntry]) -> "RollbackReceipt":
        require_hex256(plan_hash, "rollback.plan_hash")
        if not isinstance(entries, list):
            raise FlagWorkflowError("rollback.entries must be a list")
        if not all(isinstance(entry, RollbackEntry) for entry in entries):
            raise FlagWorkflowError(
                "rollback.entries must contain RollbackEntry objects"
            )
        created_at = datetime.now(timezone.utc).isoformat()
        receipt = cls(
            schema=ROLLBACK_RECEIPT_SCHEMA,
            receipt_id="rb-" + sha256_hex({
                "plan_hash": plan_hash,
                "entries": [entry.to_dict() for entry in entries],
                "created_hint": created_at,
            })[:32],
            plan_hash=plan_hash,
            created_at=created_at,
            entries=list(entries),
        )
        receipt.content_hash = receipt.to_dict()["content_hash"]
        receipt.validate()
        return receipt

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "RollbackReceipt":
        if not isinstance(raw, dict):
            raise FlagWorkflowError("rollback receipt must be a JSON object")
        _require_exact_keys(raw, {
            "schema", "receipt_id", "plan_hash", "created_at", "entries",
            "content_hash",
        }, "rollback receipt")
        entries_raw = raw["entries"]
        if not isinstance(entries_raw, list):
            raise FlagWorkflowError("rollback.entries must be a list")
        entries = []
        for index, entry_raw in enumerate(entries_raw):
            prefix = f"rollback.entries[{index}]"
            if not isinstance(entry_raw, dict):
                raise FlagWorkflowError(f"{prefix} must be an object")
            _require_exact_keys(entry_raw, {
                "ref_digest", "pre_apply_native_index", "pre_apply_flag",
                "automation_applied_flag",
            }, prefix)
            pre_flag_raw = _require_string(
                entry_raw["pre_apply_flag"], f"{prefix}.pre_apply_flag"
            )
            applied_flag_raw = _require_string(
                entry_raw["automation_applied_flag"],
                f"{prefix}.automation_applied_flag",
            )
            try:
                pre_flag = FlagColor(pre_flag_raw)
                applied_flag = FlagColor(applied_flag_raw)
            except ValueError as exc:
                raise FlagWorkflowError(
                    f"{prefix} contains a non-canonical flag"
                ) from exc
            entries.append(RollbackEntry(
                ref_digest=require_hex256(
                    entry_raw["ref_digest"], f"{prefix}.ref_digest"
                ),
                pre_apply_native_index=_require_optional_int(
                    entry_raw["pre_apply_native_index"],
                    f"{prefix}.pre_apply_native_index",
                ),
                pre_apply_flag=pre_flag,
                automation_applied_flag=applied_flag,
            ))
        receipt = cls(
            schema=_require_string(raw["schema"], "rollback.schema"),
            receipt_id=_require_string(
                raw["receipt_id"], "rollback.receipt_id"
            ),
            plan_hash=require_hex256(raw["plan_hash"], "rollback.plan_hash"),
            created_at=_require_string(
                raw["created_at"], "rollback.created_at"
            ),
            entries=entries,
            content_hash=require_hex256(
                raw["content_hash"], "rollback.content_hash"
            ),
        )
        receipt.validate()
        return receipt
