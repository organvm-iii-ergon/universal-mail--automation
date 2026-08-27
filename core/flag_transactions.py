"""Flag migration TRANSACTION ENGINE (Commit 6).

Turns the immutable plan + cryptographically bound approval into
transaction semantics — while every production entry point stays behind
the CLI NOT_READY gate.

DOCTRINE
--------
- ALL-OR-ZERO PREFLIGHT: every selected mutation is fully preflighted
  BEFORE the first write. One drifted item freezes the entire batch;
  writes performed = 0.
- SCOPED WRITES ONLY: the engine calls ONLY set_flag_color_ref /
  clear_flag_ref / resolve_scoped on the provider. The generic
  apply_actions path is never reachable from here.
- READ-AFTER-WRITE PROOF: a provider returning True is not success. The
  engine re-resolves the qualified message and verifies evidence still
  bound + exact native index + semantic mapping before recording
  ``verified``. Write-done-but-verification-failed => AMBIGUOUS, frozen.
- HONEST PARTIAL FAILURE: a mid-batch failure records exactly which
  mutations verified, which failed, which were unattempted; status is
  partially_failed — NEVER "applied". No silent automatic compensation:
  rollback requires an explicit transaction-bound receipt.
- IDEMPOTENCY: replaying an already-verified mutation performs ZERO
  provider writes and reports already_applied.
- UNLOCK-ONLY OVERRIDES: a persisted human override suppresses the ref;
  preflight refuses suppressed messages.
- CONCURRENCY: one advisory lock per plan serializes approval validation,
  ledger checks, preflight, claim, writes, and receipt append. A second
  contender performs zero writes and reports already_claimed.

Every artifact (ledger lines, receipts, lock files) lives under the
private UMA state directory: directories 0700, files 0600, fsync'd
appends, atomic replacement for rewritten JSON.
"""

from __future__ import annotations

import fcntl
import json
import os
import stat
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.flag_workflow import (
    ApprovalReceipt,
    FlagWorkflowError,
    PlannedMutation,
    _reject_duplicate_json_keys,
    _reject_nonfinite_json,
    compute_plan_hash,
    require_hex256,
    sha256_hex,
    validate_planned_mutation_contract,
)
from core.models import FlagColor, MessageReference
from providers.base import ProviderNativeStateDrift, ProviderWriteAmbiguous

TX_LEDGER_SCHEMA = "uma.flags.transactions.v1"
ROLLBACK_TX_SCHEMA = "uma.flags.rollback.tx.v1"

# Ledger states — explicit, ordered lifecycle.
ST_PREPARED = "prepared"
ST_PREFLIGHT_PASSED = "preflight_passed"
ST_APPLYING = "applying"
ST_VERIFIED_PENDING_PRIVATE_STATE = "verified_pending_private_state"
ST_VERIFIED = "verified"
ST_PARTIALLY_FAILED = "partially_failed"
ST_BLOCKED = "blocked"
ST_AMBIGUOUS = "ambiguous"
ST_FROZEN_UNATTEMPTED = "frozen_unattempted"
ST_ALREADY_VERIFIED = "already_verified"          # EVENT ONLY (see below)
ST_ROLLBACK_PENDING = "rollback_pending"
ST_ROLLED_BACK = "rolled_back"
ST_ROLLBACK_BLOCKED = "rollback_blocked"

LEDGER_STATUSES = frozenset({
    ST_PREPARED,
    ST_PREFLIGHT_PASSED,
    ST_APPLYING,
    ST_VERIFIED_PENDING_PRIVATE_STATE,
    ST_VERIFIED,
    ST_PARTIALLY_FAILED,
    ST_BLOCKED,
    ST_AMBIGUOUS,
    ST_FROZEN_UNATTEMPTED,
    ST_ALREADY_VERIFIED,
    ST_ROLLBACK_PENDING,
    ST_ROLLED_BACK,
    ST_ROLLBACK_BLOCKED,
})

# AUTHORITATIVE mutation states vs EVENT records.
#
# `already_verified` is an informational REPLAY EVENT. It must NEVER
# supersede the authoritative `verified` state: treating last-row-wins over
# a mixed stream let a third apply re-execute (P0 6b), and dropped verified
# mutations from rollback candidacy. Authority is computed from the LAST
# authoritative row; event rows are skipped entirely.
AUTHORITATIVE_STATUSES = frozenset({
    ST_VERIFIED_PENDING_PRIVATE_STATE,
    ST_VERIFIED,
    ST_ROLLED_BACK,
})

# These states mean a provider write may be in flight or may already have
# crossed the boundary without a durable proof of its outcome.  They are not
# replayable authority.  A human recovery must append a conclusive lifecycle
# row before either apply or rollback can touch the message again.
FROZEN_LATEST_STATUSES = frozenset({
    ST_APPLYING,
    ST_VERIFIED_PENDING_PRIVATE_STATE,
    ST_PARTIALLY_FAILED,
    ST_AMBIGUOUS,
    ST_FROZEN_UNATTEMPTED,
    ST_ROLLBACK_PENDING,
})


class TransactionLocked(FlagWorkflowError):
    """Another process holds the advisory lock for this plan."""


class LedgerCorrupted(FlagWorkflowError):
    """The transaction ledger cannot be trusted for authority
    reconstruction (malformed line, unparsable JSON, wrong shape).

    DOCTRINE (Commit 7, Group H): a corrupt ledger MUST NOT be interpreted
    as 'nothing previously happened'. Corruption blocks transactions with
    ZERO provider writes; it never resets idempotency or rollback safety.
    An EMPTY/blank-lines-only file IS a legitimate fresh ledger (our
    writers never create blank files, but touch(1)-style pre-creation is
    benign — there is provably no history to lose).
    """


class PrivateStateUnusable(FlagWorkflowError):
    """A private-state artifact (ledger/lock/store) is structurally
    unusable — e.g. a SYMLINK where a regular file is required. We refuse
    to follow attacker-controlled links out of the managed tree."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _open_managed_parent(path: Path, *, create: bool, label: str) -> int:
    """Open and hold the artifact parent without following managed symlinks.

    The parent is opened relative to its own parent directory, with
    ``O_NOFOLLOW|O_DIRECTORY``.  Leaf opens then use this returned fd via
    ``dir_fd``, closing the check/use race that exists with path-based lstat.
    Standard aliases above the managed root (for example macOS ``/var``) do
    not get rejected.
    """
    absolute = Path(os.path.abspath(os.fspath(path)))
    parent = absolute.parent
    anchor = parent.parent
    child_name = parent.name
    if not child_name:
        raise PrivateStateUnusable(
            f"{label} artifact cannot live directly under filesystem root"
        )
    if create:
        try:
            anchor.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            raise PrivateStateUnusable(
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
                # A concurrent first user created it; the O_NOFOLLOW reopen
                # below is the authority check.
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
        raise PrivateStateUnusable(
            f"{label} parent unusable ({parent}): {exc}"
        ) from exc
    finally:
        if anchor_fd is not None:
            os.close(anchor_fd)


def _require_prefixed_hex_id(
    value: Any,
    name: str,
    *,
    prefix: str,
    hex_length: int,
) -> str:
    """Require the exact internal ID grammar used in lock-file names."""
    expected_length = len(prefix) + hex_length
    if (
        not isinstance(value, str)
        or len(value) != expected_length
        or not value.startswith(prefix)
        or any(char not in "0123456789abcdef" for char in value[len(prefix):])
    ):
        raise FlagWorkflowError(
            f"{name} must match {prefix}<lowercase-{hex_length}-hex>"
        )
    return value


# --- Advisory lock -------------------------------------------------------------


class AdvisoryFileLock:
    """Non-blocking exclusive advisory lock around the whole transaction.

    Avoids the check-then-write race on ledger.has(): claim happens INSIDE
    the lock together with validation, preflight, writes, and receipt.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._fd: Optional[int] = None

    def __enter__(self) -> "AdvisoryFileLock":
        parent_fd: Optional[int] = None
        try:
            parent_fd = _open_managed_parent(
                self.path, create=True, label="lock"
            )
            # O_NOFOLLOW: refuse to acquire a lock through an
            # attacker-controlled symlink (Commit 7 Group O).
            fd = os.open(
                self.path.name,
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=parent_fd,
            )
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise PrivateStateUnusable(
                    f"lock is not a regular file ({self.path})"
                )
        except PrivateStateUnusable:
            raise
        except OSError as e:
            raise PrivateStateUnusable(
                f"lock path unusable ({self.path}): {e}") from e
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
        try:
            os.fchmod(fd, 0o600)            # EVERY open — pre-existing
            # 0644 lock files must be hardened too (P0 6b FIX 3).
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as e:
            os.close(fd)
            raise TransactionLocked(
                f"another process holds {self.path.name}") from e
        except Exception as e:
            os.close(fd)
            raise PrivateStateUnusable(
                f"lock acquisition failed ({self.path}): {e}") from e
        self._fd = fd
        return self

    def __exit__(self, *exc) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


# --- Transaction ledger ----------------------------------------------------------


@dataclass
class TransactionRecord:
    """One durable ledger line for ONE mutation's lifecycle step."""
    transaction_id: str
    plan_sha256: str
    approval_sha256: str
    mutation_id: str
    ref_digest: str
    pre_state: Optional[str]
    intended_state: str
    verified_post_state: Optional[str]
    timestamp: str
    status: str
    error_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": TX_LEDGER_SCHEMA,
            "transaction_id": self.transaction_id,
            "plan_sha256": self.plan_sha256,
            "approval_sha256": self.approval_sha256,
            "mutation_id": self.mutation_id,
            "ref_digest": self.ref_digest,
            "pre_state": self.pre_state,
            "intended_state": self.intended_state,
            "verified_post_state": self.verified_post_state,
            "timestamp": self.timestamp,
            "status": self.status,
            "error_code": self.error_code,
        }


class TransactionLedger:
    """Append-only JSONL with EXPLICIT transaction states.

    Durability: each line is written + flushed + fsync'd before the next
    action. File/dir permissions enforced on every open (0600/0700).
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    def _append(self, record: TransactionRecord) -> None:
        try:
            line = json.dumps(
                record.to_dict(), sort_keys=True, allow_nan=False
            ) + "\n"
        except (TypeError, ValueError) as exc:
            raise LedgerCorrupted(
                f"ledger preparation failed ({self.path}): {exc}"
            ) from exc
        parent_fd: Optional[int] = None
        try:
            parent_fd = _open_managed_parent(
                self.path, create=True, label="ledger"
            )
            fd = os.open(
                self.path.name,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND |
                os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=parent_fd,
            )
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                os.close(fd)
                raise OSError("ledger is not a regular file")
        except PrivateStateUnusable:
            raise
        except OSError as e:
            raise LedgerCorrupted(
                f"ledger not appendable ({self.path}): {e}") from e
        finally:
            if parent_fd is not None:
                os.close(parent_fd)
        try:
            os.fchmod(fd, 0o600)            # EVERY open — pre-existing
            # 0644 ledgers must be hardened too (P0 6b FIX 3).
            encoded = line.encode("utf-8")
            written = 0
            while written < len(encoded):
                count = os.write(fd, encoded[written:])
                if count <= 0:
                    raise OSError("ledger write made no forward progress")
                written += count
            os.fsync(fd)
        except OSError as e:
            raise LedgerCorrupted(
                f"ledger durability failure ({self.path}): {e}") from e
        finally:
            os.close(fd)

    def entries(self) -> List[Dict[str, Any]]:
        """Parse the ledger, FAILING CLOSED on any malformed line.

        Blank lines are skipped (benign). A non-blank line that is not
        valid JSON, or a JSON object missing the minimal authoritative
        shape (plan_sha256/mutation_id/status), raises LedgerCorrupted —
        corruption must block, never masquerade as empty history.
        """
        parent_fd: Optional[int] = None
        fd: Optional[int] = None
        try:
            parent_fd = _open_managed_parent(
                self.path, create=False, label="ledger"
            )
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise LedgerCorrupted(
                f"ledger unreadable ({self.path}): {exc}") from exc
        try:
            try:
                fd = os.open(
                    self.path.name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                return []
            except OSError as exc:
                raise LedgerCorrupted(
                    f"ledger unreadable ({self.path}): {exc}"
                ) from exc
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise LedgerCorrupted(
                    f"ledger is not a regular file ({self.path})")
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                fd = None
                raw = handle.read()
        except (OSError, UnicodeError) as exc:
            raise LedgerCorrupted(
                f"ledger unreadable ({self.path}): {exc}") from exc
        finally:
            if fd is not None:
                os.close(fd)
            if parent_fd is not None:
                os.close(parent_fd)
        out: List[Dict[str, Any]] = []
        for lineno, line in enumerate(raw.splitlines(), start=1):
            if not line.strip():
                continue                    # benign blank line
            try:
                e = json.loads(
                    line,
                    parse_constant=_reject_nonfinite_json,
                    object_pairs_hook=_reject_duplicate_json_keys,
                )
            except (json.JSONDecodeError, ValueError) as ex:
                raise LedgerCorrupted(
                    f"ledger line {lineno} malformed JSON") from ex
            if not isinstance(e, dict):
                raise LedgerCorrupted(
                    f"ledger line {lineno} is not an object")
            required = {
                "schema", "transaction_id", "plan_sha256",
                "approval_sha256", "mutation_id", "ref_digest",
                "pre_state", "intended_state", "verified_post_state",
                "timestamp", "status", "error_code",
            }
            missing = required.difference(e)
            if missing:
                raise LedgerCorrupted(
                    f"ledger line {lineno} lacks fields {sorted(missing)}"
                )
            extra = set(e).difference(required)
            if extra:
                raise LedgerCorrupted(
                    f"ledger line {lineno} has unknown fields {sorted(extra)}"
                )
            try:
                if e["schema"] != TX_LEDGER_SCHEMA:
                    raise ValueError("wrong schema")
                _require_prefixed_hex_id(
                    e["transaction_id"],
                    f"ledger line {lineno}.transaction_id",
                    prefix="tx-",
                    hex_length=24,
                )
                _require_prefixed_hex_id(
                    e["mutation_id"],
                    f"ledger line {lineno}.mutation_id",
                    prefix="mut-",
                    hex_length=24,
                )
                if not isinstance(e["intended_state"], str):
                    raise ValueError("intended_state must be a string")
                for field_name in ("plan_sha256", "approval_sha256",
                                   "ref_digest"):
                    require_hex256(e[field_name], field_name)
                for field_name in ("pre_state", "verified_post_state",
                                   "error_code"):
                    value = e[field_name]
                    if value is not None and not isinstance(value, str):
                        raise ValueError(
                            f"{field_name} must be null or a string"
                        )
                if e["status"] not in LEDGER_STATUSES:
                    raise ValueError(f"unknown status {e['status']!r}")
                valid_states = {color.value for color in FlagColor}
                writable_states = valid_states.difference({
                    FlagColor.UNKNOWN.value,
                })
                if e["intended_state"] not in writable_states:
                    raise ValueError(
                        "intended_state must be a writable FlagColor value"
                    )
                for field_name in ("pre_state", "verified_post_state"):
                    value = e[field_name]
                    if value is not None and value not in valid_states:
                        raise ValueError(
                            f"{field_name} must be a FlagColor value or null"
                        )
                if e["status"] in {
                    ST_VERIFIED_PENDING_PRIVATE_STATE,
                    ST_VERIFIED,
                    ST_ROLLED_BACK,
                } and e["verified_post_state"] != e["intended_state"]:
                    raise ValueError(
                        "verified lifecycle row must prove intended_state"
                    )
                if e["error_code"] == "":
                    raise ValueError("error_code cannot be an empty string")
                timestamp = e["timestamp"]
                if not isinstance(timestamp, str):
                    raise ValueError("timestamp must be a string")
                parsed_timestamp = datetime.fromisoformat(timestamp)
                if (
                    parsed_timestamp.tzinfo is None
                    or parsed_timestamp.utcoffset() is None
                ):
                    raise ValueError("timestamp must be timezone-aware")
            except (FlagWorkflowError, TypeError, ValueError) as exc:
                raise LedgerCorrupted(
                    f"ledger line {lineno} has invalid authoritative data: "
                    f"{exc}"
                ) from exc
            out.append(e)
        return out

    def latest_status(self, plan_hash: str, mutation_id: str) -> Optional[str]:
        """Most recent EVENT row for this plan+mutation (raw stream view).

        NEVER use for authority decisions — replay events would poison it.
        Use :meth:`authoritative_state`.
        """
        found = None
        for e in self.entries():
            if e.get("plan_sha256") == plan_hash \
                    and e.get("mutation_id") == mutation_id:
                found = e.get("status")
        return found

    def authoritative_state(self, plan_hash: str,
                            mutation_id: str) -> Optional[str]:
        """The authoritative applied-state: last AUTHORITATIVE row wins.

        Event rows (already_verified replays, preflight noise) are skipped.
        verified → rolled_back transitions are honored; a replay event
        between them changes nothing.
        """
        state = None
        for e in self.entries():
            if e.get("plan_sha256") != plan_hash \
                    or e.get("mutation_id") != mutation_id:
                continue
            if e.get("status") in AUTHORITATIVE_STATUSES:
                state = (
                    ST_VERIFIED
                    if e["status"] == ST_VERIFIED_PENDING_PRIVATE_STATE
                    else e["status"]
                )
        return state

    def has_verified(self, plan_hash: str, mutation_id: str) -> bool:
        return self.authoritative_state(
            plan_hash, mutation_id) == ST_VERIFIED

    def is_rolled_back(self, plan_hash: str, mutation_id: str) -> bool:
        return self.authoritative_state(
            plan_hash, mutation_id) == ST_ROLLED_BACK

    def latest_authoritative_record(self, plan_hash: str,
                                    mutation_id: str) -> Optional[Dict[str, Any]]:
        """The last AUTHORITATIVE row for this plan+mutation (dict or None).

        This is the provenance anchor for rollback: receipt fields must
        match THIS record, never merely themselves.
        """
        found = None
        for e in self.entries():
            if e.get("plan_sha256") != plan_hash \
                    or e.get("mutation_id") != mutation_id:
                continue
            if e.get("status") in AUTHORITATIVE_STATUSES:
                found = e
        return found

    def verified_transactions(self, plan_hash: str) -> List[Dict[str, Any]]:
        """Mutations whose AUTHORITATIVE state is verified (rollback pool).

        Replay events never remove a mutation from this set; an explicit
        rolled_back transition does.
        """
        out = []
        seen_mids = set()
        for e in self.entries():
            if e.get("plan_sha256") != plan_hash:
                continue
            mid = str(e.get("mutation_id"))
            if mid in seen_mids:
                continue
            if self.authoritative_state(plan_hash, mid) == ST_VERIFIED \
                    and e.get("status") == ST_VERIFIED:
                out.append(e)
                seen_mids.add(mid)
        return out

    def record(self, rec: TransactionRecord) -> None:
        self._append(rec)


# --- Rollback receipt (transaction-bound, own integrity hash) ---------------------


@dataclass
class TransactionRollbackReceipt:
    """Immutable rollback intent for ONE verified transaction.

    Binds the exact applied state so a later human change forces refusal:
    rollback only ever runs when current == verified_applied_state.
    """
    schema: str
    rollback_id: str
    transaction_id: str
    plan_sha256: str
    approval_sha256: str
    mutation_id: str
    ref_digest: str
    pre_native_flag: int
    pre_semantic_flag: str
    applied_native_flag: int
    applied_semantic_flag: str
    created_at: str
    content_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "schema": self.schema,
            "rollback_id": self.rollback_id,
            "transaction_id": self.transaction_id,
            "plan_sha256": self.plan_sha256,
            "approval_sha256": self.approval_sha256,
            "mutation_id": self.mutation_id,
            "ref_digest": self.ref_digest,
            "pre_native_flag": self.pre_native_flag,
            "pre_semantic_flag": self.pre_semantic_flag,
            "applied_native_flag": self.applied_native_flag,
            "applied_semantic_flag": self.applied_semantic_flag,
            "created_at": self.created_at,
        }
        d["content_hash"] = sha256_hex(d)
        return d

    def validate(self) -> None:
        if self.schema != ROLLBACK_TX_SCHEMA:
            raise FlagWorkflowError(
                f"rollback schema must be {ROLLBACK_TX_SCHEMA}")
        require_hex256(self.plan_sha256, "rollback.plan_sha256")
        require_hex256(self.approval_sha256, "rollback.approval_sha256")
        require_hex256(self.ref_digest, "rollback.ref_digest")
        _require_prefixed_hex_id(
            self.rollback_id,
            "rollback.rollback_id",
            prefix="rbx-",
            hex_length=32,
        )
        _require_prefixed_hex_id(
            self.transaction_id,
            "rollback.transaction_id",
            prefix="tx-",
            hex_length=24,
        )
        _require_prefixed_hex_id(
            self.mutation_id,
            "rollback.mutation_id",
            prefix="mut-",
            hex_length=24,
        )
        stored = require_hex256(self.content_hash, "rollback.content_hash")
        body = self.to_dict()
        body.pop("content_hash")
        if sha256_hex(body) != stored:
            raise FlagWorkflowError(
                "rollback content_hash mismatch (tampered)")
        for field_name in ("pre_native_flag", "applied_native_flag"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise FlagWorkflowError(
                    f"rollback.{field_name} must be an integer"
                )
        try:
            from providers.flag_codecs import flag_from_mailapp_index

            pre_semantic = FlagColor(self.pre_semantic_flag)
            applied_semantic = FlagColor(self.applied_semantic_flag)
        except (TypeError, ValueError) as exc:
            raise FlagWorkflowError(
                "rollback semantic flags must be canonical FlagColor values"
            ) from exc
        if pre_semantic is FlagColor.UNKNOWN \
                or applied_semantic is FlagColor.UNKNOWN:
            raise FlagWorkflowError(
                "rollback semantic flags cannot be unknown")
        if flag_from_mailapp_index(self.pre_native_flag) is not pre_semantic:
            raise FlagWorkflowError(
                "rollback pre native/semantic flag mismatch")
        if flag_from_mailapp_index(
                self.applied_native_flag) is not applied_semantic:
            raise FlagWorkflowError(
                "rollback applied native/semantic flag mismatch")
        if not isinstance(self.created_at, str):
            raise FlagWorkflowError("rollback.created_at must be a string")
        try:
            created = datetime.fromisoformat(self.created_at)
        except ValueError as exc:
            raise FlagWorkflowError(
                "rollback.created_at must be an ISO timestamp") from exc
        if created.tzinfo is None or created.utcoffset() is None:
            raise FlagWorkflowError(
                "rollback.created_at must be timezone-aware")

    @classmethod
    def create(cls, *, transaction_id: str, plan_sha256: str,
               approval_sha256: str, mutation_id: str, ref_digest: str,
               pre_native_flag: int, pre_semantic_flag: str,
               applied_native_flag: int,
               applied_semantic_flag: str) -> "TransactionRollbackReceipt":
        for field_name, value in (
            ("pre_native_flag", pre_native_flag),
            ("applied_native_flag", applied_native_flag),
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise FlagWorkflowError(
                    f"rollback.{field_name} must be an integer"
                )
        receipt = cls(
            schema=ROLLBACK_TX_SCHEMA,
            rollback_id="rbx-" + sha256_hex({
                "transaction_id": transaction_id,
                "mutation_id": mutation_id,
                "hint": _now(),
            })[:32],
            transaction_id=transaction_id,
            plan_sha256=plan_sha256,
            approval_sha256=approval_sha256,
            mutation_id=mutation_id,
            ref_digest=ref_digest,
            pre_native_flag=pre_native_flag,
            pre_semantic_flag=pre_semantic_flag,
            applied_native_flag=applied_native_flag,
            applied_semantic_flag=applied_semantic_flag,
            created_at=_now(),
        )
        receipt.content_hash = receipt.to_dict()["content_hash"]
        receipt.validate()
        return receipt


# --- Results -----------------------------------------------------------------------


@dataclass
class ApplyResult:
    status: str                      # applied|partially_failed|ambiguous|blocked|already_applied|already_claimed
    writes_performed: int = 0
    verified: List[Dict[str, Any]] = field(default_factory=list)
    failed: List[Dict[str, Any]] = field(default_factory=list)
    unattempted: List[Dict[str, Any]] = field(default_factory=list)
    already_applied: List[Dict[str, Any]] = field(default_factory=list)
    blocked_reason: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class RollbackResult:
    status: str                      # rolled_back|already_rolled_back|rollback_blocked_by_override|ambiguous|blocked
    writes_performed: int = 0
    restored_native_flag: Optional[int] = None
    error_code: Optional[str] = None


# --- Engine -------------------------------------------------------------------------


class TransactionEngine:
    """Executes approved flag migrations as verifiable transactions."""

    def __init__(self, state_dir: Path, ledger: TransactionLedger,
                 overrides: Any):
        self.state_dir = Path(state_dir)
        self.ledger = ledger
        self.overrides = overrides       # flag_workflow.OverrideStore

    # -- helpers ------------------------------------------------------------------

    @staticmethod
    def _ref_for(mutation: PlannedMutation) -> MessageReference:
        return MessageReference(
            provider=mutation.provider,
            account=mutation.account,
            mailbox=mutation.mailbox,
            provider_id=mutation.provider_id,
            observed_native_flag=mutation.observed_native_flag,
            evidence_digest=mutation.evidence_digest,
            message_id_digest=mutation.message_id_digest,
            snapshot_id=mutation.snapshot_id,
        )

    @staticmethod
    def _semantic_for_native(provider: str, native_index: int) -> FlagColor:
        from core.flag_workflow import _native_validator_for
        return _native_validator_for(provider)(native_index)

    @staticmethod
    def _native_for_semantic(provider: str, color: FlagColor) -> int:
        if provider != "mailapp":
            raise FlagWorkflowError(
                f"no native writer for provider {provider!r}")
        from providers.flag_codecs import mailapp_index_from_flag
        return mailapp_index_from_flag(color)   # KeyError for UNKNOWN

    def _record_dispatch_drift(
            self, mutation: PlannedMutation,
            drift: ProviderNativeStateDrift,
            expected_state: FlagColor) -> None:
        """Persist a same-call compare-and-set refusal as a human override."""
        observed_state = FlagColor.UNKNOWN.value
        if drift.observed_native is not None:
            observed_state = self._semantic_for_native(
                mutation.provider, drift.observed_native
            ).value
        self.overrides.detect_override(
            mutation.ref_digest,
            automation_expected_state=expected_state.value,
            human_observed_state=observed_state,
        )

    def _txid(self, plan_hash: str, mutation: PlannedMutation,
              approval: ApprovalReceipt) -> str:
        return "tx-" + sha256_hex({
            "plan": plan_hash,
            "approval": approval.content_hash,
            "mutation": mutation.mutation_id,
        })[:24]

    def _resolve_live(self, provider: Any,
                      ref: MessageReference) -> MessageReference:
        """Fresh qualified read: evidence + native + semantic in one shot."""
        return provider.resolve_scoped(ref)

    # -- preflight ------------------------------------------------------------------

    def preflight_one(self, provider: Any, plan: Dict[str, Any],
                      mutation: PlannedMutation,
                      approval: ApprovalReceipt) -> Optional[str]:
        """Return None when the target is clear to write, else an error code.

        Checks (review order): bindings -> live state -> structural gates.
        """
        # Structural gates FIRST — no provider contact needed to refuse.
        try:
            validate_planned_mutation_contract(
                mutation,
                policy_sha256=require_hex256(
                    plan.get("policy_sha256"), "plan.policy_sha256"
                ),
                snapshot_sha256=require_hex256(
                    plan.get("snapshot_sha256"), "plan.snapshot_sha256"
                ),
            )
        except FlagWorkflowError:
            return "mutation_contract_invalid"
        if mutation.auto_eligible is not True:
            return "not_auto_eligible"
        if mutation.review_required is not False:
            return "review_required"
        if mutation.proposed_flag == FlagColor.UNKNOWN:
            return "proposed_unknown_not_writable"
        if mutation.snapshot_id != plan.get("snapshot_id"):
            return "snapshot_binding_mismatch"
        if plan.get("policy_sha256") and \
                approval.policy_sha256 != plan["policy_sha256"]:
            return "policy_mismatch"
        try:
            if self.overrides.is_suppressed(mutation.ref_digest):
                return "human_override_suppressed"
        except FlagWorkflowError:
            return "override_state_unusable"
        if mutation.evidence_digest is None:
            return "no_durable_evidence"

        # Durable reference validity + exact live-state verification.
        try:
            ref = self._ref_for(mutation)
            ref.validate_scoped()
        except Exception:
            return "invalid_reference_scope"

        try:
            live = self._resolve_live(provider, ref)
        except Exception:
            return "resolve_failed"

        if live.evidence_digest != mutation.evidence_digest:
            return "evidence_drift"
        # NATIVE INDEX COMPARISON — explicit None checks ONLY. Mail.app RED
        # is native index 0; truthiness (`x or -999`) would treat a live or
        # bound RED as "missing" and structurally block every legacy red.
        expected_native = mutation.observed_native_flag
        if expected_native is None:
            return "missing_observed_native_flag"
        if live.observed_native_flag is None:
            return "native_flag_unavailable"
        if int(live.observed_native_flag) != int(expected_native):
            return "native_flag_drift"
        live_semantic = self._semantic_for_native(
            mutation.provider, int(live.observed_native_flag))
        if live_semantic != mutation.observed_flag:
            return "semantic_flag_drift"
        return None

    # -- apply ------------------------------------------------------------------------

    def apply_transaction(self, *, plan: Dict[str, Any],
                          approval: ApprovalReceipt,
                          provider: Any) -> ApplyResult:
        """Execute the approved subset as one all-or-zero-preflight batch.

        EXECUTABLE MUTATIONS ARE DERIVED FROM THE PLAN ITSELF (Commit 6d):
        callers cannot supply detached PlannedMutation objects — everything
        the engine touches is parsed from the hash-committed artifact, so
        execution data is always exactly what ``plan_hash`` commits.
        """
        plan_hash = plan.get("plan_hash")
        require_hex256(plan_hash, "plan.plan_hash")
        # Plan integrity re-check inside the engine (defense vs callers that
        # skipped schema validation).
        if compute_plan_hash(plan) != plan_hash:
            raise FlagWorkflowError("plan_hash mismatch — plan was tampered")

        lock_path = (self.state_dir / "locks" /
                     f"apply-{plan_hash[:16]}.lock")
        try:
            with AdvisoryFileLock(lock_path):
                return self._apply_locked(plan, plan_hash, approval,
                                          provider)
        except TransactionLocked:
            return ApplyResult(status="already_claimed", writes_performed=0,
                               error_code="lock_held_elsewhere")
        except (LedgerCorrupted, PrivateStateUnusable) as e:
            # Corrupt local state must BLOCK — never masquerade as fresh
            # history. Every post-dispatch persistence site is handled inside
            # the write loop with its live progress object; reaching this
            # outer handler therefore means no provider write crossed dispatch.
            return ApplyResult(status="blocked", writes_performed=0,
                               error_code=f"private_state_failure:{e}")

    def _apply_locked(self, plan: Dict[str, Any], plan_hash: str,
                      approval: ApprovalReceipt,
                      provider: Any) -> ApplyResult:
        # APPROVAL VALIDATION FIRST — inside the lock, before ledger
        # authority checks, preflight, claims, or ANY provider contact.
        # The canonical validator (ApprovalReceipt.validate) is the single
        # authority for approval rules; the engine never re-implements them.
        #
        # EXECUTABLE MUTATIONS come from the validated plan itself: parsing
        # re-runs every schema/invariant rule against hash-committed bytes,
        # so detached caller objects can never become execution authority.
        from core.flag_workflow import validate_plan_schema
        try:
            mutations = validate_plan_schema(plan)
        except FlagWorkflowError as e:
            return ApplyResult(
                status="blocked", writes_performed=0,
                blocked_reason="plan_validation_failed",
                error_code=f"plan_invalid:{e}")
        try:
            approval.validate(plan=dict(plan), plan_mutations=mutations)
        except FlagWorkflowError as e:
            # A rejected approval creates NO lifecycle records — a bad
            # approval must never leave misleading prepared/verified state.
            return ApplyResult(
                status="blocked", writes_performed=0,
                blocked_reason="approval_validation_failed",
                error_code=f"approval_invalid:{e}")

        # Validation passed: every approved id provably exists.
        by_id = {m.mutation_id: m for m in mutations}
        approved = [by_id[i] for i in approval.approved_mutation_ids]

        result = ApplyResult(status="applied")
        approval_sha = approval.content_hash
        by_id = {m.mutation_id: m for m in approved}

        # IDEMPOTENCY PASS (authority-based) + POST-ROLLBACK DOCTRINE.
        # Replay events appended here are EVENT records; they never erase
        # the authoritative verified state (P0 6b fix).
        latest_by_id = {
            m.mutation_id: self.ledger.latest_status(
                plan_hash, m.mutation_id
            )
            for m in approved
        }
        state_by_id = {
            m.mutation_id: self.ledger.authoritative_state(
                plan_hash, m.mutation_id
            )
            for m in approved
        }
        frozen_ids = [
            (m.mutation_id, latest_by_id[m.mutation_id])
            for m in approved
            if latest_by_id[m.mutation_id] in FROZEN_LATEST_STATUSES
        ]
        if frozen_ids:
            result.status = "blocked"
            result.blocked_reason = "transaction_state_frozen"
            result.error_code = "transaction_recovery_required"
            frozen_set = {mutation_id for mutation_id, _ in frozen_ids}
            result.failed.extend({
                "mutation_id": mutation_id,
                "error_code": f"transaction_frozen({status})",
            } for mutation_id, status in frozen_ids)
            for mutation in approved:
                if mutation.mutation_id in frozen_set:
                    continue
                state = state_by_id[mutation.mutation_id]
                if state == ST_VERIFIED:
                    result.already_applied.append({
                        "mutation_id": mutation.mutation_id,
                    })
                elif state == ST_ROLLED_BACK:
                    result.failed.append({
                        "mutation_id": mutation.mutation_id,
                        "error_code": "previously_rolled_back",
                    })
                else:
                    result.unattempted.append({
                        "mutation_id": mutation.mutation_id,
                    })
            return result

        try:
            suppressed_ids = [
                mutation.mutation_id
                for mutation in approved
                if self.overrides.is_suppressed(mutation.ref_digest)
            ]
        except Exception as exc:
            return ApplyResult(
                status="blocked",
                writes_performed=0,
                blocked_reason="override_state_unusable",
                error_code=f"override_state_failure:{exc}",
                unattempted=[
                    {"mutation_id": mutation.mutation_id}
                    for mutation in approved
                ],
            )
        if suppressed_ids:
            suppressed_set = set(suppressed_ids)
            result.status = "blocked"
            result.blocked_reason = "human_override_suppressed"
            result.error_code = "human_override_suppressed"
            result.failed.extend({
                "mutation_id": mutation_id,
                "error_code": "human_override_suppressed",
            } for mutation_id in suppressed_ids)
            for mutation in approved:
                if mutation.mutation_id in suppressed_set:
                    continue
                state = state_by_id[mutation.mutation_id]
                if state == ST_VERIFIED:
                    result.already_applied.append({
                        "mutation_id": mutation.mutation_id,
                    })
                elif state == ST_ROLLED_BACK:
                    result.failed.append({
                        "mutation_id": mutation.mutation_id,
                        "error_code": "previously_rolled_back",
                    })
                else:
                    result.unattempted.append({
                        "mutation_id": mutation.mutation_id,
                    })
            return result

        pending: List[PlannedMutation] = []
        rolled_back_ids: List[str] = []
        for m in approved:
            state = state_by_id[m.mutation_id]
            if state == ST_VERIFIED:
                txid = self._txid(plan_hash, m, approval)
                self.ledger.record(TransactionRecord(
                    transaction_id=txid, plan_sha256=plan_hash,
                    approval_sha256=approval_sha,
                    mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                    pre_state=None, intended_state=m.proposed_flag.value,
                    verified_post_state=None,
                    timestamp=_now(), status=ST_ALREADY_VERIFIED))
                result.already_applied.append({"mutation_id": m.mutation_id})
            elif state == ST_ROLLED_BACK:
                # A rolled-back mutation is NOT currently applied. Re-running
                # an undone migration requires a NEW plan/approval cycle —
                # deterministic refusal, zero writes.
                rolled_back_ids.append(m.mutation_id)
            else:
                pending.append(m)
        if rolled_back_ids:
            for mid in rolled_back_ids:
                self.ledger.record(TransactionRecord(
                    transaction_id=self._txid(
                        plan_hash, by_id[mid], approval),
                    plan_sha256=plan_hash, approval_sha256=approval_sha,
                    mutation_id=mid,
                    ref_digest=by_id[mid].ref_digest,
                    pre_state=None,
                    intended_state=by_id[mid].proposed_flag.value,
                    verified_post_state=None, timestamp=_now(),
                    status=ST_BLOCKED, error_code="previously_rolled_back"))
            result.status = "blocked"
            result.blocked_reason = "mutation_previously_rolled_back"
            result.error_code = "previously_rolled_back"
            result.failed.extend({"mutation_id": i,
                                  "error_code": "previously_rolled_back"}
                                 for i in rolled_back_ids)
            # A rolled-back item blocks the whole approved batch.  Pending
            # siblings were not attempted and must remain visible rather than
            # disappearing from the transaction result.
            result.unattempted.extend(
                {"mutation_id": m.mutation_id} for m in pending
            )
            for m in pending:
                self.ledger.record(TransactionRecord(
                    transaction_id=self._txid(plan_hash, m, approval),
                    plan_sha256=plan_hash,
                    approval_sha256=approval_sha,
                    mutation_id=m.mutation_id,
                    ref_digest=m.ref_digest,
                    pre_state=None,
                    intended_state=m.proposed_flag.value,
                    verified_post_state=None,
                    timestamp=_now(),
                    status=ST_FROZEN_UNATTEMPTED,
                    error_code="batch_blocked_by_previously_rolled_back",
                ))
            return result
        if not pending:
            result.status = "already_applied"
            return result

        # FULL-BATCH PREFLIGHT — all-or-zero.
        failures: List[Dict[str, Any]] = []
        pre_states: Dict[str, Optional[str]] = {}
        for m in pending:
            code = self.preflight_one(provider, plan, m, approval)
            pre_states[m.mutation_id] = code
            if code is not None:
                failures.append({"mutation_id": m.mutation_id,
                                 "error_code": code})
        if failures:
            for m in pending:
                code = pre_states[m.mutation_id]
                self.ledger.record(TransactionRecord(
                    transaction_id=self._txid(plan_hash, m, approval),
                    plan_sha256=plan_hash, approval_sha256=approval_sha,
                    mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                    pre_state=None, intended_state=m.proposed_flag.value,
                    verified_post_state=None, timestamp=_now(),
                    status=ST_BLOCKED,
                    error_code=code or "preflight_failed"))
            result.status = "blocked"
            result.blocked_reason = "batch_preflight_failed"
            result.failed = failures
            result.unattempted = [
                {"mutation_id": m.mutation_id} for m in pending
                if pre_states[m.mutation_id] is None
            ]
            return result           # writes_performed stays 0

        for m in pending:
            self.ledger.record(TransactionRecord(
                transaction_id=self._txid(plan_hash, m, approval),
                plan_sha256=plan_hash, approval_sha256=approval_sha,
                mutation_id=m.mutation_id, ref_digest=m.ref_digest,
                pre_state=m.observed_flag.value,
                intended_state=m.proposed_flag.value,
                verified_post_state=None, timestamp=_now(),
                status=ST_PREFLIGHT_PASSED))

        # WRITE PHASE — scoped methods ONLY; freeze on first non-verified.
        # ``writes_performed`` is incremented immediately when the provider
        # confirms dispatch, before readback or private-state persistence.  A
        # later proof/persistence failure must never erase that write boundary.
        remaining = list(pending)
        while remaining:
            m = remaining.pop(0)
            txid = self._txid(plan_hash, m, approval)
            ref = self._ref_for(m)
            expected_native = self._native_for_semantic(
                m.provider, m.proposed_flag)
            try:
                self.ledger.record(TransactionRecord(
                    transaction_id=txid, plan_sha256=plan_hash,
                    approval_sha256=approval_sha,
                    mutation_id=m.mutation_id,
                    ref_digest=m.ref_digest,
                    pre_state=m.observed_flag.value,
                    intended_state=m.proposed_flag.value,
                    verified_post_state=None, timestamp=_now(),
                    status=ST_APPLYING))
            except (LedgerCorrupted, PrivateStateUnusable) as exc:
                # No write for the current item crossed dispatch.  Earlier
                # verified writes, if any, remain truthfully counted.
                result.status = (
                    "ambiguous" if result.writes_performed else "blocked"
                )
                result.blocked_reason = "private_state_failure"
                result.error_code = f"private_state_failure:{exc}"
                result.unattempted.extend(
                    {"mutation_id": item.mutation_id}
                    for item in [m, *remaining]
                )
                return result

            write_counted = False
            try:
                try:
                    if m.proposed_flag == FlagColor.NO_FLAG:
                        ok = provider.clear_flag_ref(ref)
                    else:
                        ok = provider.set_flag_color_ref(
                            ref, m.proposed_flag
                        )
                except ProviderWriteAmbiguous as exc:
                    # The provider contract says dispatch occurred or may have
                    # occurred.  Count it before any attempt to persist the
                    # ambiguous outcome.
                    result.writes_performed += 1
                    write_counted = True
                    raise FlagStateAmbiguous(
                        f"provider_write_ambiguous:{exc}"
                    ) from exc
                if ok is not True:
                    # An explicit non-True return is the sole post-call signal
                    # that the provider refused the write before dispatch.
                    raise ProviderRefused("provider returned non-True")

                result.writes_performed += 1
                write_counted = True
                # MANDATORY read-after-write proof — provider True is NOT
                # success.  Any exception or mismatch after this boundary is
                # an ambiguous performed write.
                try:
                    live = self._resolve_live(provider, ref)
                    post_native_raw = live.observed_native_flag
                    if live.evidence_digest != m.evidence_digest:
                        raise FlagStateAmbiguous(
                            "evidence changed during write"
                        )
                    if post_native_raw is None or \
                            int(post_native_raw) != expected_native:
                        raise FlagStateAmbiguous(
                            f"post-write native {post_native_raw!r} != "
                            f"{expected_native}")
                    post_semantic = self._semantic_for_native(
                        m.provider, int(post_native_raw))
                    if post_semantic != m.proposed_flag:
                        raise FlagStateAmbiguous(
                            "post-write semantic mismatch"
                        )
                except FlagStateAmbiguous:
                    raise
                except Exception as exc:
                    raise FlagStateAmbiguous(
                        f"post_write_verification_failed:{exc}"
                    ) from exc
            except ProviderNativeStateDrift as exc:
                error_code = "native_flag_drift_at_dispatch"
                result.failed.append({
                    "mutation_id": m.mutation_id,
                    "status": ST_BLOCKED,
                    "error_code": error_code,
                })
                result.status = (
                    "partially_failed" if result.writes_performed else "blocked"
                )
                result.blocked_reason = "human_intervention_detected"
                result.error_code = error_code
                try:
                    self._record_dispatch_drift(m, exc, m.observed_flag)
                    self.ledger.record(TransactionRecord(
                        transaction_id=txid, plan_sha256=plan_hash,
                        approval_sha256=approval_sha,
                        mutation_id=m.mutation_id,
                        ref_digest=m.ref_digest,
                        pre_state=m.observed_flag.value,
                        intended_state=m.proposed_flag.value,
                        verified_post_state=None, timestamp=_now(),
                        status=ST_BLOCKED, error_code=error_code))
                except Exception as persist_exc:
                    result.status = (
                        "ambiguous" if result.writes_performed else "blocked"
                    )
                    result.blocked_reason = "private_state_failure"
                    result.error_code = (
                        f"private_state_failure:{persist_exc}"
                    )
                break
            except ProviderRefused as exc:
                result.failed.append({
                    "mutation_id": m.mutation_id,
                    "status": ST_BLOCKED,
                    "error_code": f"provider_refused:{exc}",
                })
                result.status = "partially_failed"
                try:
                    self.ledger.record(TransactionRecord(
                        transaction_id=txid, plan_sha256=plan_hash,
                        approval_sha256=approval_sha,
                        mutation_id=m.mutation_id,
                        ref_digest=m.ref_digest,
                        pre_state=m.observed_flag.value,
                        intended_state=m.proposed_flag.value,
                        verified_post_state=None, timestamp=_now(),
                        status=ST_BLOCKED,
                        error_code=f"provider_refused:{exc}"))
                except (LedgerCorrupted, PrivateStateUnusable) as persist_exc:
                    result.status = (
                        "ambiguous" if result.writes_performed else "blocked"
                    )
                    result.blocked_reason = "private_state_failure"
                    result.error_code = (
                        f"private_state_failure:{persist_exc}"
                    )
                break
            except FlagStateAmbiguous as exc:
                # ``FlagStateAmbiguous`` can only arise after a True return or
                # ProviderWriteAmbiguous.  Keep a belt-and-braces guard so a
                # future branch cannot accidentally report zero.
                if not write_counted:
                    result.writes_performed += 1
                    write_counted = True
                result.failed.append({
                    "mutation_id": m.mutation_id,
                    "status": ST_AMBIGUOUS,
                    "error_code": str(exc),
                })
                result.status = "ambiguous"
                result.error_code = f"write_outcome_ambiguous:{exc}"
                try:
                    self.ledger.record(TransactionRecord(
                        transaction_id=txid, plan_sha256=plan_hash,
                        approval_sha256=approval_sha,
                        mutation_id=m.mutation_id,
                        ref_digest=m.ref_digest,
                        pre_state=m.observed_flag.value,
                        intended_state=m.proposed_flag.value,
                        verified_post_state=None, timestamp=_now(),
                        status=ST_AMBIGUOUS, error_code=str(exc)))
                except (LedgerCorrupted, PrivateStateUnusable) as persist_exc:
                    result.blocked_reason = "private_state_failure"
                    result.error_code = (
                        f"private_state_failure:{persist_exc}"
                    )
                break
            except Exception as exc:                 # pre-dispatch provider failure
                result.failed.append({
                    "mutation_id": m.mutation_id,
                    "status": ST_BLOCKED,
                    "error_code": f"provider_error:{exc}",
                })
                result.status = "partially_failed"
                try:
                    self.ledger.record(TransactionRecord(
                        transaction_id=txid, plan_sha256=plan_hash,
                        approval_sha256=approval_sha,
                        mutation_id=m.mutation_id,
                        ref_digest=m.ref_digest,
                        pre_state=m.observed_flag.value,
                        intended_state=m.proposed_flag.value,
                        verified_post_state=None, timestamp=_now(),
                        status=ST_BLOCKED,
                        error_code=f"provider_error:{exc}"))
                except (LedgerCorrupted, PrivateStateUnusable) as persist_exc:
                    result.status = (
                        "ambiguous" if result.writes_performed else "blocked"
                    )
                    result.blocked_reason = "private_state_failure"
                    result.error_code = (
                        f"private_state_failure:{persist_exc}"
                    )
                break

            # Provider proof succeeded, but the transaction is not complete
            # until BOTH override state and final ledger authority are durable.
            # This one row preserves verified authority (so a recovery never
            # repeats the provider write) while its latest-state status freezes
            # apply/rollback until the private store is also durable.
            try:
                self.ledger.record(TransactionRecord(
                    transaction_id=txid,
                    plan_sha256=plan_hash,
                    approval_sha256=approval_sha,
                    mutation_id=m.mutation_id,
                    ref_digest=m.ref_digest,
                    pre_state=m.observed_flag.value,
                    intended_state=m.proposed_flag.value,
                    verified_post_state=m.proposed_flag.value,
                    timestamp=_now(),
                    status=ST_VERIFIED_PENDING_PRIVATE_STATE,
                    error_code="override_state_pending",
                ))
            except (LedgerCorrupted, PrivateStateUnusable) as exc:
                result.failed.append({
                    "mutation_id": m.mutation_id,
                    "status": ST_AMBIGUOUS,
                    "error_code": f"verified_ledger_failure:{exc}",
                })
                result.status = "ambiguous"
                result.blocked_reason = "private_state_failure"
                result.error_code = f"private_state_failure:{exc}"
                break
            try:
                # Record automation post-state WITHOUT ever clearing
                # overrides (unlock-only contract lives in OverrideStore).
                self.overrides.record_automation_state(
                    m.ref_digest, m.proposed_flag.value, True)
            except Exception as exc:
                try:
                    self.ledger.record(TransactionRecord(
                        transaction_id=txid,
                        plan_sha256=plan_hash,
                        approval_sha256=approval_sha,
                        mutation_id=m.mutation_id,
                        ref_digest=m.ref_digest,
                        pre_state=m.observed_flag.value,
                        intended_state=m.proposed_flag.value,
                        verified_post_state=m.proposed_flag.value,
                        timestamp=_now(),
                        status=ST_AMBIGUOUS,
                        error_code=f"override_state_failure:{exc}",
                    ))
                except (LedgerCorrupted, PrivateStateUnusable):
                    # The pending-private-state row remains the durable freeze
                    # marker and verified authority anchor.
                    pass
                result.failed.append({
                    "mutation_id": m.mutation_id,
                    "status": ST_AMBIGUOUS,
                    "error_code": f"override_state_failure:{exc}",
                })
                result.status = "ambiguous"
                result.blocked_reason = "private_state_failure"
                result.error_code = f"override_state_failure:{exc}"
                break
            try:
                self.ledger.record(TransactionRecord(
                    transaction_id=txid, plan_sha256=plan_hash,
                    approval_sha256=approval_sha,
                    mutation_id=m.mutation_id,
                    ref_digest=m.ref_digest,
                    pre_state=m.observed_flag.value,
                    intended_state=m.proposed_flag.value,
                    verified_post_state=m.proposed_flag.value,
                    timestamp=_now(), status=ST_VERIFIED))
            except (LedgerCorrupted, PrivateStateUnusable) as exc:
                result.failed.append({
                    "mutation_id": m.mutation_id,
                    "status": ST_AMBIGUOUS,
                    "error_code": f"verified_ledger_failure:{exc}",
                })
                result.status = "ambiguous"
                result.blocked_reason = "private_state_failure"
                result.error_code = f"private_state_failure:{exc}"
                break
            result.verified.append({
                "mutation_id": m.mutation_id,
                "transaction_id": txid,
                "verified_post_state": m.proposed_flag.value,
            })

        # Honest remainder accounting after any mid-batch freeze.  Populate
        # the result before attempting ledger writes so a second persistence
        # failure cannot make pending mutations disappear.
        if result.status in {"partially_failed", "ambiguous", "blocked"}:
            result.unattempted.extend(
                {"mutation_id": m.mutation_id} for m in remaining)
            for m in remaining:
                try:
                    self.ledger.record(TransactionRecord(
                        transaction_id=self._txid(plan_hash, m, approval),
                        plan_sha256=plan_hash,
                        approval_sha256=approval_sha,
                        mutation_id=m.mutation_id,
                        ref_digest=m.ref_digest,
                        pre_state=None,
                        intended_state=m.proposed_flag.value,
                        verified_post_state=None,
                        timestamp=_now(),
                        status=ST_FROZEN_UNATTEMPTED,
                        error_code="batch_frozen_after_failure"))
                except (LedgerCorrupted, PrivateStateUnusable) as exc:
                    result.status = (
                        "ambiguous" if result.writes_performed else "blocked"
                    )
                    result.blocked_reason = "private_state_failure"
                    result.error_code = f"private_state_failure:{exc}"
                    break
        return result

    # -- rollback -----------------------------------------------------------------
    # Rollback lives in ScopedRollbackEngine: receipts store ONLY digests +
    # native/semantic states (PII-free), so scope recovery requires the
    # private plan's durable bindings, supplied at engine construction.


class ScopedRollbackEngine(TransactionEngine):
    """Rollback bound to the IMMUTABLE PLAN (Commit 6d).

    The receipt intentionally stores only digests + native/semantic states
    (PII-free). Scope reconstruction parses executable mutations FROM the
    hash-committed plan on every rollback — never from a free-standing
    caller-supplied mutation list. Plan integrity is re-verified under the
    lock before anything else.
    """

    def __init__(self, state_dir: Path, ledger: TransactionLedger,
                 overrides: Any, plan: Dict[str, Any]):
        super().__init__(state_dir, ledger, overrides)
        self._plan = dict(plan)

    def _mutations_by_id(self) -> Dict[str, PlannedMutation]:
        from core.flag_workflow import validate_plan_schema
        if compute_plan_hash(self._plan) != self._plan.get("plan_hash"):
            raise FlagWorkflowError(
                "rollback plan_hash mismatch — plan artifact tampered")
        return {m.mutation_id: m for m in validate_plan_schema(self._plan)}

    @staticmethod
    def _can_defer_receipt_validation(
        receipt: TransactionRollbackReceipt,
        error: FlagWorkflowError,
    ) -> bool:
        """Allow safe lineage comparison for self-consistent forgeries.

        Strict receipt validation remains the artifact contract.  The engine
        may nevertheless classify a correctly re-hashed receipt whose fields
        disagree with one another or whose transaction ID is noncanonical,
        provided every value needed to find authoritative plan/ledger state is
        still typed and path-safe.  Byte tampering, traversal-shaped IDs, and
        all other malformed receipts continue to raise before state access.
        """
        detail = str(error)
        if not (
            "native/semantic flag mismatch" in detail
            or "rollback.transaction_id must match" in detail
        ):
            return False
        try:
            if receipt.content_hash != receipt.to_dict()["content_hash"]:
                return False
            if receipt.schema != ROLLBACK_TX_SCHEMA:
                return False
            require_hex256(receipt.plan_sha256, "rollback.plan_sha256")
            require_hex256(receipt.approval_sha256, "rollback.approval_sha256")
            require_hex256(receipt.ref_digest, "rollback.ref_digest")
            _require_prefixed_hex_id(
                receipt.rollback_id,
                "rollback.rollback_id",
                prefix="rbx-",
                hex_length=32,
            )
            _require_prefixed_hex_id(
                receipt.mutation_id,
                "rollback.mutation_id",
                prefix="mut-",
                hex_length=24,
            )
            transaction_id = receipt.transaction_id
            if (
                not isinstance(transaction_id, str)
                or not transaction_id
                or len(transaction_id) > 128
                or any(
                    not char.isascii()
                    or not (char.isalnum() or char in "._-")
                    for char in transaction_id
                )
            ):
                return False
            for native in (
                receipt.pre_native_flag,
                receipt.applied_native_flag,
            ):
                if isinstance(native, bool) or not isinstance(native, int):
                    return False
            for semantic in (
                receipt.pre_semantic_flag,
                receipt.applied_semantic_flag,
            ):
                if FlagColor(semantic) is FlagColor.UNKNOWN:
                    return False
            created = datetime.fromisoformat(receipt.created_at)
            if created.tzinfo is None or created.utcoffset() is None:
                return False
        except (FlagWorkflowError, TypeError, ValueError):
            return False
        return True

    def rollback_transaction(self, *, receipt: TransactionRollbackReceipt,
                             provider: Any) -> RollbackResult:
        try:
            receipt.validate()
        except FlagWorkflowError as exc:
            if not self._can_defer_receipt_validation(receipt, exc):
                raise
        # MUTUAL EXCLUSION (Commit 7, Group I): rollback must never race an
        # active apply on the same plan. Take the APPLY lock for the plan
        # FIRST; only then the rollback-specific lock.
        apply_lock_path = (self.state_dir / "locks" /
                           f"apply-{receipt.plan_sha256[:16]}.lock")
        rb_lock_path = (self.state_dir / "locks" /
                        f"rb-{receipt.transaction_id[:16]}.lock")
        try:
            with AdvisoryFileLock(apply_lock_path), \
                    AdvisoryFileLock(rb_lock_path):
                return self._scoped_rollback_locked(receipt, provider)
        except TransactionLocked:
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code="apply_in_progress_or_locked")
        except (LedgerCorrupted, PrivateStateUnusable) as e:
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code=f"private_state_failure:{e}")

    def _ambiguous_rollback_result(
            self, receipt: TransactionRollbackReceipt,
            error_code: str) -> RollbackResult:
        """Persist and report a rollback that crossed the write boundary."""
        try:
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=receipt.applied_semantic_flag,
                intended_state=receipt.pre_semantic_flag,
                verified_post_state=None,
                timestamp=_now(),
                status=ST_ROLLBACK_PENDING,
                error_code=error_code,
            ))
        except (LedgerCorrupted, PrivateStateUnusable) as exc:
            error_code = f"{error_code};private_state_failure:{exc}"
        return RollbackResult(
            status="ambiguous",
            writes_performed=1,
            error_code=error_code,
        )

    def _scoped_rollback_locked(
            self, receipt: TransactionRollbackReceipt,
            provider: Any) -> RollbackResult:
        latest = self.ledger.latest_status(receipt.plan_sha256,
                                           receipt.mutation_id)
        if latest in FROZEN_LATEST_STATUSES:
            return RollbackResult(
                status="blocked",
                writes_performed=0,
                error_code=f"transaction_frozen({latest})",
            )
        # Idempotency on AUTHORITATIVE state: already rolled back →
        # ZERO-write no-op. Replay/event rows can never flip this.
        state = self.ledger.authoritative_state(receipt.plan_sha256,
                                                receipt.mutation_id)
        if state == ST_ROLLED_BACK:
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=receipt.pre_semantic_flag,
                intended_state=receipt.pre_semantic_flag,
                verified_post_state=receipt.pre_semantic_flag,
                timestamp=_now(), status=ST_ROLLED_BACK,
                error_code="idempotent_noop"))
            return RollbackResult(status="already_rolled_back",
                                  writes_performed=0)
        if state != ST_VERIFIED:
            return RollbackResult(
                status="blocked", writes_performed=0,
                error_code=f"transaction_not_verified({state})")

        # ---------------------------------------------------------------
        # LINEAGE BINDING: the receipt is SELF-integrity only (SHA-256 is
        # integrity, NOT authentication — anyone can recompute a hash).
        # Authoritative truth is reconstructed from the immutable
        # PlannedMutation + the ledger's VERIFIED record; every receipt
        # field must MATCH that record or rollback refuses with ZERO
        # writes. Receipt fields are informational from here on.
        # ---------------------------------------------------------------
        rec = self.ledger.latest_authoritative_record(
            receipt.plan_sha256, receipt.mutation_id)
        try:
            by_id = self._mutations_by_id()
        except FlagWorkflowError as e:
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code=f"rollback_plan_invalid:{e}")
        mutation = by_id.get(receipt.mutation_id)
        expected_applied_native = self._native_for_semantic(
            mutation.provider, mutation.proposed_flag) \
            if mutation else None
        lineage_expectations = {
            "transaction_id": (receipt.transaction_id,
                               rec.get("transaction_id") if rec else None),
            "plan_sha256": (receipt.plan_sha256, receipt.plan_sha256),
            "approval_sha256": (receipt.approval_sha256,
                                rec.get("approval_sha256") if rec else None),
            "mutation_id": (receipt.mutation_id,
                            receipt.mutation_id),
            "ref_digest": (receipt.ref_digest,
                           mutation.ref_digest if mutation else None),
            "pre_semantic_flag": (receipt.pre_semantic_flag,
                                  mutation.observed_flag.value
                                  if mutation else None),
            "pre_native_flag": (
                receipt.pre_native_flag,
                mutation.observed_native_flag if mutation else None),
            "applied_semantic_flag": (
                receipt.applied_semantic_flag,
                mutation.proposed_flag.value if mutation else None),
            "applied_native_flag": (
                receipt.applied_native_flag, expected_applied_native),
            "ledger_status": (
                rec.get("status") if rec else None, ST_VERIFIED),
            "ledger_ref_digest": (
                rec.get("ref_digest") if rec else None,
                mutation.ref_digest if mutation else None),
            "ledger_pre_state": (
                rec.get("pre_state") if rec else None,
                mutation.observed_flag.value if mutation else None),
            "ledger_intended_state": (
                rec.get("intended_state") if rec else None,
                mutation.proposed_flag.value if mutation else None),
            "ledger_verified_post_state": (
                rec.get("verified_post_state") if rec else None,
                mutation.proposed_flag.value if mutation else None),
        }
        for field_name, (got, expected) in lineage_expectations.items():
            if got != expected:
                # The audit row itself is anchored to authoritative lineage,
                # never copied from the forged receipt that triggered it.
                if rec is not None and mutation is not None:
                    self.ledger.record(TransactionRecord(
                        transaction_id=rec["transaction_id"],
                        plan_sha256=rec["plan_sha256"],
                        approval_sha256=rec["approval_sha256"],
                        mutation_id=rec["mutation_id"],
                        ref_digest=mutation.ref_digest,
                        pre_state=None,
                        intended_state=mutation.observed_flag.value,
                        verified_post_state=None,
                        timestamp=_now(),
                        status=ST_ROLLBACK_BLOCKED,
                        error_code=(
                            f"receipt_lineage_mismatch:{field_name}"
                        ),
                    ))
                return RollbackResult(
                    status="blocked", writes_performed=0,
                    error_code=f"receipt_lineage_mismatch:{field_name}")
        # Narrow for mypy: a None mutation would have failed ref_digest
        # lineage above.
        if mutation is None:  # pragma: no cover
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code="receipt_lineage_mismatch:mutation")

        # UNLOCK-ONLY OVERRIDE CONTRACT applies to rollback too.  Once a
        # human intervention suppresses a reference, merely changing the live
        # color back to the automation-applied value cannot silently restore
        # our authority; only an explicit OverrideStore.unlock may do so.
        try:
            if self.overrides.is_suppressed(mutation.ref_digest):
                return RollbackResult(
                    status="rollback_blocked_by_override",
                    writes_performed=0,
                    error_code="human_override_suppressed",
                )
        except Exception as exc:
            return RollbackResult(
                status="blocked",
                writes_performed=0,
                error_code=f"override_state_failure:{exc}",
            )

        # DERIVED truth (never receipt fields) drives the write target and
        # the current-state gate:
        prior_color = mutation.observed_flag
        expected_applied_native = self._native_for_semantic(
            mutation.provider, mutation.proposed_flag)

        ref = self._ref_for(mutation)
        try:
            live = self._resolve_live(provider, ref)
        except Exception as e:
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=receipt.pre_semantic_flag,
                intended_state=receipt.pre_semantic_flag,
                verified_post_state=None, timestamp=_now(),
                status=ST_ROLLBACK_BLOCKED,
                error_code=f"resolve_failed:{e}"))
            return RollbackResult(status="blocked", writes_performed=0,
                                  error_code="resolve_failed")

        current_native = live.observed_native_flag
        # OVERRIDE-SAFETY: current MUST equal the DERIVED applied state
        # (mutation.proposed_flag via provider codec) — never the receipt's
        # self-asserted applied state. A human having touched the message
        # since means we must NOT clobber their choice with the old color.
        if current_native is None or \
                int(current_native) != int(expected_applied_native):
            applied_semantic_derived = self._semantic_for_native(
                mutation.provider, int(expected_applied_native)).value
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=applied_semantic_derived,
                intended_state=prior_color.value,
                verified_post_state=(
                    self._semantic_for_native(
                        mutation.provider, int(current_native)).value
                    if current_native is not None else None),
                timestamp=_now(), status=ST_ROLLBACK_BLOCKED,
                error_code="human_intervention_detected"))
            # Persist detection as a suppression so future preflight refuses.
            observed_semantic = (
                self._semantic_for_native(
                    mutation.provider, int(current_native)).value
                if current_native is not None else "unknown_unknown")
            try:
                self.overrides.detect_override(
                    mutation.ref_digest,
                    automation_expected_state=applied_semantic_derived,
                    human_observed_state=observed_semantic)
            except Exception as exc:
                return RollbackResult(
                    status="blocked",
                    writes_performed=0,
                    error_code=f"override_state_failure:{exc}",
                )
            return RollbackResult(
                status="rollback_blocked_by_override", writes_performed=0,
                error_code="human_intervention_detected")

        expected_prior_native = self._native_for_semantic(
            mutation.provider, prior_color)
        # The provider compare-and-set contract reads the expected CURRENT
        # native state from the reference.  For rollback that state is the
        # automation-applied value, not the plan's original observation.
        rollback_ref = replace(
            ref, observed_native_flag=expected_applied_native
        )
        # Durable pre-dispatch claim: a process death after provider dispatch
        # but before proof leaves this as the latest row, so retry freezes with
        # zero further writes instead of dispatching the rollback twice.
        self.ledger.record(TransactionRecord(
            transaction_id=receipt.transaction_id,
            plan_sha256=receipt.plan_sha256,
            approval_sha256=receipt.approval_sha256,
            mutation_id=receipt.mutation_id,
            ref_digest=receipt.ref_digest,
            pre_state=receipt.applied_semantic_flag,
            intended_state=receipt.pre_semantic_flag,
            verified_post_state=None,
            timestamp=_now(),
            status=ST_ROLLBACK_PENDING,
            error_code="rollback_dispatch_pending",
        ))
        try:
            if prior_color == FlagColor.NO_FLAG:
                ok = provider.clear_flag_ref(rollback_ref)
            else:
                ok = provider.set_flag_color_ref(rollback_ref, prior_color)
        except ProviderNativeStateDrift as exc:
            error_code = "human_intervention_detected_at_dispatch"
            try:
                self._record_dispatch_drift(
                    mutation, exc, mutation.proposed_flag
                )
                self.ledger.record(TransactionRecord(
                    transaction_id=receipt.transaction_id,
                    plan_sha256=receipt.plan_sha256,
                    approval_sha256=receipt.approval_sha256,
                    mutation_id=receipt.mutation_id,
                    ref_digest=receipt.ref_digest,
                    pre_state=receipt.applied_semantic_flag,
                    intended_state=receipt.pre_semantic_flag,
                    verified_post_state=None,
                    timestamp=_now(),
                    status=ST_ROLLBACK_BLOCKED,
                    error_code=error_code,
                ))
            except Exception as persist_exc:
                return RollbackResult(
                    status="blocked", writes_performed=0,
                    error_code=f"private_state_failure:{persist_exc}",
                )
            return RollbackResult(
                status="rollback_blocked_by_override",
                writes_performed=0,
                error_code=error_code,
            )
        except ProviderWriteAmbiguous as exc:
            return self._ambiguous_rollback_result(
                receipt, f"provider_write_ambiguous:{exc}"
            )
        except Exception as exc:
            try:
                self.ledger.record(TransactionRecord(
                    transaction_id=receipt.transaction_id,
                    plan_sha256=receipt.plan_sha256,
                    approval_sha256=receipt.approval_sha256,
                    mutation_id=receipt.mutation_id,
                    ref_digest=receipt.ref_digest,
                    pre_state=receipt.applied_semantic_flag,
                    intended_state=receipt.pre_semantic_flag,
                    verified_post_state=None,
                    timestamp=_now(),
                    status=ST_ROLLBACK_BLOCKED,
                    error_code=f"provider_error:{exc}",
                ))
            except (LedgerCorrupted, PrivateStateUnusable) as persist_exc:
                return RollbackResult(
                    status="blocked",
                    writes_performed=0,
                    error_code=f"private_state_failure:{persist_exc}",
                )
            return RollbackResult(
                status="blocked",
                writes_performed=0,
                error_code=f"provider_error:{exc}",
            )

        if ok is not True:
            try:
                self.ledger.record(TransactionRecord(
                    transaction_id=receipt.transaction_id,
                    plan_sha256=receipt.plan_sha256,
                    approval_sha256=receipt.approval_sha256,
                    mutation_id=receipt.mutation_id,
                    ref_digest=receipt.ref_digest,
                    pre_state=receipt.applied_semantic_flag,
                    intended_state=receipt.pre_semantic_flag,
                    verified_post_state=None,
                    timestamp=_now(),
                    status=ST_ROLLBACK_BLOCKED,
                    error_code="provider_refused:provider returned non-True",
                ))
            except (LedgerCorrupted, PrivateStateUnusable) as exc:
                return RollbackResult(
                    status="blocked",
                    writes_performed=0,
                    error_code=f"private_state_failure:{exc}",
                )
            return RollbackResult(
                status="blocked",
                writes_performed=0,
                error_code="provider_refused:provider returned non-True",
            )

        # ``True`` means dispatch crossed the write boundary.  Everything
        # below can only prove the rollback, never restore a zero-write claim.
        try:
            live2 = self._resolve_live(provider, ref)
            if live2.evidence_digest != mutation.evidence_digest:
                raise FlagStateAmbiguous(
                    "evidence changed during rollback"
                )
            if live2.observed_native_flag is None or \
                    int(live2.observed_native_flag) != expected_prior_native:
                raise FlagStateAmbiguous("post-rollback native mismatch")
        except FlagStateAmbiguous as exc:
            return self._ambiguous_rollback_result(receipt, str(exc))
        except Exception as exc:
            return self._ambiguous_rollback_result(
                receipt, f"post_rollback_verification_failed:{exc}"
            )

        try:
            self.ledger.record(TransactionRecord(
                transaction_id=receipt.transaction_id,
                plan_sha256=receipt.plan_sha256,
                approval_sha256=receipt.approval_sha256,
                mutation_id=receipt.mutation_id,
                ref_digest=receipt.ref_digest,
                pre_state=receipt.applied_semantic_flag,
                intended_state=receipt.pre_semantic_flag,
                verified_post_state=receipt.pre_semantic_flag,
                timestamp=_now(), status=ST_ROLLED_BACK))
        except (LedgerCorrupted, PrivateStateUnusable) as exc:
            return self._ambiguous_rollback_result(
                receipt, f"rollback_ledger_failure:{exc}"
            )
        return RollbackResult(status="rolled_back", writes_performed=1,
                              restored_native_flag=expected_prior_native)


class FlagStateAmbiguous(Exception):
    """Write executed but post-write verification could not prove success."""


class ProviderRefused(Exception):
    """Provider explicitly reports the mutation did NOT happen (False)."""
