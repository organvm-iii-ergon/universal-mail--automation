"""Canary-only production boundary for the Mail.app flag transaction engine.

The generic transaction engine remains reusable for adversarial tests.  This
module is the much narrower production contract: one complete snapshot-derived
plan, one explicit approval, one Mail.app surface, and one to three targets.
"""

from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.flag_transactions import (
    BatchRollbackResult,
    ScopedRollbackEngine,
    TransactionEngine,
    TransactionLedger,
    TransactionRollbackReceipt,
    transaction_id_for,
)
from core.flag_workflow import (
    ApprovalReceipt,
    FlagSnapshot,
    FlagWorkflowError,
    OverrideStore,
    PlannedMutation,
    PURPOSE_ACTIVATION_CANARY,
    PURPOSE_MIGRATION,
    SELECTION_SOURCE_AUTOMATIC,
    SELECTION_SOURCE_HUMAN_CANARY,
    _atomic_write_private_json,
    _json_object_from_path,
    load_approval,
    load_plan,
    load_snapshot,
    require_hex256,
    sha256_hex,
    validate_plan_snapshot_lineage,
    write_private_approval,
    write_private_plan,
    write_private_snapshot,
)
from providers.flag_codecs import mailapp_index_from_flag

FIRST_ACTIVATION_CANARY_MIN = 1
FIRST_ACTIVATION_CANARY_MAX = 3
CANARY_ROLLBACK_BUNDLE_SCHEMA = "uma.flags.canary.rollback_bundle.v2"


def _filesystem_fold(path: Path) -> str:
    """Conservative macOS-safe spelling for collision comparison."""
    return unicodedata.normalize("NFD", os.fspath(path)).casefold()


def _resolved_or_absolute(path: Path) -> Path:
    """Resolve existing aliases, falling back to an absolute lexical path."""
    candidate = Path(path).expanduser()
    try:
        return candidate.resolve(strict=False)
    except OSError:
        return Path(os.path.abspath(os.fspath(candidate)))


def _path_within(path: Path, directory: Path) -> bool:
    """Return whether *path* is conservatively inside *directory* on macOS."""
    candidate_folded = _filesystem_fold(_resolved_or_absolute(path))
    directory_folded = _filesystem_fold(_resolved_or_absolute(directory))
    try:
        return os.path.commonpath([
            candidate_folded, directory_folded,
        ]) == directory_folded
    except ValueError:
        return False


def _canary_id_for(
        plan_sha256: str, approval_sha256: str,
        mutation_ids: List[str]) -> str:
    """Return the canonical id for one exact approved activation set."""
    require_hex256(plan_sha256, "canary.plan_sha256")
    require_hex256(approval_sha256, "canary.approval_sha256")
    if not isinstance(mutation_ids, list) or not mutation_ids:
        raise FlagWorkflowError(
            "canary mutation_ids must be a non-empty list"
        )
    if not all(isinstance(value, str) and value for value in mutation_ids):
        raise FlagWorkflowError(
            "canary mutation_ids must contain non-empty strings"
        )
    return "canary-" + sha256_hex({
        "plan_sha256": plan_sha256,
        "approval_sha256": approval_sha256,
        "mutation_ids": sorted(mutation_ids),
    })[:32]


def default_flags_state_dir() -> Path:
    """Return the private flag-workflow state root."""
    return Path(
        os.environ.get(
            "UMA_FLAGS_STATE_DIR",
            str(Path.home() / ".local" / "share" / "uma" / "flags"),
        )
    ).expanduser()


def _paths_alias(left: Path, right: Path) -> bool:
    """Return whether two artifact paths name the same filesystem target."""
    left_path = Path(left).expanduser()
    right_path = Path(right).expanduser()
    try:
        if left_path.exists() and right_path.exists() \
                and os.path.samefile(left_path, right_path):
            return True
    except OSError:
        pass
    left_resolved = _resolved_or_absolute(left_path)
    right_resolved = _resolved_or_absolute(right_path)
    return (
        left_resolved == right_resolved
        or _filesystem_fold(left_resolved)
        == _filesystem_fold(right_resolved)
    )


def validate_canary_output_paths(
        *, activation: "CanaryActivation",
        bundle: "CanaryRollbackBundle",
        state_dir: Path,
        plan_input: Path,
        snapshot_input: Path,
        approval_input: Path,
        receipt_output: Optional[Path],
        proposal_output: Optional[Path]) -> Path:
    """Reject output aliases before any activation artifact is replaced.

    The provider is constructed only after this check.  A proposal can never
    overwrite rollback authority, and neither optional output can replace an
    input or a managed plan/snapshot/approval artifact.
    """
    root = Path(state_dir).expanduser()
    canonical_rollback_path = (
        root / "receipts" / f"{bundle.canary_id}.json"
    )
    rollback_path = (
        Path(receipt_output).expanduser()
        if receipt_output is not None
        else canonical_rollback_path
    )
    if proposal_output is not None and _path_within(
            Path(proposal_output), root):
        raise FlagWorkflowError(
            "proposal output aliases the managed state directory and is "
            "forbidden"
        )
    if receipt_output is not None and _path_within(rollback_path, root) \
            and not _paths_alias(
                rollback_path, canonical_rollback_path
            ):
        raise FlagWorkflowError(
            "receipt output inside managed state must be the current "
            "canary's canonical rollback destination"
        )
    protected = {
        "input plan": Path(plan_input).expanduser(),
        "input snapshot": Path(snapshot_input).expanduser(),
        "input approval": Path(approval_input).expanduser(),
        "managed plan": root / "plans" / f"{activation.plan_hash}.json",
        "managed snapshot": (
            root / "snapshots" / f"{activation.snapshot.snapshot_id}.json"
        ),
        "managed approval": (
            root / "approvals" /
            f"{activation.approval.content_hash}.json"
        ),
        "transaction ledger": root / "ledger" / "transactions.jsonl",
        "override store": root / "overrides.json",
    }
    outputs = {"rollback output": rollback_path}
    if proposal_output is not None:
        outputs["proposal output"] = Path(proposal_output).expanduser()

    for output_label, output_path in outputs.items():
        for protected_label, protected_path in protected.items():
            if _paths_alias(output_path, protected_path):
                raise FlagWorkflowError(
                    f"{output_label} aliases {protected_label}"
                )
    if proposal_output is not None and _paths_alias(
        rollback_path, Path(proposal_output).expanduser()
    ):
        raise FlagWorkflowError(
            "proposal output aliases rollback output"
        )
    return rollback_path


@dataclass(frozen=True)
class CanaryActivation:
    """Fully validated activation artifacts and their approved subset."""

    plan: Dict[str, Any]
    snapshot: FlagSnapshot
    approval: ApprovalReceipt
    mutations: List[PlannedMutation]
    selected: List[PlannedMutation]
    cli_limit: int

    @property
    def plan_hash(self) -> str:
        return str(self.plan["plan_hash"])

    @property
    def scope(self) -> tuple[str, str, str]:
        first = self.selected[0]
        return first.provider, first.account, first.mailbox


@dataclass
class CanaryRollbackBundle:
    """One deterministic, private rollback intent for the whole canary."""

    schema: str
    canary_id: str
    plan_sha256: str
    snapshot_sha256: str
    policy_sha256: str
    approval_sha256: str
    selection_source: str
    purpose: str
    manual_canary: bool
    created_at: str
    receipts: List[TransactionRollbackReceipt] = field(default_factory=list)
    content_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        body = {
            "schema": self.schema,
            "canary_id": self.canary_id,
            "plan_sha256": self.plan_sha256,
            "snapshot_sha256": self.snapshot_sha256,
            "policy_sha256": self.policy_sha256,
            "approval_sha256": self.approval_sha256,
            "selection_source": self.selection_source,
            "purpose": self.purpose,
            "manual_canary": self.manual_canary,
            "created_at": self.created_at,
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }
        body["content_hash"] = sha256_hex(body)
        return body

    def validate(self) -> None:
        if self.schema != CANARY_ROLLBACK_BUNDLE_SCHEMA:
            raise FlagWorkflowError(
                f"rollback bundle schema must be "
                f"{CANARY_ROLLBACK_BUNDLE_SCHEMA}"
            )
        if not (
            isinstance(self.canary_id, str)
            and self.canary_id.startswith("canary-")
            and len(self.canary_id) == 39
            and all(
                char in "0123456789abcdef"
                for char in self.canary_id[7:]
            )
        ):
            raise FlagWorkflowError(
                "rollback bundle canary_id must be canary-<32 lowercase hex>"
            )
        require_hex256(self.plan_sha256, "bundle.plan_sha256")
        require_hex256(self.snapshot_sha256, "bundle.snapshot_sha256")
        require_hex256(self.policy_sha256, "bundle.policy_sha256")
        require_hex256(self.approval_sha256, "bundle.approval_sha256")
        if (
            self.selection_source == SELECTION_SOURCE_AUTOMATIC
            and self.purpose == PURPOSE_MIGRATION
            and self.manual_canary is False
        ):
            pass
        elif (
            self.selection_source == SELECTION_SOURCE_HUMAN_CANARY
            and self.purpose == PURPOSE_ACTIVATION_CANARY
            and self.manual_canary is True
        ):
            pass
        else:
            raise FlagWorkflowError(
                "rollback bundle authority must be automatic migration or "
                "human activation canary"
            )
        stored = require_hex256(self.content_hash, "bundle.content_hash")
        if not isinstance(self.created_at, str) or not self.created_at:
            raise FlagWorkflowError(
                "rollback bundle created_at must be a non-empty string"
            )
        if not isinstance(self.receipts, list) or not (
            FIRST_ACTIVATION_CANARY_MIN
            <= len(self.receipts)
            <= FIRST_ACTIVATION_CANARY_MAX
        ):
            raise FlagWorkflowError(
                "rollback bundle must contain 1..3 receipts"
            )
        mutation_ids = []
        ref_digests = []
        for receipt in self.receipts:
            if not isinstance(receipt, TransactionRollbackReceipt):
                raise FlagWorkflowError(
                    "rollback bundle contains a non-receipt value"
                )
            receipt.validate()
            if receipt.plan_sha256 != self.plan_sha256:
                raise FlagWorkflowError(
                    "rollback receipt plan hash differs from bundle"
                )
            if receipt.approval_sha256 != self.approval_sha256:
                raise FlagWorkflowError(
                    "rollback receipt approval hash differs from bundle"
                )
            if receipt.created_at != self.created_at:
                raise FlagWorkflowError(
                    "rollback receipt timestamp differs from bundle"
                )
            mutation_ids.append(receipt.mutation_id)
            ref_digests.append(receipt.ref_digest)
        if len(mutation_ids) != len(set(mutation_ids)):
            raise FlagWorkflowError(
                "rollback bundle contains duplicate mutation ids"
            )
        if len(ref_digests) != len(set(ref_digests)):
            raise FlagWorkflowError(
                "rollback bundle contains duplicate references"
            )
        expected_canary_id = _canary_id_for(
            self.plan_sha256,
            self.approval_sha256,
            mutation_ids,
        )
        if self.canary_id != expected_canary_id:
            raise FlagWorkflowError(
                "rollback bundle canary_id does not match its exact "
                "activation set"
            )
        for receipt in self.receipts:
            expected_transaction_id = transaction_id_for(
                self.plan_sha256,
                receipt.mutation_id,
                self.approval_sha256,
            )
            if receipt.transaction_id != expected_transaction_id:
                raise FlagWorkflowError(
                    "rollback receipt transaction id is not canonical"
                )
        if self.to_dict()["content_hash"] != stored:
            raise FlagWorkflowError(
                "rollback bundle content_hash mismatch (tampered)"
            )

    @classmethod
    def create(cls, activation: CanaryActivation) -> "CanaryRollbackBundle":
        mutation_ids = [
            mutation.mutation_id for mutation in activation.selected
        ]
        canary_id = _canary_id_for(
            activation.plan_hash,
            activation.approval.content_hash,
            mutation_ids,
        )
        receipts = []
        for mutation in activation.selected:
            native = mutation.observed_native_flag
            if isinstance(native, bool) or not isinstance(native, int):
                raise FlagWorkflowError(
                    f"{mutation.mutation_id}: rollback pre-state is unknown"
                )
            applied_flag = activation.approval.execution_flag_for(mutation)
            receipts.append(TransactionRollbackReceipt.create(
                transaction_id=transaction_id_for(
                    activation.plan_hash,
                    mutation.mutation_id,
                    activation.approval.content_hash,
                ),
                plan_sha256=activation.plan_hash,
                approval_sha256=activation.approval.content_hash,
                mutation_id=mutation.mutation_id,
                ref_digest=mutation.ref_digest,
                pre_native_flag=native,
                pre_semantic_flag=mutation.observed_flag.value,
                applied_native_flag=mailapp_index_from_flag(
                    applied_flag
                ),
                applied_semantic_flag=applied_flag.value,
                created_at=activation.approval.issued_at,
            ))
        bundle = cls(
            schema=CANARY_ROLLBACK_BUNDLE_SCHEMA,
            canary_id=canary_id,
            plan_sha256=activation.plan_hash,
            snapshot_sha256=activation.plan["snapshot_sha256"],
            policy_sha256=activation.plan["policy_sha256"],
            approval_sha256=activation.approval.content_hash,
            selection_source=activation.approval.selection_source,
            purpose=activation.approval.purpose,
            manual_canary=activation.approval.manual_canary,
            created_at=activation.approval.issued_at,
            receipts=receipts,
        )
        bundle.content_hash = bundle.to_dict()["content_hash"]
        bundle.validate()
        return bundle

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "CanaryRollbackBundle":
        if not isinstance(raw, dict):
            raise FlagWorkflowError(
                "rollback bundle must be a JSON object"
            )
        required = {
            "schema", "canary_id", "plan_sha256", "snapshot_sha256",
            "policy_sha256", "approval_sha256", "selection_source",
            "purpose", "manual_canary", "created_at", "receipts",
            "content_hash",
        }
        missing = required.difference(raw)
        extra = set(raw).difference(required)
        if missing or extra:
            raise FlagWorkflowError(
                "rollback bundle fields mismatch: "
                f"missing={sorted(missing)}, extra={sorted(extra)}"
            )
        string_fields = required.difference({"receipts", "manual_canary"})
        for field_name in string_fields:
            if not isinstance(raw[field_name], str):
                raise FlagWorkflowError(
                    f"rollback bundle {field_name} must be a string"
                )
        receipts_raw = raw["receipts"]
        if not isinstance(receipts_raw, list):
            raise FlagWorkflowError(
                "rollback bundle receipts must be a list"
            )
        if not isinstance(raw["manual_canary"], bool):
            raise FlagWorkflowError(
                "rollback bundle manual_canary must be a boolean"
            )
        bundle = cls(
            schema=raw["schema"],
            canary_id=raw["canary_id"],
            plan_sha256=raw["plan_sha256"],
            snapshot_sha256=raw["snapshot_sha256"],
            policy_sha256=raw["policy_sha256"],
            approval_sha256=raw["approval_sha256"],
            selection_source=raw["selection_source"],
            purpose=raw["purpose"],
            manual_canary=raw["manual_canary"],
            created_at=raw["created_at"],
            receipts=[
                TransactionRollbackReceipt.from_dict(receipt)
                for receipt in receipts_raw
            ],
            content_hash=raw["content_hash"],
        )
        bundle.validate()
        return bundle


def load_canary_activation(
        *, plan_path: Path, snapshot_path: Path, approval_path: Path,
        cli_limit: int,
        require_fresh_approval: bool = True,
        human_selected: bool = False) -> CanaryActivation:
    """Load and cross-validate every apply artifact before provider use."""
    if not isinstance(require_fresh_approval, bool):
        raise FlagWorkflowError(
            "require_fresh_approval must be a boolean"
        )
    if not isinstance(human_selected, bool):
        raise FlagWorkflowError("human_selected must be a boolean")
    if (
        isinstance(cli_limit, bool)
        or not isinstance(cli_limit, int)
        or not (
            FIRST_ACTIVATION_CANARY_MIN
            <= cli_limit
            <= FIRST_ACTIVATION_CANARY_MAX
        )
    ):
        raise FlagWorkflowError("canary limit must be within [1,3]")

    snapshot = load_snapshot(Path(snapshot_path))
    plan = load_plan(Path(plan_path))
    mutations = validate_plan_snapshot_lineage(plan, snapshot)
    approval = load_approval(Path(approval_path))
    approval.validate(
        plan=dict(plan),
        plan_mutations=mutations,
        require_current_window=require_fresh_approval,
    )
    if approval.is_human_canary != human_selected:
        if approval.is_human_canary:
            raise FlagWorkflowError(
                "human activation canary requires explicit --human-selected"
            )
        raise FlagWorkflowError(
            "--human-selected requires a human activation canary approval"
        )
    if not (
        FIRST_ACTIVATION_CANARY_MIN
        <= approval.canary_limit
        <= FIRST_ACTIVATION_CANARY_MAX
    ):
        raise FlagWorkflowError(
            "approval canary_limit must be within [1,3] for first activation"
        )
    approved_ids = approval.approved_mutation_ids
    if not (
        FIRST_ACTIVATION_CANARY_MIN
        <= len(approved_ids)
        <= FIRST_ACTIVATION_CANARY_MAX
    ):
        raise FlagWorkflowError(
            "first activation must approve between 1 and 3 mutations"
        )
    if len(approved_ids) > cli_limit:
        raise FlagWorkflowError(
            f"{len(approved_ids)} approved mutations exceed CLI limit "
            f"{cli_limit}"
        )
    by_id = {mutation.mutation_id: mutation for mutation in mutations}
    selected = [by_id[mutation_id] for mutation_id in approved_ids]
    scopes = {
        (mutation.provider, mutation.account, mutation.mailbox)
        for mutation in selected
    }
    if len(scopes) != 1:
        raise FlagWorkflowError(
            "first activation must target one exact account/mailbox surface"
        )
    if selected[0].provider != "mailapp":
        raise FlagWorkflowError(
            "first activation supports only the Mail.app provider"
        )
    return CanaryActivation(
        plan=plan,
        snapshot=snapshot,
        approval=approval,
        mutations=mutations,
        selected=selected,
        cli_limit=cli_limit,
    )


def load_canary_rollback(
        *, plan_path: Path, snapshot_path: Path,
        approval_path: Path, receipt_path: Path,
        human_selected: bool = False,
        ) -> tuple[Dict[str, Any], FlagSnapshot, CanaryRollbackBundle]:
    """Load and cross-bind the exact approved activation before provider use."""
    activation = load_canary_activation(
        plan_path=Path(plan_path),
        snapshot_path=Path(snapshot_path),
        approval_path=Path(approval_path),
        cli_limit=FIRST_ACTIVATION_CANARY_MAX,
        require_fresh_approval=False,
        human_selected=human_selected,
    )
    plan = activation.plan
    snapshot = activation.snapshot
    bundle = CanaryRollbackBundle.from_dict(
        _json_object_from_path(Path(receipt_path), "rollback bundle")
    )
    expected = CanaryRollbackBundle.create(activation)
    if bundle.to_dict() != expected.to_dict():
        raise FlagWorkflowError(
            "rollback bundle does not match the exact approved activation "
            "set"
        )
    return plan, snapshot, bundle


def make_transaction_engine(
        state_dir: Path) -> tuple[TransactionEngine, TransactionLedger]:
    """Construct the canonical private-state engine without a provider."""
    root = Path(state_dir).expanduser()
    ledger = TransactionLedger(root / "ledger" / "transactions.jsonl")
    overrides = OverrideStore(root / "overrides.json")
    return TransactionEngine(root, ledger, overrides), ledger


def make_rollback_engine(
        state_dir: Path, plan: Dict[str, Any]
        ) -> ScopedRollbackEngine:
    """Construct the plan-derived rollback engine without a provider."""
    root = Path(state_dir).expanduser()
    ledger = TransactionLedger(root / "ledger" / "transactions.jsonl")
    overrides = OverrideStore(root / "overrides.json")
    return ScopedRollbackEngine(root, ledger, overrides, plan)


def persist_canary_material(
        activation: CanaryActivation,
        bundle: CanaryRollbackBundle,
        state_dir: Path,
        receipt_output: Optional[Path] = None) -> Dict[str, Path]:
    """Persist every private rollback prerequisite before live dispatch."""
    root = Path(state_dir).expanduser()
    plan_path = root / "plans" / f"{activation.plan_hash}.json"
    approval_path = (
        root / "approvals" /
        f"{activation.approval.content_hash}.json"
    )
    snapshot_path = write_private_snapshot(
        activation.snapshot, root / "snapshots"
    )
    write_private_plan(activation.plan, plan_path)
    write_private_approval(
        activation.approval, approval_path, plan=activation.plan
    )
    bundle_path = (
        Path(receipt_output).expanduser()
        if receipt_output is not None
        else root / "receipts" / f"{bundle.canary_id}.json"
    )
    bundle.validate()
    _atomic_write_private_json(
        bundle_path,
        bundle.to_dict(),
        prefix=".tmp-flags-canary-rollback-",
    )
    return {
        "snapshot": snapshot_path,
        "plan": plan_path,
        "approval": approval_path,
        "rollback": bundle_path,
    }


def redacted_canary_proposal(
        activation: CanaryActivation,
        bundle: CanaryRollbackBundle) -> Dict[str, Any]:
    """Return a shareable proposal with no raw account/message identity."""
    provider, account, mailbox = activation.scope
    scope_digest = sha256_hex({
        "provider": provider,
        "account": account,
        "mailbox": mailbox,
    })
    by_id = {
        receipt.mutation_id: receipt for receipt in bundle.receipts
    }
    return {
        "schema": "uma.flags.canary.proposal.public.v1",
        "canary_id": bundle.canary_id,
        "message_count": len(activation.selected),
        "provider": provider,
        "scope_digest": scope_digest,
        "snapshot_sha256": activation.plan["snapshot_sha256"],
        "plan_sha256": activation.plan_hash,
        "policy_sha256": activation.plan["policy_sha256"],
        "approval_sha256": activation.approval.content_hash,
        "selection_source": activation.approval.selection_source,
        "purpose": activation.approval.purpose,
        "manual_canary": activation.approval.manual_canary,
        "rollback_bundle_sha256": bundle.content_hash,
        "messages": [
            {
                "transaction_id": by_id[mutation.mutation_id].transaction_id,
                "mutation_id": mutation.mutation_id,
                "message_ref_digest": mutation.ref_digest,
                "current_flag": mutation.observed_flag.value,
                "classifier_proposed_flag": mutation.proposed_flag.value,
                "temporary_test_flag": (
                    activation.approval.execution_flag_for(mutation).value
                ),
                "reason": mutation.reason,
                "reason_code": mutation.reason_code,
                "confidence": mutation.confidence,
                "rollback_pre_state": {
                    "native_flag": mutation.observed_native_flag,
                    "semantic_flag": mutation.observed_flag.value,
                },
            }
            for mutation in activation.selected
        ],
    }


def write_public_canary_proposal(
        proposal: Dict[str, Any], path: Path) -> Path:
    """Write an already-redacted proposal atomically as a private default."""
    return _atomic_write_private_json(
        Path(path), proposal, prefix=".tmp-flags-canary-proposal-"
    )


__all__ = [
    "BatchRollbackResult",
    "CanaryActivation",
    "CanaryRollbackBundle",
    "FIRST_ACTIVATION_CANARY_MAX",
    "default_flags_state_dir",
    "load_canary_activation",
    "load_canary_rollback",
    "make_rollback_engine",
    "make_transaction_engine",
    "persist_canary_material",
    "redacted_canary_proposal",
    "validate_canary_output_paths",
    "write_public_canary_proposal",
]
