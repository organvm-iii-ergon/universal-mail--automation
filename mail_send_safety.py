"""Safety contracts for :mod:`mail_send`.

This module is deliberately free of SMTP and IMAP calls.  It turns an outgoing
message into a stable authorization binding, validates an independently-created
receipt against that binding, and reads credential env files as data (never as
shell code).
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage, Message
from email.utils import getaddresses, parseaddr
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

AUTHORIZATION_SCHEMA = "uma.mail_send_authorization.v1"
AUTHORIZATION_SIGNATURE_ALGORITHM = "Ed25519"
ATTEMPT_CLAIM_SCHEMA = "uma.mail_send_attempt_claim.v1"
AUTHORIZATION_ACTIONS = frozenset({"compose", "reply", "from_draft", "self_test"})
ATTEMPT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ED25519_SIGNATURE_RE = re.compile(r"^[0-9a-f]{128}$")
_CREDENTIAL_KEYS = frozenset(
    {"GMAIL_USER", "GMAIL_APP_PASSWORD", "IMAP_USER", "IMAP_PASS"}
)
_ASSIGNMENT_RE = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_AUTHORIZATION_KEY_BYTES = 4 * 1024
MAX_AUTHORIZATION_TTL = timedelta(minutes=15)


class AuthorizationError(ValueError):
    """The authorization receipt does not grant this exact send."""


class CredentialFileError(ValueError):
    """A credential file contains an invalid allowed-key assignment."""


@dataclass(frozen=True)
class AuthorizationGrant:
    """A validated, time-bounded grant for one exact message attempt."""

    action: str
    attempt_id: str
    binding_sha256: str
    expires_at: datetime
    receipt_path: Path
    receipt_sha256: str
    authorization_public_key_path: Path
    authorization_public_key_fingerprint: str
    authorized_by: str


def validate_attempt_id(attempt_id: str) -> str:
    """Return a safe, stable attempt ID or raise fail-closed."""
    if not ATTEMPT_ID_RE.fullmatch(attempt_id or ""):
        raise AuthorizationError(
            "attempt ID must be 8-128 characters and use only letters, digits, '.', '_', ':', or '-'"
        )
    return attempt_id


def _parse_env_value(raw: str, *, path: Path, line_number: int) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {"'", '"'}:
        if len(value) < 2 or value[-1] != value[0]:
            raise CredentialFileError(
                f"{path}:{line_number}: unmatched credential quote"
            )
        try:
            parsed = ast.literal_eval(value)
        except (SyntaxError, ValueError) as exc:
            raise CredentialFileError(
                f"{path}:{line_number}: invalid quoted credential value"
            ) from exc
        if not isinstance(parsed, str):
            raise CredentialFileError(
                f"{path}:{line_number}: credential value must be text"
            )
        return parsed
    # Unquoted values are literal data.  In particular, '$()', backticks, '$VAR',
    # semicolons, and shell metacharacters are never evaluated or interpolated.
    return value


def parse_credential_env_file(path: str | Path) -> dict[str, str]:
    """Parse credential assignments without sourcing or evaluating the file.

    Only the four SMTP/IMAP credential keys are returned.  Other assignments and
    shell-looking lines are ignored, so a credential file cannot execute code.
    """
    try:
        resolved, raw = _read_regular_file(
            path,
            label="credential file",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
        text = raw.decode("utf-8")
    except (AuthorizationError, UnicodeDecodeError) as exc:
        raise CredentialFileError(
            f"cannot read credential file {Path(path).expanduser()}: {exc}"
        ) from exc

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _ASSIGNMENT_RE.fullmatch(line)
        if not match:
            continue
        key, raw_value = match.groups()
        if key not in _CREDENTIAL_KEYS:
            continue
        values[key] = _parse_env_value(
            raw_value, path=resolved, line_number=line_number
        )
    return values


def resolve_smtp_credentials(
    credential_files: Sequence[str | Path] | None,
    environ: Mapping[str, str],
) -> tuple[str, str] | None:
    """Resolve one complete credential pair, with process env taking precedence."""
    environment_values = {
        key: environ[key] for key in _CREDENTIAL_KEYS if environ.get(key)
    }
    # A complete hydrated environment pair is authoritative over every file,
    # even when a file happens to contain a complete pair for the other alias.
    for user_key, password_key in (
        ("IMAP_USER", "IMAP_PASS"),
        ("GMAIL_USER", "GMAIL_APP_PASSWORD"),
    ):
        if environment_values.get(user_key) and environment_values.get(password_key):
            return environment_values[user_key], environment_values[password_key]

    values: dict[str, str] = {}
    for path in credential_files or ():
        values.update(parse_credential_env_file(path))
    values.update(environment_values)

    for user_key, password_key in (
        ("IMAP_USER", "IMAP_PASS"),
        ("GMAIL_USER", "GMAIL_APP_PASSWORD"),
    ):
        user = values.get(user_key)
        password = values.get(password_key)
        if user and password:
            return user, password
    return None


def normalize_address(value: str) -> str:
    """Normalize an RFC address for receipt and SMTP-envelope comparison."""
    address = parseaddr(value or "")[1].strip()
    if "@" not in address:
        return address
    local, domain = address.rsplit("@", 1)
    return f"{local}@{domain.casefold()}"


def _header_addresses(msg: Message, header: str) -> list[str]:
    addresses = {
        normalize_address(address)
        for _, address in getaddresses(msg.get_all(header, []))
        if normalize_address(address)
    }
    return sorted(addresses)


def normalized_recipients(msg: Message) -> dict[str, list[str]]:
    """Return role-preserving, deduplicated, normalized recipients."""
    return {
        "to": _header_addresses(msg, "To"),
        "cc": _header_addresses(msg, "Cc"),
        "bcc": _header_addresses(msg, "Bcc"),
    }


def _decoded_payload(part: Message) -> bytes:
    payload = part.get_payload(decode=True)
    if payload is not None:
        return payload
    value = part.get_payload()
    if isinstance(value, str):
        return value.encode(
            part.get_content_charset() or "utf-8", errors="surrogateescape"
        )
    return b""


def _header_parameters(part: Message, header: str) -> list[list[str]]:
    """Return semantic MIME parameters while excluding random wire boundaries."""
    params = part.get_params(header=header, failobj=[]) or []
    return sorted(
        [[str(name).casefold(), str(value)] for name, value in params[1:] if str(name).casefold() != "boundary"]
    )


def _message_parts(msg: Message) -> tuple[list[dict], list[dict], list[dict]]:
    bodies: list[dict] = []
    attachments: list[dict] = []
    structure: list[dict] = []

    def visit(part: Message, path: tuple[int, ...]) -> None:
        content_type = part.get_content_type().casefold()
        if part.is_multipart():
            children = list(part.iter_parts())
            structure.append(
                {
                    "path": list(path),
                    "kind": "multipart",
                    "content_type": content_type,
                    "content_type_parameters": _header_parameters(part, "Content-Type"),
                    "children": len(children),
                }
            )
            for index, child in enumerate(children):
                visit(child, (*path, index))
            return
        payload = _decoded_payload(part)
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        digest = hashlib.sha256(payload).hexdigest()
        metadata = {
            "path": list(path),
            "content_type": content_type,
            "content_type_parameters": _header_parameters(part, "Content-Type"),
            "content_disposition": str(part.get("Content-Disposition") or ""),
            "content_disposition_parameters": _header_parameters(
                part, "Content-Disposition"
            ),
            "content_id": str(part.get("Content-ID") or ""),
            "content_transfer_encoding": str(
                part.get("Content-Transfer-Encoding") or ""
            ).casefold(),
            "size": len(payload),
            "sha256": digest,
        }
        structure.append(
            {
                "path": list(path),
                "kind": "attachment"
                if disposition == "attachment" or filename is not None
                else "body",
                "content_type": content_type,
            }
        )
        if disposition == "attachment" or filename is not None:
            attachments.append(
                {
                    **metadata,
                    "filename": str(filename or ""),
                }
            )
        else:
            bodies.append(metadata)

    visit(msg, ())
    return bodies, attachments, structure


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _semantic_headers(msg: Message) -> list[list[str]]:
    """Bind non-MIME headers not represented by dedicated binding fields."""
    represented = {
        "to",
        "cc",
        "bcc",
        "subject",
        "message-id",
        "in-reply-to",
        "references",
        "mime-version",
        "content-type",
        "content-transfer-encoding",
        "content-disposition",
    }
    return [
        [name.casefold(), str(value)]
        for name, value in msg.raw_items()
        if name.casefold() not in represented
    ]


def authorization_binding(
    msg: EmailMessage,
    *,
    envelope_sender: str,
    action: str,
    attempt_id: str,
    effect_context: Mapping[str, str] | None = None,
) -> dict:
    """Build the stable exact-message binding an authorization receipt must copy."""
    validate_attempt_id(attempt_id)
    if action not in AUTHORIZATION_ACTIONS:
        raise AuthorizationError(f"unsupported authorization action: {action!r}")
    sender = normalize_address(envelope_sender)
    if not sender:
        raise AuthorizationError("authorization sender is not a valid address")
    context = dict(effect_context or {})
    if any(
        not isinstance(key, str) or not isinstance(value, str)
        for key, value in context.items()
    ):
        raise AuthorizationError(
            "authorization effect context must contain text fields"
        )
    bodies, attachments, structure = _message_parts(msg)
    core = {
        "schema": AUTHORIZATION_SCHEMA,
        "action": action,
        "attempt_id": attempt_id,
        "sender": sender,
        "recipients": normalized_recipients(msg),
        "subject": str(msg.get("Subject") or ""),
        "message_id": str(msg.get("Message-ID") or ""),
        "thread": {
            "in_reply_to": str(msg.get("In-Reply-To") or ""),
            "references": str(msg.get("References") or ""),
        },
        "headers": _semantic_headers(msg),
        # The body digest covers a canonical manifest of every non-attachment MIME
        # body part, so text/html alternatives cannot change without invalidation.
        "body_sha256": _canonical_sha256(bodies),
        "attachments": attachments,
        "mime_structure_sha256": _canonical_sha256(structure),
        # Bind the selected remote source as well as the outgoing content.  A
        # previewed reply/draft cannot silently retarget a different IMAP UID.
        "effect_context": context,
    }
    return {**core, "binding_sha256": _canonical_sha256(core)}


def authorization_request(binding: Mapping[str, object]) -> dict:
    """Return a non-authorizing template suitable for a dry-run preview."""
    return {
        **dict(binding),
        "authorized": False,
        "authorized_by": "",
        "signature_algorithm": AUTHORIZATION_SIGNATURE_ALGORITHM,
        "key_id": "<authorization key id>",
        "signature": "<Ed25519 signature over the canonical receipt without signature>",
        "issued_at": "<RFC3339 UTC>",
        "expires_at": "<RFC3339 UTC>",
    }


def _read_regular_file(
    path: str | Path,
    *,
    label: str,
    max_bytes: int,
    private: bool = False,
) -> tuple[Path, bytes]:
    """Read one stable regular file without following its final symlink.

    Authorization inputs are control-plane files, not arbitrary streams.  Reading
    through a symlink or a group/world-writable file would let a path replacement
    race choose what is authorized.  Key files additionally have to be private to
    the effective user.
    """
    resolved = Path(path).expanduser()
    try:
        initial = resolved.lstat()
    except OSError as exc:
        raise AuthorizationError(f"cannot read {label} {resolved}: {exc}") from exc
    if stat.S_ISLNK(initial.st_mode) or not stat.S_ISREG(initial.st_mode):
        raise AuthorizationError(f"{label} must be a regular file, not a symlink")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(resolved, flags)
    except OSError as exc:
        raise AuthorizationError(f"cannot read {label} {resolved}: {exc}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise AuthorizationError(f"{label} must be a regular file")
        if (initial.st_dev, initial.st_ino) != (before.st_dev, before.st_ino):
            raise AuthorizationError(f"{label} changed before it could be opened")
        if before.st_nlink != 1:
            raise AuthorizationError(f"{label} must have exactly one filesystem link")
        if before.st_size > max_bytes:
            raise AuthorizationError(f"{label} exceeds {max_bytes} bytes")
        if before.st_mode & 0o022:
            raise AuthorizationError(f"{label} must not be group/world writable")
        if private:
            if hasattr(os, "getuid") and before.st_uid != os.getuid():
                raise AuthorizationError(f"{label} must be owned by the current user")
            if before.st_mode & 0o077:
                raise AuthorizationError(
                    f"{label} permissions must be 0600 or stricter"
                )
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise AuthorizationError(f"{label} exceeds {max_bytes} bytes")
        after = os.fstat(fd)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise AuthorizationError(f"{label} changed while it was being read")
        return resolved, raw
    finally:
        os.close(fd)


def _signature_payload(receipt: Mapping[str, object]) -> bytes:
    signable = {key: value for key, value in receipt.items() if key != "signature"}
    return json.dumps(
        signable, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _public_key_fingerprint(public_key: bytes) -> str:
    """Fingerprint a public verification key without treating it as a secret."""
    return hashlib.sha3_256(public_key).hexdigest()


def authorization_key_id(key: bytes) -> str:
    """Return the fingerprint of the independently-custodied public key."""
    return _public_key_fingerprint(key)[:16]


def authorization_signature(receipt: Mapping[str, object], key: bytes) -> str:
    """Sign a receipt with an Ed25519 private key held outside the sender."""
    try:
        signer = (
            Ed25519PrivateKey.from_private_bytes(key)
            if len(key) == 32
            else load_pem_private_key(key, password=None)  # allow-secret
        )
    except (TypeError, ValueError) as exc:
        raise AuthorizationError("authorization private key is invalid") from exc
    if not isinstance(signer, Ed25519PrivateKey):
        raise AuthorizationError("authorization private key must be Ed25519")
    return signer.sign(_signature_payload(receipt)).hex()


def _load_authorization_key(
    path: str | Path,
) -> tuple[Path, bytes, Ed25519PublicKey]:
    key_path, key = _read_regular_file(
        path,
        label="authorization public key file",
        max_bytes=_MAX_AUTHORIZATION_KEY_BYTES,
    )
    try:
        verifier = (
            Ed25519PublicKey.from_public_bytes(key)
            if len(key) == 32
            else load_pem_public_key(key)
        )
    except (TypeError, ValueError) as exc:
        raise AuthorizationError("authorization public key is invalid") from exc
    if not isinstance(verifier, Ed25519PublicKey):
        raise AuthorizationError("authorization public key must be Ed25519")
    canonical = verifier.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return key_path, canonical, verifier


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuthorizationError(
            f"authorization receipt {field} must be an RFC3339 timestamp"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError(
            f"authorization receipt {field} is not RFC3339"
        ) from exc
    if parsed.tzinfo is None:
        raise AuthorizationError(
            f"authorization receipt {field} must include a timezone"
        )
    return parsed.astimezone(timezone.utc)


def validate_authorization_receipt(
    path: str | Path,
    expected_binding: Mapping[str, object],
    *,
    authorization_key_file: str | Path,
    now: datetime | None = None,
) -> AuthorizationGrant:
    """Validate a receipt for this exact binding and return a time-bounded grant."""
    receipt_path, raw = _read_regular_file(
        path,
        label="authorization receipt",
        max_bytes=_MAX_RECEIPT_BYTES,
    )
    try:
        receipt = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthorizationError(
            "authorization receipt is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(receipt, dict):
        raise AuthorizationError("authorization receipt must be a JSON object")
    if receipt.get("authorized") is not True:
        raise AuthorizationError(
            "authorization receipt does not explicitly set authorized=true"
        )
    if (
        not isinstance(receipt.get("authorized_by"), str)
        or not receipt["authorized_by"].strip()
    ):
        raise AuthorizationError("authorization receipt must name authorized_by")

    key_path, authorization_key, verifier = _load_authorization_key(
        authorization_key_file
    )
    if receipt.get("signature_algorithm") != AUTHORIZATION_SIGNATURE_ALGORITHM:
        raise AuthorizationError(
            f"authorization receipt signature_algorithm must be {AUTHORIZATION_SIGNATURE_ALGORITHM}"
        )
    if receipt.get("key_id") != authorization_key_id(authorization_key):
        raise AuthorizationError("authorization receipt key_id does not match the key")
    signature = receipt.get("signature")
    if not isinstance(signature, str) or not ED25519_SIGNATURE_RE.fullmatch(signature):
        raise AuthorizationError("authorization receipt signature is invalid")
    try:
        verifier.verify(bytes.fromhex(signature), _signature_payload(receipt))
    except InvalidSignature:
        raise AuthorizationError("authorization receipt signature verification failed")

    for field, expected in expected_binding.items():
        if receipt.get(field) != expected:
            raise AuthorizationError(f"authorization receipt mismatch: {field}")
    digest = expected_binding.get("binding_sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise AuthorizationError("expected authorization binding is invalid")

    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    expires_at = _parse_timestamp(receipt.get("expires_at"), "expires_at")
    if expires_at <= current:
        raise AuthorizationError("authorization receipt has expired")
    issued_at = _parse_timestamp(receipt.get("issued_at"), "issued_at")
    if issued_at > current:
        raise AuthorizationError("authorization receipt was issued in the future")
    if issued_at >= expires_at:
        raise AuthorizationError("authorization receipt expires before it was issued")
    if expires_at - issued_at > MAX_AUTHORIZATION_TTL:
        raise AuthorizationError(
            f"authorization receipt lifetime exceeds {int(MAX_AUTHORIZATION_TTL.total_seconds())} seconds"
        )

    return AuthorizationGrant(
        action=str(expected_binding["action"]),
        attempt_id=str(expected_binding["attempt_id"]),
        binding_sha256=digest,
        expires_at=expires_at,
        receipt_path=receipt_path,
        receipt_sha256=hashlib.sha256(raw).hexdigest(),
        authorization_public_key_path=key_path,
        authorization_public_key_fingerprint=_public_key_fingerprint(
            authorization_key
        ),
        authorized_by=receipt["authorized_by"].strip(),
    )


def assert_grant_current(
    grant: AuthorizationGrant,
    expected_binding: Mapping[str, object],
    *,
    now: datetime | None = None,
) -> None:
    """Recheck the in-memory grant immediately before the SMTP effect."""
    _receipt_path, receipt_raw = _read_regular_file(
        grant.receipt_path,
        label="authorization receipt",
        max_bytes=_MAX_RECEIPT_BYTES,
    )
    if hashlib.sha256(receipt_raw).hexdigest() != grant.receipt_sha256:
        raise AuthorizationError("authorization receipt changed before SMTP send")
    _key_path, authorization_key, _verifier = _load_authorization_key(
        grant.authorization_public_key_path
    )
    if (
        _public_key_fingerprint(authorization_key)
        != grant.authorization_public_key_fingerprint
    ):
        raise AuthorizationError("authorization key changed before SMTP send")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if grant.expires_at <= current:
        raise AuthorizationError("authorization grant expired before SMTP send")
    if grant.action != expected_binding.get("action"):
        raise AuthorizationError("authorization grant action changed before SMTP send")
    if grant.attempt_id != expected_binding.get("attempt_id"):
        raise AuthorizationError("authorization grant attempt changed before SMTP send")
    if grant.binding_sha256 != expected_binding.get("binding_sha256"):
        raise AuthorizationError("message changed after authorization")


def _open_attempt_store(path: str | Path) -> tuple[Path, int, os.stat_result]:
    """Open/create a directory with no symlink traversal in any component."""
    root = Path(os.path.abspath(Path(path).expanduser()))
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        current_fd = os.open(os.sep, flags)
    except OSError as exc:
        raise AuthorizationError(f"cannot anchor attempt store {root}: {exc}") from exc
    try:
        for component in root.parts[1:]:
            try:
                next_fd = os.open(component, flags, dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(component, 0o700, dir_fd=current_fd)
                except FileExistsError:
                    # A concurrent creator won. The no-follow open below decides
                    # whether the winner created the required real directory.
                    pass
                next_fd = os.open(component, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return root, current_fd, os.fstat(current_fd)
    except (OSError, TypeError, NotImplementedError) as exc:
        os.close(current_fd)
        raise AuthorizationError(
            f"cannot prepare symlink-safe attempt store {root}: {exc}"
        ) from exc


def claim_authorized_attempt(
    grant: AuthorizationGrant,
    expected_binding: Mapping[str, object],
    attempt_store: str | Path,
    *,
    now: datetime | None = None,
) -> Path:
    """Durably claim one attempt before SMTP, refusing every replay.

    The marker is created with ``O_EXCL`` under a non-symlink directory and is
    fsynced before this function returns.  A crash or ambiguous SMTP outcome keeps
    the marker, deliberately forcing a fresh attempt ID instead of a duplicate send.
    """
    assert_grant_current(grant, expected_binding, now=now)
    root, directory_fd, root_stat = _open_attempt_store(attempt_store)
    if not stat.S_ISDIR(root_stat.st_mode):
        os.close(directory_fd)
        raise AuthorizationError("attempt store must be a real directory")
    if root_stat.st_mode & 0o022:
        os.close(directory_fd)
        raise AuthorizationError("attempt store must not be group/world writable")
    if hasattr(os, "getuid") and root_stat.st_uid != os.getuid():
        os.close(directory_fd)
        raise AuthorizationError("attempt store must be owned by the current user")

    filename = hashlib.sha256(grant.attempt_id.encode("utf-8")).hexdigest() + ".json"
    payload = json.dumps(
        {
            "schema": ATTEMPT_CLAIM_SCHEMA,
            "attempt_id": grant.attempt_id,
            "action": grant.action,
            "binding_sha256": grant.binding_sha256,
            "authorization_receipt_sha256": grant.receipt_sha256,
            "authorized_by": grant.authorized_by,
            "claimed_at": (now or datetime.now(timezone.utc))
            .astimezone(timezone.utc)
            .isoformat(),
            "state": "claimed_before_smtp",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    try:
        opened_root = os.fstat(directory_fd)
        if (opened_root.st_dev, opened_root.st_ino) != (
            root_stat.st_dev,
            root_stat.st_ino,
        ):
            raise AuthorizationError("attempt store changed while it was being opened")
        if not stat.S_ISDIR(opened_root.st_mode) or opened_root.st_mode & 0o022:
            raise AuthorizationError("attempt store permissions changed")
        if hasattr(os, "getuid") and opened_root.st_uid != os.getuid():
            raise AuthorizationError("attempt store ownership changed")
        file_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            fd = os.open(filename, file_flags, 0o600, dir_fd=directory_fd)
        except FileExistsError as exc:
            raise AuthorizationError(
                f"attempt ID {grant.attempt_id!r} was already claimed; use a fresh attempt ID"
            ) from exc
        except (OSError, TypeError, NotImplementedError) as exc:
            raise AuthorizationError(f"cannot claim attempt ID: {exc}") from exc
        try:
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write while claiming attempt")
                view = view[written:]
            os.fsync(fd)
        except OSError as exc:
            # Never remove an ambiguously persisted marker.  Safety requires a fresh
            # attempt after any claim failure.
            raise AuthorizationError(
                f"could not durably claim attempt ID: {exc}"
            ) from exc
        finally:
            os.close(fd)
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            raise AuthorizationError(
                f"attempt claim directory could not be synced: {exc}"
            ) from exc
    finally:
        os.close(directory_fd)
    return root / filename
