"""
1Password credential loading utilities.

Provides functions to load secrets from 1Password CLI or environment variables,
with fallback support for different configuration styles.
"""

import json
import logging
import os
import subprocess
from typing import Optional, Tuple, Dict, Any

logger = logging.getLogger(__name__)


def _run_op(cmd: list, description: str, sensitive: bool = False) -> str:
    """
    Execute a 1Password CLI command.

    Args:
        cmd: Command and arguments
        description: Description for error messages
        sensitive: If True, don't include stderr in error messages

    Returns:
        Command output (stdout)

    Raises:
        RuntimeError: If command fails
    """
    try:
        result = subprocess.run(
            cmd,
            check=True,
            text=True,
            capture_output=True,
        )
        return result.stdout.strip()
    except FileNotFoundError as exc:
        raise RuntimeError(f"1Password CLI not found while {description}.") from exc
    except subprocess.CalledProcessError as exc:
        if sensitive:
            raise RuntimeError(f"1Password CLI failed while {description}.") from None
        detail = exc.stderr.strip() or "unknown error"
        raise RuntimeError(f"1Password CLI failed while {description}: {detail}") from exc


def op_read(ref: str, account: Optional[str] = None) -> str:
    """
    Read a secret from 1Password using reference syntax.

    Args:
        ref: 1Password reference (e.g., "op://Vault/Item/Field")
        account: Optional account identifier

    Returns:
        The secret value
    """
    cmd = ["op", "read", ref]
    account = account or os.getenv("OP_ACCOUNT")
    if account:
        cmd.extend(["--account", account])
    return _run_op(cmd, f"reading secret {ref}")


def op_item_get(
    item: str,
    field: str,
    vault: Optional[str] = None,
    account: Optional[str] = None,
) -> str:
    """
    Read a field from a 1Password item.

    Args:
        item: Item name or ID
        field: Field name
        vault: Optional vault name
        account: Optional account identifier

    Returns:
        The field value
    """
    cmd = ["op", "item", "get", item, f"--field={field}"]
    account = account or os.getenv("OP_ACCOUNT")
    if account:
        cmd.extend(["--account", account])
    if vault:
        cmd.extend(["--vault", vault])
    return _run_op(cmd, f"reading field {field} from item {item}")


def op_item_edit(
    item: str,
    field: str,
    value: str,
    vault: Optional[str] = None,
    account: Optional[str] = None,
) -> None:
    """
    Write a value to a 1Password item field.

    Args:
        item: Item name or ID
        field: Field name
        value: Value to write
        vault: Optional vault name
        account: Optional account identifier
    """
    cmd = ["op", "item", "edit", item, f"{field}={value}"]
    account = account or os.getenv("OP_ACCOUNT")
    if account:
        cmd.extend(["--account", account])
    if vault:
        cmd.extend(["--vault", vault])
    _run_op(cmd, f"writing field {field} to item {item}", sensitive=True)


def parse_op_ref(ref: str) -> Optional[Tuple[str, str, str]]:
    """
    Parse a 1Password reference into components.

    Args:
        ref: Reference string (e.g., "op://Vault/Item/Field")

    Returns:
        Tuple of (item, field, vault) or None if invalid
    """
    if not ref.startswith("op://"):
        return None
    parts = ref[len("op://"):].split("/")
    if len(parts) < 3:
        return None
    vault = parts[0]
    item = parts[1]
    field = "/".join(parts[2:])
    return item, field, vault


def load_secret(
    env_var: str,
    op_ref_env: Optional[str] = None,
    item_env: Optional[str] = None,
    field_env: Optional[str] = None,
    vault_env: Optional[str] = None,
    default: Optional[str] = None,
) -> Optional[str]:
    """
    Load a secret from environment variable or 1Password.

    Tries sources in order:
    1. Direct environment variable (env_var)
    2. 1Password reference from op_ref_env
    3. 1Password item/field/vault from separate env vars

    Args:
        env_var: Primary environment variable name
        op_ref_env: Env var containing 1Password reference
        item_env: Env var containing 1Password item name
        field_env: Env var containing 1Password field name
        vault_env: Env var containing 1Password vault name
        default: Default value if not found

    Returns:
        The secret value, or default if not found
    """
    # Try direct env var
    value = os.getenv(env_var)
    if value:
        return value

    # Try 1Password reference
    if op_ref_env:
        ref = os.getenv(op_ref_env)
        if ref:
            try:
                return op_read(ref)
            except RuntimeError as e:
                logger.warning(f"Failed to read from 1Password ref: {e}")

    # Try item/field/vault
    if item_env and field_env:
        item = os.getenv(item_env)
        field = os.getenv(field_env)
        vault = os.getenv(vault_env) if vault_env else None
        if item and field:
            try:
                return op_item_get(item, field, vault)
            except RuntimeError as e:
                logger.warning(f"Failed to read from 1Password item: {e}")

    return default


def load_json_secret(
    env_var: str,
    op_ref_env: Optional[str] = None,
    item_env: Optional[str] = None,
    field_env: Optional[str] = None,
    vault_env: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Load a JSON secret from environment variable or 1Password.

    Same as load_secret but parses the result as JSON.

    Args:
        env_var: Primary environment variable name
        op_ref_env: Env var containing 1Password reference
        item_env: Env var containing 1Password item name
        field_env: Env var containing 1Password field name
        vault_env: Env var containing 1Password vault name

    Returns:
        Parsed JSON dict, or None if not found

    Raises:
        RuntimeError: If JSON parsing fails
    """
    raw = load_secret(env_var, op_ref_env, item_env, field_env, vault_env)
    if not raw:
        return None

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid JSON in {env_var} / {op_ref_env} / {item_env}.{field_env}."
        ) from exc


def store_json_secret(
    data: Dict[str, Any],
    op_ref_env: Optional[str] = None,
    item_env: Optional[str] = None,
    field_env: Optional[str] = None,
    vault_env: Optional[str] = None,
) -> None:
    """
    Store a JSON secret to 1Password.

    Args:
        data: Dict to serialize as JSON
        op_ref_env: Env var containing 1Password reference
        item_env: Env var containing 1Password item name
        field_env: Env var containing 1Password field name
        vault_env: Env var containing 1Password vault name

    Raises:
        RuntimeError: If storage not configured or fails
    """
    compact = json.dumps(data, separators=(",", ":"), sort_keys=True)

    # Try 1Password reference
    if op_ref_env:
        ref = os.getenv(op_ref_env)
        if ref:
            parsed = parse_op_ref(ref)
            if parsed:
                item, field, vault = parsed
                op_item_edit(item, field, compact, vault)
                return

    # Try item/field/vault
    if item_env and field_env:
        item = os.getenv(item_env)
        field = os.getenv(field_env)
        vault = os.getenv(vault_env) if vault_env else None
        if item and field:
            op_item_edit(item, field, compact, vault)
            return

    raise RuntimeError(
        "Token storage not configured. Set 1Password reference or item/field env vars."
    )
