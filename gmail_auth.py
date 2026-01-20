"""
Shared Gmail authentication utilities.
Loads OAuth client config and tokens from 1Password-backed env sources.
"""

import json
import os
import subprocess
from typing import Optional, Tuple

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

DEFAULT_SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

def _run_op(cmd: list, description: str, sensitive: bool = False) -> str:
    try:
        result = subprocess.run(
            cmd,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.stdout.strip()
    except FileNotFoundError as exc:
        raise RuntimeError(f"1Password CLI not found while {description}.") from exc
    except subprocess.CalledProcessError as exc:
        if sensitive:
            raise RuntimeError(f"1Password CLI failed while {description}.") from None
        detail = exc.stderr.strip() or "unknown error"
        raise RuntimeError(f"1Password CLI failed while {description}: {detail}") from exc


def _op_read(ref: str) -> str:
    cmd = ["op", "read", ref]
    account = os.getenv("OP_ACCOUNT")
    if account:
        cmd.extend(["--account", account])
    return _run_op(cmd, f"reading secret {ref}")


def _op_item_get(item: str, field: str, vault: Optional[str]) -> str:
    cmd = ["op", "item", "get", item, f"--field={field}"]
    account = os.getenv("OP_ACCOUNT")
    if account:
        cmd.extend(["--account", account])
    if vault:
        cmd.extend(["--vault", vault])
    return _run_op(cmd, f"reading field {field} from item {item}")


def _op_item_edit(item: str, field: str, value: str, vault: Optional[str]) -> None:
    cmd = ["op", "item", "edit", item, f"{field}={value}"]
    account = os.getenv("OP_ACCOUNT")
    if account:
        cmd.extend(["--account", account])
    if vault:
        cmd.extend(["--vault", vault])
    _run_op(cmd, f"writing field {field} to item {item}", sensitive=True)


def _load_json_secret(
    env_var: str,
    op_ref_env: str,
    item_env: str,
    field_env: str,
    vault_env: str,
) -> Optional[dict]:
    raw = os.getenv(env_var)
    if not raw:
        ref = os.getenv(op_ref_env)
        if ref:
            raw = _op_read(ref)
        else:
            item = os.getenv(item_env)
            field = os.getenv(field_env)
            vault = os.getenv(vault_env)
            if item and field:
                raw = _op_item_get(item, field, vault)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid JSON in {env_var} / {op_ref_env} / {item_env}.{field_env}.") from exc


def _parse_op_ref(ref: str) -> Optional[Tuple[str, str, str]]:
    if not ref.startswith("op://"):
        return None
    parts = ref[len("op://") :].split("/")
    if len(parts) < 3:
        return None
    vault = parts[0]
    item = parts[1]
    field = "/".join(parts[2:])
    return item, field, vault


def load_client_config() -> dict:
    config = _load_json_secret(
        env_var="GMAIL_OAUTH_JSON",
        op_ref_env="GMAIL_OAUTH_OP_REF",
        item_env="OP_GMAIL_OAUTH_ITEM",
        field_env="OP_GMAIL_OAUTH_FIELD",
        vault_env="OP_GMAIL_OAUTH_VAULT",
    )
    if not config:
        raise RuntimeError(
            "Missing Gmail OAuth client config. "
            "Set GMAIL_OAUTH_JSON or GMAIL_OAUTH_OP_REF (or OP_GMAIL_OAUTH_ITEM/OP_GMAIL_OAUTH_FIELD)."
        )
    return config


def load_token_info() -> Optional[dict]:
    return _load_json_secret(
        env_var="GMAIL_TOKEN_JSON",
        op_ref_env="GMAIL_TOKEN_OP_REF",
        item_env="OP_GMAIL_TOKEN_ITEM",
        field_env="OP_GMAIL_TOKEN_FIELD",
        vault_env="OP_GMAIL_TOKEN_VAULT",
    )


def _token_write_target() -> Optional[Tuple[str, str, Optional[str]]]:
    item = os.getenv("OP_GMAIL_TOKEN_ITEM")
    field = os.getenv("OP_GMAIL_TOKEN_FIELD")
    vault = os.getenv("OP_GMAIL_TOKEN_VAULT")
    if item and field:
        return item, field, vault
    ref = os.getenv("GMAIL_TOKEN_OP_REF")
    if ref:
        parsed = _parse_op_ref(ref)
        if parsed:
            return parsed[0], parsed[1], parsed[2]
    return None


def store_token_info(creds: Credentials) -> None:
    target = _token_write_target()
    if not target:
        raise RuntimeError(
            "Token storage not configured. "
            "Set OP_GMAIL_TOKEN_ITEM/OP_GMAIL_TOKEN_FIELD or GMAIL_TOKEN_OP_REF to allow write-back."
        )
    token_json = json.loads(creds.to_json())
    compact = json.dumps(token_json, separators=(",", ":"), sort_keys=True)
    item, field, vault = target
    _op_item_edit(item, field, compact, vault)


def get_credentials(scopes: Optional[list] = None) -> Credentials:
    scopes = scopes or DEFAULT_SCOPES
    token_info = load_token_info()
    creds = None
    if token_info:
        creds = Credentials.from_authorized_user_info(token_info, scopes=scopes)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            store_token_info(creds)
        else:
            client_config = load_client_config()
            flow = InstalledAppFlow.from_client_config(client_config, scopes)
            creds = flow.run_local_server(port=0)
            store_token_info(creds)

    return creds


def build_gmail_service(scopes: Optional[list] = None):
    creds = get_credentials(scopes=scopes)
    return build("gmail", "v1", credentials=creds)
