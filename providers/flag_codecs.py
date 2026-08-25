"""Pure provider CODEC for Mail.app native flag indexes.

This module is deliberately I/O-FREE: no AppleScript, no osascript, no
provider construction, no connections, no enumeration. It exists so
artifact validation (snapshot load/plan) can prove native↔semantic
consistency in a COMPLETELY FRESH PROCESS without importing the runtime
provider implementation (``providers.mailapp``), whose import pulls in
subprocess machinery and whose registration was previously the only place
the codec lived.

Importing this module performs exactly one side effect: idempotent,
non-overwriting registration of the Mail.app transport validator into
core.flag_workflow's registry. That is a pure in-memory operation.
"""

from __future__ import annotations

from core.flag_workflow import register_native_flag_validator
from core.models import FlagColor

PROVIDER_NAME = "mailapp"

# The EXACT Mail.app transport mapping (single source of truth).
MAILAPP_INDEX_TO_FLAG = {
    -1: FlagColor.NO_FLAG,
    0: FlagColor.RED,
    1: FlagColor.ORANGE,
    2: FlagColor.YELLOW,
    3: FlagColor.GREEN,
    4: FlagColor.BLUE,
    5: FlagColor.PURPLE,
    6: FlagColor.GRAY,
}
MAILAPP_FLAG_TO_INDEX = {v: k for k, v in MAILAPP_INDEX_TO_FLAG.items()}


def flag_from_mailapp_index(index: int) -> FlagColor:
    """Convert a Mail.app flag index to a semantic FlagColor.

    Unknown indices map to FlagColor.UNKNOWN, never to NO_FLAG.
    """
    return MAILAPP_INDEX_TO_FLAG.get(index, FlagColor.UNKNOWN)


def mailapp_index_from_flag(flag: FlagColor) -> int:
    """Convert a semantic FlagColor to a Mail.app flag index.

    Raises KeyError for UNKNOWN — there is no valid native index for it.
    """
    return MAILAPP_FLAG_TO_INDEX[flag]


def validate_mailapp_native_pair(native_index):
    """Registry signature: native index -> expected semantic color.

    ``None`` means "no native index captured" which the snapshot transport
    contract reserves for UNKNOWN observations; unknown integers likewise
    transport as UNKNOWN (they are counted, never silently recolored).
    """
    if native_index is None:
        return FlagColor.UNKNOWN
    return flag_from_mailapp_index(native_index)


def register() -> None:
    """Idempotent registration into the workflow validator registry."""
    register_native_flag_validator(PROVIDER_NAME, validate_mailapp_native_pair)


# Self-registration on import AND an explicit re-entrant hook for the
# workflow bootstrap (importlib returns cached modules without re-running
# module bodies, so bootstrap must be able to call register() itself).
register()
