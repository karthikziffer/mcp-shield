"""Output column masking applied after the database returns a result set."""

from __future__ import annotations

from typing import Any

from ..identity import Identity
from .loader import Policy

Row = dict[str, Any]


def redact_rows(rows: list[Row], *, table: str, identity: Identity, policy: Policy) -> list[Row]:
    """Apply column masks to a result set in-place semantics (returns a new list)."""
    raise NotImplementedError


def mask_value(value: Any, mask: str) -> Any:
    """Apply a named mask (e.g. 'name', 'email', 'full') to a single value."""
    raise NotImplementedError
