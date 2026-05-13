"""Output column masking applied after the database returns a result set."""

from __future__ import annotations

from typing import Any

from ..identity import Identity
from .loader import Policy

Row = dict[str, Any]


def redact_rows(rows: list[Row], *, table: str, identity: Identity, policy: Policy) -> list[Row]:
    """Apply column masks to a result set. Returns a new list of new dicts —
    callers can keep the originals for logging without worrying about mutation.

    The ``identity`` argument is accepted for forward compatibility; current
    rules apply uniformly regardless of role.
    """
    del identity
    masks_by_column = {r.column: r.mask for r in policy.redaction if r.table == table}
    if not masks_by_column:
        return [dict(row) for row in rows]

    out: list[Row] = []
    for row in rows:
        new_row = dict(row)
        for column, mask in masks_by_column.items():
            if column in new_row:
                new_row[column] = mask_value(new_row[column], mask)
        out.append(new_row)
    return out


def mask_value(value: Any, mask: str) -> Any:
    """Apply a named mask to a single value. Unknown masks fall back to ``full``."""
    if value is None:
        return None
    masker = _MASKS.get(mask, _mask_full)
    return masker(value)


def _mask_full(_: Any) -> str:
    return "***"


def _mask_email(value: Any) -> str:
    text = str(value)
    if "@" not in text:
        return _mask_full(text)
    local, _, domain = text.partition("@")
    if not local:
        return f"***@{domain}"
    head = local[0]
    return f"{head}***@{domain}"


def _mask_name(value: Any) -> str:
    text = str(value).strip()
    if not text:
        return ""
    parts = text.split()
    return " ".join((p[0] + "." if p else p) for p in parts)


_MASKS: dict[str, Any] = {
    "full": _mask_full,
    "email": _mask_email,
    "name": _mask_name,
}
