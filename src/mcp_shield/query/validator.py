"""Structural validation: function whitelist, statement type, suspicious patterns."""

from __future__ import annotations

from .parser import ParsedQuery


class ValidationError(Exception):
    pass


def validate(
    parsed: ParsedQuery,
    *,
    allowed_functions: set[str],
    allow_writes: bool = False,
) -> None:
    """Raise ValidationError if the query uses disallowed functions, statement
    types, or structurally suspicious constructs (e.g. recursive CTEs when
    disabled, multi-statement payloads, comment-based injection)."""
    raise NotImplementedError
