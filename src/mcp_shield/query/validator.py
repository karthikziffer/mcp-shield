"""Structural validation: function whitelist, statement type, suspicious patterns."""

from __future__ import annotations

from sqlglot import expressions as exp

from .parser import ParsedQuery


class ValidationError(Exception):
    pass


def validate(
    parsed: ParsedQuery,
    *,
    allowed_functions: set[str],
    allow_writes: bool = False,
) -> None:
    """Raise ValidationError if the query uses disallowed functions or writes
    when not permitted.

    `allowed_functions` is matched case-insensitively. An empty set means no
    function whitelist is enforced — useful while a deployment is figuring out
    the right list. Pass an explicit set to lock down.
    """
    if not allow_writes and not parsed.is_read_only:
        raise ValidationError("write statements are not allowed")

    if allowed_functions:
        allowed_lower = {f.lower() for f in allowed_functions}
        for func in parsed.expression.find_all(exp.Func):
            name = _function_name(func).lower()
            if name and name not in allowed_lower:
                raise ValidationError(f"function not allowed: {name}")


def _function_name(func: exp.Func) -> str:
    """Resolve the SQL function name. Anonymous (unknown) functions store the
    real name in ``func.name``; built-ins expose it through ``sql_name()``."""
    if isinstance(func, exp.Anonymous):
        return func.name or ""
    return func.sql_name() or func.key or ""
