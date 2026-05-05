"""SQL rewriting: inject RLS predicates, cap rows with LIMIT, drop denied columns."""

from __future__ import annotations

from .parser import ParsedQuery


def rewrite(
    parsed: ParsedQuery,
    *,
    rls_predicates: dict[str, str],
    deny_columns: dict[str, list[str]],
    default_limit: int,
) -> str:
    """Return a rewritten SQL string with RLS, column deny-list, and LIMIT applied."""
    raise NotImplementedError
