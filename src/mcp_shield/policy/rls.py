"""Row-level security predicates per role + table."""

from __future__ import annotations

from ..identity import Identity
from .loader import Policy


def predicates_for(identity: Identity, tables: list[str], policy: Policy) -> dict[str, str]:
    """Return {table: SQL predicate} for every table the identity touches.

    Predicates may reference identity claims via ``{identity.claims[key]}`` style
    placeholders; the rewriter is responsible for safe substitution.
    """
    raise NotImplementedError
