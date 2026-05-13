"""Row-level security predicates per role + table."""

from __future__ import annotations

import re

from ..identity import Identity
from .loader import Policy

_CLAIM_PLACEHOLDER = re.compile(r"\{identity\.claims\[(?P<key>[^\]]+)\]\}")


class MissingClaim(Exception):
    pass


def predicates_for(identity: Identity, tables: list[str], policy: Policy) -> dict[str, str]:
    """Return {table: SQL predicate} for every table the identity touches.

    For tables matched by multiple roles the predicates are OR-combined — any
    role that grants access wins. Claim placeholders ``{identity.claims[KEY]}``
    are substituted with the identity's claim value, SQL-escaped for safe
    interpolation into a string literal.
    """
    role_set = set(identity.roles)
    requested = set(tables)
    by_table: dict[str, list[str]] = {}

    for rule in policy.rls:
        if rule.role not in role_set or rule.table not in requested:
            continue
        predicate = _substitute_claims(rule.predicate, identity)
        by_table.setdefault(rule.table, []).append(predicate)

    return {table: _combine(predicates) for table, predicates in by_table.items()}


def _substitute_claims(predicate: str, identity: Identity) -> str:
    def replace(match: re.Match[str]) -> str:
        key = match.group("key")
        if key not in identity.claims:
            raise MissingClaim(f"identity is missing required claim {key!r}")
        return _sql_escape(identity.claims[key])

    return _CLAIM_PLACEHOLDER.sub(replace, predicate)


def _sql_escape(value: object) -> str:
    """Escape a claim value for safe interpolation. We assume the placeholder
    sits inside string-literal quotes in the predicate template, so we only
    need to neutralize single quotes by doubling them."""
    return str(value).replace("'", "''")


def _combine(predicates: list[str]) -> str:
    if len(predicates) == 1:
        return predicates[0]
    return " OR ".join(f"({p})" for p in predicates)
