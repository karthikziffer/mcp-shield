"""Role-based access checks for tools and tables."""

from __future__ import annotations

from ..identity import Identity
from .loader import Policy, RBACRule


class AccessDenied(Exception):
    pass


def check_tool(identity: Identity, tool_name: str, policy: Policy) -> None:
    """Raise AccessDenied if none of the identity's roles allow this tool."""
    rules = _rules_for(identity, policy)
    if not rules:
        raise AccessDenied(f"no role grants access to tool {tool_name!r}")
    if not any(tool_name in r.allow_tools for r in rules):
        raise AccessDenied(f"tool {tool_name!r} not allowed for roles {list(identity.roles)}")


def check_tables(identity: Identity, tables: list[str], policy: Policy) -> None:
    """Raise AccessDenied if any table is denied globally, denied for any of the
    identity's roles, or not in the union of allow_tables across those roles."""
    if not tables:
        return

    denied_globally = set(policy.deny_tables)
    rules = _rules_for(identity, policy)
    if not rules:
        raise AccessDenied(f"no role grants table access for roles {list(identity.roles)}")

    allowed_union: set[str] = set()
    role_denied: set[str] = set()
    for rule in rules:
        allowed_union.update(rule.allow_tables)
        role_denied.update(rule.deny_tables)

    for table in tables:
        if table in denied_globally:
            raise AccessDenied(f"table {table!r} is globally denied")
        if table in role_denied:
            raise AccessDenied(f"table {table!r} is denied for roles {list(identity.roles)}")
        if table not in allowed_union:
            raise AccessDenied(
                f"table {table!r} is not in allow_tables for roles {list(identity.roles)}"
            )


def _rules_for(identity: Identity, policy: Policy) -> list[RBACRule]:
    role_set = set(identity.roles)
    return [r for r in policy.rbac if r.role in role_set]
