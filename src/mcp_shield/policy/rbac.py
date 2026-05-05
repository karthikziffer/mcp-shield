"""Role-based access checks for tools and tables."""

from __future__ import annotations

from ..identity import Identity
from .loader import Policy


class AccessDenied(Exception):
    pass


def check_tool(identity: Identity, tool_name: str, policy: Policy) -> None:
    """Raise AccessDenied if the identity may not invoke the named tool."""
    raise NotImplementedError


def check_tables(identity: Identity, tables: list[str], policy: Policy) -> None:
    """Raise AccessDenied if the identity may not read any of these tables."""
    raise NotImplementedError
