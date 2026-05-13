"""RBAC — tool and table access checks."""

import pytest

from mcp_shield import Identity, Policy
from mcp_shield.policy import RBACRule
from mcp_shield.policy.rbac import AccessDenied, check_tables, check_tool


def _id(*roles: str) -> Identity:
    return Identity(user_id="u", roles=roles, session_id="s")


def test_check_tool_allows_when_role_grants():
    policy = Policy(rbac=[RBACRule(role="analyst", allow_tools=["read_query"])])
    check_tool(_id("analyst"), "read_query", policy)


def test_check_tool_denies_unmatched_tool():
    policy = Policy(rbac=[RBACRule(role="analyst", allow_tools=["read_query"])])
    with pytest.raises(AccessDenied):
        check_tool(_id("analyst"), "write_query", policy)


def test_check_tool_denies_when_no_role_matches():
    policy = Policy(rbac=[RBACRule(role="analyst", allow_tools=["read_query"])])
    with pytest.raises(AccessDenied, match="no role"):
        check_tool(_id("nobody"), "read_query", policy)


def test_check_tables_allows_role_table():
    policy = Policy(rbac=[RBACRule(role="analyst", allow_tables=["orders"])])
    check_tables(_id("analyst"), ["orders"], policy)


def test_check_tables_denies_table_not_in_allow_list():
    policy = Policy(rbac=[RBACRule(role="analyst", allow_tables=["orders"])])
    with pytest.raises(AccessDenied, match="customers"):
        check_tables(_id("analyst"), ["customers"], policy)


def test_check_tables_respects_global_deny():
    policy = Policy(
        rbac=[RBACRule(role="analyst", allow_tables=["orders", "users_credentials"])],
        deny_tables=["users_credentials"],
    )
    with pytest.raises(AccessDenied, match="globally denied"):
        check_tables(_id("analyst"), ["users_credentials"], policy)


def test_check_tables_unions_multiple_roles():
    policy = Policy(
        rbac=[
            RBACRule(role="analyst", allow_tables=["orders"]),
            RBACRule(role="ops", allow_tables=["jobs"]),
        ]
    )
    check_tables(_id("analyst", "ops"), ["orders", "jobs"], policy)


def test_check_tables_empty_list_is_noop():
    check_tables(_id("analyst"), [], Policy())
